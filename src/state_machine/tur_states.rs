// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    client::client::ClientConnection,
    control_block::test_unit_ready::build_test_unit_ready,
    models::{
        command::{
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::HEADER_LEN,
        data_fromat::{PduRequest, PduResponse},
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

#[derive(Debug)]
pub struct TurCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub itt: u32,
    pub cmd_sn: Arc<AtomicU32>,
    pub exp_stat_sn: Arc<AtomicU32>,
    pub lun: u64,
    pub buf: [u8; HEADER_LEN],
    pub cbd: [u8; 16],

    pub last_response: Option<PduResponse<ScsiCommandResponse>>,
    state: Option<TurStates>,
}

impl<'a> TurCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        lun: u64,
    ) -> Self {
        Self {
            conn,
            itt: itt.fetch_add(1, Ordering::SeqCst),
            cmd_sn,
            exp_stat_sn,
            lun,
            buf: [0u8; HEADER_LEN],
            cbd: [0u8; 16],
            last_response: None,
            state: Some(TurStates::Idle(Idle)),
            _lt: PhantomData,
        }
    }

    async fn send_tur(&mut self) -> Result<()> {
        build_test_unit_ready(&mut self.cbd, 0);

        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let esn = self.exp_stat_sn.load(Ordering::SeqCst);

        let header = ScsiCommandRequestBuilder::new()
            .initiator_task_tag(self.itt)
            .lun(self.lun)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(esn)
            .task_attribute(TaskAttribute::Simple)
            .expected_data_transfer_length(0)
            .scsi_descriptor_block(&self.cbd);

        header.header.to_bhs_bytes(&mut self.buf)?;
        let pdu = PduRequest::<ScsiCommandRequest>::new_request(self.buf, &self.conn.cfg);

        self.conn.send_request(self.itt, pdu).await?;
        Ok(())
    }

    async fn recv_tur_resp(&mut self) -> Result<()> {
        let rsp = self
            .conn
            .read_response::<ScsiCommandResponse>(self.itt)
            .await?;
        self.last_response = Some(rsp);

        let lr = self.last_response.as_ref().expect("saved above");
        let hv = lr.header_view()?;

        self.exp_stat_sn
            .store(hv.stat_sn.get().wrapping_add(1), Ordering::SeqCst);

        let scsi_status = hv.status.decode()?;
        if scsi_status != ScsiStatus::Good {
            let data = lr.data()?;
            if !data.is_empty() {
                bail!(
                    "TEST UNIT READY failed: status={:?}, sense ({} bytes)={:02X?}",
                    scsi_status,
                    data.len(),
                    data
                );
            }
            bail!("TEST UNIT READY failed: status={:?}", scsi_status);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Idle;
#[derive(Debug)]
pub struct Wait;

#[derive(Debug)]
pub enum TurStates {
    Idle(Idle),
    Wait(Wait),
}

type TurStepOut = Transition<TurStates, Result<()>>;

impl<'ctx> StateMachine<TurCtx<'ctx>, TurStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = TurStepOut> + Send + 'a>>
    where
        Self: 'a,
        TurCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut TurCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_tur().await {
                Ok(()) => Transition::Next(TurStates::Wait(Wait), Ok(())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<TurCtx<'ctx>, TurStepOut> for Wait {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = TurStepOut> + Send + 'a>>
    where
        Self: 'a,
        TurCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut TurCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.recv_tur_resp().await {
                Ok(()) => Transition::Done(Ok(())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachineCtx<TurCtx<'ctx>, PduResponse<ScsiCommandResponse>>
    for TurCtx<'ctx>
{
    async fn execute(
        &mut self,
        _cancel: &CancellationToken,
    ) -> Result<PduResponse<ScsiCommandResponse>> {
        debug!("Loop TUR");

        loop {
            let state = self.state.take().context("state must be set TurCtx")?;
            let tr = match state {
                TurStates::Idle(s) => s.step(self).await,
                TurStates::Wait(s) => s.step(self).await,
            };

            match tr {
                Transition::Next(next, r) => {
                    r?;
                    self.state = Some(next);
                },
                Transition::Stay(Ok(_)) => {},
                Transition::Stay(Err(e)) => return Err(e),
                Transition::Done(r) => {
                    r?;
                    return self
                        .last_response
                        .take()
                        .ok_or_else(|| anyhow!("no last response in ctx"));
                },
            }
        }
    }
}
