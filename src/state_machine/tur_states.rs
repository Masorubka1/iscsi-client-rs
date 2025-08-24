// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Result, bail};

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
        data_fromat::PDUWithData,
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct TurCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub lun: u64,
    pub buf: [u8; HEADER_LEN],
    pub cbd: [u8; 16],
}

impl<'a> TurCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        lun: u64,
    ) -> Self {
        Self {
            conn,
            itt,
            cmd_sn,
            exp_stat_sn,
            lun,
            buf: [0u8; HEADER_LEN],
            cbd: [0u8; 16],
        }
    }

    async fn send_tur(&mut self) -> Result<TurStatus> {
        build_test_unit_ready(&mut self.cbd, 0);

        let itt = self.itt.fetch_add(1, Ordering::SeqCst);
        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.fetch_add(1, Ordering::SeqCst);

        let header = ScsiCommandRequestBuilder::new()
            .initiator_task_tag(itt)
            .lun(self.lun)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn)
            .task_attribute(TaskAttribute::Simple)
            .read()
            .write()
            .expected_data_transfer_length(0)
            .scsi_descriptor_block(&self.cbd);

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;
        let pdu: PDUWithData<ScsiCommandRequest> =
            PDUWithData::from_header_slice(self.buf);
        self.conn.send_request(itt, pdu).await?;

        Ok(TurStatus {
            itt,
            cmd_sn,
            exp_stat_sn,
        })
    }

    async fn recv_tur_resp(&self, expected: TurStatus) -> Result<()> {
        let TurStatus { itt, .. } = expected;

        let rsp = self.conn.read_response::<ScsiCommandResponse>(itt).await?;
        let hv = rsp.header_view()?;

        // SCSI Status == GOOD (0x00)
        let scsi_status = hv.status.decode()?;
        if scsi_status != ScsiStatus::Good {
            bail!("TEST UNIT READY failed: {:?}", rsp);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TurStatus {
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

pub struct Idle;
pub struct Wait {
    pending: TurStatus,
}

pub enum TurStates {
    Idle(Idle),
    Wait(Wait),
}

type TurStepOut = Transition<TurStates, Result<TurStatus>>;

impl<'ctx> StateMachine<TurCtx<'ctx>, TurStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = TurStepOut> + Send + 'a>>
    where
        Self: 'a,
        TurCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut TurCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_tur().await {
                Ok(st) => Transition::Next(
                    TurStates::Wait(Wait {
                        pending: st.clone(),
                    }),
                    Ok(st),
                ),
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

    fn step<'a>(&'a mut self, ctx: &'a mut TurCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.recv_tur_resp(self.pending.clone()).await {
                Ok(()) => Transition::Done(Ok(self.pending.clone())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

pub async fn run_tur(mut state: TurStates, ctx: &mut TurCtx<'_>) -> Result<TurStatus> {
    loop {
        let trans = match &mut state {
            TurStates::Idle(s) => s.step(ctx).await,
            TurStates::Wait(s) => s.step(ctx).await,
        };

        match trans {
            Transition::Next(next_state, _r) => state = next_state,
            Transition::Stay(Ok(_)) => {},
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(r) => return r,
        }
    }
}
