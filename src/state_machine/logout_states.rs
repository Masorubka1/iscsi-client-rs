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
    models::{
        common::HEADER_LEN,
        data_fromat::PDUWithData,
        logout::{
            common::{LogoutReason, LogoutResponseCode},
            request::{LogoutRequest, LogoutRequestBuilder},
            response::LogoutResponse,
        },
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

#[derive(Debug)]
pub struct LogoutCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub itt: u32,
    pub cmd_sn: Arc<AtomicU32>,
    pub exp_stat_sn: Arc<AtomicU32>,
    pub cid: u16,
    pub reason: LogoutReason,
    pub buf: [u8; HEADER_LEN],

    pub last_response: Option<PDUWithData<LogoutResponse>>,
    state: Option<LogoutStates>,
}

impl<'a> LogoutCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        cid: u16,
        reason: LogoutReason,
    ) -> Self {
        Self {
            conn,
            itt: itt.fetch_add(1, Ordering::SeqCst),
            cmd_sn,
            exp_stat_sn,
            cid,
            reason,
            buf: [0u8; HEADER_LEN],
            state: Some(LogoutStates::Idle(Idle)),
            last_response: None,
            _lt: PhantomData,
        }
    }

    async fn send_logout(&mut self) -> Result<()> {
        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.load(Ordering::SeqCst);
        let header = LogoutRequestBuilder::new(self.reason.clone(), self.itt, self.cid)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn);

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;

        let builder: PDUWithData<LogoutRequest> =
            PDUWithData::from_header_slice(self.buf, &self.conn.cfg);
        self.conn.send_request(self.itt, builder).await?;

        Ok(())
    }

    async fn receive_logout_resp(&mut self) -> Result<()> {
        let rsp = self.conn.read_response::<LogoutResponse>(self.itt).await?;
        let hv = rsp.header_view()?;

        self.exp_stat_sn
            .store(hv.stat_sn.get().wrapping_add(1), Ordering::SeqCst);

        if hv.response.decode()? != LogoutResponseCode::Success {
            bail!("LogoutResp: target returned {:?}", hv.response);
        }

        self.last_response = Some(rsp);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Idle;

#[derive(Debug)]
pub struct Wait;

#[derive(Debug)]
pub enum LogoutStates {
    Idle(Idle),
    Wait(Wait),
}

type LogoutStepOut = Transition<LogoutStates, Result<()>>;

impl<'ctx> StateMachine<LogoutCtx<'ctx>, LogoutStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = LogoutStepOut> + Send + 'a>>
    where
        Self: 'a,
        LogoutCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LogoutCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_logout().await {
                Ok(st) => Transition::Next(LogoutStates::Wait(Wait), Ok(st)),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<LogoutCtx<'ctx>, LogoutStepOut> for Wait {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = LogoutStepOut> + Send + 'a>>
    where
        Self: 'a,
        LogoutCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LogoutCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.receive_logout_resp().await {
                Ok(()) => Transition::Done(Ok(())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachineCtx<LogoutCtx<'ctx>, PDUWithData<LogoutResponse>>
    for LogoutCtx<'ctx>
{
    async fn execute(
        &mut self,
        _cancel: &CancellationToken,
    ) -> Result<PDUWithData<LogoutResponse>> {
        debug!("Loop logout");
        loop {
            let state = self.state.take().context("state must be set LogoutCtx")?;
            let trans = match state {
                LogoutStates::Idle(s) => s.step(self).await,
                LogoutStates::Wait(s) => s.step(self).await,
            };

            match trans {
                Transition::Next(next_state, _r) => {
                    self.state = Some(next_state);
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
