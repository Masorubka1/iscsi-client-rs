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
        data_fromat::{PduRequest, PduResponse},
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

/// This structure represents the context for a NOP-Out/NOP-In exchange.
///
/// It holds all the necessary information to manage the state of a NOP-Out/NOP-In operation,
/// including connection details and command parameters.
#[derive(Debug)]
pub struct NopCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: Arc<AtomicU32>,
    pub ttt: u32,
    pub buf: [u8; HEADER_LEN],

    last_response: Option<PduResponse<NopInResponse>>,
    state: Option<NopStates>,
}

impl<'a> NopCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: u64,
        itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        ttt: u32,
    ) -> Self {
        Self {
            conn,
            lun,
            itt: itt.fetch_add(1, Ordering::SeqCst),
            cmd_sn: cmd_sn.load(Ordering::SeqCst),
            exp_stat_sn,
            ttt,
            buf: [0u8; HEADER_LEN],
            state: Some(NopStates::Start(Start)),
            last_response: None,
            _lt: PhantomData,
        }
    }

    pub fn set_default_state(&mut self) {
        self.state = Some(NopStates::Start(Start));
    }

    pub fn validate_last_response_header(&mut self) -> Result<&NopInResponse> {
        match &self.last_response {
            Some(l) => match l.header_view() {
                Ok(last) => {
                    self.exp_stat_sn
                        .store(last.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
                    Ok(last)
                },
                Err(e) => Err(e),
            },
            None => Err(anyhow!("no last response in ctx")),
        }
    }

    pub fn for_reply(
        conn: Arc<ClientConnection>,
        _itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        response: PduResponse<NopInResponse>,
    ) -> Result<Self> {
        let header = response.header_view()?;
        Ok(Self {
            conn,
            lun: 0,
            itt: 0,
            cmd_sn: cmd_sn.load(Ordering::SeqCst),
            exp_stat_sn,
            ttt: header.target_task_tag.get(),
            buf: [0u8; HEADER_LEN],
            last_response: Some(response),
            state: Some(NopStates::Reply(Reply)),
            _lt: PhantomData,
        })
    }

    async fn send_nop_out(&mut self) -> Result<()> {
        let exp_stat_sn = self.exp_stat_sn.load(Ordering::SeqCst);

        let header = NopOutRequestBuilder::new()
            .cmd_sn(self.cmd_sn)
            .lun(self.lun)
            .initiator_task_tag(self.itt)
            .target_task_tag(self.ttt)
            .exp_stat_sn(exp_stat_sn)
            .immediate();

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;

        let builder = PduRequest::<NopOutRequest>::new_request(self.buf, &self.conn.cfg);
        self.conn.send_request(self.itt, builder).await?;
        Ok(())
    }

    async fn recieve_nop_in(&mut self) -> Result<()> {
        match self.conn.read_response::<NopInResponse>(self.itt).await {
            Ok(rsp) => {
                self.last_response = Some(rsp);
                Ok(())
            },
            Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
        }
    }
}

/// Represents the initial state of a NOP-Out operation.
#[derive(Debug)]
pub struct Start;

/// Represents the state of waiting for a NOP-In response.
#[derive(Debug)]
pub struct Wait;

/// Represents the state of sending a NOP-Out in reply to a NOP-In.
#[derive(Debug)]
pub struct Reply;

/// Defines the possible states for a NOP-Out/NOP-In operation state machine.
#[derive(Debug)]
pub enum NopStates {
    Start(Start),
    Wait(Wait),
    Reply(Reply),
}

type NopStepOut = Transition<NopStates, Result<()>>;

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Start {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_nop_out().await {
                Ok(st) => Transition::Next(NopStates::Wait(Wait), Ok(st)),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Wait {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.recieve_nop_in().await {
                Ok(()) => Transition::Done(Ok(())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Reply {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            if let Err(e) = ctx.validate_last_response_header() {
                return Transition::Done(Err(e));
            }

            // ITT for response NOP-In = 0xFFFF_FFFF
            // TTT — copy from NOP-In (ctx.ttt)
            let hdr = NopOutRequestBuilder::new()
                .immediate()
                .lun(0)
                .initiator_task_tag(u32::MAX)
                .target_task_tag(ctx.ttt)
                .cmd_sn(ctx.cmd_sn)
                .exp_stat_sn(ctx.exp_stat_sn.load(Ordering::SeqCst))
                .header;

            if let Err(e) = hdr.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }
            let pdu = PduRequest::<NopOutRequest>::new_request(ctx.buf, &ctx.conn.cfg);

            // Response — fire-and-forget
            if let Err(e) = ctx.conn.send_request(u32::MAX, pdu).await {
                return Transition::Done(Err(e));
            }

            Transition::Done(Ok(()))
        })
    }
}

impl<'s> StateMachineCtx<NopCtx<'s>, PduResponse<NopInResponse>> for NopCtx<'s> {
    async fn execute(
        &mut self,
        _cancel: &CancellationToken,
    ) -> Result<PduResponse<NopInResponse>> {
        debug!("Loop Nop");
        loop {
            let state = self.state.take().context("state must be set NopCtx")?;
            let trans = match state {
                NopStates::Start(s) => s.step(self).await,
                NopStates::Wait(s) => s.step(self).await,
                NopStates::Reply(s) => s.step(self).await,
            };

            match trans {
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
