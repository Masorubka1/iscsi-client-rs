// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use tracing::debug;

use crate::{
    client::client::ClientConnection,
    models::{
        common::HEADER_LEN,
        data_fromat::PDUWithData,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

#[derive(Debug)]
pub struct NopCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: &'a AtomicU32,
    pub ttt: u32,
    pub buf: [u8; HEADER_LEN],

    last_response: Option<PDUWithData<NopInResponse>>,
    state: Option<NopStates>,
}

impl<'a> NopCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: u64,
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        ttt: u32,
    ) -> Self {
        Self {
            conn,
            lun,
            itt: itt.load(Ordering::SeqCst),
            cmd_sn: cmd_sn.load(Ordering::SeqCst),
            exp_stat_sn,
            ttt,
            buf: [0u8; HEADER_LEN],
            state: Some(NopStates::Start(Start)),
            last_response: None,
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
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        response: PDUWithData<NopInResponse>,
    ) -> Result<Self> {
        let (lun, ttt) = {
            let header = response.header_view()?;
            (header.lun.get(), header.target_task_tag.get())
        };

        let mut s = Self::new(conn, lun, itt, cmd_sn, exp_stat_sn, ttt);
        s.last_response = Some(response);

        s.state = Some(NopStates::Reply(Reply));
        Ok(s)
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

        let builder: PDUWithData<NopOutRequest> =
            PDUWithData::from_header_slice(self.buf);
        self.conn.send_request(self.itt, builder).await?;
        Ok(())
    }

    async fn recieve_nop_in(&self) -> Result<()> {
        match self.conn.read_response::<NopInResponse>(self.itt).await {
            Ok(_rsp) => Ok(()),
            Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct Start;
#[derive(Debug)]
pub struct Wait;
#[derive(Debug)]
pub struct Reply;

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
            let (lun, ttt) = { (ctx.lun, ctx.ttt) };

            let (stat_sn, exp_cmd_sn) = {
                let last = match ctx.validate_last_response_header() {
                    Ok(last) => last,
                    Err(e) => return Transition::Done(Err(e)),
                };
                (last.stat_sn.get(), last.exp_cmd_sn.get())
            };

            // ITT for response NOP-In = 0xFFFF_FFFF
            // TTT — copy from NOP-In (ctx.ttt)
            let hdr = NopOutRequestBuilder::new()
                .immediate()
                .lun(lun)
                .initiator_task_tag(u32::MAX)
                .target_task_tag(ttt)
                .cmd_sn(stat_sn)
                .exp_stat_sn(exp_cmd_sn)
                .header;

            if let Err(e) = hdr.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }
            let pdu: PDUWithData<NopOutRequest> = PDUWithData::from_header_slice(ctx.buf);

            // Response — fire-and-forget
            if let Err(e) = ctx.conn.send_segment(pdu).await {
                return Transition::Done(Err(e));
            }

            Transition::Done(Ok(()))
        })
    }
}

impl<'ctx> StateMachineCtx<NopCtx<'ctx>> for NopCtx<'ctx> {
    async fn execute(&mut self) -> Result<()> {
        debug!("Loop Nop");
        loop {
            let state = self.state.take().context("state must be set NopCtx")?;
            let trans = match state {
                NopStates::Start(s) => s.step(self).await,
                NopStates::Wait(s) => s.step(self).await,
                NopStates::Reply(s) => s.step(self).await,
            };

            match trans {
                Transition::Next(next_state, r) => {
                    r?;
                    self.state = Some(next_state);
                },
                Transition::Stay(Ok(_)) => {},
                Transition::Stay(Err(e)) => return Err(e),
                Transition::Done(err) => {
                    return err;
                },
            }
        }
    }
}
