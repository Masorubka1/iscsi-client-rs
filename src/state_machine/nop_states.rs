// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Result, anyhow, bail};

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
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct NopCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub ttt: u32,
    pub buf: [u8; HEADER_LEN],

    pub reply_from_in: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct NopStatus {
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
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
            itt,
            cmd_sn,
            exp_stat_sn,
            ttt,
            buf: [0u8; HEADER_LEN],
            reply_from_in: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_reply(
        conn: Arc<ClientConnection>,
        lun: u64,
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        ttt: u32,
        exp_cmd_sn_from_in: u32,
        stat_sn_from_in: u32,
    ) -> Self {
        let mut s = Self::new(conn, lun, itt, cmd_sn, exp_stat_sn, ttt);
        s.reply_from_in = Some((exp_cmd_sn_from_in, stat_sn_from_in));
        s
    }

    async fn send_nop_out(&mut self) -> Result<NopStatus> {
        let cmd_sn = self.cmd_sn.load(Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.fetch_add(1, Ordering::SeqCst);
        let itt = self.itt.fetch_add(1, Ordering::SeqCst);

        let header = NopOutRequestBuilder::new()
            .cmd_sn(cmd_sn)
            .lun(self.lun)
            .initiator_task_tag(itt)
            .target_task_tag(self.ttt)
            .exp_stat_sn(exp_stat_sn)
            .immediate();

        let _ = header
            .header
            .to_bhs_bytes(self.buf.as_mut_slice())
            .map_err(|e| {
                Transition::<PDUWithData<NopInResponse>, anyhow::Error>::Done(e)
            });

        let builder: PDUWithData<NopOutRequest> =
            PDUWithData::from_header_slice(self.buf);
        self.conn.send_request(itt, builder).await?;
        Ok(NopStatus {
            itt,
            cmd_sn,
            exp_stat_sn,
        })
    }

    async fn recieve_nop_in(&self, exp_status: NopStatus) -> Result<()> {
        let NopStatus {
            itt,
            cmd_sn: _,
            exp_stat_sn: _,
        } = exp_status;
        match self.conn.read_response::<NopInResponse>(itt).await {
            Ok(_rsp) => Ok(()),
            Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
        }
    }
}

pub struct Idle;
pub struct Wait {
    pending: NopStatus,
}
pub struct Reply;

pub enum NopStates {
    Idle(Idle),
    Wait(Wait),
    Reply(Reply),
}

type NopStepOut = Transition<NopStates, Result<NopStatus>>;

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_nop_out().await {
                Ok(st) => Transition::Next(
                    NopStates::Wait(Wait {
                        pending: st.clone(),
                    }),
                    Ok(st),
                ),
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

    fn step<'a>(&'a mut self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.recieve_nop_in(self.pending.clone()).await {
                Ok(()) => Transition::Done(Ok(self.pending.clone())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<NopCtx<'ctx>, Transition<NopStates, Result<NopStatus>>>
    for Reply
{
    type StepResult<'a>
        = Pin<
        Box<dyn Future<Output = Transition<NopStates, Result<NopStatus>>> + Send + 'a>,
    >
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let (exp_cmd_from_in, stat_sn_from_in) = match ctx.reply_from_in {
                Some(v) => v,
                None => {
                    return Transition::Done(Err(anyhow!(
                        "Reply state requires reply_from_in"
                    )));
                },
            };

            let want_exp_stat = stat_sn_from_in.wrapping_add(1);
            let _ =
                ctx.exp_stat_sn
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                        Some(cur.max(want_exp_stat))
                    });
            let exp_stat_to_send = ctx.exp_stat_sn.load(Ordering::SeqCst);

            // ITT for response NOP-In = 0xFFFF_FFFF
            // TTT — copy from NOP-In (ctx.ttt)
            let hdr = NopOutRequestBuilder::new()
                .immediate()
                .lun(ctx.lun)
                .initiator_task_tag(u32::MAX)
                .target_task_tag(ctx.ttt)
                .cmd_sn(exp_cmd_from_in)
                .exp_stat_sn(exp_stat_to_send)
                .header;

            if let Err(e) = hdr.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }
            let pdu: PDUWithData<NopOutRequest> = PDUWithData::from_header_slice(ctx.buf);

            // Response — fire-and-forget
            if let Err(e) = ctx.conn.send_segment(pdu).await {
                return Transition::Done(Err(e));
            }

            let st = NopStatus {
                itt: u32::MAX,
                cmd_sn: exp_cmd_from_in,
                exp_stat_sn: exp_stat_to_send,
            };
            Transition::Done(Ok(st))
        })
    }
}

pub async fn run_nop(mut state: NopStates, ctx: &mut NopCtx<'_>) -> Result<NopStatus> {
    loop {
        let trans = match &mut state {
            NopStates::Idle(s) => s.step(ctx).await,
            NopStates::Wait(s) => s.step(ctx).await,
            NopStates::Reply(s) => s.step(ctx).await,
        };

        match trans {
            Transition::Next(next_state, _r) => {
                state = next_state;
            },
            Transition::Stay(Ok(_)) => {},
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(r) => return r,
        }
    }
}
