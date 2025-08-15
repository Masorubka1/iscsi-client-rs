use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Result, anyhow};

use crate::{
    client::client::ClientConnection,
    models::{
        command::{
            common::TaskAttribute,
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
        },
        data::response::ScsiDataIn,
        data_fromat::PDUWithData,
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct ReadCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub lun: [u8; 8],
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub read_len: u32,
    pub cdb: [u8; 16],
}

impl<'a> ReadCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: [u8; 8],
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        read_len: u32,
        cdb: [u8; 16],
    ) -> Self {
        Self {
            conn,
            lun,
            itt,
            cmd_sn,
            exp_stat_sn,
            read_len,
            cdb,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReadResult {
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    pub data: Vec<u8>,
}

/* ===== States & transitions ===== */

#[derive(Debug, Clone)]
struct PendingRead {
    itt: u32,
    cmd_sn: u32,
}

pub struct ReadStart;
pub struct ReadWait {
    pending: PendingRead,
}

pub enum ReadStates {
    Start(ReadStart),
    Wait(ReadWait),
}

type ReadStepOut = Transition<ReadStates, Result<ReadResult>>;

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for ReadStart {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let sn = ctx.cmd_sn.fetch_add(1, Ordering::SeqCst);
            let esn = ctx.exp_stat_sn.load(Ordering::SeqCst);
            let itt = ctx.itt.fetch_add(1, Ordering::SeqCst);

            let header = ScsiCommandRequestBuilder::new()
                .lun(&ctx.lun)
                .initiator_task_tag(itt)
                .cmd_sn(sn)
                .exp_stat_sn(esn)
                .expected_data_transfer_length(ctx.read_len)
                .scsi_descriptor_block(&ctx.cdb)
                .read()
                .task_attribute(TaskAttribute::Simple);

            let builder: PDUWithData<ScsiCommandRequest> =
                PDUWithData::from_header(header.header);

            if let Err(e) = ctx.conn.send_request(itt, builder).await {
                return Transition::Done(Err(e));
            }

            let pending = PendingRead { itt, cmd_sn: sn };

            Transition::Next(
                ReadStates::Wait(ReadWait { pending }),
                Ok(ReadResult {
                    itt,
                    cmd_sn: sn,
                    exp_stat_sn: esn,
                    data: Vec::with_capacity(ctx.read_len as usize),
                }),
            )
        })
    }
}

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for ReadWait {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let rsp = match ctx.conn.read_response::<ScsiDataIn>(self.pending.itt).await {
                Ok(r) => r,
                Err(e) => return Transition::Done(Err(anyhow!("unexpected PDU: {}", e))),
            };

            if rsp.header.stat_sn_or_rsvd != 0 {
                let next_esn = rsp.header.stat_sn_or_rsvd.wrapping_add(1);
                ctx.exp_stat_sn.store(next_esn, Ordering::SeqCst);
            }

            let out = ReadResult {
                itt: self.pending.itt,
                cmd_sn: self.pending.cmd_sn,
                exp_stat_sn: ctx.exp_stat_sn.load(Ordering::SeqCst),
                data: rsp.data,
            };
            Transition::Done(Ok(out))
        })
    }
}

pub async fn run_read(
    mut state: ReadStates,
    ctx: &mut ReadCtx<'_>,
) -> Result<ReadResult> {
    loop {
        let tr = match &mut state {
            ReadStates::Start(s) => s.step(ctx).await,
            ReadStates::Wait(s) => s.step(ctx).await,
        };

        match tr {
            Transition::Next(next, _r) => {
                state = next;
            },
            Transition::Stay(Ok(_)) => { /* progress tick */ },
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(result) => return result,
        }
    }
}
