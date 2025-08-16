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
        common::SendingData,
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
                .task_attribute(TaskAttribute::Simple)
                .header;

            let builder: PDUWithData<ScsiCommandRequest> =
                PDUWithData::from_header(header);

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
            let mut buf = vec![0u8; ctx.read_len as usize];
            let mut filled_hi = 0usize;
            let mut done = false;

            // Получаем PDUs до статуса (S) или SCSI Response
            while !done {
                let pdu: PDUWithData<ScsiDataIn> =
                    match ctx.conn.read_response(self.pending.itt).await {
                        Ok(p) => p,
                        Err(e) => {
                            return Transition::Done(Err(anyhow!("unexpected PDU: {e}")));
                        },
                    };

                let off = pdu.header.buffer_offset as usize;
                let len = pdu.data.len();

                if off
                    .checked_add(len)
                    .map(|e| e <= buf.len())
                    .unwrap_or(false)
                {
                    buf[off..off + len].copy_from_slice(&pdu.data);
                    if off + len > filled_hi {
                        filled_hi = off + len;
                    }
                } else {
                    return Transition::Done(Err(anyhow!(
                        "target sent more data than expected: off={} len={} cap={}",
                        off,
                        len,
                        buf.len()
                    )));
                }

                if pdu.header.stat_sn_or_rsvd != 0 {
                    let next_esn = pdu.header.stat_sn_or_rsvd.wrapping_add(1);
                    ctx.exp_stat_sn.store(next_esn, Ordering::SeqCst);
                }

                let status_present = pdu.header.get_final_bit();
                if status_present {
                    done = true;
                }
            }

            if filled_hi < buf.len() {
                buf.truncate(filled_hi);
            }

            let out = ReadResult {
                itt: self.pending.itt,
                cmd_sn: self.pending.cmd_sn,
                exp_stat_sn: ctx.exp_stat_sn.load(Ordering::SeqCst),
                data: buf,
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
