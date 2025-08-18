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
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        data::{response::ScsiDataIn, sense_data::SenseData},
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

#[derive(Debug, Clone)]
struct PendingRead {
    itt: u32,
    cmd_sn: u32,
}

pub struct ReadStart;
pub struct ReadWaitData {
    pending: PendingRead,
}

pub struct ReadWaitResp {
    pending: PendingRead,
    buf: Vec<u8>,
    filled_hi: usize,
    expected: usize,
    status_in_datain: Option<ScsiStatus>,
    residual_in_datain: Option<u32>,
}

pub enum ReadStates {
    Start(ReadStart),
    WaitData(ReadWaitData),
    WaitResp(ReadWaitResp),
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
                ReadStates::WaitData(ReadWaitData { pending }),
                Ok(ReadResult {
                    itt,
                    cmd_sn: sn,
                    exp_stat_sn: esn,
                    data: vec![],
                }),
            )
        })
    }
}

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for ReadWaitData {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let expected = ctx.read_len as usize;
            let mut buf = vec![0u8; expected];
            let mut filled_hi = 0usize;

            let mut status_in_datain: Option<ScsiStatus> = None;
            let mut residual_in_datain: Option<u32> = None;

            loop {
                let pdu: PDUWithData<ScsiDataIn> =
                    match ctx.conn.read_response(self.pending.itt).await {
                        Ok(p) => p,
                        Err(e) => {
                            return Transition::Done(Err(anyhow!(
                                "unexpected PDU while Data-In: {e}"
                            )));
                        },
                    };

                let off = pdu.header.buffer_offset as usize;
                let len = pdu.data.len();
                if off
                    .checked_add(len)
                    .map(|e| e <= buf.len())
                    .unwrap_or(false)
                {
                    if len != 0 {
                        buf[off..off + len].copy_from_slice(&pdu.data);
                        filled_hi = filled_hi.max(off + len);
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
                    ctx.exp_stat_sn.store(
                        pdu.header.stat_sn_or_rsvd.wrapping_add(1),
                        Ordering::SeqCst,
                    );
                }

                let final_bit = pdu.header.get_real_final_bit();
                let s_bit = pdu.header.get_status_bit();

                if s_bit {
                    status_in_datain = pdu.header.scsi_status().cloned();
                    residual_in_datain = Some(pdu.header.residual_count);
                }

                if final_bit {
                    break;
                }
            }

            let next = ReadWaitResp {
                pending: self.pending.clone(),
                buf,
                filled_hi,
                expected,
                status_in_datain,
                residual_in_datain,
            };

            Transition::Next(
                ReadStates::WaitResp(next),
                Ok(ReadResult {
                    itt: self.pending.itt,
                    cmd_sn: self.pending.cmd_sn,
                    exp_stat_sn: ctx.exp_stat_sn.load(Ordering::SeqCst),
                    data: vec![],
                }),
            )
        })
    }
}

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for ReadWaitResp {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let (status_u8, residual, sense_opt) = if let Some(st) =
                self.status_in_datain.clone()
            {
                if st == ScsiStatus::Good {
                    (st, self.residual_in_datain.unwrap_or(0), None)
                } else {
                    let rsp: PDUWithData<ScsiCommandResponse> =
                        match ctx.conn.read_response(self.pending.itt).await {
                            Ok(p) => p,
                            Err(e) => {
                                return Transition::Done(Err(anyhow!(
                                    "expected ScsiCommandResponse after S=1 Data-In: {e}"
                                )));
                            },
                        };
                    ctx.exp_stat_sn
                        .store(rsp.header.stat_sn.wrapping_add(1), Ordering::SeqCst);
                    (
                        st,
                        rsp.header.residual_count,
                        if rsp.data.is_empty() {
                            None
                        } else {
                            Some(rsp.data)
                        },
                    )
                }
            } else {
                let rsp: PDUWithData<ScsiCommandResponse> =
                    match ctx.conn.read_response(self.pending.itt).await {
                        Ok(p) => p,
                        Err(e) => {
                            return Transition::Done(Err(anyhow!(
                                "expected ScsiCommandResponse after Data-In FINAL: {e}"
                            )));
                        },
                    };
                ctx.exp_stat_sn
                    .store(rsp.header.stat_sn.wrapping_add(1), Ordering::SeqCst);
                (
                    rsp.header.status.clone(),
                    rsp.header.residual_count,
                    if rsp.data.is_empty() {
                        None
                    } else {
                        Some(rsp.data)
                    },
                )
            };

            if status_u8 != ScsiStatus::Good {
                if let Some(sb) = sense_opt {
                    if let Ok(sense) = SenseData::parse(&sb) {
                        return Transition::Done(Err(anyhow!(
                            "SCSI CheckCondition: {:?}",
                            sense
                        )));
                    } else {
                        return Transition::Done(Err(anyhow!(
                            "SCSI CheckCondition (sense {} bytes): {:02X?}",
                            sb.len(),
                            sb
                        )));
                    }
                } else {
                    return Transition::Done(Err(anyhow!(
                        "SCSI status != GOOD ({:?}) and no sense provided",
                        status_u8
                    )));
                }
            }

            let got = self.filled_hi;
            if got != self.expected {
                return Transition::Done(Err(anyhow!(
                    "short/long read: expected {} bytes, got {}; residual={}",
                    self.expected,
                    got,
                    residual
                )));
            }

            let mut data = self.buf.clone();
            data.truncate(self.expected);

            let out = ReadResult {
                itt: self.pending.itt,
                cmd_sn: self.pending.cmd_sn,
                exp_stat_sn: ctx.exp_stat_sn.load(Ordering::SeqCst),
                data,
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
            ReadStates::WaitData(s) => s.step(ctx).await,
            ReadStates::WaitResp(s) => s.step(ctx).await,
        };

        match tr {
            Transition::Next(next, _r) => {
                state = next;
            },
            Transition::Stay(Ok(_)) => { /* tick */ },
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(result) => return result,
        }
    }
}
