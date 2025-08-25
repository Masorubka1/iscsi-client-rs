// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    vec,
};

use anyhow::{Result, anyhow};
use tracing::debug;

use crate::{
    client::client::ClientConnection,
    models::{
        command::{
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::{BasicHeaderSegment, HEADER_LEN},
        data::{response::ScsiDataIn, sense_data::SenseData},
        data_fromat::PDUWithData,
        opcode::{BhsOpcode, Opcode},
        parse::Pdu,
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub enum ReadPdu {
    DataIn(PDUWithData<ScsiDataIn>),
    CmdResp(PDUWithData<ScsiCommandResponse>),
}

#[derive(Debug)]
pub struct ReadCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub read_len: u32,
    pub cdb: [u8; 16],
    pub buf: [u8; HEADER_LEN],
}

impl<'a> ReadCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: u64,
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
            buf: [0u8; HEADER_LEN],
        }
    }

    pub async fn recv_any(&self, itt: u32) -> anyhow::Result<ReadPdu> {
        let (p_any, data): (PDUWithData<Pdu>, Vec<u8>) = self.conn.read_response_raw(itt).await?;
        let op = BhsOpcode::try_from(p_any.header_buf[0])?.opcode;
        let pdu_local = match op {
            Opcode::ScsiDataIn => Ok(ReadPdu::DataIn({
                let mut pdu = p_any.rebind_pdu::<ScsiDataIn>()?;

                let header = pdu.header_view()?;

                let hd = self
                    .conn
                    .cfg
                    .login
                    .negotiation
                    .header_digest
                    .eq_ignore_ascii_case("CRC32C");
                let hd = header.get_header_diggest(hd);
                let dd = self
                    .conn
                    .cfg
                    .login
                    .negotiation
                    .data_digest
                    .eq_ignore_ascii_case("CRC32C");
                let dd = header.get_data_diggest(dd);

                pdu.parse_with_buff(data.as_slice(), hd != 0, dd != 0)?;
                pdu
            })),
            Opcode::ScsiCommandResp => Ok(ReadPdu::CmdResp({
                let mut pdu = p_any.rebind_pdu::<ScsiCommandResponse>()?;

                let header = pdu.header_view()?;

                let hd = self
                    .conn
                    .cfg
                    .login
                    .negotiation
                    .header_digest
                    .eq_ignore_ascii_case("CRC32C");
                let hd = header.get_header_diggest(hd);
                let dd = self
                    .conn
                    .cfg
                    .login
                    .negotiation
                    .data_digest
                    .eq_ignore_ascii_case("CRC32C");
                let dd = header.get_data_diggest(dd);

                pdu.parse_with_buff(data.as_slice(), hd != 0, dd != 0)?;
                pdu
            })),
            other => anyhow::bail!("unexpected PDU opcode for read path: {other:?}"),
        };
        debug!("READ {pdu_local:?}");
        pdu_local
    }

    async fn send_read_request(&mut self) -> Result<(PendingRead, u32)> {
        let sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let esn = self.exp_stat_sn.load(Ordering::SeqCst);
        let itt = self.itt.fetch_add(1, Ordering::SeqCst);

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun)
            .initiator_task_tag(itt)
            .cmd_sn(sn)
            .exp_stat_sn(esn)
            .expected_data_transfer_length(self.read_len)
            .scsi_descriptor_block(&self.cdb)
            .read()
            .task_attribute(TaskAttribute::Simple);

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;

        let builder: PDUWithData<ScsiCommandRequest> = PDUWithData::from_header_slice(self.buf);
        self.conn.send_request(itt, builder).await?;

        Ok((PendingRead { itt, cmd_sn: sn }, esn))
    }

    pub async fn recv_datain(&self, itt: u32) -> Result<PDUWithData<ScsiDataIn>> {
        self.conn.read_response(itt).await
    }

    pub fn apply_datain(
        &self,
        pdu: &PDUWithData<ScsiDataIn>,
        buf: &mut [u8],
        filled_hi: &mut usize,
    ) -> Result<(bool, Option<ScsiStatus>, Option<u32>)> {
        let h = pdu.header_view()?;

        let off = h.buffer_offset.get() as usize;
        let len = pdu.data.len();

        match off.checked_add(len) {
            Some(end) if end <= buf.len() => {
                if len != 0 {
                    buf[off..end].copy_from_slice(&pdu.data);
                    *filled_hi = (*filled_hi).max(end);
                }
            }
            _ => {
                return Err(anyhow!(
                    "target sent more data than expected: off={} len={} cap={}",
                    off,
                    len,
                    buf.len()
                ));
            }
        }

        if h.stat_sn_or_rsvd.get() != 0 {
            self.exp_stat_sn
                .store(h.stat_sn_or_rsvd.get().wrapping_add(1), Ordering::SeqCst);
        }

        let final_bit = h.get_real_final_bit();
        let s_bit = h.get_status_bit();

        let (status_in, residual_in) = if s_bit {
            (h.scsi_status(), Some(h.residual_count.get()))
        } else {
            (None, None)
        };

        Ok((final_bit, status_in, residual_in))
    }

    pub async fn finalize_status_after_datain(
        &self,
        itt: u32,
        status_in_datain: Option<ScsiStatus>,
        residual_in_datain: Option<u32>,
        cmd_resp: Option<PDUWithData<ScsiCommandResponse>>,
    ) -> Result<(ScsiStatus, u32, Option<Vec<u8>>)> {
        if let Some(st) = status_in_datain
            && st == ScsiStatus::Good
        {
            return Ok((st, residual_in_datain.unwrap_or_default(), None));
        }

        let rsp: PDUWithData<ScsiCommandResponse> = match cmd_resp {
            Some(r) => r,
            None => self.conn.read_response(itt).await?,
        };

        let h = rsp.header_view()?;
        let status = h
            .status
            .decode()
            .map_err(|e| anyhow!("SCSI status decode: {e}"))?;
        self.exp_stat_sn
            .store(h.stat_sn.get().wrapping_add(1), Ordering::SeqCst);

        let sense = if rsp.data.is_empty() {
            None
        } else {
            Some(rsp.data.clone())
        };
        Ok((status, h.residual_count.get(), sense))
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
    cmd_resp: Option<PDUWithData<ScsiCommandResponse>>,
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
            let (pending, esn) = match ctx.send_read_request().await {
                Ok(v) => v,
                Err(e) => return Transition::Done(Err(e)),
            };

            Transition::Next(
                ReadStates::WaitData(ReadWaitData {
                    pending: pending.clone(),
                }),
                Ok(ReadResult {
                    itt: pending.itt,
                    cmd_sn: pending.cmd_sn,
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
            let mut early_cmdresp: Option<PDUWithData<ScsiCommandResponse>> = None;

            loop {
                let p = match ctx.recv_any(self.pending.itt).await {
                    Ok(p) => p,
                    Err(e) => {
                        return Transition::Done(Err(anyhow!("unexpected PDU while Data-In: {e}")));
                    }
                };

                match p {
                    ReadPdu::DataIn(pdu) => {
                        let (is_final, s_opt, r_opt) =
                            match ctx.apply_datain(&pdu, &mut buf, &mut filled_hi) {
                                Ok(v) => v,
                                Err(e) => return Transition::Done(Err(e)),
                            };

                        if let Some(s) = s_opt {
                            status_in_datain = Some(s);
                        }
                        if let Some(r) = r_opt {
                            residual_in_datain = Some(r);
                        }

                        if is_final {
                            break;
                        }
                    }
                    ReadPdu::CmdResp(rsp) => {
                        early_cmdresp = Some(rsp);
                        break;
                    }
                }
            }

            let next = ReadWaitResp {
                pending: self.pending.clone(),
                buf,
                filled_hi,
                expected,
                status_in_datain,
                residual_in_datain,
                cmd_resp: early_cmdresp,
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
            let cmd_resp = self.cmd_resp.take();

            let (status, residual, sense_opt) = match ctx
                .finalize_status_after_datain(
                    self.pending.itt,
                    self.status_in_datain.clone(),
                    self.residual_in_datain,
                    cmd_resp,
                )
                .await
            {
                Ok(v) => v,
                Err(e) => return Transition::Done(Err(e)),
            };

            if status != ScsiStatus::Good {
                if let Some(sb) = sense_opt {
                    if let Ok(sense) = SenseData::parse(&sb) {
                        return Transition::Done(Err(anyhow!("SCSI CheckCondition: {:?}", sense)));
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
                        status
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

            Transition::Done(Ok(ReadResult {
                itt: self.pending.itt,
                cmd_sn: self.pending.cmd_sn,
                exp_stat_sn: ctx.exp_stat_sn.load(Ordering::SeqCst),
                data,
            }))
        })
    }
}

pub async fn run_read(mut state: ReadStates, ctx: &mut ReadCtx<'_>) -> Result<ReadResult> {
    loop {
        let tr = match &mut state {
            ReadStates::Start(s) => s.step(ctx).await,
            ReadStates::WaitData(s) => s.step(ctx).await,
            ReadStates::WaitResp(s) => s.step(ctx).await,
        };

        match tr {
            Transition::Next(next, _r) => {
                state = next;
            }
            Transition::Stay(Ok(_)) => { /* tick */ }
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(result) => return result,
        }
    }
}
