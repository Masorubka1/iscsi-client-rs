// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
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
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

#[derive(Debug)]
pub enum ReadPdu {
    DataIn(PDUWithData<ScsiDataIn>),
    CmdResp(PDUWithData<ScsiCommandResponse>),
}

#[derive(Debug)]
pub struct ReadRuntime {
    pub acc: Vec<u8>,
    pub cur_cmd_sn: Option<u32>,
    pub status_in_datain: Option<ScsiStatus>,
    pub residual_in_datain: Option<u32>,
}

#[derive(Debug)]
pub struct ReadCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: u32,
    pub cmd_sn: Arc<AtomicU32>,
    pub exp_stat_sn: Arc<AtomicU32>,
    pub read_len: u32,
    pub cdb: [u8; 16],
    pub buf: [u8; HEADER_LEN],

    pub last_response: Option<PDUWithData<ScsiCommandResponse>>,
    pub rt: ReadRuntime,
    state: Option<ReadStates>,
}

impl<'a> ReadCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: u64,
        itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        read_len: u32,
        cdb: [u8; 16],
    ) -> Self {
        Self {
            conn,
            lun,
            itt: itt.fetch_add(1, Ordering::SeqCst),
            cmd_sn,
            exp_stat_sn,
            read_len,
            cdb,
            buf: [0u8; HEADER_LEN],
            last_response: None,
            rt: ReadRuntime {
                acc: Vec::with_capacity(read_len as usize),
                cur_cmd_sn: None,
                status_in_datain: None,
                residual_in_datain: None,
            },
            state: Some(ReadStates::Start(Start)),
            _lt: PhantomData,
        }
    }

    pub async fn recv_any(&self, itt: u32) -> anyhow::Result<ReadPdu> {
        let (p_any, data): (PDUWithData<Pdu>, Vec<u8>) =
            self.conn.read_response_raw(itt).await?;
        let op = BhsOpcode::try_from(p_any.header_buf[0])?.opcode;

        let hd = self
            .conn
            .cfg
            .login
            .negotiation
            .header_digest
            .eq_ignore_ascii_case("CRC32C");
        let dd = self
            .conn
            .cfg
            .login
            .negotiation
            .data_digest
            .eq_ignore_ascii_case("CRC32C");

        let pdu_local = match op {
            Opcode::ScsiDataIn => Ok(ReadPdu::DataIn({
                let mut pdu = p_any.rebind_pdu::<ScsiDataIn>()?;

                let header = pdu.header_view()?;

                let hd = header.get_header_diggest(hd);
                let dd = header.get_data_diggest(dd);

                pdu.parse_with_buff(data.as_slice(), hd != 0, dd != 0)?;
                pdu
            })),
            Opcode::ScsiCommandResp => Ok(ReadPdu::CmdResp({
                let mut pdu = p_any.rebind_pdu::<ScsiCommandResponse>()?;

                let header = pdu.header_view()?;

                let hd = header.get_header_diggest(hd);
                let dd = header.get_data_diggest(dd);

                pdu.parse_with_buff(data.as_slice(), hd != 0, dd != 0)?;
                pdu
            })),
            other => anyhow::bail!("unexpected PDU opcode for read path: {other:?}"),
        };
        debug!("READ {pdu_local:?}");
        pdu_local
    }

    async fn send_read_request(&mut self) -> Result<u32> {
        let sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let esn = self.exp_stat_sn.load(Ordering::SeqCst);

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun)
            .initiator_task_tag(self.itt)
            .cmd_sn(sn)
            .exp_stat_sn(esn)
            .expected_data_transfer_length(self.read_len)
            .scsi_descriptor_block(&self.cdb)
            .read()
            .task_attribute(TaskAttribute::Simple);

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;
        let builder: PDUWithData<ScsiCommandRequest> =
            PDUWithData::from_header_slice(self.buf);
        self.conn.send_request(self.itt, builder).await?;

        self.rt.cur_cmd_sn = Some(sn);
        Ok(esn)
    }

    pub async fn recv_datain(&self, itt: u32) -> Result<PDUWithData<ScsiDataIn>> {
        self.conn.read_response(itt).await
    }

    pub fn apply_datain_append(&mut self, pdu: &PDUWithData<ScsiDataIn>) -> Result<bool> {
        let h = pdu.header_view()?;

        let off = h.buffer_offset.get() as usize;
        if off != self.rt.acc.len() {
            return Err(anyhow!(
                "unexpected buffer_offset: got {}, expected {}",
                off,
                self.rt.acc.len()
            ));
        }
        if !pdu.data.is_empty() {
            self.rt.acc.extend_from_slice(&pdu.data);
        }

        if h.stat_sn_or_rsvd.get() != 0 {
            self.exp_stat_sn
                .store(h.stat_sn_or_rsvd.get().wrapping_add(1), Ordering::SeqCst);
        }
        if h.get_status_bit() {
            self.rt.status_in_datain = h.scsi_status();
            self.rt.residual_in_datain = Some(h.residual_count.get());
        }

        Ok(h.get_real_final_bit())
    }

    pub async fn finalize_status_after_datain(
        &mut self,
        itt: u32,
    ) -> Result<(ScsiStatus, u32, Option<Vec<u8>>)> {
        if let Some(ScsiStatus::Good) = self.rt.status_in_datain {
            return Ok((
                ScsiStatus::Good,
                self.rt.residual_in_datain.unwrap_or_default(),
                None,
            ));
        }

        let rsp: PDUWithData<ScsiCommandResponse> = match self.last_response.take() {
            Some(r) => r,
            None => self.conn.read_response(itt).await?,
        };
        self.last_response = Some(rsp);

        let lr = self.last_response.as_ref().expect("saved above");
        let h = lr.header_view()?;

        let status = h
            .status
            .decode()
            .map_err(|e| anyhow!("SCSI status decode: {e}"))?;
        self.exp_stat_sn
            .store(h.stat_sn.get().wrapping_add(1), Ordering::SeqCst);

        let sense = if lr.data.is_empty() {
            None
        } else {
            Some(lr.data.clone())
        };
        Ok((status, h.residual_count.get(), sense))
    }
}

#[derive(Debug)]
pub struct Start;
#[derive(Debug)]
pub struct ReadWait;
#[derive(Debug)]
pub struct Finish;

#[derive(Debug)]
pub enum ReadStates {
    Start(Start),
    Wait(ReadWait),
    Finish(Finish),
}

type ReadStepOut = Transition<ReadStates, Result<()>>;

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for Start {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            if let Err(e) = ctx.send_read_request().await {
                return Transition::Done(Err(e));
            }
            Transition::Next(ReadStates::Wait(ReadWait), Ok(()))
        })
    }
}

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for ReadWait {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            loop {
                match ctx.recv_any(ctx.itt).await {
                    Ok(ReadPdu::DataIn(pdu)) => {
                        let is_final = match ctx.apply_datain_append(&pdu) {
                            Ok(f) => f,
                            Err(e) => return Transition::Done(Err(e)),
                        };
                        if is_final {
                            break;
                        }
                    },
                    Ok(ReadPdu::CmdResp(rsp)) => {
                        ctx.last_response = Some(rsp);
                        break;
                    },
                    Err(e) => {
                        return Transition::Done(Err(anyhow!(
                            "unexpected PDU while read: {e}"
                        )));
                    },
                }
            }
            Transition::Next(ReadStates::Finish(Finish), Ok(()))
        })
    }
}

impl<'ctx> StateMachine<ReadCtx<'ctx>, ReadStepOut> for Finish {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = ReadStepOut> + Send + 'a>>
    where
        Self: 'a,
        ReadCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut ReadCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let (status, residual, sense_opt) =
                match ctx.finalize_status_after_datain(ctx.itt).await {
                    Ok(v) => v,
                    Err(e) => return Transition::Done(Err(e)),
                };

            if status != ScsiStatus::Good {
                if let Some(sb) = sense_opt {
                    if let Ok(sense) = SenseData::parse(&sb) {
                        return Transition::Done(Err(anyhow!(
                            "SCSI CheckCondition: {:?}",
                            sense
                        )));
                    }
                    return Transition::Done(Err(anyhow!(
                        "SCSI CheckCondition (sense {} bytes): {:02X?}",
                        sb.len(),
                        sb
                    )));
                }
                return Transition::Done(Err(anyhow!(
                    "SCSI status != GOOD ({:?}) and no sense provided",
                    status
                )));
            }

            let expected = ctx.read_len as usize;
            if ctx.rt.acc.len() != expected || residual != 0 {
                return Transition::Done(Err(anyhow!(
                    "short/long read: expected {} bytes, got {}; residual={}",
                    expected,
                    ctx.rt.acc.len(),
                    residual
                )));
            }

            Transition::Done(Ok(()))
        })
    }
}

#[derive(Debug)]
pub struct ReadOutcome {
    /// Concatenated payload from all Data-In PDUs (in order).
    pub data: Vec<u8>,
    /// Final SCSI Command Response (if target sent one).
    /// When status was carried by the last Data-In (S-bit set), this is None.
    pub last_response: Option<PDUWithData<ScsiCommandResponse>>,
}

impl<'ctx> StateMachineCtx<ReadCtx<'ctx>, ReadOutcome> for ReadCtx<'ctx> {
    async fn execute(&mut self) -> Result<ReadOutcome> {
        debug!("Loop Read");

        loop {
            let state = self.state.take().context("state must be set ReadCtx")?;
            let tr = match state {
                ReadStates::Start(s) => s.step(self).await,
                ReadStates::Wait(s) => s.step(self).await,
                ReadStates::Finish(s) => s.step(self).await,
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
                    return Ok(ReadOutcome {
                        data: std::mem::take(&mut self.rt.acc),
                        last_response: self.last_response.take(),
                    });
                },
            }
        }
    }
}
