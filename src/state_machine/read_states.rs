// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! This module defines the state machine for the iSCSI SCSI Read command.

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
    },
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    client::{client::ClientConnection, pool_sessions::ExecuteEnv},
    models::{
        command::{
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::HEADER_LEN,
        data::{response::ScsiDataIn, sense_data::SenseData},
        data_fromat::{PduRequest, PduResponse},
        identifiers::{
            AtomicCmdSn, AtomicStatSn, DataSn, Itt, IttGen, Lun, StatSn,
        },
        opcode::{BhsOpcode, Opcode},
        parse::Pdu,
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

/// Represents the types of PDUs that can be received during a SCSI Read
/// operation.
#[derive(Debug)]
pub enum ReadPdu {
    DataIn(PduResponse<ScsiDataIn>),
    CmdResp(PduResponse<ScsiCommandResponse>),
}

/// Holds the runtime state for a SCSI Read operation.
#[derive(Debug)]
pub struct ReadRuntime {
    pub acc: Vec<u8>,
    pub cur_cmd_sn: Option<u32>,
    /// DataSN expected on the next Data-In PDU.
    pub expected_data_sn: DataSn,
    pub status_in_datain: Option<ScsiStatus>,
    pub residual_in_datain: Option<u32>,
}

#[derive(Debug)]
pub struct ReadCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub lun: Lun,
    pub itt: Itt,
    pub cmd_sn: Arc<AtomicCmdSn>,
    pub exp_stat_sn: Arc<AtomicStatSn>,
    pub read_len: u32,
    pub cdb: [u8; 16],
    pub buf: [u8; HEADER_LEN],

    pub last_response: Option<PduResponse<ScsiCommandResponse>>,
    pub rt: ReadRuntime,
    state: Option<ReadStates>,
}

impl<'a> ReadCtx<'a> {
    pub fn from_execute_env(
        env: ExecuteEnv,
        lun: Lun,
        read_len: u32,
        cdb: [u8; 16],
    ) -> Self {
        Self::new(
            env.conn,
            lun,
            env.itt_gen.as_ref(),
            env.cmd_sn,
            env.exp_stat_sn,
            read_len,
            cdb,
        )
    }

    pub fn new(
        conn: Arc<ClientConnection>,
        lun: Lun,
        itt_gen: &IttGen,
        cmd_sn: Arc<AtomicCmdSn>,
        exp_stat_sn: Arc<AtomicStatSn>,
        read_len: u32,
        cdb: [u8; 16],
    ) -> Self {
        Self {
            conn,
            lun,
            itt: itt_gen.fetch_inc(),
            cmd_sn,
            exp_stat_sn,
            read_len,
            cdb,
            buf: [0u8; HEADER_LEN],
            last_response: None,
            rt: ReadRuntime {
                acc: Vec::with_capacity(read_len as usize),
                cur_cmd_sn: None,
                expected_data_sn: DataSn::ZERO,
                status_in_datain: None,
                residual_in_datain: None,
            },
            state: Some(ReadStates::Start(Start)),
            _lt: PhantomData,
        }
    }

    /// Receives any PDU related to the read operation.
    pub async fn recv_any(&self, itt: Itt) -> anyhow::Result<ReadPdu> {
        let (p_any, data): (PduResponse<Pdu>, Bytes) =
            self.conn.read_response_raw(itt).await?;
        let op = BhsOpcode::try_from(p_any.header_buf[0])?.opcode;

        let pdu_local = match op {
            Opcode::ScsiDataIn => Ok(ReadPdu::DataIn({
                let mut pdu = p_any.rebind_pdu::<ScsiDataIn>()?;
                pdu.parse_with_buff(&data)?;
                pdu
            })),
            Opcode::ScsiCommandResp => Ok(ReadPdu::CmdResp({
                let mut pdu = p_any.rebind_pdu::<ScsiCommandResponse>()?;
                pdu.parse_with_buff(&data)?;
                pdu
            })),
            other => anyhow::bail!("unexpected PDU opcode for read path: {other:?}"),
        };
        debug!("READ {pdu_local:?}");
        pdu_local
    }

    async fn send_read_request(&mut self) -> Result<()> {
        let sn = self.cmd_sn.fetch_inc();
        let esn = self.exp_stat_sn.load();

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun.get())
            .initiator_task_tag(self.itt)
            .cmd_sn(sn)
            .exp_stat_sn(esn)
            .expected_data_transfer_length(self.read_len)
            .scsi_descriptor_block(&self.cdb)
            .read()
            .task_attribute(TaskAttribute::Simple);

        header.header.to_bhs_bytes(self.buf.as_mut_slice())?;
        let builder =
            PduRequest::<ScsiCommandRequest>::new_request(self.buf, &self.conn.cfg);
        self.conn.send_request(self.itt, builder).await?;

        self.rt.cur_cmd_sn = Some(sn.get());
        Ok(())
    }

    /// Receives a Data-In PDU.
    pub async fn recv_datain(&self, itt: Itt) -> Result<PduResponse<ScsiDataIn>> {
        self.conn.read_response(itt).await
    }

    /// Appends the data from a Data-In PDU to the accumulator.
    pub fn apply_datain_append(&mut self, pdu: &PduResponse<ScsiDataIn>) -> Result<bool> {
        let h = pdu.header_view()?;
        let received_data_sn = DataSn::new(h.data_sn.get());
        anyhow::ensure!(
            received_data_sn == self.rt.expected_data_sn,
            "unexpected DataSN: expected {}, received {}",
            self.rt.expected_data_sn,
            received_data_sn
        );
        self.rt.expected_data_sn = self.rt.expected_data_sn.next();

        let off = h.buffer_offset.get() as usize;
        if off != self.rt.acc.len() {
            return Err(anyhow!(
                "unexpected buffer_offset: got {}, expected {}",
                off,
                self.rt.acc.len()
            ));
        }

        let data = pdu.data()?;

        if !data.is_empty() {
            self.rt.acc.extend_from_slice(data);
        }

        if h.stat_sn_or_rsvd.get() != 0 {
            self.exp_stat_sn
                .observe(StatSn::new(h.stat_sn_or_rsvd.get()));
        }
        if h.get_status_bit() {
            self.rt.status_in_datain = h.scsi_status();
            self.rt.residual_in_datain = Some(h.residual_effective());
        }

        Ok(h.get_real_final_bit())
    }

    /// Finalizes the status of the read operation after all data has been
    /// received.
    pub async fn finalize_status_after_datain(
        &mut self,
        itt: Itt,
    ) -> Result<(ScsiStatus, u32, Option<Vec<u8>>)> {
        if let Some(ScsiStatus::Good) = self.rt.status_in_datain {
            return Ok((
                ScsiStatus::Good,
                self.rt.residual_in_datain.unwrap_or_default(),
                None,
            ));
        }

        let rsp: PduResponse<ScsiCommandResponse> = match self.last_response.take() {
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
        anyhow::ensure!(
            DataSn::new(h.exp_data_sn.get()) == self.rt.expected_data_sn,
            "unexpected ExpDataSN: expected {}, received {}",
            self.rt.expected_data_sn,
            h.exp_data_sn.get()
        );
        self.exp_stat_sn.observe(StatSn::new(h.stat_sn.get()));

        let data = lr.data()?;

        let sense = if data.is_empty() {
            None
        } else {
            Some(data.to_vec())
        };
        Ok((status, h.residual_effective(), sense))
    }
}

/// Represents the initial state of a read operation.
#[derive(Debug)]
pub struct Start;

/// Represents the state of waiting for data from the target.
#[derive(Debug)]
pub struct ReadWait;

/// Represents the final state of a read operation.
#[derive(Debug)]
pub struct Finish;

/// Defines the possible states for a SCSI Read operation state machine.
#[derive(Debug)]
pub enum ReadStates {
    /// The initial state.
    Start(Start),
    /// Waiting for data.
    Wait(ReadWait),
    /// The final state.
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

            let requested = ctx.read_len as usize;
            let expected_after_residual = requested.saturating_sub(residual as usize);
            let got = ctx.rt.acc.len();

            if got != expected_after_residual {
                return Transition::Done(Err(anyhow!(
                    "read length mismatch: requested={}, residual={}, \
                     expected_after_residual={}, got={}",
                    requested,
                    residual,
                    expected_after_residual,
                    got
                )));
            }

            Transition::Done(Ok(()))
        })
    }
}

/// Represents the outcome of a completed SCSI Read operation.
#[derive(Debug)]
pub struct ReadOutcome {
    /// The data received from the target.
    pub data: Vec<u8>,
    /// The final SCSI Command Response, if one was sent.
    pub last_response: Option<PduResponse<ScsiCommandResponse>>,
}

impl<'ctx> StateMachineCtx<ReadCtx<'ctx>, ReadOutcome> for ReadCtx<'ctx> {
    async fn execute(&mut self, _cancel: &CancellationToken) -> Result<ReadOutcome> {
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
