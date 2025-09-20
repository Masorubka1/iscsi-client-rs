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
    cfg::enums::YesNo,
    client::client::ClientConnection,
    models::{
        command::{
            common::{ResponseCode, ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::{BasicHeaderSegment, Builder, HEADER_LEN, SendingData},
        data::{
            request::{ScsiDataOut, ScsiDataOutBuilder},
            sense_data::SenseData,
        },
        data_fromat::{PduRequest, PduResponse},
        ready_2_transfer::response::ReadyToTransfer,
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

#[derive(Debug)]
pub struct WriteCtx<'a> {
    _lt: PhantomData<&'a ()>,

    pub conn: Arc<ClientConnection>,
    pub lun: u64,
    pub itt: u32,
    pub cmd_sn: Arc<AtomicU32>,
    pub exp_stat_sn: Arc<AtomicU32>,

    pub cdb: [u8; 16],
    pub payload: Vec<u8>,
    pub buf: [u8; HEADER_LEN],

    pub sent_bytes: usize,
    pub total_bytes: usize,

    pub last_response: Option<PduResponse<ScsiCommandResponse>>,
    state: Option<WriteStates>,
}

#[allow(clippy::too_many_arguments)]
impl<'a> WriteCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        lun: u64,
        itt: Arc<AtomicU32>,
        cmd_sn: Arc<AtomicU32>,
        exp_stat_sn: Arc<AtomicU32>,
        cdb: [u8; 16],
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            conn,
            lun,
            itt: itt.fetch_add(1, Ordering::SeqCst),
            cmd_sn,
            exp_stat_sn,
            cdb,
            payload: payload.into(),
            buf: [0u8; HEADER_LEN],
            sent_bytes: 0,
            total_bytes: 0,
            last_response: None,
            state: Some(WriteStates::Start(Start)),
            _lt: PhantomData,
        }
    }

    /// Send the SCSI Command (WRITE) with **no** data in the command PDU.
    async fn send_write_command(&mut self) -> Result<()> {
        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let esn = self.exp_stat_sn.load(Ordering::SeqCst);

        self.total_bytes = self.payload.len();

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun)
            .initiator_task_tag(self.itt)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(esn)
            .expected_data_transfer_length(self.total_bytes as u32)
            .scsi_descriptor_block(&self.cdb)
            .write()
            .task_attribute(TaskAttribute::Simple);

        header.header.to_bhs_bytes(&mut self.buf)?;
        let pdu = PduRequest::<ScsiCommandRequest>::new_request(self.buf, &self.conn.cfg);
        self.conn.send_request(self.itt, pdu).await?;

        Ok(())
    }

    async fn recv_r2t(&self, itt: u32) -> Result<PduResponse<ReadyToTransfer>> {
        let r2t: PduResponse<ReadyToTransfer> = self.conn.read_response(itt).await?;
        let header = r2t.header_view()?;
        self.exp_stat_sn
            .store(header.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
        Ok(r2t)
    }

    /// Send exactly the requested R2T window.
    /// Returns (bytes_sent, next_data_sn).
    async fn send_data(
        &mut self,
        itt: u32,
        ttt: u32,
        offset: usize,
        len: usize,
    ) -> Result<usize> {
        let mut next_data_sn = 0;
        if len == 0 {
            bail!("Refuse to send Data-Out with zero length");
        }
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("offset+len overflow"))?;
        if end > self.payload.len() {
            bail!(
                "Data window [{offset}..{end}) exceeds payload {}",
                self.payload.len()
            );
        }

        let mrdsl = self.peer_mrdsl();
        if mrdsl == 0 {
            bail!("MRDSL is zero");
        }
        let to_send_total = len;

        let mut sent = 0usize;
        while sent < to_send_total {
            let take = (to_send_total - sent).min(mrdsl);
            let off = offset + sent;
            let last_chunk_in_window = sent + take == to_send_total;

            let header = ScsiDataOutBuilder::new()
                .lun(self.lun)
                .initiator_task_tag(itt)
                .target_transfer_tag(ttt)
                .exp_stat_sn(self.exp_stat_sn.load(Ordering::SeqCst))
                .buffer_offset(off as u32)
                .data_sn(next_data_sn);

            header.header.to_bhs_bytes(self.buf.as_mut_slice())?;

            let mut pdu =
                PduRequest::<ScsiDataOut>::new_request(self.buf, &self.conn.cfg);

            let header = pdu.header_view_mut()?;

            header.set_data_length_bytes(take as u32);
            if last_chunk_in_window {
                header.set_final_bit();
            } else {
                header.set_continue_bit();
            }

            pdu.append_data(&self.payload[off..off + take]);

            self.conn.send_request(itt, pdu).await?;

            next_data_sn = next_data_sn.wrapping_add(1);
            sent += take;
        }

        Ok(sent)
    }

    /// Wait for the SCSI Response and validate success.
    async fn wait_scsi_response(&mut self, itt: u32) -> Result<()> {
        let rsp: PduResponse<ScsiCommandResponse> = self.conn.read_response(itt).await?;
        let header = rsp.header_view()?;
        self.exp_stat_sn
            .store(header.stat_sn.get().wrapping_add(1), Ordering::SeqCst);

        if header.response.decode()? != ResponseCode::CommandCompleted {
            bail!("WRITE failed: response={:?}", header.response);
        }
        if header.status.decode()? != ScsiStatus::Good {
            let sense = SenseData::parse(rsp.data()?)?;
            bail!("WRITE failed: {:?}", sense);
        }

        self.last_response = Some(rsp);

        Ok(())
    }

    #[inline]
    fn peer_initial_r2t(&self) -> bool {
        self.conn.cfg.extra_data.r2t.initial_r2t == YesNo::Yes
    }

    #[inline]
    fn peer_immediate_data(&self) -> bool {
        self.conn.cfg.extra_data.r2t.immediate_data == YesNo::Yes
    }

    #[inline]
    fn peer_first_burst(&self) -> usize {
        self.conn.cfg.login.negotiation.first_burst_length as usize
    }

    #[inline]
    fn peer_max_burst(&self) -> usize {
        self.conn.cfg.login.negotiation.max_burst_length as usize
    }

    #[inline]
    fn peer_mrdsl(&self) -> usize {
        self.conn.cfg.login.negotiation.max_recv_data_segment_length as usize
    }

    async fn send_write_cmd_with_immediate(&mut self, imm_len: usize) -> Result<()> {
        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let esn = self.exp_stat_sn.load(Ordering::SeqCst);
        self.total_bytes = self.payload.len();

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun)
            .initiator_task_tag(self.itt)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(esn)
            .expected_data_transfer_length(self.total_bytes as u32)
            .scsi_descriptor_block(&self.cdb)
            .write()
            .task_attribute(TaskAttribute::Simple);

        header.header.to_bhs_bytes(&mut self.buf)?;
        let mut pdu =
            PduRequest::<ScsiCommandRequest>::new_request(self.buf, &self.conn.cfg);

        if imm_len > 0 {
            pdu.append_data(&self.payload[0..imm_len]);
        }

        self.conn.send_request(self.itt, pdu).await?;
        self.sent_bytes = imm_len;
        Ok(())
    }

    async fn send_unsolicited_window(
        &mut self,
        offset: usize,
        len: usize,
    ) -> Result<usize> {
        let mrdsl = self.peer_mrdsl();
        if len == 0 {
            return Ok(0);
        }
        if offset + len > self.payload.len() {
            bail!(
                "unsolicited window [{offset}..{}) exceeds payload {}",
                offset + len,
                self.payload.len()
            );
        }

        let mut next_data_sn = 0u32;
        let mut sent = 0usize;
        while sent < len {
            let take = (len - sent).min(mrdsl);
            let off = offset + sent;
            let last = sent + take == len;

            let header = ScsiDataOutBuilder::new()
                .lun(self.lun)
                .initiator_task_tag(self.itt)
                .target_transfer_tag(u32::MAX)
                .exp_stat_sn(self.exp_stat_sn.load(Ordering::SeqCst))
                .buffer_offset(off as u32)
                .data_sn(next_data_sn);

            header.header.to_bhs_bytes(self.buf.as_mut_slice())?;

            let mut pdu =
                PduRequest::<ScsiDataOut>::new_request(self.buf, &self.conn.cfg);
            {
                let h = pdu.header_view_mut()?;
                h.set_data_length_bytes(take as u32);
                if last {
                    h.set_final_bit();
                } else {
                    h.set_continue_bit();
                }
            }
            pdu.append_data(&self.payload[off..off + take]);
            self.conn.send_request(self.itt, pdu).await?;

            next_data_sn = next_data_sn.wrapping_add(1);
            sent += take;
        }
        Ok(sent)
    }
}

#[derive(Debug)]
pub struct Start;
#[derive(Debug)]
pub struct WaitR2T;
#[derive(Debug)]
pub struct Finish;

#[derive(Debug)]
pub enum WriteStates {
    Start(Start),
    WaitR2T(WaitR2T),
    Finish(Finish),
}

pub type WriteStep = Transition<WriteStates, Result<()>>;

/// IssueCmd
///
/// 1) Send SCSI Command (WRITE) with *no* data in the command PDU.
/// 2) If payload is empty → go straight to waiting for SCSI Response. Otherwise
///    → wait for R2T.
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for Start {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            ctx.total_bytes = ctx.payload.len();

            let use_immediate = !ctx.peer_initial_r2t() && ctx.peer_immediate_data();
            if use_immediate && ctx.total_bytes > 0 {
                let fbl = ctx
                    .peer_first_burst()
                    .min(ctx.peer_max_burst())
                    .min(ctx.total_bytes);
                let imm_len = fbl.min(ctx.peer_mrdsl());
                if let Err(e) = ctx.send_write_cmd_with_immediate(imm_len).await {
                    return Transition::Done(Err(e));
                }

                if fbl > imm_len {
                    match ctx.send_unsolicited_window(imm_len, fbl - imm_len).await {
                        Ok(s) => {
                            ctx.sent_bytes += s;
                        },
                        Err(e) => return Transition::Done(Err(e)),
                    }
                }

                if ctx.sent_bytes >= ctx.total_bytes {
                    Transition::Next(WriteStates::Finish(Finish), Ok(()))
                } else {
                    Transition::Next(WriteStates::WaitR2T(WaitR2T), Ok(()))
                }
            } else {
                if let Err(e) = ctx.send_write_command().await {
                    return Transition::Done(Err(e));
                }
                if ctx.total_bytes == 0 {
                    Transition::Next(WriteStates::Finish(Finish), Ok(()))
                } else {
                    Transition::Next(WriteStates::WaitR2T(WaitR2T), Ok(()))
                }
            }
        })
    }
}

/// WaitR2T
///
/// Await an R2T. Compute the data window (offset,len) safely,
/// then move to SendWindow. We assume sequential windows.
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for WaitR2T {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let itt = ctx.itt;
            let r2t = match ctx.recv_r2t(itt).await {
                Ok(v) => v,
                Err(e) => return Transition::Done(Err(e)),
            };
            let h = match r2t.header_view() {
                Ok(h) => h,
                Err(e) => {
                    return Transition::Done(Err(anyhow!(
                        "failed read ReadyToTransfer: {e}"
                    )));
                },
            };

            let ttt = h.target_transfer_tag.get();
            let offset = h.buffer_offset.get() as usize;
            let want = h.desired_data_transfer_length.get() as usize;

            if offset >= ctx.payload.len() {
                return Transition::Done(Err(anyhow!(
                    "R2T buffer_offset {} beyond payload {}",
                    offset,
                    ctx.payload.len()
                )));
            }
            let remaining = ctx.payload.len() - offset;
            let len = want.min(remaining);
            if len == 0 {
                return Transition::Done(Err(anyhow!(
                    "R2T window has zero DesiredDataTransferLength (offset={offset}, \
                     want={want})"
                )));
            }

            let sent = match ctx.send_data(itt, ttt, offset, len).await {
                Ok(x) => x,
                Err(e) => return Transition::Done(Err(e)),
            };
            ctx.sent_bytes = ctx.sent_bytes.saturating_add(sent);

            if ctx.sent_bytes >= ctx.total_bytes {
                Transition::Next(WriteStates::Finish(Finish), Ok(()))
            } else {
                Transition::Stay(Ok(()))
            }
        })
    }
}

/// WaitResp
///
/// Final step: wait for SCSI Command Response and validate GOOD status.
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for Finish {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let itt = ctx.itt;
            match ctx.wait_scsi_response(itt).await {
                Ok(()) => Transition::Done(Ok(())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

#[derive(Debug)]
pub struct WriteOutcome {
    /// Final SCSI Command Response (always present for WRITE).
    pub last_response: PduResponse<ScsiCommandResponse>,
    /// Bytes actually sent (sum over all Data-Out PDUs).
    pub sent_bytes: usize,
    /// Total intended bytes (payload length).
    pub total_bytes: usize,
}

impl<'ctx> StateMachineCtx<WriteCtx<'ctx>, WriteOutcome> for WriteCtx<'ctx> {
    async fn execute(&mut self, _cancel: &CancellationToken) -> Result<WriteOutcome> {
        debug!("Loop WRITE");

        loop {
            let state = self.state.take().context("state must be set WriteCtx")?;
            let tr = match &state {
                WriteStates::Start(s) => s.step(self).await,
                WriteStates::WaitR2T(s) => s.step(self).await,
                WriteStates::Finish(s) => s.step(self).await,
            };

            match tr {
                Transition::Next(next, r) => {
                    r?;
                    self.state = Some(next);
                },
                Transition::Stay(Ok(_)) => {
                    self.state = Some(match state {
                        WriteStates::Start(_) => WriteStates::Start(Start),
                        WriteStates::WaitR2T(_) => WriteStates::WaitR2T(WaitR2T),
                        WriteStates::Finish(_) => WriteStates::Finish(Finish),
                    });
                },
                Transition::Stay(Err(e)) => return Err(e),
                Transition::Done(r) => {
                    r?;
                    return Ok(WriteOutcome {
                        last_response: self
                            .last_response
                            .take()
                            .ok_or_else(|| anyhow!("no last response in ctx"))?,
                        sent_bytes: self.sent_bytes,
                        total_bytes: self.total_bytes,
                    });
                },
            }
        }
    }
}
