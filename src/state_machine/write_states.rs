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
use tracing::debug;

use crate::{
    cfg::config::Config,
    client::client::ClientConnection,
    models::{
        command::{
            common::{ResponseCode, ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data::{
            request::{ScsiDataOut, ScsiDataOutBuilder},
            sense_data::SenseData,
        },
        data_fromat::PDUWithData,
        ready_2_transfer::response::ReadyToTransfer,
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct WriteCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub cfg: Arc<Config>,
    pub lun: u64,
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,

    pub cdb: [u8; 16],
    pub payload: Vec<u8>,
    pub buf: [u8; HEADER_LEN],
}

#[derive(Debug, Clone)]
pub struct WriteStatus {
    pub itt: u32,
    pub next_data_sn: u32,
    pub sent_bytes: usize,
    pub total_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
impl<'a> WriteCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        cfg: Arc<Config>,
        lun: u64,
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        cdb: [u8; 16],
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            conn,
            cfg,
            lun,
            itt,
            cmd_sn,
            exp_stat_sn,
            cdb,
            payload: payload.into(),
            buf: [0u8; HEADER_LEN],
        }
    }

    /// Send the SCSI Command (WRITE) with **no** data in the command PDU.
    async fn send_write_command(&mut self) -> Result<WriteStatus> {
        let itt = self.itt.fetch_add(1, Ordering::SeqCst);
        let cmd_sn = self.cmd_sn.fetch_add(1, Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.load(Ordering::SeqCst);

        let header = ScsiCommandRequestBuilder::new()
            .lun(self.lun)
            .initiator_task_tag(itt)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn)
            .expected_data_transfer_length(self.payload.len() as u32)
            .scsi_descriptor_block(&self.cdb)
            .write()
            .task_attribute(TaskAttribute::Simple);

        let _ = header
            .header
            .to_bhs_bytes(self.buf.as_mut_slice())
            .map_err(|e| {
                Transition::<PDUWithData<ScsiCommandResponse>, anyhow::Error>::Done(e)
            });

        let pdu: PDUWithData<ScsiCommandRequest> =
            PDUWithData::from_header_slice(self.buf);

        self.conn.send_request(itt, pdu).await?;

        Ok(WriteStatus {
            itt,
            next_data_sn: 0,
            sent_bytes: 0,
            total_bytes: self.payload.len(),
        })
    }

    async fn recv_r2t(&self, itt: u32) -> Result<PDUWithData<ReadyToTransfer>> {
        let r2t: PDUWithData<ReadyToTransfer> = self.conn.read_response(itt).await?;
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
        mut next_data_sn: u32,
        ttt: u32,
        offset: usize,
        len: usize,
    ) -> Result<(usize, u32)> {
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

        let mrdsl = self.cfg.login.negotiation.max_recv_data_segment_length as usize;
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

            let _ = header
                .header
                .to_bhs_bytes(self.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<ScsiCommandResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu: PDUWithData<ScsiDataOut> =
                PDUWithData::from_header_slice(self.buf);

            let header = pdu.header_view_mut()?;

            header.set_data_length_bytes(take as u32);
            if last_chunk_in_window {
                header.set_final_bit();
            } else {
                header.set_continue_bit();
            }

            pdu.data.extend_from_slice(&self.payload[off..off + take]);

            self.conn.send_request(itt, pdu).await?;

            next_data_sn = next_data_sn.wrapping_add(1);
            sent += take;
        }

        Ok((sent, next_data_sn))
    }

    /// Wait for the SCSI Response and validate success.
    async fn wait_scsi_response(&mut self, itt: u32) -> Result<()> {
        let rsp: PDUWithData<ScsiCommandResponse> = self.conn.read_response(itt).await?;
        let header = rsp.header_view()?;
        self.exp_stat_sn
            .store(header.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
        if header.response.decode()? != ResponseCode::CommandCompleted {
            bail!("WRITE failed: response={:?}", header.response);
        }
        if header.status.decode()? != ScsiStatus::Good {
            let sense = SenseData::parse(&rsp.data)?;
            bail!("WRITE failed: {:?}", sense);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct IssueCmd;
#[derive(Debug)]
pub struct WaitR2T {
    st: WriteStatus,
}
#[derive(Debug)]
pub struct SendWindow {
    st: WriteStatus,
    ttt: u32,
    offset: usize,
    len: usize,
}
#[derive(Debug)]
pub struct WaitResp {
    st: WriteStatus,
}

/// WRITE state machine types
#[derive(Debug)]
pub enum WriteStates {
    IssueCmd(IssueCmd),
    WaitR2T(WaitR2T),
    SendWindow(SendWindow),
    WaitResp(WaitResp),
}

pub type WriteStep = Transition<WriteStates, Result<WriteStatus>>;

/// IssueCmd
///
/// 1) Send SCSI Command (WRITE) with *no* data in the command PDU.
/// 2) If payload is empty → go straight to waiting for SCSI Response. Otherwise
///    → wait for R2T.
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for IssueCmd {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_write_command().await {
                Ok(st0) => {
                    let mut st = st0;

                    let allow_unsolicited = ctx
                        .cfg
                        .extra_data
                        .r2t
                        .immediate_data
                        .eq_ignore_ascii_case("Yes")
                        && ctx
                            .cfg
                            .extra_data
                            .r2t
                            .initial_r2t
                            .eq_ignore_ascii_case("No");

                    if st.total_bytes > 0 && allow_unsolicited {
                        let first = st
                            .total_bytes
                            .min(ctx.cfg.login.negotiation.first_burst_length as usize);
                        if first > 0 {
                            // Unsolicited Data-Out: TTT = 0xFFFF_FFFF, offset=0
                            match ctx.send_data(st.itt, 0, 0xFFFF_FFFF, 0, first).await {
                                Ok((sent, next_sn)) => {
                                    st.next_data_sn = next_sn;
                                    st.sent_bytes += sent;
                                },
                                Err(e) => return Transition::Done(Err(e)),
                            }
                        }
                    }

                    if st.sent_bytes >= st.total_bytes {
                        Transition::Next(
                            WriteStates::WaitResp(WaitResp { st: st.clone() }),
                            Ok(st),
                        )
                    } else {
                        Transition::Next(
                            WriteStates::WaitR2T(WaitR2T { st: st.clone() }),
                            Ok(st),
                        )
                    }
                },
                Err(e) => Transition::Done(Err(e)),
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

    fn step<'a>(&'a mut self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let itt = self.st.itt;
            let r2t = match ctx.recv_r2t(itt).await {
                Ok(h) => h,
                Err(e) => return Transition::Done(Err(e)),
            };

            let header = match r2t.header_view() {
                Ok(header) => header,
                Err(e) => {
                    return Transition::Done(Err(anyhow!(
                        "failed read pdu ReadyToTransfer: {e}"
                    )));
                },
            };

            let ttt = header.target_transfer_tag.get();
            let offset = header.buffer_offset.get() as usize;
            let want = header.desired_data_transfer_length.get() as usize;

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

            Transition::Next(
                WriteStates::SendWindow(SendWindow {
                    st: self.st.clone(),
                    ttt,
                    offset,
                    len,
                }),
                Ok(self.st.clone()),
            )
        })
    }
}

/// SendWindow
///
/// Send exactly the window requested by R2T (respect MRDSL).
/// Data-Out is internally chunked by the *builder* (one send_request).
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for SendWindow {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            // Send a *single* Data-Out request with the whole window;
            // ScsiDataOutBuilder will split into MRDSL-sized PDUs and
            // set F/DataSN/BufferOffset per-chunk.
            let (sent, next_sn) = match ctx
                .send_data(self.st.itt, 0, self.ttt, self.offset, self.len)
                .await
            {
                Ok(x) => x,
                Err(e) => return Transition::Done(Err(e)),
            };

            let mut st = self.st.clone();
            st.next_data_sn = next_sn;
            st.sent_bytes = st.sent_bytes.saturating_add(sent);

            if st.sent_bytes >= st.total_bytes {
                Transition::Next(
                    WriteStates::WaitResp(WaitResp { st: st.clone() }),
                    Ok(st),
                )
            } else {
                Transition::Next(WriteStates::WaitR2T(WaitR2T { st: st.clone() }), Ok(st))
            }
        })
    }
}

/// WaitResp
///
/// Final step: wait for SCSI Command Response and validate GOOD status.
impl<'ctx> StateMachine<WriteCtx<'ctx>, WriteStep> for WaitResp {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = WriteStep> + Send + 'a>>
    where
        Self: 'a,
        WriteCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut WriteCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.wait_scsi_response(self.st.itt).await {
                Ok(()) => Transition::Done(Ok(self.st.clone())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

/// Drive the write state machine until it completes.
/// Returns final `WriteStatus` or error.
pub async fn run_write(
    mut state: WriteStates,
    ctx: &mut WriteCtx<'_>,
) -> Result<WriteStatus> {
    loop {
        debug!("{state:?}");
        state = match state {
            WriteStates::IssueCmd(ref mut s) => match s.step(ctx).await {
                Transition::Next(next, _) => next,
                Transition::Stay(Ok(_)) => WriteStates::IssueCmd(IssueCmd),
                Transition::Stay(Err(e)) | Transition::Done(Err(e)) => return Err(e),
                Transition::Done(Ok(done)) => return Ok(done),
            },
            WriteStates::WaitR2T(ref mut s) => match s.step(ctx).await {
                Transition::Next(next, _) => next,
                Transition::Stay(Ok(_)) => {
                    WriteStates::WaitR2T(WaitR2T { st: s.st.clone() })
                },
                Transition::Stay(Err(e)) | Transition::Done(Err(e)) => return Err(e),
                Transition::Done(Ok(done)) => return Ok(done),
            },
            WriteStates::SendWindow(ref mut s) => match s.step(ctx).await {
                Transition::Next(next, _) => next,
                Transition::Stay(Ok(_)) => WriteStates::SendWindow(SendWindow {
                    st: s.st.clone(),
                    ttt: s.ttt,
                    offset: s.offset,
                    len: s.len,
                }),
                Transition::Stay(Err(e)) | Transition::Done(Err(e)) => return Err(e),
                Transition::Done(Ok(done)) => return Ok(done),
            },
            WriteStates::WaitResp(ref mut s) => match s.step(ctx).await {
                Transition::Next(next, _) => next,
                Transition::Stay(Ok(_)) => {
                    WriteStates::WaitResp(WaitResp { st: s.st.clone() })
                },
                Transition::Stay(Err(e)) | Transition::Done(Err(e)) => return Err(e),
                Transition::Done(Ok(done)) => return Ok(done),
            },
        }
    }
}
