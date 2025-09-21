// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    any::type_name,
    fmt::{self, Debug},
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use once_cell::sync::OnceCell;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    select,
    sync::{Mutex, mpsc},
    time::{Instant, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    cfg::{config::Config, enums::Digest},
    client::{
        common::{RawPdu, io_with_timeout},
        pdu_connection::{FromBytes, ToBytes},
        pool_sessions::Pool,
    },
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::{PduResponse, ZeroCopyType},
        nop::{request::NopOutRequest, response::NopInResponse},
        parse::Pdu,
    },
    state_machine::nop_states::NopCtx,
};

/// A weak reference to a session in the pool, used for unsolicited NOP-In auto-replies.
///
/// Contains a weak reference to the session pool and identifies a specific
/// session and connection within that pool.
#[derive(Debug, Clone)]
struct SessionRef {
    /// Weak reference to the session pool to avoid circular references
    pool: Weak<Pool>,
    /// Target Session Identifying Handle
    tsih: u16,
    /// Connection ID within the session
    cid: u16,
}

/// Represents a single iSCSI connection over a TCP stream.
///
/// This struct manages sending requests (PDUs) and receiving responses, and is responsible for
/// framing PDUs based on the information in their headers. It handles the low-level TCP
/// communication with proper framing according to the iSCSI protocol.
#[derive(Debug)]
pub struct ClientConnection {
    /// TCP read half protected by mutex for concurrent access
    pub reader: Mutex<OwnedReadHalf>,
    /// TCP write half protected by mutex for concurrent access
    pub writer: Mutex<OwnedWriteHalf>,
    /// Configuration parameters for this connection
    pub cfg: Config,
    /// Map of ITT to sender channels for outgoing PDUs
    sending: DashMap<u32, mpsc::Sender<RawPdu>>,
    /// Map of ITT to receiver channels for incoming PDUs
    reciver: DashMap<u32, mpsc::Receiver<RawPdu>>,

    /// Reference to the session this connection belongs to
    session_ref: OnceCell<SessionRef>,

    /// Global "kill now" token: if cancelled, both read and write paths abort
    /// immediately.
    cancel: CancellationToken,
    /// "Soft stop" gate for writes: when cancelled, new writes are rejected,
    /// but the read loop keeps draining in-flight responses.
    pub(crate) stop_writes: CancellationToken,
}

impl ClientConnection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config, cancel: CancellationToken) -> Result<Arc<Self>> {
        let stream = TcpStream::connect(&cfg.login.security.target_address).await?;
        stream.set_linger(None)?;
        stream.set_nodelay(true)?;

        let (r, w) = stream.into_split();

        let conn = Self::from_split_no_reader(r, w, cfg, cancel);

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = reader.read_loop().await {
                warn!("read loop exited: {e}");
            }
        });

        Ok(conn)
    }

    pub fn bind_pool_session(&self, pool: Weak<Pool>, tsih: u16, cid: u16) {
        let _ = self.session_ref.set(SessionRef { pool, tsih, cid });
    }

    #[inline]
    pub fn cancel_now(&self) {
        self.cancel.cancel();
    }

    pub fn from_split_no_reader(
        r: OwnedReadHalf,
        w: OwnedWriteHalf,
        cfg: Config,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            cfg,
            sending: DashMap::new(),
            reciver: DashMap::new(),
            session_ref: OnceCell::new(),
            cancel,
            stop_writes: CancellationToken::new(),
        })
    }

    /// Forbid new writes (no FIN). The reader continues to receive and deliver
    /// all in-flight responses into per-ITT channels.
    fn quiesce_writes(&self) {
        self.stop_writes.cancel();
    }

    /// Wait until all in-flight requests have received their FINAL PDUs
    /// and have been delivered to per-ITT channels. Does not tear down TCP.
    /// Can be interrupted by the global `cancel` token.
    async fn wait_inflight_drained(&self, max_wait: Duration) -> Result<()> {
        let deadline = Instant::now() + max_wait;

        let mut left = self.sending.iter().map(|c| *c.key()).collect::<Vec<_>>();
        left.sort();
        debug!("left_sending {:?}", left);
        loop {
            if self.sending.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("drain timeout: still {} in-flight", self.sending.len());
            }
            select! {
                _ = self.cancel.cancelled() => return Err(anyhow!("cancelled")),
                _ = sleep(Duration::from_millis(100)) => {},
            }
        }
    }

    /// Convenience: forbid new writes and wait for the input side to drain.
    /// No FIN is sent; use `half_close_writes()` if you also want a write-side
    /// FIN.
    pub async fn graceful_quiesce(&self, max_wait: Duration) -> Result<()> {
        self.quiesce_writes();
        self.wait_inflight_drained(max_wait).await
    }

    /// Optionally half-close the write side (send FIN). This is irreversible.
    /// Useful for full shutdown after draining. The reader will still consume
    /// any remaining inbound PDUs until EOF.
    pub async fn half_close_writes(&self) -> Result<()> {
        let mut w = self.writer.lock().await;
        let _ = w.shutdown().await; // ignore errors if already closed
        Ok(())
    }

    /// Hard stop: cancel both read and write paths immediately.
    /// Prefer `graceful_quiesce()` + `half_close_writes()` for graceful
    /// shutdowns.
    pub fn kill_now(&self) {
        self.cancel.cancel();
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write(
        &self,
        mut req: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + fmt::Debug,
    ) -> Result<()> {
        if self.cancel.is_cancelled() {
            bail!("cancelled");
        }

        let mut w = self.writer.lock().await;
        let (out_header, out_data) = req.to_bytes(
            self.cfg.login.negotiation.max_recv_data_segment_length as usize,
            self.cfg.login.negotiation.header_digest == Digest::CRC32C,
            self.cfg.login.negotiation.data_digest == Digest::CRC32C,
        )?;
        debug!("SEND {req:?}");
        debug!(
            "Size_header: {} Size_data: {}",
            out_header.len(),
            out_data.len()
        );

        io_with_timeout(
            "write header (write_all)",
            w.write_all(&out_header),
            self.cfg.extra_data.connections.timeout_connection,
            &self.cancel,
        )
        .await?;

        if !out_data.is_empty() {
            io_with_timeout(
                "write data (write_all)",
                w.write_all(&out_data),
                self.cfg.extra_data.connections.timeout_connection,
                &self.cancel,
            )
            .await?;
        }

        Ok(())
    }

    pub async fn send_request(
        &self,
        initiator_task_tag: u32,
        req: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + Debug,
    ) -> Result<()> {
        if self.cancel.is_cancelled() {
            bail!("cancelled");
        }

        let is_forget = initiator_task_tag == u32::MAX;
        if !is_forget && !self.sending.contains_key(&initiator_task_tag) {
            let (tx, rx) = mpsc::channel::<RawPdu>(32);
            self.sending.insert(initiator_task_tag, tx);
            self.reciver.insert(initiator_task_tag, rx);
        }

        if let Err(e) = self.write(req).await {
            if !is_forget {
                let _ = self.sending.remove(&initiator_task_tag);
                let _ = self.reciver.remove(&initiator_task_tag);
            }
            return Err(e);
        }

        Ok(())
    }

    pub async fn read_response_raw<T: BasicHeaderSegment + Debug>(
        &self,
        initiator_task_tag: u32,
    ) -> Result<(PduResponse<T>, Bytes)> {
        let mut rx = self
            .reciver
            .remove(&initiator_task_tag)
            .map(|(_, rx)| rx)
            .ok_or_else(|| anyhow!("no pending request with itt={initiator_task_tag}"))?;

        let RawPdu { header, payload } = tokio::select! {
            _ = self.cancel.cancelled() => return Err(anyhow!("cancelled")),
            msg = rx.recv() => msg.ok_or_else(|| anyhow!("conn closed before answer"))?,
        };

        let mut hdr_arr: [u8; HEADER_LEN] = header.as_ref().try_into().map_err(|_| {
            anyhow!("failed to convert header Bytes to [u8; {}]", HEADER_LEN)
        })?;

        let pdu_header = Pdu::from_bhs_bytes(&mut hdr_arr)?;
        debug!(
            "{} is final bit: {}",
            type_name::<T>(),
            pdu_header.get_final_bit()
        );
        if !pdu_header.get_final_bit() {
            let _ = self.reciver.insert(initiator_task_tag, rx);
        }

        let pdu = PduResponse::<T>::from_header_slice(hdr_arr, &self.cfg);

        Ok((pdu, payload))
    }

    pub async fn read_response<
        T: BasicHeaderSegment + FromBytes + Debug + ZeroCopyType,
    >(
        &self,
        initiator_task_tag: u32,
    ) -> Result<PduResponse<T>> {
        let (mut pdu, data) = self.read_response_raw(initiator_task_tag).await?;

        let header: &T = pdu.header_view()?;

        let hd = self.cfg.login.negotiation.header_digest == Digest::CRC32C;
        let hd = header.get_header_diggest(hd);
        let dd = self.cfg.login.negotiation.data_digest == Digest::CRC32C;
        let dd = header.get_data_diggest(dd);

        pdu.parse_with_buff(&data, hd != 0, dd != 0)?;

        Ok(pdu)
    }

    async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut scratch = BytesMut::with_capacity(
            self.cfg.login.negotiation.first_burst_length as usize,
        );

        let hd = self.cfg.login.negotiation.header_digest == Digest::CRC32C;
        let dd = self.cfg.login.negotiation.data_digest == Digest::CRC32C;

        loop {
            if self.cancel.is_cancelled() {
                bail!("cancelled");
            }

            scratch.clear();

            scratch.resize(HEADER_LEN, 0);
            {
                let mut r = self.reader.lock().await;
                io_with_timeout(
                    "read header",
                    r.read_exact(&mut scratch[..HEADER_LEN]),
                    self.cfg.extra_data.connections.timeout_connection,
                    &self.cancel,
                )
                .await?;
            }

            let pdu_hdr = {
                let hdr_slice: &mut [u8] = &mut scratch[..HEADER_LEN];
                Pdu::from_bhs_bytes(hdr_slice)?
            };
            debug!("PRE BHS: {pdu_hdr:?}");
            let itt = pdu_hdr.get_initiator_task_tag();
            let fin_bit = pdu_hdr.get_final_bit();

            let mut total = pdu_hdr.total_length_bytes();
            debug!("total {total}");
            if total > HEADER_LEN {
                total += pdu_hdr.get_header_diggest(hd) + pdu_hdr.get_data_diggest(dd);
            } else {
                total += pdu_hdr.get_header_diggest(hd);
            }
            let payload_len = total.saturating_sub(HEADER_LEN);
            debug!("total with crc32c {total}");

            if payload_len > 0 {
                let old = scratch.len();
                scratch.resize(old + payload_len, 0);
                let mut r = self.reader.lock().await;
                io_with_timeout(
                    "read payload",
                    r.read_exact(&mut scratch[old..old + payload_len]),
                    self.cfg.extra_data.connections.timeout_connection,
                    &self.cancel,
                )
                .await?;
            }

            let combined: Bytes = scratch.split_to(total).freeze();
            let header = combined.slice(0..HEADER_LEN);
            let payload = combined.slice(HEADER_LEN..total);

            if let Some((itt, tx)) = self.sending.remove(&itt) {
                let _ = tx.send(RawPdu { header, payload }).await;
                if !fin_bit {
                    self.sending.insert(itt, tx);
                }
            } else {
                if header.len() == HEADER_LEN {
                    let mut hdr_arr = [0u8; HEADER_LEN];
                    hdr_arr.copy_from_slice(&header);
                    if self
                        .try_handle_unsolicited_nop_in(hdr_arr, payload.clone())
                        .await
                    {
                        continue;
                    }
                }
                bail!("no pending sender channel for itt={itt}");
            }
        }
    }

    pub async fn send_keepalive_via_pool_lun(self: &Arc<Self>, lun: u64) -> Result<()> {
        let sr = self
            .session_ref
            .get()
            .ok_or_else(|| anyhow!("connection is not bound to a pool/session"))?;
        let pool = sr
            .pool
            .upgrade()
            .ok_or_else(|| anyhow!("pool has been dropped"))?;

        pool.execute_with(sr.tsih, sr.cid, move |conn, itt, cmd_sn, exp_stat_sn| {
            NopCtx::new(
                conn,
                lun,
                itt,
                cmd_sn,
                exp_stat_sn,
                NopOutRequest::DEFAULT_TAG,
            )
        })
        .await?;
        Ok(())
    }

    pub async fn send_keepalive_via_pool(self: &Arc<Self>) -> Result<()> {
        self.send_keepalive_via_pool_lun(1u64 << 48).await
    }

    async fn try_handle_unsolicited_nop_in(
        self: &Arc<Self>,
        hdr: [u8; HEADER_LEN],
        payload: Bytes,
    ) -> bool {
        let mut pdu = PduResponse::<NopInResponse>::from_header_slice(hdr, &self.cfg);

        let (hd, dd, ttt) = {
            let header = match pdu.header_view() {
                Ok(h) => h,
                Err(e) => {
                    warn!("NOP-In header_view failed: {e}");
                    return false;
                },
            };

            let hd_en = self.cfg.login.negotiation.header_digest == Digest::CRC32C;
            let dd_en = self.cfg.login.negotiation.data_digest == Digest::CRC32C;

            let hd = header.get_header_diggest(hd_en);
            let dd = header.get_data_diggest(dd_en);
            let ttt = header.target_task_tag.get();
            (hd, dd, ttt)
        };

        if let Err(e) = pdu.parse_with_buff(&payload, hd != 0, dd != 0) {
            debug!("NOP-In parse failed (probably other opcode): {e}");
            return false;
        }

        if ttt == 0xffff_ffff {
            debug!("NOP-In (TTT=0xffffffff): reply not required");
            return true;
        }

        let Some(sr) = self.session_ref.get().cloned() else {
            warn!("NOP-In: missing Pool/session binding; cannot auto-reply");
            return false;
        };
        let Some(pool) = sr.pool.upgrade() else {
            warn!("NOP-In: Pool dropped; cannot auto-reply");
            return false;
        };

        let pdu_for_reply = pdu;
        tokio::spawn(async move {
            let res = pool
                .execute_with(sr.tsih, sr.cid, |conn, itt, cmd_sn, exp_stat_sn| {
                    NopCtx::for_reply(conn, itt, cmd_sn, exp_stat_sn, pdu_for_reply)
                        .expect("failed to build NopCtx::for_reply")
                })
                .await;
            if let Err(e) = res {
                warn!("NOP-In auto-reply failed: {e}");
            } else {
                debug!("NOP-In auto-replied (TSIH={}, CID={})", sr.tsih, sr.cid);
            }
        });

        true
    }
}
