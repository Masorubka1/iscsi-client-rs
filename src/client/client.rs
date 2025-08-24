// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    any::type_name,
    fmt::{self, Debug},
    sync::{Arc, atomic::AtomicU32},
};

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, mpsc},
};
use tracing::{debug, warn};

use crate::{
    cfg::config::Config,
    client::{
        common::{RawPdu, io_with_timeout},
        pdu_connection::{FromBytes, ToBytes},
    },
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::{PDUWithData, ZeroCopyType},
        nop::response::NopInResponse,
        parse::Pdu,
    },
    state_machine::nop_states::{NopCtx, NopStates, Reply, run_nop},
};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
#[derive(Debug)]
pub struct ClientConnection {
    pub reader: Mutex<OwnedReadHalf>,
    pub writer: Mutex<OwnedWriteHalf>,
    pub cfg: Config,
    sending: DashMap<u32, mpsc::Sender<RawPdu>>,
    reciver: DashMap<u32, mpsc::Receiver<RawPdu>>,
    pub counters: Counters,
}

#[derive(Debug, Default)]
pub struct Counters {
    pub itt: AtomicU32,
    pub cmd_sn: AtomicU32,
    pub exp_stat_sn: AtomicU32,
}

impl ClientConnection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config) -> Result<Arc<Self>> {
        let stream = TcpStream::connect(&cfg.login.security.target_address).await?;
        stream.set_linger(None)?;

        let (r, w) = stream.into_split();

        let conn = Self::from_split_no_reader(r, w, cfg);

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = reader.read_loop().await {
                warn!("read loop exited: {e}");
            }
        });

        Ok(conn)
    }

    pub fn from_split_no_reader(
        r: OwnedReadHalf,
        w: OwnedWriteHalf,
        cfg: Config,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            cfg,
            sending: DashMap::new(),
            reciver: DashMap::new(),
            counters: Counters::default(),
        })
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write(
        &self,
        mut req: impl ToBytes<Header = Vec<u8>> + fmt::Debug,
    ) -> Result<()> {
        let mut w = self.writer.lock().await;
        let (out_header, out_data) = req.to_bytes(
            self.cfg.login.negotiation.max_recv_data_segment_length as usize,
            self.cfg
                .login
                .negotiation
                .header_digest
                .eq_ignore_ascii_case("CRC32C"),
            self.cfg
                .login
                .negotiation
                .data_digest
                .eq_ignore_ascii_case("CRC32C"),
        )?;
        debug!("SEND {req:?}");
        debug!(
            "Size_header: {} Size_data: {}",
            out_header.len(),
            out_data.len()
        );
        io_with_timeout("write header", w.write_all(&out_header)).await?;
        if !out_data.is_empty() {
            io_with_timeout("write data", w.write_all(&out_data)).await?;
        }
        Ok(())
    }

    pub async fn send_segment(
        &self,
        req: impl ToBytes<Header = Vec<u8>> + fmt::Debug,
    ) -> Result<()> {
        self.write(req).await
    }

    pub async fn send_request(
        &self,
        initiator_task_tag: u32,
        req: impl ToBytes<Header = Vec<u8>> + Debug,
    ) -> Result<()> {
        if !self.sending.contains_key(&initiator_task_tag) {
            let (tx, rx) = mpsc::channel::<RawPdu>(32);
            self.sending.insert(initiator_task_tag, tx);
            self.reciver.insert(initiator_task_tag, rx);
        }

        if let Err(e) = self.write(req).await {
            let _ = self.sending.remove(&initiator_task_tag);
            let _ = self.reciver.remove(&initiator_task_tag);
            return Err(e);
        }

        Ok(())
    }

    pub async fn read_response_raw<T: BasicHeaderSegment + Debug>(
        &self,
        initiator_task_tag: u32,
    ) -> Result<(PDUWithData<T>, Vec<u8>)> {
        let mut rx = self
            .reciver
            .remove(&initiator_task_tag)
            .map(|(_, rx)| rx)
            .ok_or_else(|| anyhow!("no pending request with itt={initiator_task_tag}"))?;

        let RawPdu {
            mut last_hdr_with_updated_data,
            data,
        } = rx.recv().await.ok_or_else(|| {
            anyhow!("Failed to read response: connection closed before answer")
        })?;

        let pdu_header = Pdu::from_bhs_bytes(&mut last_hdr_with_updated_data)?;
        debug!(
            "{} is final bit: {}",
            type_name::<T>(),
            pdu_header.get_final_bit()
        );
        if !pdu_header.get_final_bit() {
            let _ = self.reciver.insert(initiator_task_tag, rx);
        }

        let pdu = PDUWithData::<T>::from_header_slice(last_hdr_with_updated_data);

        Ok((pdu, data))
    }

    pub async fn read_response<
        T: BasicHeaderSegment + FromBytes + Debug + ZeroCopyType,
    >(
        &self,
        initiator_task_tag: u32,
    ) -> Result<PDUWithData<T>> {
        let (mut pdu, data) = self.read_response_raw(initiator_task_tag).await?;

        let header: &T = pdu.header_view()?;

        let hd = self
            .cfg
            .login
            .negotiation
            .header_digest
            .eq_ignore_ascii_case("CRC32C");
        let hd = header.get_header_diggest(hd);
        let dd = self
            .cfg
            .login
            .negotiation
            .data_digest
            .eq_ignore_ascii_case("CRC32C");
        let dd = header.get_data_diggest(dd);

        pdu.parse_with_buff(data.as_slice(), hd != 0, dd != 0)?;

        Ok(pdu)
    }

    async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut hdr = [0u8; HEADER_LEN];

        let hd = self
            .cfg
            .login
            .negotiation
            .header_digest
            .eq_ignore_ascii_case("CRC32C");
        let dd = self
            .cfg
            .login
            .negotiation
            .data_digest
            .eq_ignore_ascii_case("CRC32C");

        loop {
            {
                let mut r = self.reader.lock().await;
                io_with_timeout("read header", r.read_exact(&mut hdr)).await?;
            }

            let pdu_hdr = Pdu::from_bhs_bytes(&mut hdr)?;
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
            debug!("total with crc32c {total}");

            let payload = if total > HEADER_LEN {
                let mut data = vec![0u8; total - HEADER_LEN];
                let mut r = self.reader.lock().await;
                io_with_timeout("read payload", r.read_exact(&mut data)).await?;
                data
            } else {
                vec![]
            };

            if let Some((itt, tx)) = self.sending.remove(&itt) {
                let _ = tx
                    .send(RawPdu {
                        last_hdr_with_updated_data: hdr,
                        data: payload,
                    })
                    .await;
                if !fin_bit {
                    self.sending.insert(itt, tx);
                }
            } else {
                if self.try_handle_unsolicited_nop_in(hdr).await {
                    continue;
                }
                warn!(
                    "Failed attempt to write to unexisted sender channel with itt {itt}"
                );
            }
        }
    }

    async fn try_handle_unsolicited_nop_in(
        self: &Arc<Self>,
        hdr: [u8; HEADER_LEN],
    ) -> bool {
        let mut hdr_copy = hdr;
        let nop_in = match NopInResponse::from_bhs_bytes(&mut hdr_copy) {
            Ok(n) => n,
            Err(_) => return false,
        };

        let ttt = nop_in.target_task_tag.get();
        let lun = nop_in.lun.get();
        let stat_sn_in = nop_in.stat_sn.get();
        let exp_cmd_in = nop_in.exp_cmd_sn.get();

        if ttt == 0xffff_ffff {
            debug!("NOP-In (TTT=0xffffffff): reply not required");
            return true;
        }
        let conn = Arc::clone(self);
        tokio::spawn(async move {
            let mut ctx = NopCtx::for_reply(
                conn.clone(),
                lun,
                &conn.counters.itt,
                &conn.counters.cmd_sn,
                &conn.counters.exp_stat_sn,
                ttt,
                exp_cmd_in,
                stat_sn_in,
            );
            if let Err(e) = run_nop(NopStates::Reply(Reply), &mut ctx).await {
                tracing::warn!("NOP-In auto-reply failed: {e}");
            } else {
                tracing::debug!("NOP-In auto-replied (TTT=0x{ttt:08x})");
            }
        });
        true
    }
}
