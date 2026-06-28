// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{any::type_name, fmt::Debug, sync::Arc};

use anyhow::{Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use tracing::{debug, warn};

use super::ClientConnection;
use crate::{
    client::{common::RawPdu, pdu_connection::FromBytes},
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::{PduResponse, ZeroCopyType},
        nop::response::NopInResponse,
        parse::Pdu,
    },
};

impl ClientConnection {
    pub async fn read_response_raw<T: BasicHeaderSegment + Debug>(
        &self,
        initiator_task_tag: u32,
    ) -> Result<(PduResponse<T>, Bytes)> {
        self.ensure_active()?;
        let mut receiver = self.pending.take_receiver(initiator_task_tag)?;

        let RawPdu {
            mut header,
            payload,
        } = tokio::select! {
            biased;
            response = receiver.recv() => {
                response.ok_or_else(|| anyhow!("connection closed before response"))?
            },
            _ = self.cancel.cancelled() => return Err(anyhow!("cancelled")),
        };

        let pdu_header = Pdu::from_bhs_bytes(&mut header)?;
        debug!(
            "{} is final bit: {}",
            type_name::<T>(),
            pdu_header.get_final_bit()
        );
        if !pdu_header.get_final_bit() {
            self.pending.restore_receiver(initiator_task_tag, receiver);
        }

        Ok((
            PduResponse::<T>::from_header_slice(header, &self.cfg),
            payload,
        ))
    }

    pub async fn read_response<
        T: BasicHeaderSegment + FromBytes + Debug + ZeroCopyType,
    >(
        &self,
        initiator_task_tag: u32,
    ) -> Result<PduResponse<T>> {
        let (mut pdu, data) = self.read_response_raw(initiator_task_tag).await?;
        if let Err(error) = pdu.parse_with_buff(&data) {
            self.poison(format!("invalid response PDU: {error}"));
            return Err(error);
        }
        Ok(pdu)
    }

    pub(super) async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut scratch =
            BytesMut::with_capacity(self.cfg.login.flow.first_burst_length as usize);

        loop {
            let (raw_itt, is_final, pdu) = self.read_pdu(&mut scratch).await?;

            if self
                .pending
                .deliver(raw_itt, pdu.clone(), is_final)
                .await
                .is_ok()
            {
                continue;
            }

            if self
                .try_handle_unsolicited_nop_in(pdu.header, pdu.payload)
                .await
            {
                continue;
            }

            bail!("no pending request for itt={raw_itt}");
        }
    }

    async fn read_pdu(&self, scratch: &mut BytesMut) -> Result<(u32, bool, RawPdu)> {
        self.ensure_active()?;
        scratch.clear();
        scratch.resize(HEADER_LEN, 0);

        let mut reader = self.reader.lock().await;
        self.read_exact_with_timeout(
            &mut reader,
            &mut scratch[..HEADER_LEN],
            "read header",
        )
        .await?;

        let header = Pdu::from_bhs_bytes(&mut scratch[..HEADER_LEN])?;
        debug!("RECV BHS: {header:?}");

        let itt = header.get_initiator_task_tag();
        let is_final = header.get_final_bit();
        let (header_digest, data_digest) = self.digest_flags();
        let data_length = header.total_length_bytes();
        let data_digest_length = if data_length > HEADER_LEN {
            header.get_data_diggest(data_digest)
        } else {
            0
        };
        let total_length =
            data_length + header.get_header_diggest(header_digest) + data_digest_length;

        scratch.resize(total_length, 0);
        if total_length > HEADER_LEN {
            self.read_exact_with_timeout(
                &mut reader,
                &mut scratch[HEADER_LEN..],
                "read payload",
            )
            .await?;
        }
        drop(reader);

        let mut raw_header = [0u8; HEADER_LEN];
        raw_header.copy_from_slice(&scratch[..HEADER_LEN]);
        let bytes = scratch.split_to(total_length).freeze();
        Ok((
            itt,
            is_final,
            RawPdu {
                header: raw_header,
                payload: bytes.slice(HEADER_LEN..),
            },
        ))
    }

    async fn try_handle_unsolicited_nop_in(
        self: &Arc<Self>,
        header: [u8; HEADER_LEN],
        payload: Bytes,
    ) -> bool {
        let mut pdu = PduResponse::<NopInResponse>::from_header_slice(header, &self.cfg);

        let target_task_tag = {
            let header = match pdu.header_view() {
                Ok(header) => header,
                Err(error) => {
                    warn!("NOP-In header_view failed: {error}");
                    return false;
                },
            };
            header.target_task_tag.get()
        };

        if let Err(error) = pdu.parse_with_buff(&payload) {
            debug!("NOP-In parse failed (probably other opcode): {error}");
            return false;
        }

        if target_task_tag == u32::MAX {
            debug!("NOP-In (TTT=0xffffffff): reply not required");
            return true;
        }

        let Some(session_ref) = self.session_ref.get().cloned() else {
            warn!("NOP-In: missing Pool/session binding; cannot auto-reply");
            return false;
        };
        let Some(pool) = session_ref.pool.upgrade() else {
            warn!("NOP-In: Pool dropped; cannot auto-reply");
            return false;
        };

        tokio::spawn(async move {
            let result = pool
                .execute_nop_reply(session_ref.tsih, session_ref.cid, pdu)
                .await;
            if let Err(error) = result {
                warn!("NOP-In auto-reply failed: {error}");
            } else {
                debug!(
                    "NOP-In auto-replied (TSIH={}, CID={})",
                    session_ref.tsih, session_ref.cid
                );
            }
        });

        true
    }
}
