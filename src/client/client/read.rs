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
        identifiers::Itt,
        nop::response::NopInResponse,
        parse::Pdu,
    },
};

impl ClientConnection {
    pub(crate) async fn read_response_raw<T: BasicHeaderSegment + Debug>(
        &self,
        itt: Itt,
    ) -> Result<(PduResponse<T>, Bytes)> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        self.ensure_active()?;
        let mut receiver = self.pending.take_receiver(itt)?;

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
            self.pending.restore_receiver(itt, receiver);
        }

        Ok((
            PduResponse::<T>::from_header_slice(header, &self.cfg),
            payload,
        ))
    }

    pub(crate) async fn read_response<
        T: BasicHeaderSegment + FromBytes + Debug + ZeroCopyType,
    >(
        &self,
        itt: Itt,
    ) -> Result<PduResponse<T>> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let (mut pdu, data) = self.read_response_raw(itt).await?;
        if let Err(error) = pdu.parse_with_buff(&data) {
            self.poison(format!("invalid response PDU: {error}"));
            return Err(error);
        }
        Ok(pdu)
    }

    pub(super) async fn read_loop(self: Arc<Self>) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let mut scratch =
            BytesMut::with_capacity(self.cfg.login.flow.first_burst_length as usize);

        loop {
            #[cfg(feature = "profiling-puffin")]
            profiling::finish_frame!();
            self.ensure_active()?;
            let mut pdu = self.transport.read_pdu(&mut scratch).await?;
            let (raw_itt, is_final) = {
                let header = Pdu::from_bhs_bytes(&mut pdu.header)?;
                (header.get_initiator_task_tag(), header.get_final_bit())
            };

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

            // When not bound to a session (e.g. during SendTargets discovery),
            // silently discard unsolicited PDUs that we cannot route.
            if self.session_ref.get().is_none() {
                debug!(
                    "discarding unsolicited PDU itt={} (no pool binding)",
                    raw_itt
                );
                continue;
            }

            bail!("no pending request for itt={raw_itt}");
        }
    }

    async fn try_handle_unsolicited_nop_in(
        self: &Arc<Self>,
        header: [u8; HEADER_LEN],
        payload: Bytes,
    ) -> bool {
        #[cfg(feature = "profiling-puffin")]
        profiling::scope!("try_handle_unsolicited_nop_in");
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
            warn!("NOP-In: missing session binding; cannot auto-reply");
            return false;
        };
        let Some(session) = session_ref.session.upgrade() else {
            warn!("NOP-In: session dropped; cannot auto-reply");
            return false;
        };

        tokio::spawn(async move {
            let result = session.execute_nop_reply(session_ref.cid, pdu).await;
            if let Err(error) = result {
                warn!("NOP-In auto-reply failed: {error}");
            } else {
                debug!(
                    "NOP-In auto-replied (TSIH={}, CID={})",
                    session.tsih, session_ref.cid
                );
            }
        });

        true
    }
}
