// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{fmt, fmt::Debug};

use anyhow::Result;
use bytes::Bytes;
use tracing::debug;

use super::ClientConnection;
use crate::{
    client::{common::is_timeout_error, pdu_connection::ToBytes},
    models::{common::HEADER_LEN, identifiers::Itt},
};

impl ClientConnection {
    /// Optionally half-close the write side (send FIN). This is irreversible.
    /// Useful for full shutdown after draining. The reader will still consume
    /// any remaining inbound PDUs until EOF.
    pub(crate) async fn half_close_writes(&self) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        let _ = self.transport.half_close_writes().await;
        Ok(())
    }

    async fn write(
        &self,
        mut request: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + fmt::Debug,
    ) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        self.ensure_writable()?;

        let (header, data) = request
            .to_bytes(self.cfg.login.flow.max_recv_data_segment_length as usize)?;
        debug!("SEND {request:?}");
        debug!("Size_header: {} Size_data: {}", header.len(), data.len());

        self.transport
            .write_pdu(&header, &data)
            .await
            .map_err(|error| {
                if is_timeout_error(&error) {
                    self.poison(format!("write PDU timeout: {error}"));
                }
                error
            })
    }

    pub(crate) async fn send_request(
        &self,
        itt: Itt,
        request: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + Debug,
    ) -> Result<()> {
        #[cfg(feature = "profiling-puffin")]
        profiling::function_scope!();
        self.ensure_writable()?;

        let expects_response = itt.get() != u32::MAX;
        if expects_response {
            self.pending.register(itt);
        }

        if let Err(error) = self.write(request).await {
            if expects_response {
                self.pending.remove(itt);
            }
            return Err(error);
        }

        Ok(())
    }
}
