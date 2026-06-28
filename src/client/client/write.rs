// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{fmt, fmt::Debug};

use anyhow::Result;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::ClientConnection;
use crate::{client::pdu_connection::ToBytes, models::common::HEADER_LEN};

impl ClientConnection {
    /// Optionally half-close the write side (send FIN). This is irreversible.
    /// Useful for full shutdown after draining. The reader will still consume
    /// any remaining inbound PDUs until EOF.
    pub async fn half_close_writes(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
        Ok(())
    }

    async fn write(
        &self,
        mut request: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + fmt::Debug,
    ) -> Result<()> {
        self.ensure_writable()?;

        let mut writer = self.writer.lock().await;
        let (header, data) = request
            .to_bytes(self.cfg.login.flow.max_recv_data_segment_length as usize)?;
        debug!("SEND {request:?}");
        debug!("Size_header: {} Size_data: {}", header.len(), data.len());

        self.write_all_with_timeout(&mut writer, &header, "write header")
            .await?;

        if !data.is_empty() {
            self.write_all_with_timeout(&mut writer, &data, "write data")
                .await?;
        }

        Ok(())
    }

    pub async fn send_request(
        &self,
        initiator_task_tag: u32,
        request: impl ToBytes<Header = [u8; HEADER_LEN], Body = Bytes> + Debug,
    ) -> Result<()> {
        self.ensure_writable()?;

        let expects_response = initiator_task_tag != u32::MAX;
        if expects_response {
            self.pending.register(initiator_task_tag);
        }

        if let Err(error) = self.write(request).await {
            if expects_response {
                self.pending.remove(initiator_task_tag);
            }
            return Err(error);
        }

        Ok(())
    }
}
