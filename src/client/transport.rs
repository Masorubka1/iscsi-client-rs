//! TCP transport for sending and receiving complete iSCSI PDUs.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::time::Duration;

use anyhow::Result;
use bytes::BytesMut;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    cfg::{config::Config, enums::Digest},
    client::common::{RawPdu, io_with_timeout},
    models::{
        common::{BasicHeaderSegment, HEADER_LEN},
        parse::Pdu,
    },
};

/// Owns the socket and its framing rules. Session state and response routing
/// belong to the connection using this transport.
#[derive(Debug)]
pub(super) struct Transport {
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
    timeout: Duration,
    header_digest: bool,
    data_digest: bool,
    cancel: CancellationToken,
}

impl Transport {
    pub(super) async fn connect(cfg: &Config, cancel: CancellationToken) -> Result<Self> {
        let stream = io_with_timeout(
            "connect",
            TcpStream::connect(&cfg.login.transport.target_address),
            cfg.runtime.timeout_connection,
            &cancel,
        )
        .await?;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            timeout: cfg.runtime.timeout_connection,
            header_digest: cfg.login.integrity.header_digest == Digest::CRC32C,
            data_digest: cfg.login.integrity.data_digest == Digest::CRC32C,
            cancel,
        })
    }

    /// Reads exactly one PDU, retaining any following PDU in the TCP stream.
    pub(super) async fn read_pdu(&self, scratch: &mut BytesMut) -> Result<RawPdu> {
        #[cfg(feature = "profiling-puffin")]
        profiling::scope!("read_pdu");
        scratch.clear();
        scratch.resize(HEADER_LEN, 0);
        let mut reader = self.reader.lock().await;
        self.read_exact(&mut reader, &mut scratch[..HEADER_LEN], "read header")
            .await?;

        let header = Pdu::from_bhs_bytes(&mut scratch[..HEADER_LEN])?;
        debug!("RECV BHS: {header:?}");
        let data_length = header.total_length_bytes();
        let data_digest_length = if data_length > HEADER_LEN {
            header.get_data_diggest(self.data_digest)
        } else {
            0
        };
        let total_length = data_length
            + header.get_header_diggest(self.header_digest)
            + data_digest_length;
        scratch.resize(total_length, 0);
        if total_length > HEADER_LEN {
            self.read_exact(&mut reader, &mut scratch[HEADER_LEN..], "read payload")
                .await?;
        }

        let mut header = [0; HEADER_LEN];
        header.copy_from_slice(&scratch[..HEADER_LEN]);
        let bytes = scratch.split_to(total_length).freeze();
        Ok(RawPdu {
            header,
            payload: bytes.slice(HEADER_LEN..),
        })
    }

    /// Keeps the header and payload under one write lock so concurrent PDUs
    /// cannot interleave on the wire.
    pub(super) async fn write_pdu(
        &self,
        header: &[u8; HEADER_LEN],
        data: &[u8],
    ) -> Result<()> {
        let mut writer = self.writer.lock().await;
        self.write_all(&mut writer, header, "write header").await?;
        if !data.is_empty() {
            self.write_all(&mut writer, data, "write data").await?;
        }
        Ok(())
    }

    pub(super) async fn half_close_writes(&self) -> Result<()> {
        self.writer.lock().await.shutdown().await?;
        Ok(())
    }

    async fn read_exact(
        &self,
        reader: &mut OwnedReadHalf,
        buf: &mut [u8],
        label: &'static str,
    ) -> Result<()> {
        io_with_timeout(label, reader.read_exact(buf), self.timeout, &self.cancel)
            .await?;
        Ok(())
    }

    async fn write_all(
        &self,
        writer: &mut OwnedWriteHalf,
        buf: &[u8],
        label: &'static str,
    ) -> Result<()> {
        io_with_timeout(label, writer.write_all(buf), self.timeout, &self.cancel).await
    }
}
