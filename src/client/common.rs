// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use thiserror::Error;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::models::common::HEADER_LEN;

#[derive(Debug, Error)]
pub(crate) enum ClientIoError {
    #[error("{label} cancelled")]
    Cancelled { label: &'static str },
    #[error("{label} timeout")]
    Timeout { label: &'static str },
}

pub(super) fn is_timeout_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ClientIoError>()
        .is_some_and(|client_error| matches!(client_error, ClientIoError::Timeout { .. }))
}

pub(super) async fn io_with_timeout<F, T>(
    label: &'static str,
    fut: F,
    io_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    #[cfg(feature = "profiling-puffin")]
    profiling::scope!("io_with_timeout", label);
    tokio::select! {
        _ = cancel.cancelled() => Err(ClientIoError::Cancelled { label }.into()),
        res = timeout(io_timeout, fut) => {
            match res {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err(ClientIoError::Timeout { label }.into()),
            }
        }
    }
}

/// Represents a raw, unparsed iSCSI PDU (Protocol Data Unit).
///
/// This structure contains the raw bytes of an iSCSI PDU split into header and
/// payload sections. The PDU format follows the iSCSI RFC specification with a
/// fixed-size Basic Header Segment (BHS) and a variable-length payload that may
/// contain Additional Header Segments, data, and digests.
#[derive(Debug, Clone)]
pub(crate) struct RawPdu {
    /// Basic Header Segment - exactly 48 bytes according to iSCSI specification
    ///
    /// Contains the fundamental PDU information including opcode, flags,
    /// lengths, sequence numbers, and other protocol-specific fields.
    pub(crate) header: [u8; HEADER_LEN],
    /// Variable-length payload section
    ///
    /// May contain Additional Header Segments (AHS), padding, Header Digest
    /// (HD), data payload, padding, and Data Digest (DD) depending on PDU
    /// type and configuration.
    pub(crate) payload: Bytes,
}
