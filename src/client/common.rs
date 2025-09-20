// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub(super) async fn io_with_timeout<F, T>(
    label: &'static str,
    fut: F,
    io_timeout: Duration,
    cancel: &CancellationToken,
) -> Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(anyhow!("{label} cancelled")),
        res = timeout(io_timeout, fut) => {
            match res {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err(anyhow!("{label} timeout")),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawPdu {
    /// Exactly 48 bytes (BHS)
    pub header: Bytes,
    /// BODY (AHS + pad + [HD?] + DATA + pad + [DD?])
    pub payload: Bytes,
}
