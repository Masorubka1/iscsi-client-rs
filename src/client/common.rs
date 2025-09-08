// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::models::common::HEADER_LEN;

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

#[derive(Debug)]
pub struct RawPdu {
    pub last_hdr_with_updated_data: [u8; HEADER_LEN],
    pub data: Vec<u8>,
}
