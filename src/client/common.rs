// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::time::timeout;

use crate::models::common::HEADER_LEN;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn io_with_timeout<F, T>(label: &'static str, fut: F) -> Result<T>
where F: Future<Output = std::io::Result<T>> {
    match timeout(IO_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("{label} timeout")),
    }
}

#[derive(Debug)]
pub struct RawPdu {
    pub last_hdr_with_updated_data: [u8; HEADER_LEN],
    pub data: Vec<u8>,
}
