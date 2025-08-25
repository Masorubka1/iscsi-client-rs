// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::config::Config, client::client::ClientConnection, utils::generate_isid,
};

pub fn test_path() -> String {
    std::env::var("TEST_CONFIG").unwrap_or_else(|_| "tests/config.yaml".into())
}

pub fn load_config() -> Result<Config> {
    let path = test_path();
    let pb = PathBuf::from(path);
    let cfg = Config::load_from_file(&pb).with_context(|| format!("failed to load {:?}", pb))?;
    Ok(cfg)
}

pub async fn connect_cfg(cfg: &Config) -> Result<Arc<ClientConnection>> {
    ClientConnection::connect(cfg.clone()).await
}

pub fn test_isid() -> [u8; 6] {
    generate_isid().0
}
