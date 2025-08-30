// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config, logger::init_logger},
    client::{client::ClientConnection, pool_sessions::Pool},
    models::{logout::common::LogoutReason, nop::request::NopOutRequest},
    state_machine::{logout_states::LogoutCtx, nop_states::NopCtx},
};
use tokio::time::{sleep, timeout};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let _init_logger = init_logger("tests/config_logger.yaml")?;

    // Load config
    let cfg = resolve_config_path("docker/lio/config.lio.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    // Create pool and attach weak self for unsolicited NOP auto-replies
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    // Optionally: warm up a TCP to verify target is reachable (not strictly
    // required)
    let _probe = ClientConnection::connect(cfg.clone()).await?;
    info!("Target is reachable");

    // ---- Login N sessions from config ----
    let tsihs = pool
        .login_sessions_from_cfg(&cfg)
        .await
        .context("login_all failed")?;
    info!("Logged {} sessions", tsihs.len());

    // Use CID=0 for all newly created sessions
    let cid: u16 = 0;
    let lun = 1u64 << 48;

    // Send 3 keep-alive NOPs per session (sequentially for simplicity)
    for &tsih in &tsihs {
        for _ in 0..3 {
            timeout(
                Duration::from_secs(10),
                pool.execute_with(tsih, cid, |conn, itt, cmd_sn, exp_stat_sn| {
                    NopCtx::new(
                        conn,
                        lun,
                        itt,
                        cmd_sn,
                        exp_stat_sn,
                        NopOutRequest::DEFAULT_TAG,
                    )
                }),
            )
            .await
            .context("nop timeout")??;
        }
    }

    // Let unsolicited NOP-In (if any) come in
    sleep(Duration::from_secs(5)).await;

    // Logout all sessions (or call `logout_session(tsih)` in a loop)
    for &tsih in &tsihs {
        timeout(
            Duration::from_secs(10),
            pool.execute_with(tsih, cid, |conn, itt, cmd_sn, exp_stat_sn| {
                LogoutCtx::new(
                    conn,
                    itt,
                    cmd_sn,
                    exp_stat_sn,
                    cid,
                    LogoutReason::CloseSession,
                )
            }),
        )
        .await
        .context("logout timeout")??;
    }

    Ok(())
}
