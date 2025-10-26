// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    client::pool_sessions::Pool,
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_chap_ok() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;

    // Skip if auth method is not CHAP in the test config
    if !matches!(cfg.login.auth, AuthConfig::Chap(_)) {
        eprintln!("skip: auth.method != chap in TEST_CONFIG");
        return Ok(());
    }

    // Pool setup (needed for counters + auto NOP handling)
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    // Pre-connected TCP (helper) and attach into a new session as CID=0
    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    // ---- Login via pool (CHAP path selected by cfg) ----
    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    // ---- NOP keep-alive via pool ----
    let lun = get_lun();
    pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
        NopCtx::new(
            c,
            lun,
            itt,         // Arc<AtomicU32>
            cmd_sn,      // Arc<AtomicU32>
            exp_stat_sn, // Arc<AtomicU32>
            NopOutRequest::DEFAULT_TAG,
        )
    })
    .await
    .context("NOP failed")?;

    pool.shutdown_gracefully(Duration::from_secs(10)).await?;

    Ok(())
}
