// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    state_machine::tur_states::TurCtx,
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn login_and_tur() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    // ---- Pool ----
    let pool = Pool::new(&cfg);

    // ---- Login via Pool ----
    let isid = test_isid();
    let cid = 1u16.into();
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // ---- TEST UNIT READY via Pool ----
    let _ = pool
        .execute_with_ctx(tsih, cid, |env| TurCtx::from_execute_env(env, lun))
        .await;

    pool.execute_with_ctx(tsih, cid, |env| TurCtx::from_execute_env(env, lun))
        .await
        .context("TUR failed")?;

    pool.shutdown_gracefully(Duration::from_secs(10)).await?;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed from pool after CloseSession"
    );

    Ok(())
}
