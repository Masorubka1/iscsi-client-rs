// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::Arc;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};
use tokio::time::{Duration, sleep, timeout};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_close_session() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    // ---- Pool setup ----
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    // ---- Login via Pool ----
    let isid = test_isid();
    let cid: u16 = 1;
    let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // ---- NOP x3 via pool ----
    for _ in 0..3 {
        timeout(
            Duration::from_secs(10),
            pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                NopCtx::new(
                    c,
                    lun,
                    itt,         // Arc<AtomicU32>
                    cmd_sn,      // Arc<AtomicU32>
                    exp_stat_sn, // Arc<AtomicU32>
                    NopOutRequest::DEFAULT_TAG,
                )
            }),
        )
        .await
        .context("nop timeout")??;
    }

    sleep(Duration::from_secs(1)).await;

    timeout(
        cfg.extra_data.connections.timeout_connection,
        pool.logout_all(),
    )
    .await
    .context("logout timeout")??;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed from pool after CloseSession"
    );

    Ok(())
}
