// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    models::nop::request::NopOutRequest,
    state_machine::nop_states::NopCtx,
};
use tokio::time::timeout;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn login_and_nop() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    // Use a pre-connected TCP (helper), then attach it as CID=0 into a new session
    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // NOP-Out (keep-alive) via pool.execute_with
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

    timeout(Duration::from_secs(10), pool.logout_session(tsih))
        .await
        .context("logout timeout")??;

    Ok(())
}
