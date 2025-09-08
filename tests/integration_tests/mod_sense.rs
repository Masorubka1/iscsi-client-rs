// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::Arc;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::mod_sense::{fill_mode_sense6_simple, fill_mode_sense10_simple},
    state_machine::{read_states::ReadCtx, tur_states::TurCtx},
};
use tokio::time::timeout;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// Integration: login (via Pool) -> TEST UNIT READY -> MODE SENSE(10) -> MODE
/// SENSE(6)
#[tokio::test]
async fn login_tur_mode_sense_pool() -> Result<()> {
    let _ = init_logger(&test_path());

    // --- Pool + connect + login ---
    let cfg: Arc<Config> = Arc::new(load_config()?);

    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // --- TEST UNIT READY ---
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
        })
        .await;
    pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
        TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
    })
    .await
    .context("TUR failed")?;

    // --- MODE SENSE(10) ---
    let ms10 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb10 = [0u8; 16];
            // Page code 0x3F, allocation length 8
            fill_mode_sense10_simple(&mut cdb10, 0x3F, 8);
            // ReadCtx возвращает ReadResult { data, last_response }
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb10)
        })
        .await
        .context("MODE SENSE(10) failed")?;
    assert_eq!(ms10.data.len(), 8, "MODE SENSE(10) must return 8 bytes");

    // --- MODE SENSE(6) ---
    let ms6 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb6 = [0u8; 16];
            // Page code 0x3F, allocation length 4
            fill_mode_sense6_simple(&mut cdb6, 0x3F, 4);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 4, cdb6)
        })
        .await
        .context("MODE SENSE(6) failed")?;
    assert_eq!(ms6.data.len(), 4, "MODE SENSE(6) must return 4 bytes");

    // --- CloseSession + ensure session is gone ---
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
