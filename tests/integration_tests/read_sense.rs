// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::request_sense::fill_request_sense_simple,
    state_machine::{read_states::ReadCtx, tur_states::TurCtx},
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// login -> TUR (expect UA/CC) -> REQUEST SENSE (8B) -> REQUEST SENSE (full)
/// -> TUR (GOOD) -> INQUIRY (GOOD) — всё через Pool + logout
#[tokio::test]
async fn login_ua_request_sense_then_clear_with_tur_pool() -> Result<()> {
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

    // === Step 1: TUR — сразу после логина может быть UA (CHECK CONDITION).
    // Нам нужно лишь спровоцировать UA и не падать тестом.
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
        })
        .await;

    // === Step 2: REQUEST SENSE (8 bytes header)
    let rs8 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_request_sense_simple(&mut cdb, 8);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await
        .context("REQUEST SENSE (8) failed")?;
    assert_eq!(rs8.data.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = rs8.data[7] as usize;
    let total_needed = 8 + add_len;

    // === Step 3: REQUEST SENSE (full size 8 + add_len)
    let sfull = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_request_sense_simple(&mut cdb, total_needed as u8);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, total_needed as u32, cdb)
        })
        .await
        .context("REQUEST SENSE (full) failed")?;
    assert_eq!(
        sfull.data.len(),
        total_needed,
        "unexpected REQUEST SENSE length"
    );
    let resp_code = sfull.data[0] & 0x7F;
    assert!(
        resp_code == 0x70 || resp_code == 0x71,
        "unexpected sense response code: 0x{resp_code:02X}"
    );

    // === Step 4: TUR retry — теперь UA должна быть очищена (ожидаем GOOD)
    pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
        TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
    })
    .await
    .context("TUR after sense failed")?;

    // === Step 5: STANDARD INQUIRY (6), alloc=36 — ожидаем GOOD
    let inq = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            // INQUIRY(6)
            cdb[0] = 0x12;
            cdb[4] = 36;
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 36, cdb)
        })
        .await
        .context("INQUIRY failed")?;
    assert_eq!(inq.data.len(), 36, "INQUIRY should return 36 bytes now");

    // --- CloseSession + ensure session is gone ---
    pool.shutdown_gracefully(Duration::from_secs(10)).await?;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed from pool after CloseSession"
    );

    Ok(())
}
