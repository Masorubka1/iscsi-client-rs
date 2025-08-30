// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::report_luns::{fill_report_luns, select_report},
    state_machine::{read_states::ReadCtx, tur_states::TurCtx},
};
use tokio::time::timeout;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// Integration: login -> TUR -> REPORT LUNS (header) -> REPORT LUNS (full)
#[tokio::test]
async fn login_tur_report_luns_pool() -> Result<()> {
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

    // --- LUNs we use in this test ---
    let lun_for_tur = get_lun();
    let lun_report = 0u64; // REPORT LUNS always sends to LUN=0

    // --- TEST UNIT READY ---
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun_for_tur)
        })
        .await;
    pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
        TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun_for_tur)
    })
    .await
    .context("TUR failed")?;

    // --- REPORT LUNS (step 1): only header ---
    let hdr = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_report_luns(
                &mut cdb,
                select_report::ALL_MAPPED,
                /* allocation_len */ 16,
                /* control */ 0x00,
            );
            ReadCtx::new(c, lun_report, itt, cmd_sn, exp_stat_sn, 16, cdb)
        })
        .await
        .context("REPORT LUNS header read failed")?;
    assert_eq!(hdr.data.len(), 16, "REPORT LUNS header must be 16 bytes");

    let lun_list_len =
        u32::from_be_bytes([hdr.data[0], hdr.data[1], hdr.data[2], hdr.data[3]]) as usize;
    assert_eq!(lun_list_len % 8, 0, "LUN LIST LENGTH must be multiple of 8");

    // --- REPORT LUNS (step 2): full list (8 bytes header + list) ---
    let total_needed = 8 + lun_list_len;
    let full = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_report_luns(
                &mut cdb,
                select_report::ALL_MAPPED,
                total_needed as u32,
                0x00,
            );
            ReadCtx::new(
                c,
                lun_report,
                itt,
                cmd_sn,
                exp_stat_sn,
                total_needed as u32,
                cdb,
            )
        })
        .await
        .context("REPORT LUNS full read failed")?;

    assert_eq!(
        full.data.len(),
        total_needed,
        "unexpected REPORT LUNS length"
    );
    assert_eq!(
        &full.data[4..8],
        &[0, 0, 0, 0],
        "reserved bytes must be zero"
    );

    let entries = lun_list_len / 8;
    // Для lio обычно 1, для tgt — 2 (в зависимости от конфигурации окружения)
    assert!(entries == 1 || entries == 2, "entries={entries}");

    // --- Logout + ensure cleanup ---
    timeout(Duration::from_secs(10), pool.logout_session(tsih))
        .await
        .context("logout timeout")??;
    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed from pool after CloseSession"
    );

    Ok(())
}
