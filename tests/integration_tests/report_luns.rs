// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::report_luns::{fill_report_luns, select_report},
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
        tur_states::TurCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// Integration: login -> TUR -> REPORT LUNS (header) -> REPORT LUNS (full)
#[tokio::test]
async fn login_tur_report_luns() -> Result<()> {
    let _ = init_logger(&test_path());

    // --- Connect & Login ---
    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    let isid = test_isid();
    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid */ 1,
        /* tsih */ 0,
    );

    match cfg.login.auth {
        AuthConfig::Chap(_) => lctx.set_chap_login(),
        AuthConfig::None => lctx.set_plain_login(),
    }

    lctx.execute().await.context("login failed")?;
    let login_pdu = lctx
        .last_response
        .as_ref()
        .context("no login last_response")?;
    let lh = login_pdu.header_view().context("login header")?;

    // --- Sequencing counters & a default LUN we use elsewhere ---
    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun_report = 0u64;

    // --- TEST UNIT READY ---
    let lun_for_tur = get_lun();
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun_for_tur);
    let _ = tctx.execute().await;
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun_for_tur);
    tctx.execute().await.context("TUR failed")?;

    // --- REPORT LUNS (step 1): fetch only 8-byte header (LUN LIST LENGTH +
    // reserved) ---
    let mut cdb_hdr = [0u8; 16];
    fill_report_luns(
        &mut cdb_hdr,
        select_report::ALL_MAPPED,
        /* allocation_len */ 16,
        /* control */ 0x00,
    );

    let mut rctx_hdr = ReadCtx::new(
        conn.clone(),
        lun_report,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        16,
        cdb_hdr,
    );
    rctx_hdr
        .execute()
        .await
        .context("REPORT LUNS header read failed")?;
    let hdr_bytes = rctx_hdr.rt.acc;

    assert_eq!(hdr_bytes.len(), 16, "REPORT LUNS header must be 16 bytes");

    let lun_list_len =
        u32::from_be_bytes([hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]])
            as usize;
    assert_eq!(lun_list_len % 8, 0, "LUN LIST LENGTH must be multiple of 8");

    // --- REPORT LUNS (step 2): read whole header+list ---
    let total_needed = 8 + lun_list_len; // header (8) + list
    let mut cdb_full = [0u8; 16];
    fill_report_luns(
        &mut cdb_full,
        select_report::ALL_MAPPED,
        total_needed as u32,
        0x00,
    );

    let mut rctx_full = ReadCtx::new(
        conn.clone(),
        lun_report,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_needed as u32,
        cdb_full,
    );
    rctx_full
        .execute()
        .await
        .context("REPORT LUNS full read failed")?;
    let full_bytes = rctx_full.rt.acc;

    assert_eq!(
        full_bytes.len(),
        total_needed,
        "unexpected REPORT LUNS length"
    );
    assert_eq!(
        &full_bytes[4..8],
        &[0, 0, 0, 0],
        "reserved bytes must be zero"
    );

    let entries = lun_list_len / 8;
    println!("lun_list_len {lun_list_len:?}");
    // FOR lio entries == 1; for tgt entries == 2
    assert!(entries == 2 || entries == 1);

    Ok(())
}
