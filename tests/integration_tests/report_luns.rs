// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::report_luns::{fill_report_luns, select_report},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        tur_states::{Idle as TurIdle, TurCtx, TurStates, run_tur},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

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

    let login_state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };

    let login_status = run_login(login_state, &mut lctx).await?;

    // --- Sequencing counters & a default LUN we use elsewhere ---
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun_report = 0u64;

    // --- TEST UNIT READY ---
    let lun_for_tur = 1u64 << 48;
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun_for_tur);
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx).await;
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx).await?;

    // --- REPORT LUNS (step 1): fetch only 8-byte header (LUN LIST LENGTH +
    // reserved) ---
    let mut cdb_hdr = [0u8; 16];
    let _ = fill_report_luns(
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
    let hdr = run_read(ReadStates::Start(ReadStart), &mut rctx_hdr).await?;
    assert_eq!(hdr.data.len(), 16, "REPORT LUNS header must be 16 bytes");

    let lun_list_len =
        u32::from_be_bytes([hdr.data[0], hdr.data[1], hdr.data[2], hdr.data[3]]) as usize;
    assert_eq!(lun_list_len % 8, 0, "LUN LIST LENGTH must be multiple of 8");

    // --- REPORT LUNS (step 2): read all header
    let total_needed = 8 + lun_list_len; // header + list
    let mut cdb_full = [0u8; 16];
    let _ = fill_report_luns(
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
    let full = run_read(ReadStates::Start(ReadStart), &mut rctx_full).await?;
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
    println!("lun_list_len {lun_list_len:?}");
    // FOR lio entries == 1; for tgt entries == 2
    assert!(entries == 2 || entries == 1);

    Ok(())
}
