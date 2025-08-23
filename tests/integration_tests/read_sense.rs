// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::request_sense::fill_request_sense_simple,
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        test_unit_ready::{Idle as TurIdle, TurCtx, TurStates, run_tur},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

/// login -> TUR (expect UA/CC) -> REQUEST SENSE (8B) -> REQUEST SENSE (full) ->
/// TUR (GOOD) -> INQUIRY (GOOD)
#[tokio::test]
async fn login_ua_request_sense_then_clear_with_tur() -> Result<()> {
    let _ = init_logger(&test_path());

    // --- Connect & Login ---
    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    let mut lctx =
        LoginCtx::new(conn.clone(), &cfg, isid, /* cid */ 1, /* tsih */ 0);
    let login_state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };
    let login_status = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1u64 << 48;

    // === Step 1: TUR — expect CHECK CONDITION (UA) after login.
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx).await.err();

    // === Step 2: REQUEST SENSE
    let mut rs_hdr = [0u8; 16];
    let _ = fill_request_sense_simple(&mut rs_hdr, 8);
    let mut rctx_rs8 =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 8, rs_hdr);
    let s8 = run_read(ReadStates::Start(ReadStart), &mut rctx_rs8).await?;
    assert_eq!(s8.data.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = s8.data[7] as usize;
    let total_needed = 8 + add_len;

    // === Step 3: REQUEST SENSE (full size 8 + add_len)
    let mut rs_full = [0u8; 16];
    let _ = fill_request_sense_simple(&mut rs_full, total_needed as u8);
    let mut rctx_rs_full = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_needed as u32,
        rs_full,
    );
    let sfull = run_read(ReadStates::Start(ReadStart), &mut rctx_rs_full).await?;
    assert_eq!(
        sfull.data.len(),
        total_needed,
        "unexpected REQUEST SENSE length"
    );
    let resp_code = sfull.data[0] & 0x7F;
    assert!(
        resp_code == 0x70 || resp_code == 0x71,
        "unexpected sense response code"
    );

    // === Step 4: TUR retry — now UA should be empty → expect GOOD
    let mut tctx2 = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx2).await?;

    // === Step 5: STANDARD INQUIRY (6), alloc=36 — expect GOOD
    let mut inq_cdb = [0u8; 16];
    inq_cdb[..6].fill(0);
    inq_cdb[0] = 0x12; // INQUIRY(6)
    inq_cdb[4] = 36;
    let mut rctx_inq =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 36, inq_cdb);
    let inq = run_read(ReadStates::Start(ReadStart), &mut rctx_inq).await?;
    assert_eq!(
        inq.data.len(),
        36,
        "INQUIRY should succeed after UA is cleared"
    );

    Ok(())
}
