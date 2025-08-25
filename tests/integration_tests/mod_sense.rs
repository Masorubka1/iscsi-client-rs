// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::mod_sense::{fill_mode_sense6_simple, fill_mode_sense10_simple},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        tur_states::{Idle as TurIdle, TurCtx, TurStates, run_tur},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

/// Integration: login -> TEST UNIT READY -> MODE SENSE(10) -> MODE SENSE(6)
/// Uses the existing ReadCtx state machine for Data-In commands.
#[tokio::test]
async fn login_tur_mode_sense() -> Result<()> {
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

    // --- Sequencing counters & LUN ---
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1u64 << 48;

    // --- TEST UNIT READY ---
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _tur_status = run_tur(TurStates::Idle(TurIdle), &mut tctx).await;
    let _tur_status = run_tur(TurStates::Idle(TurIdle), &mut tctx).await?;

    // --- MODE SENSE(10): request only the 8-byte header to avoid short/long read
    // issues (target will truncate to allocation length if mode data is
    // larger).
    let mut cdb = [0u8; 16];
    let _ = fill_mode_sense10_simple(
        &mut cdb, /* page_code= */ 0x3F, /* alloc= */ 8,
    );

    let mut rctx10 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        /* read_len= */ 8,
        cdb,
    );
    let res10 = run_read(ReadStates::Start(ReadStart), &mut rctx10).await?;
    assert_eq!(res10.data.len(), 8, "MODE SENSE(10) must return 8 bytes");

    // --- MODE SENSE(6): request only the 4-byte header
    let mut cdb6 = [0u8; 16];
    let _ = fill_mode_sense6_simple(
        &mut cdb6, /* page_code= */ 0x3F, /* alloc= */ 4,
    );

    let mut rctx6 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        /* read_len= */ 4,
        cdb6,
    );
    let res6 = run_read(ReadStates::Start(ReadStart), &mut rctx6).await?;
    assert_eq!(res6.data.len(), 4, "MODE SENSE(6) must return 4 bytes");

    Ok(())
}
