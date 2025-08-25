// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        tur_states::{Idle, TurCtx, TurStates, run_tur},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

#[tokio::test]
async fn login_and_tur() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    // ---- Login ----
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

    // ---- Counters and LUN ----
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1u64 << 48; // same LUN encoding as other tests

    // ---- TEST UNIT READY ----
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _tur_status = run_tur(TurStates::Idle(Idle), &mut tctx).await;
    let _tur_status = run_tur(TurStates::Idle(Idle), &mut tctx).await?;

    Ok(())
}
