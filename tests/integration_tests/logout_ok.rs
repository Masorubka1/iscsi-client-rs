// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    models::logout::common::LogoutReason,
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        logout_states::{self, LogoutCtx, LogoutStates, run_logout},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

#[tokio::test]
async fn logout_close_session() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    let isid = test_isid();
    let cid = 1u16;
    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, cid, /* tsih= */ 2);

    let login_state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };
    let login_status = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));

    let reason = LogoutReason::CloseSession;

    let mut loctx =
        LogoutCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, cid, reason);
    let status = run_logout(LogoutStates::Idle(logout_states::Idle), &mut loctx).await?;

    assert!(
        status.cmd_sn >= login_status.exp_cmd_sn,
        "CmdSN didn't advance on logout"
    );
    assert!(
        status.exp_stat_sn >= login_status.stat_sn,
        "StatSN didn't advance on logout"
    );

    Ok(())
}
