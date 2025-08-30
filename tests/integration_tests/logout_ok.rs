// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    models::nop::request::NopOutRequest,
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, logout_states::LogoutCtx,
        nop_states::NopCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn logout_close_session() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    // -------- Login ----------
    let isid = test_isid();
    let cid = 1u16;
    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, cid, /* tsih= */ 0);

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

    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(lh.initiator_task_tag.wrapping_add(1));

    let cmd_sn_before = cmd_sn.load(std::sync::atomic::Ordering::SeqCst);
    let exp_stat_sn_before = exp_stat_sn.load(std::sync::atomic::Ordering::SeqCst);

    // -------- NOP (NOP-Out -> NOP-In) ----------
    let lun = get_lun();
    let ttt = NopOutRequest::DEFAULT_TAG;
    let mut nctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);
    nctx.execute().await.context("nop failed")?;

    // -------- Logout ----------
    let reason = iscsi_client_rs::models::logout::common::LogoutReason::CloseSession;
    let mut loctx =
        LogoutCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, cid, reason);
    loctx.execute().await.context("logout failed")?;

    let cmd_sn_after = cmd_sn.load(std::sync::atomic::Ordering::SeqCst);
    let exp_stat_sn_after = exp_stat_sn.load(std::sync::atomic::Ordering::SeqCst);

    assert!(
        cmd_sn_after >= cmd_sn_before,
        "CmdSN didn't advance on logout (before={cmd_sn_before}, after={cmd_sn_after})"
    );
    assert!(
        exp_stat_sn_after >= exp_stat_sn_before,
        "ExpStatSN didn't advance on logout (before={exp_stat_sn_before}, \
         after={exp_stat_sn_after})"
    );

    Ok(())
}
