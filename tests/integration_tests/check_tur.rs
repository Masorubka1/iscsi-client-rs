// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, tur_states::TurCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

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

    match cfg.login.auth {
        AuthConfig::Chap(_) => lctx.set_chap_login(),
        AuthConfig::None => lctx.set_plain_login(),
    };

    lctx.execute().await?;

    let login_status = lctx.last_response.as_ref().expect("Wee").header_view()?;

    // ---- Counters and LUN ----
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(login_status.initiator_task_tag.wrapping_add(1));
    let lun = get_lun();

    // ---- TEST UNIT READY ----
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = tctx.execute().await;
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    tctx.execute().await?;

    Ok(())
}
