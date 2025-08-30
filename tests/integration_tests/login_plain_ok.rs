// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    models::nop::request::NopOutRequest,
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, nop_states::NopCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn login_and_nop() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;

    let conn = connect_cfg(&cfg).await?;

    // ---- Login (execute) ----
    let isid = test_isid();
    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid */ 1,
        /* tsih */ 0,
    );
    lctx.set_plain_login();
    lctx.execute().await.context("login failed")?;

    let login_pdu = lctx.last_response.as_ref().expect("login last_response");
    let lh = login_pdu.header_view().context("login header")?;

    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = get_lun();

    // ---- NOP (execute) ----
    let ttt = NopOutRequest::DEFAULT_TAG;
    let mut nctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);
    nctx.execute().await.context("NOP failed")?;

    Ok(())
}
