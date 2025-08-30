// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::mod_sense::{fill_mode_sense6_simple, fill_mode_sense10_simple},
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
        tur_states::TurCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

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

    // --- Sequencing counters & LUN ---
    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = get_lun();

    // --- TEST UNIT READY ---
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = tctx.execute().await;
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    tctx.execute().await.context("TUR failed")?;

    // --- MODE SENSE(10) ---
    let mut cdb10 = [0u8; 16];
    fill_mode_sense10_simple(&mut cdb10, /* page_code */ 0x3F, /* alloc */ 8);

    let mut rctx10 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        /* read_len= */ 8,
        cdb10,
    );
    rctx10.execute().await.context("MODE SENSE(10) failed")?;
    let res10 = rctx10.rt.acc;
    assert_eq!(res10.len(), 8, "MODE SENSE(10) must return 8 bytes");

    // --- MODE SENSE(6) ---
    let mut cdb6 = [0u8; 16];
    fill_mode_sense6_simple(&mut cdb6, /* page_code */ 0x3F, /* alloc */ 4);

    let mut rctx6 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        /* read_len= */ 4,
        cdb6,
    );
    rctx6.execute().await.context("MODE SENSE(6) failed")?;
    let res6 = rctx6.rt.acc;
    assert_eq!(res6.len(), 4, "MODE SENSE(6) must return 4 bytes");

    Ok(())
}
