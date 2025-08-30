// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::request_sense::fill_request_sense_simple,
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
        tur_states::TurCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

/// login -> TUR (expect UA/CC) -> REQUEST SENSE (8B) -> REQUEST SENSE (full) ->
/// TUR (GOOD) -> INQUIRY (GOOD)
#[tokio::test]
async fn login_ua_request_sense_then_clear_with_tur() -> Result<()> {
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

    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = get_lun();

    // === Step 1: TUR — expect CHECK CONDITION (UA) after login.
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = tctx.execute().await;

    // === Step 2: REQUEST SENSE (8 bytes)
    let mut rs_hdr = [0u8; 16];
    fill_request_sense_simple(&mut rs_hdr, 8);
    let mut rctx_rs8 =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 8, rs_hdr);
    rctx_rs8
        .execute()
        .await
        .context("REQUEST SENSE (8) failed")?;
    let s8 = rctx_rs8.rt.acc;
    assert_eq!(s8.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = s8[7] as usize;
    let total_needed = 8 + add_len;

    // === Step 3: REQUEST SENSE (full size 8 + add_len)
    let mut rs_full = [0u8; 16];
    fill_request_sense_simple(&mut rs_full, total_needed as u8);
    let mut rctx_rs_full = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_needed as u32,
        rs_full,
    );
    rctx_rs_full
        .execute()
        .await
        .context("REQUEST SENSE (full) failed")?;
    let sfull = rctx_rs_full.rt.acc;
    assert_eq!(sfull.len(), total_needed, "unexpected REQUEST SENSE length");
    let resp_code = sfull[0] & 0x7F;
    assert!(
        resp_code == 0x70 || resp_code == 0x71,
        "unexpected sense response code"
    );

    // === Step 4: TUR retry — now UA should be cleared → expect GOOD
    let mut tctx2 = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    tctx2.execute().await.context("TUR after sense failed")?;

    // === Step 5: STANDARD INQUIRY (6), alloc=36 — expect GOOD
    let mut inq_cdb = [0u8; 16];
    inq_cdb[..6].fill(0);
    inq_cdb[0] = 0x12; // INQUIRY(6)
    inq_cdb[4] = 36;

    let mut rctx_inq =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 36, inq_cdb);
    rctx_inq.execute().await.context("INQUIRY failed")?;
    let inq = rctx_inq.rt.acc;
    assert_eq!(inq.len(), 36, "INQUIRY should succeed after UA is cleared");

    Ok(())
}
