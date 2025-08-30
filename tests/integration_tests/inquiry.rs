// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! Integration: login -> TUR (expect UA/CC) -> REQUEST SENSE (8 + full)
//!             -> TUR (GOOD) -> INQUIRY (standard 36)
//!             -> VPD 0x00 header (4) -> full -> optionally 0x80/0x83

use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    control_block::{
        inquiry::{
            VpdPage, fill_inquiry_standard_simple, fill_inquiry_vpd_simple,
            parse_inquiry_standard, parse_vpd_device_id, parse_vpd_supported_pages,
            parse_vpd_unit_serial,
        },
        request_sense::fill_request_sense_simple,
    },
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
        tur_states::TurCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn login_tur_sense_inquiry_vpd() -> Result<()> {
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

    // --- Sequencing counters & LUN (method-0: LUN 1 -> 1<<48) ---
    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = get_lun();

    // === Step 1: TUR — expect CHECK CONDITION (Unit Attention) on first command
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = tctx.execute().await;

    // === Step 2: REQUEST SENSE (8 bytes header)
    let mut cdb = [0u8; 16];
    fill_request_sense_simple(&mut cdb, 8);
    let mut rctx_rs8 =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 8, cdb);
    rctx_rs8
        .execute()
        .await
        .context("REQUEST SENSE (8) failed")?;
    let s8 = rctx_rs8.rt.acc;
    assert_eq!(s8.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = s8[7] as usize;
    let total_sense = 8 + add_len;

    // === Step 3: REQUEST SENSE (full)
    let mut cdb = [0u8; 16];
    fill_request_sense_simple(&mut cdb, total_sense as u8);
    let mut rctx_rs_full = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_sense as u32,
        cdb,
    );
    rctx_rs_full
        .execute()
        .await
        .context("REQUEST SENSE (full) failed")?;

    // === Step 4: TUR again — UA should be cleared (expect GOOD)
    let mut tctx2 = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    tctx2.execute().await.context("TUR after sense failed")?;

    // === Step 5: Standard INQUIRY (6) — 36 bytes
    let mut inq_cdb = [0u8; 16];
    fill_inquiry_standard_simple(&mut inq_cdb, 36);
    let mut rctx_inq =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 36, inq_cdb);
    rctx_inq.execute().await.context("INQUIRY failed")?;
    let inq = rctx_inq.rt.acc;
    assert_eq!(inq.len(), 36, "INQUIRY should return 36 bytes here");

    let std_info = parse_inquiry_standard(&inq)?;
    assert!(!std_info.vendor_id.is_empty());
    assert!(!std_info.product_id.is_empty());
    assert!(!std_info.product_rev.is_empty());

    // === Step 6: VPD 0x00 (Supported Pages) — header then full
    // 6a) header-only (4 bytes)
    let mut vpd00_cdb = [0u8; 16];
    fill_inquiry_vpd_simple(&mut vpd00_cdb, VpdPage::SupportedPages, 4);
    let mut rctx_vpd00_hdr =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, vpd00_cdb);
    rctx_vpd00_hdr
        .execute()
        .await
        .context("VPD 0x00 header read failed")?;
    let vpd00_hdr = rctx_vpd00_hdr.rt.acc;
    assert_eq!(vpd00_hdr.len(), 4, "VPD 0x00 header must be 4 bytes");
    let page_len = u16::from_be_bytes([vpd00_hdr[2], vpd00_hdr[3]]) as usize;
    let total_vpd00 = 4 + page_len;

    // 6b) full page
    let mut vpd00_cdb = [0u8; 16];
    fill_inquiry_vpd_simple(&mut vpd00_cdb, VpdPage::SupportedPages, total_vpd00 as u8);
    let mut rctx_vpd00_full = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_vpd00 as u32,
        vpd00_cdb,
    );
    rctx_vpd00_full
        .execute()
        .await
        .context("VPD 0x00 full read failed")?;
    let vpd00 = rctx_vpd00_full.rt.acc;
    assert_eq!(vpd00.len(), total_vpd00, "unexpected VPD 0x00 size");
    let pages = parse_vpd_supported_pages(&vpd00)?;
    assert!(!pages.is_empty(), "supported VPD pages list is empty");

    // === Step 7: Optionally fetch Unit Serial (0x80) if supported
    if pages.iter().any(|&p| p == VpdPage::UnitSerial as u8) {
        // header
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::UnitSerial, 4);
        let mut rctx_hdr =
            ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, cdb);
        rctx_hdr.execute().await.context("VPD 0x80 header failed")?;
        let hdr = rctx_hdr.rt.acc;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let total = 4 + len;

        // full
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::UnitSerial, total as u8);
        let mut rctx_full = ReadCtx::new(
            conn.clone(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            total as u32,
            cdb,
        );
        rctx_full.execute().await.context("VPD 0x80 full failed")?;
        let page = rctx_full.rt.acc;
        let sn = parse_vpd_unit_serial(&page)?;
        assert!(!sn.is_empty(), "Unit Serial (VPD 0x80) is empty");
    }

    // === Step 8: Optionally fetch Device Identification (0x83) if supported
    if pages.iter().any(|&p| p == VpdPage::DeviceId as u8) {
        // header
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::DeviceId, 4);
        let mut rctx_hdr =
            ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, cdb);
        rctx_hdr.execute().await.context("VPD 0x83 header failed")?;
        let hdr = rctx_hdr.rt.acc;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let total = 4 + len;

        // full
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::DeviceId, total as u8);
        let mut rctx_full = ReadCtx::new(
            conn.clone(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            total as u32,
            cdb,
        );
        rctx_full.execute().await.context("VPD 0x83 full failed")?;
        let page = rctx_full.rt.acc;
        let descs = parse_vpd_device_id(&page)?;
        assert!(!descs.is_empty(), "VPD 0x83 returned no descriptors");
    }

    // Basic log for visibility (optional)
    println!(
        "INQUIRY: vendor='{}' product='{}' rev='{}' (pages: {:?})",
        std_info.vendor_id, std_info.product_id, std_info.product_rev, pages
    );

    Ok(())
}
