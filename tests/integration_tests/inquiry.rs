// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! Integration: login -> TUR (expect UA/CC) -> REQUEST SENSE (8 + full)
//!             -> TUR (GOOD) -> INQUIRY (standard 36)
//!             -> VPD 0x00 header (4) -> full -> optionally 0x80/0x83

use std::sync::atomic::AtomicU32;

use anyhow::Result;
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
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        tur_states::{Idle as TurIdle, TurCtx, TurStates, run_tur},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

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
    let login_state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };
    let login_status = run_login(login_state, &mut lctx).await?;

    // --- Sequencing counters & LUN (method-0: LUN 1 -> 1<<48) ---
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1u64 << 48;

    // === Step 1: TUR — expect CHECK CONDITION (Unit Attention) on first command
    // after login
    let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx).await.err();

    // === Step 2: REQUEST SENSE (8 bytes header) to learn additional length
    let mut cdb = [0u8; 16];
    fill_request_sense_simple(&mut cdb, 8);
    let mut rctx_rs8 =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 8, cdb);
    let s8 = run_read(ReadStates::Start(ReadStart), &mut rctx_rs8).await?;
    assert_eq!(s8.data.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = s8.data[7] as usize;
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
    let _sfull = run_read(ReadStates::Start(ReadStart), &mut rctx_rs_full).await?;

    // === Step 4: TUR again — UA should be cleared now (expect GOOD)
    let mut tctx2 = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
    let _ = run_tur(TurStates::Idle(TurIdle), &mut tctx2).await?;

    // === Step 5: Standard INQUIRY (6) — 36 bytes
    let mut inq_cdb = [0u8; 16];
    fill_inquiry_standard_simple(&mut inq_cdb, 36);
    let mut rctx_inq =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 36, inq_cdb);
    let inq = run_read(ReadStates::Start(ReadStart), &mut rctx_inq).await?;
    assert_eq!(inq.data.len(), 36, "INQUIRY should return 36 bytes here");

    let std_info = parse_inquiry_standard(&inq.data)?;
    // Quick sanity
    assert!(!std_info.vendor_id.is_empty());
    assert!(!std_info.product_id.is_empty());
    assert!(!std_info.product_rev.is_empty());

    // === Step 6: VPD 0x00 (Supported Pages) — two-pass (header then full), to
    // avoid short/long read 6a) Header-only, 4 bytes
    let mut vpd00_cdb = [0u8; 16];
    fill_inquiry_vpd_simple(&mut vpd00_cdb, VpdPage::SupportedPages, 4);
    let mut rctx_vpd00_hdr =
        ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, vpd00_cdb);
    let vpd00_hdr = run_read(ReadStates::Start(ReadStart), &mut rctx_vpd00_hdr).await?;
    assert_eq!(vpd00_hdr.data.len(), 4, "VPD 0x00 header must be 4 bytes");
    let page_len = u16::from_be_bytes([vpd00_hdr.data[2], vpd00_hdr.data[3]]) as usize;
    let total_vpd00 = 4 + page_len;

    // 6b) Full page
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
    let vpd00 = run_read(ReadStates::Start(ReadStart), &mut rctx_vpd00_full).await?;
    assert_eq!(vpd00.data.len(), total_vpd00, "unexpected VPD 0x00 size");
    let pages = parse_vpd_supported_pages(&vpd00.data)?;
    assert!(!pages.is_empty(), "supported VPD pages list is empty");

    // === Step 7: Optionally fetch Unit Serial (0x80) if supported
    if pages.iter().any(|&p| p == VpdPage::UnitSerial as u8) {
        // header
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::UnitSerial, 4);
        let mut rctx_hdr =
            ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, cdb);
        let hdr = run_read(ReadStates::Start(ReadStart), &mut rctx_hdr).await?;
        let len = u16::from_be_bytes([hdr.data[2], hdr.data[3]]) as usize;
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
        let page = run_read(ReadStates::Start(ReadStart), &mut rctx_full).await?;
        let sn = parse_vpd_unit_serial(&page.data)?;
        // Not strictly required by spec to be non-empty, but most targets set it
        assert!(!sn.is_empty(), "Unit Serial (VPD 0x80) is empty");
    }

    // === Step 8: Optionally fetch Device Identification (0x83) if supported
    if pages.iter().any(|&p| p == VpdPage::DeviceId as u8) {
        // header
        let mut cdb = [0u8; 16];
        fill_inquiry_vpd_simple(&mut cdb, VpdPage::DeviceId, 4);
        let mut rctx_hdr =
            ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 4, cdb);
        let hdr = run_read(ReadStates::Start(ReadStart), &mut rctx_hdr).await?;
        let len = u16::from_be_bytes([hdr.data[2], hdr.data[3]]) as usize;
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
        let page = run_read(ReadStates::Start(ReadStart), &mut rctx_full).await?;
        let descs = parse_vpd_device_id(&page.data)?;
        assert!(!descs.is_empty(), "VPD 0x83 returned no descriptors");
    }

    // Basic log for visibility (optional)
    println!(
        "INQUIRY: vendor='{}' product='{}' rev='{}' (pages: {:?})",
        std_info.vendor_id, std_info.product_id, std_info.product_rev, pages
    );

    Ok(())
}
