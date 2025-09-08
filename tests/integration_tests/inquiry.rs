// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! Integration: login -> TUR (expect UA/CC) -> REQUEST SENSE (8 + full)
//!             -> TUR (GOOD) -> INQUIRY (standard 36)
//!             -> VPD 0x00 header (4) -> full -> optionally 0x80/0x83

use std::sync::Arc;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::{
        inquiry::{
            VpdPage, fill_inquiry_standard_simple, fill_inquiry_vpd_simple,
            parse_inquiry_standard, parse_vpd_device_id, parse_vpd_supported_pages,
            parse_vpd_unit_serial,
        },
        request_sense::fill_request_sense_simple,
    },
    state_machine::{read_states::ReadCtx, tur_states::TurCtx},
};
use tokio::time::timeout;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test]
async fn login_tur_sense_inquiry_vpd() -> Result<()> {
    let _ = init_logger(&test_path());

    // --- Pool + connect + login ---
    let cfg: Arc<Config> = Arc::new(load_config()?);

    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // === Step 1: TUR — first command can return CHECK CONDITION (UA)
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
        })
        .await;

    // === Step 2: REQUEST SENSE (8 bytes header)
    let s8 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_request_sense_simple(&mut cdb, 8);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await
        .context("REQUEST SENSE (8) failed")?
        .data;
    assert_eq!(s8.len(), 8, "REQUEST SENSE header must be 8 bytes");
    let add_len = s8[7] as usize;
    let total_sense = 8 + add_len;

    // === Step 3: REQUEST SENSE (full)
    let _sfull = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_request_sense_simple(&mut cdb, total_sense as u8);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, total_sense as u32, cdb)
        })
        .await
        .context("REQUEST SENSE (full) failed")?
        .data;

    // === Step 4: TUR again — UA должна уйти (expect GOOD)
    pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
        TurCtx::new(c, itt, cmd_sn, exp_stat_sn, lun)
    })
    .await
    .context("TUR after sense failed")?;

    // === Step 5: Standard INQUIRY — 36 bytes
    let inq = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_inquiry_standard_simple(&mut cdb, 36);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 36, cdb)
        })
        .await
        .context("INQUIRY failed")?
        .data;
    assert_eq!(inq.len(), 36, "INQUIRY should return 36 bytes here");

    let std_info = parse_inquiry_standard(&inq)?;
    assert!(!std_info.vendor_id.is_empty());
    assert!(!std_info.product_id.is_empty());
    assert!(!std_info.product_rev.is_empty());

    // === Step 6: VPD 0x00 (Supported Pages) — header then full
    // 6a) header-only (4 bytes)
    let vpd00_hdr = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_inquiry_vpd_simple(&mut cdb, VpdPage::SupportedPages, 4);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 4, cdb)
        })
        .await
        .context("VPD 0x00 header read failed")?
        .data;
    assert_eq!(vpd00_hdr.len(), 4, "VPD 0x00 header must be 4 bytes");
    let page_len = u16::from_be_bytes([vpd00_hdr[2], vpd00_hdr[3]]) as usize;
    let total_vpd00 = 4 + page_len;

    // 6b) full page
    let vpd00 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            fill_inquiry_vpd_simple(&mut cdb, VpdPage::SupportedPages, total_vpd00 as u8);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, total_vpd00 as u32, cdb)
        })
        .await
        .context("VPD 0x00 full read failed")?
        .data;
    assert_eq!(vpd00.len(), total_vpd00, "unexpected VPD 0x00 size");
    let pages = parse_vpd_supported_pages(&vpd00)?;
    assert!(!pages.is_empty(), "supported VPD pages list is empty");

    // === Step 7: Optionally VPD 0x80 (Unit Serial)
    if pages.iter().any(|&p| p == VpdPage::UnitSerial as u8) {
        // header
        let hdr = pool
            .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                fill_inquiry_vpd_simple(&mut cdb, VpdPage::UnitSerial, 4);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 4, cdb)
            })
            .await
            .context("VPD 0x80 header failed")?
            .data;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let total = 4 + len;

        // full
        let page = pool
            .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                fill_inquiry_vpd_simple(&mut cdb, VpdPage::UnitSerial, total as u8);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, total as u32, cdb)
            })
            .await
            .context("VPD 0x80 full failed")?
            .data;
        let sn = parse_vpd_unit_serial(&page)?;
        assert!(!sn.is_empty(), "Unit Serial (VPD 0x80) is empty");
    }

    // === Step 8: Optionally VPD 0x83 (Device Identification)
    if pages.iter().any(|&p| p == VpdPage::DeviceId as u8) {
        // header
        let hdr = pool
            .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                fill_inquiry_vpd_simple(&mut cdb, VpdPage::DeviceId, 4);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 4, cdb)
            })
            .await
            .context("VPD 0x83 header failed")?
            .data;
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let total = 4 + len;

        // full
        let page = pool
            .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                fill_inquiry_vpd_simple(&mut cdb, VpdPage::DeviceId, total as u8);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, total as u32, cdb)
            })
            .await
            .context("VPD 0x83 full failed")?
            .data;
        let descs = parse_vpd_device_id(&page)?;
        assert!(!descs.is_empty(), "VPD 0x83 returned no descriptors");
    }

    println!(
        "INQUIRY: vendor='{}' product='{}' rev='{}' (pages: {:?})",
        std_info.vendor_id, std_info.product_id, std_info.product_rev, pages
    );

    timeout(
        cfg.extra_data.connections.timeout_connection,
        pool.logout_all(),
    )
    .await
    .context("logout timeout")??;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed after CloseSession"
    );

    Ok(())
}
