// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev


use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config, enums::Digest},
    control_block::read_capacity::{
        Rc10Raw, Rc16Raw, build_read_capacity10, build_read_capacity16,
        parse_read_capacity10_zerocopy, parse_read_capacity16_zerocopy,
    },
    models::{
        command::{
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
        },
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data::response::ScsiDataIn,
        data_fromat::PDUWithData,
    },
};

use crate::unit_tests::load_fixture;

#[test]
fn test_read_capacity10_request_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected = load_fixture(
        "tests/unit_tests/fixtures/scsi_commands/read_capacity10_request.hex",
    )?;

    let lun_bytes = [0, 1, 0, 0, 0, 0, 0, 0];
    let lun_be = u64::from_be_bytes(lun_bytes);
    let itt = 5;
    let cmd_sn = 3;
    let exp_stat_sn = 5;

    // READ CAPACITY(10): expect 8 bytes of parameter data
    let mut cdb = [0u8; 16];
    build_read_capacity10(&mut cdb, 0, false, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(lun_be)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(8)
        .scsi_descriptor_block(&cdb)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut pdu = PDUWithData::<ScsiCommandRequest>::from_header_slice(header_buf, &cfg);

    let (hdr_bytes, body_bytes) = pdu.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;

    assert_eq!(&hdr_bytes[..], &expected[..HEADER_LEN], "BHS mismatch");
    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "READ CAPACITY(10) payload mismatch"
    );

    Ok(())
}

#[test]
fn test_read_capacity16_request_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected = load_fixture(
        "tests/unit_tests/fixtures/scsi_commands/read_capacity16_request.hex",
    )?;

    let lun_bytes = [0, 1, 0, 0, 0, 0, 0, 0];
    let lun_be = u64::from_be_bytes(lun_bytes);
    let itt = 5;
    let cmd_sn = 3;
    let exp_stat_sn = 5;

    // READ CAPACITY(16): via SERVICE ACTION IN(16), allocation length = 32
    let mut cdb = [0u8; 16];
    build_read_capacity16(&mut cdb, 0, false, 32, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(lun_be)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(32)
        .scsi_descriptor_block(&cdb)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut pdu = PDUWithData::<ScsiCommandRequest>::from_header_slice(header_buf, &cfg);

    let (hdr_bytes, body_bytes) = pdu.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;

    assert_eq!(&hdr_bytes[..], &expected[..HEADER_LEN], "BHS mismatch");
    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "READ CAPACITY(16) payload mismatch"
    );

    Ok(())
}

/// READ CAPACITY(10) — response
#[test]
fn test_rc10_response_parse() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let raw = load_fixture(
        "tests/unit_tests/fixtures/scsi_commands/read_capacity10_response.hex",
    )
    .context("failed to load rc10_response fixture")?;
    assert!(
        raw.len() >= HEADER_LEN,
        "fixture too small: {} < {}",
        raw.len(),
        HEADER_LEN
    );

    let (hdr_bytes, body_bytes) = raw.split_at(HEADER_LEN);

    // zerocopy header view
    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(hdr_bytes);

    let mut pdu = PDUWithData::<ScsiDataIn>::from_header_slice(hdr_buf, &cfg);
    pdu.parse_with_buff(body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;

    let header = pdu.header_view()?;

    // Flags and status
    assert!(header.flags.fin(), "FINAL must be set");
    assert!(header.flags.s(), "S (status present) must be set");
    assert_eq!(
        header.scsi_status(),
        Some(ScsiStatus::Good),
        "SCSI status must be GOOD (0)"
    );

    // Length checks
    assert_eq!(
        pdu.data()?.len(),
        header.get_data_length_bytes(),
        "payload length != DataSegmentLength"
    );
    assert!(
        pdu.data()?.len() >= 8,
        "RC(10) payload must be at least 8 bytes"
    );

    // Parse RC(10) payload
    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&pdu.data()?)
        .context("failed to zerocopy-parse RC(10) body")?;

    let blk = rc10.block_len.get();
    assert!(
        blk >= 256 && blk.is_power_of_two(),
        "block_len looks odd: {blk}"
    );
    let total = rc10.total_bytes();
    assert!(total > 0, "total capacity must be > 0");

    Ok(())
}

/// READ CAPACITY(16) — response
#[test]
fn test_rc16_response_parse() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let raw = load_fixture(
        "tests/unit_tests/fixtures/scsi_commands/read_capacity16_response.hex",
    )
    .context("failed to load rc16_response fixture")?;
    assert!(
        raw.len() >= HEADER_LEN,
        "fixture too small: {} < {}",
        raw.len(),
        HEADER_LEN
    );

    let (hdr_bytes, body_bytes) = raw.split_at(HEADER_LEN);

    // zerocopy header view
    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(hdr_bytes);

    let mut pdu = PDUWithData::<ScsiDataIn>::from_header_slice(hdr_buf, &cfg);
    pdu.parse_with_buff(body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;

    let header = pdu.header_view()?;

    assert!(header.flags.fin(), "FINAL must be set");
    assert!(header.flags.s(), "S (status present) must be set");
    assert_eq!(
        header.scsi_status(),
        Some(ScsiStatus::Good),
        "SCSI status must be GOOD (0)"
    );

    assert_eq!(
        pdu.data()?.len(),
        header.get_data_length_bytes(),
        "payload length != DataSegmentLength"
    );
    assert!(
        pdu.data()?.len() >= 12,
        "RC(16) payload must be at least 12 bytes (max_lba[8] + blk_len[4])"
    );

    let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&pdu.data()?)
        .context("failed to zerocopy-parse RC(16) body head")?;

    let blk = rc16.block_len.get();
    assert!(
        blk >= 256 && blk.is_power_of_two(),
        "block_len looks odd: {blk}"
    );
    let total = rc16.total_bytes();
    assert!(total > 0, "total capacity must be > 0");

    Ok(())
}
