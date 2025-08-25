// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    control_block::read::build_read10,
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

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_read_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read10_request.hex")?;

    let lun_bytes = [0, 1, 0, 0, 0, 0, 0, 0];
    let lun_be = u64::from_be_bytes(lun_bytes);

    let itt = 4;
    let cmd_sn = 1;
    let exp_stat_sn = 4;

    let mut cdb_read = [0u8; 16];
    build_read10(&mut cdb_read, 0x1234, 16, 0, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(lun_be)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(512u32)
        .scsi_descriptor_block(&cdb_read)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PDUWithData::<ScsiCommandRequest>::from_header_slice(header_buf);

    let (hdr_bytes, body_bytes) = &builder.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login
            .negotiation
            .header_digest
            .eq_ignore_ascii_case("CRC32C"),
        cfg.login
            .negotiation
            .data_digest
            .eq_ignore_ascii_case("CRC32C"),
    )?;

    assert_eq!(&hdr_bytes[..], &expected[..HEADER_LEN], "BHS mismatch");
    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "READ PDU payload mismatch"
    );
    Ok(())
}

#[test]
fn test_read_response_good() -> Result<()> {
    let raw =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read10_response_good.hex")
            .context("failed to load read_response_good fixture")?;
    assert!(
        raw.len() >= HEADER_LEN,
        "fixture too small: {} < {}",
        raw.len(),
        HEADER_LEN
    );

    let (hdr_bytes, body_bytes) = raw.split_at(HEADER_LEN);

    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(hdr_bytes);

    let mut pdu = PDUWithData::<ScsiDataIn>::from_header_slice(hdr_buf);
    pdu.parse_with_buff(body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;

    let header = pdu.header_view()?;

    assert!(header.flags.fin(), "FINAL bit must be set");
    assert!(header.flags.s(), "S bit (status present) must be set");

    assert_eq!(
        header.scsi_status(),
        Some(ScsiStatus::Good),
        "SCSI status must be GOOD(0)"
    );

    assert!(!pdu.header_view()?.flags.ack(), "A bit must be 0");
    // assert!(!pdu.header.flags.o(), "O bit must be 0");
    assert!(!header.flags.u(), "U bit must be 0");

    assert_eq!(
        pdu.data.len(),
        header.get_data_length_bytes(),
        "payload length mismatch: data.len() vs DataSegmentLength"
    );

    let payload = vec![0x00; header.get_data_length_bytes()];
    assert_eq!(&pdu.data, &payload);

    Ok(())
}
