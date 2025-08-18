use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
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
        data::response::{DataInFlags, ScsiDataIn},
        data_fromat::PDUWithData,
    },
};

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_read_capacity10_request_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected = load_fixture(
        "tests/unit_tests/fixtures/scsi_commands/read_capacity10_request.hex",
    )?;

    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let itt = 5;
    let cmd_sn = 3;
    let exp_stat_sn = 5;

    // READ CAPACITY(10): expect 8 bytes of parameter data
    let mut cdb = [0u8; 16];
    build_read_capacity10(&mut cdb, 0, false, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(8)
        .scsi_descriptor_block(&cdb)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut pdu = PDUWithData::<ScsiCommandRequest>::from_header(header_builder.header);

    let (hdr_bytes, body_bytes) = pdu.build(
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

    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let itt = 5;
    let cmd_sn = 3;
    let exp_stat_sn = 5;

    // READ CAPACITY(16): via SERVICE ACTION IN(16), allocation length = 32
    let mut cdb = [0u8; 16];
    build_read_capacity16(&mut cdb, 0, false, 32, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(32)
        .scsi_descriptor_block(&cdb)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut pdu = PDUWithData::<ScsiCommandRequest>::from_header(header_builder.header);

    let (hdr_bytes, body_bytes) = pdu.build(
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
        "READ CAPACITY(16) payload mismatch"
    );

    Ok(())
}

/// READ CAPACITY(10) — response
#[test]
fn test_rc10_response_parse() -> Result<()> {
    // TODO: поправь путь на свой
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

    let hdr = ScsiDataIn::from_bhs_bytes(hdr_bytes)
        .context("failed to parse ScsiDataIn BHS")?;

    assert!(hdr.flags.contains(DataInFlags::FINAL), "FINAL must be set");
    assert!(
        hdr.flags.contains(DataInFlags::S),
        "S (status present) must be set"
    );
    assert_eq!(
        hdr.scsi_status(),
        Some(&ScsiStatus::Good),
        "SCSI status must be GOOD (0)"
    );

    let pdu = PDUWithData::<ScsiDataIn>::parse(hdr, body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;

    assert_eq!(
        pdu.data.len(),
        pdu.header.get_data_length_bytes(),
        "payload length != DataSegmentLength"
    );
    assert!(
        pdu.data.len() >= 8,
        "RC(10) payload must be at least 8 bytes"
    );

    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&pdu.data)
        .context("failed to zerocopy-parse RC(10) body")?;

    let blk = rc10.block_len.get();
    assert!(
        blk >= 256 && blk.is_power_of_two(),
        "block_len looks odd: {blk}"
    );
    let total = rc10.total_bytes();
    assert!(total > 0, "total capacity must be > 0");

    // (Опционально) жесткие ожидания под свой таргет/фикстуру:
    // const E_MAX_LBA_10: u32 = 0x0022_67FF; // пример
    // const E_BLK_LEN_10: u32 = 512;
    // assert_eq!(rc10.max_lba.get(), E_MAX_LBA_10);
    // assert_eq!(blk, E_BLK_LEN_10);

    Ok(())
}

/// READ CAPACITY(16) — response
#[test]
fn test_rc16_response_parse() -> Result<()> {
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

    let hdr = ScsiDataIn::from_bhs_bytes(hdr_bytes)
        .context("failed to parse ScsiDataIn BHS")?;
    assert!(hdr.flags.contains(DataInFlags::FINAL), "FINAL must be set");
    assert!(
        hdr.flags.contains(DataInFlags::S),
        "S (status present) must be set"
    );
    assert_eq!(
        hdr.scsi_status(),
        Some(&ScsiStatus::Good),
        "SCSI status must be GOOD (0)"
    );

    let pdu = PDUWithData::<ScsiDataIn>::parse(hdr, body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;
    assert_eq!(
        pdu.data.len(),
        pdu.header.get_data_length_bytes(),
        "payload length != DataSegmentLength"
    );
    assert!(
        pdu.data.len() >= 12,
        "RC(16) payload must be at least 12 bytes (max_lba[8] + blk_len[4])"
    );

    let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&pdu.data)
        .context("failed to zerocopy-parse RC(16) body head")?;

    let blk = rc16.block_len.get();
    assert!(
        blk >= 256 && blk.is_power_of_two(),
        "block_len looks odd: {blk}"
    );
    let total = rc16.total_bytes();
    assert!(total > 0, "total capacity must be > 0");

    // (Опционально) жесткие ожидания под конкретную фикстуру:
    // const E_MAX_LBA_16: u64 = 0x0000_0000_0022_67FF; // пример
    // const E_BLK_LEN_16: u32 = 512;
    // assert_eq!(rc16.max_lba.get(), E_MAX_LBA_16);
    // assert_eq!(blk, E_BLK_LEN_16);

    Ok(())
}
