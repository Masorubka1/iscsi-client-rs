use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    control_block::common::build_read10,
    models::{
        command::{
            common::TaskAttribute,
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
fn test_read_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read_request.hex")?;

    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let itt = 4;
    let cmd_sn = 1;
    let exp_stat_sn = 4;

    let mut cdb_read = [0u8; 16];
    build_read10(&mut cdb_read, 0x1234, 16, 0, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(512u32)
        .scsi_descriptor_block(&cdb_read)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut builder =
        PDUWithData::<ScsiCommandRequest>::from_header(header_builder.header);

    let chunks = builder.build(&cfg)?;
    assert_eq!(
        chunks.len(),
        1,
        "READ PDU (without data) payload must be 1 chunk"
    );

    let (hdr_bytes, body_bytes) = &chunks[0];

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
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read_response_good.hex")
            .context("failed to load read_response_good fixture")?;
    assert!(
        raw.len() >= HEADER_LEN,
        "fixture too small: {} < {}",
        raw.len(),
        HEADER_LEN
    );

    let (hdr_bytes, body_bytes) = raw.split_at(HEADER_LEN);

    let hdr = ScsiDataIn::from_bhs_bytes(hdr_bytes)
        .context("failed to parse ScsiDataIn BHS")?;
    let pdu = PDUWithData::<ScsiDataIn>::parse(hdr, body_bytes, false, false)
        .context("failed to parse ScsiDataIn PDU body")?;

    assert!(
        pdu.header.flags.contains(DataInFlags::FINAL),
        "FINAL bit must be set"
    );
    assert!(
        pdu.header.flags.contains(DataInFlags::S),
        "S bit (status present) must be set"
    );
    assert_eq!(
        pdu.header.scsi_status(),
        Some(0),
        "SCSI status must be GOOD(0)"
    );

    assert!(
        !pdu.header.flags.contains(DataInFlags::A),
        "A bit must be 0"
    );
    /*assert!(
        !pdu.header.flags.contains(DataInFlags::O),
        "O bit must be 0"
    );*/
    assert!(
        !pdu.header.flags.contains(DataInFlags::U),
        "U bit must be 0"
    );

    assert_eq!(
        pdu.data.len(),
        pdu.header.get_data_length_bytes(),
        "payload length mismatch: data.len() vs DataSegmentLength"
    );

    let payload = vec![0x00; pdu.header.get_data_length_bytes()];
    assert_eq!(&pdu.data, &payload);

    Ok(())
}
