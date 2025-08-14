use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    control_block::common::build_write10,
    models::{
        command::{
            common::{ResponseCode, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::{Builder, HEADER_LEN},
        data_fromat::PDUWithData,
    },
};

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_write_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected = load_fixture("tests/fixtures/scsi_commands/write_request.hex")?;

    let expected_hdr = ScsiCommandRequest::from_bhs_bytes(&expected[..HEADER_LEN])?;

    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let itt = 2;
    let cmd_sn = 0;
    let exp_stat_sn = 2;

    let mut cdb = [0u8; 16];
    build_write10(&mut cdb, 0x1234, 0, 0, 1);
    let write_buf = vec![0x01; 512];

    let header = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(write_buf.len() as u32)
        .scsi_descriptor_block(&cdb)
        .write()
        .task_attribute(TaskAttribute::Simple);

    let mut pdu = PDUWithData::<ScsiCommandRequest>::from_header(header.header);
    pdu.append_data(write_buf);

    let chunks = pdu.build(&cfg)?;
    assert_eq!(chunks.len(), 1, "WRITE PDU must be a single chunk");

    let (hdr_bytes, body_bytes) = &chunks[0];

    assert_eq!(
        ScsiCommandRequest::from_bhs_bytes(hdr_bytes)?,
        expected_hdr,
        "BHS mismatch"
    );

    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "Data-Out payload mismatch"
    );

    Ok(())
}

#[test]
fn test_write_response_parse() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/scsi_commands/write_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let hdr_only = ScsiCommandResponse::from_bhs_bytes(&bytes[..HEADER_LEN])?;
    let parsed = PDUWithData::<ScsiCommandResponse>::parse(
        hdr_only,
        &bytes[HEADER_LEN..],
        true,
        false,
    )?;

    assert!(parsed.data.is_empty());
    assert!(parsed.header_digest.is_some());
    assert!(parsed.data_digest.is_none());

    assert_eq!(parsed.header.stat_sn, 1914934025, "Unexpected StatSN");
    assert_eq!(parsed.header.exp_cmd_sn, 104, "Unexpected ExpCmdSN");
    assert_eq!(parsed.header.exp_data_sn, 0, "Unexpected ExpDataSN");
    assert_eq!(
        parsed.header.response,
        ResponseCode::CommandCompleted,
        "Expected GOOD status"
    );

    Ok(())
}
