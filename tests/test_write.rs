use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::pdu_connection::ToBytes,
    handlers::simple_scsi_command::build_write12,
    models::{
        command::{
            common::{ResponseCode, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
            response::ScsiCommandResponse,
        },
        common::Builder,
    },
};

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_write10_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;
    let expected = load_fixture("tests/fixtures/write10_request.hex")?;
    let expected_hdr = ScsiCommandRequest::from_bhs_bytes(&expected)?;

    let header_len = ScsiCommandRequest::HEADER_LEN;

    let lun = [0u8; 8];
    let itt = 1090519040;
    let cmd_sn = 103;
    let exp_stat_sn = 1914934025;

    let mut cdb = [0u8; 12];
    build_write12(&mut cdb, 0x1234, 1, 0, 0);
    let write_buf = vec![0x01; 512];

    let builder = ScsiCommandRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(write_buf.len() as u32)
        .scsi_descriptor_block(&cdb)
        .write()
        .finall()
        .task_attribute(TaskAttribute::Simple)
        .append_data(write_buf.clone());

    assert_eq!(&builder.header, &expected_hdr, "BHS mismatch");

    let (hdr_bytes, body_bytes) = builder.to_bytes(&cfg)?;

    assert_eq!(&hdr_bytes[..], &expected[..header_len], "BHS mismatch");

    assert_eq!(body_bytes, write_buf, "Data-Out payload mismatch");

    Ok(())
}

#[test]
fn test_write10_response_parse() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/write10_response.hex")?;
    assert!(bytes.len() >= ScsiCommandResponse::HEADER_LEN);

    let (hdr, data, digest) = ScsiCommandResponse::parse(&bytes)?;

    assert!(data.is_empty(), "Expected no Data-In for WRITE response");

    println!("{digest:?}");
    assert!(
        digest.is_none(),
        "Expected no digest on a normal WRITE response"
    );

    assert_eq!(hdr.stat_sn, 1914934025, "Unexpected StatSN");
    assert_eq!(hdr.exp_cmd_sn, 104, "Unexpected ExpCmdSN");
    assert_eq!(
        hdr.response,
        ResponseCode::CommandCompleted,
        "Expected GOOD status"
    );

    Ok(())
}
