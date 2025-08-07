use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    handlers::simple_scsi_command::build_read10,
    models::{
        command::{
            common::TaskAttribute,
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
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
fn test_read_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected = load_fixture("tests/fixtures/read_request.hex")?;

    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let itt = 2;
    let cmd_sn = 0;
    let exp_stat_sn = 2;

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
