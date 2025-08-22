// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    control_block::write::build_write10,
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

    let expected =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/write10_request.hex")?;

    let lun_bytes = [0, 1, 0, 0, 0, 0, 0, 0];
    let lun_be = u64::from_be_bytes(lun_bytes);
    let itt = 2;
    let cmd_sn = 0;
    let exp_stat_sn = 2;

    let mut cdb = [0u8; 16];
    build_write10(&mut cdb, 0x1234, 0, 0, 1);

    // 512 байт immediate data (или первый burst — как в фикстуре)
    let write_buf = vec![0x01; 512];

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(lun_be)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(write_buf.len() as u32)
        .scsi_descriptor_block(&cdb)
        .write()
        .task_attribute(TaskAttribute::Simple);

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PDUWithData::<ScsiCommandRequest>::from_header_slice(header_buf);
    builder.append_data(write_buf);

    let hd = cfg
        .login
        .negotiation
        .header_digest
        .eq_ignore_ascii_case("CRC32C");
    let dd = cfg
        .login
        .negotiation
        .data_digest
        .eq_ignore_ascii_case("CRC32C");

    let (hdr_bytes, body_bytes) = &builder.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        hd,
        dd,
    )?;

    assert_eq!(&hdr_bytes[..], &expected[..HEADER_LEN], "BHS mismatch");
    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "Data-Out payload mismatch"
    );

    Ok(())
}

#[test]
fn test_write_response_parse() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let bytes =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/write10_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let hd = cfg
        .login
        .negotiation
        .header_digest
        .eq_ignore_ascii_case("CRC32C");
    let dd = cfg
        .login
        .negotiation
        .data_digest
        .eq_ignore_ascii_case("CRC32C");

    // zerocopy: создаём PDU поверх копии заголовка и парсим тело
    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(&bytes[..HEADER_LEN]);

    let mut pdu = PDUWithData::<ScsiCommandResponse>::from_header_slice(hdr_buf);
    pdu.parse_with_buff(&bytes[HEADER_LEN..], hd, dd)?;

    assert!(pdu.data.is_empty());
    assert!(pdu.header_digest.is_none());
    assert!(pdu.data_digest.is_none());

    let header = pdu.header_view()?;

    assert_eq!(header.stat_sn.get(), 1_914_934_025, "Unexpected StatSN");
    assert_eq!(header.exp_cmd_sn.get(), 104, "Unexpected ExpCmdSN");
    assert_eq!(header.exp_data_sn.get(), 0, "Unexpected ExpDataSN");

    assert_eq!(
        header.response.decode()?,
        ResponseCode::CommandCompleted,
        "Expected GOOD status"
    );

    Ok(())
}
