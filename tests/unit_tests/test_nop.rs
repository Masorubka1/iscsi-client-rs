// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{Builder, HEADER_LEN},
        data_fromat::PDUWithData,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
        opcode::{BhsOpcode, Opcode},
    },
};
use zerocopy::FromBytes;

// Helper to load a hex fixture and decode it to a byte vector.
fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

fn parse_nop_out(bytes: &[u8]) -> Result<PDUWithData<NopOutRequest>> {
    let mut header_buf = [0u8; HEADER_LEN];
    header_buf.copy_from_slice(&bytes[..HEADER_LEN]);
    let mut pdu = PDUWithData::<NopOutRequest>::from_header_slice(header_buf);
    pdu.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;
    Ok(pdu)
}

fn parse_nop_in(bytes: &[u8]) -> Result<PDUWithData<NopInResponse>> {
    let mut header_buf = [0u8; HEADER_LEN];
    header_buf.copy_from_slice(&bytes[..HEADER_LEN]);
    let mut pdu = PDUWithData::<NopInResponse>::from_header_slice(header_buf);
    pdu.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;
    Ok(pdu)
}

#[test]
fn test_nop_out_minimal() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;

    let bytes = load_fixture("tests/unit_tests/fixtures/nop/nop_out_request.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let parsed = parse_nop_out(&bytes)?;
    assert!(parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let itt = 1;
    let ttt = NopOutRequest::DEFAULT_TAG;
    let cmd_sn = 0;
    let exp_sn = 1;

    let header_builder = NopOutRequestBuilder::new()
        .lun(0)
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .immediate();

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PDUWithData::<NopOutRequest>::from_header_slice(header_buf);

    let (hdr_bytes, body) = &builder.build(
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

    assert!(body.is_empty(), "NOP-Out payload must be empty");

    let mut built_hdr = [0u8; HEADER_LEN];
    built_hdr.copy_from_slice(hdr_bytes.as_ref());
    assert_eq!(built_hdr, parsed.header_buf, "NOP-OUT ping header mismatch");

    Ok(())
}

#[test]
fn test_nop_in_parse() -> Result<()> {
    let bytes = load_fixture("tests/unit_tests/fixtures/nop/nop_in_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let parsed = parse_nop_in(&bytes)?;
    assert!(parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let hdr = <NopInResponse as FromBytes>::ref_from_bytes(&parsed.header_buf)
        .expect("valid NOP-In BHS");

    let op = BhsOpcode::try_from(hdr.opcode.raw())?;
    assert_eq!(op.opcode, Opcode::NopIn, "expected NOP-IN opcode 0x20");

    assert_eq!(hdr.stat_sn.get(), 3699214689);
    assert_eq!(hdr.exp_cmd_sn.get(), 191);

    Ok(())
}

/*#[test]
fn test_nop_out_header_digest() -> Result<()> {
    let expected = load_fixture("tests/fixtures/nop_out_request_crc_header.hex")?;
    assert_eq!(expected.len(), 48);

    // build the same header with our builder, enabling header-digest
    let lun = [0u8; 8];
    let itt = 0x11112222;
    let ttt = NopInOut::DEFAULT_TAG;
    let cmd_sn = 0x33334444;
    let exp_sn = 0x55556666;
    let builder = NopOutRequestBuilder::new(lun, itt, ttt, exp_sn)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .with_header_digest();

    let (hdr, data) = builder.to_bytes();
    assert!(data.is_empty(), "no payload expected");

    // verify whole 48-byte header matches fixture
    assert_eq!(&hdr[..], &expected[..], "header-digest mismatch");
    Ok(())
}

#[test]
fn test_nop_out_data_digest() -> Result<()> {
    let expected = load_fixture("tests/fixtures/nop_out_request_crc_data.hex")?;
    let lun = [0u8; 8];
    let itt = 0x01020304;
    let ttt = NopInOut::DEFAULT_TAG;
    let cmd_sn = 0x0A0B0C0D;
    let exp_sn = 0x0E0F1011;
    let payload = b"HEARTBEAT".to_vec();

    let builder = NopOutRequestBuilder::new(lun, itt, ttt, exp_sn)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn)
        .with_data(payload)
        .with_data_digest();

    let (hdr, mut bytes) = builder.to_bytes();
    let mut actual = Vec::with_capacity(48 + bytes.len());
    actual.extend_from_slice(&hdr);
    actual.append(&mut bytes);

    assert_eq!(&actual[..], &expected[..], "data-digest mismatch");
    Ok(())
}*/
