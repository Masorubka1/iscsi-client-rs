// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::PDUWithData,
        nop::request::NopOutRequest,
        opcode::{BhsOpcode, Opcode},
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
    },
};
use zerocopy::FromBytes as ZFromBytes;

// Helper to load a hex fixture and decode it to a byte vector.
fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_text_request() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;

    let bytes = load_fixture("tests/unit_tests/fixtures/text/text_request.hex")?;
    assert!(bytes.len() > HEADER_LEN);

    let mut header_buf = [0u8; HEADER_LEN];
    header_buf.copy_from_slice(&bytes[..HEADER_LEN]);
    let mut parsed_fixture = PDUWithData::<TextRequest>::from_header_slice(header_buf);
    parsed_fixture.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;

    let itt = 1;
    let ttt = NopOutRequest::DEFAULT_TAG;
    let cmd_sn = 1;
    let exp_sn = 1939077135;

    let header_builder = TextRequestBuilder::new()
        .lun(0) // builder takes u64
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn);

    let mut hdr_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut hdr_buf)?;
    let mut builder = PDUWithData::<TextRequest>::from_header_slice(hdr_buf);
    builder.append_data(parsed_fixture.data.clone());

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

    assert_eq!(
        &hdr_bytes[..],
        &bytes[..HEADER_LEN],
        "TextRequest header mismatch"
    );
    assert_eq!(
        &body_bytes[..],
        &bytes[HEADER_LEN..],
        "TextRequest body mismatch"
    );

    let parsed_hdr_view =
        <TextRequest as ZFromBytes>::ref_from_bytes(&parsed_fixture.header_buf)
            .expect("valid TextRequest BHS view");

    assert_eq!(
        builder.header_view()?.get_data_length_bytes(),
        parsed_hdr_view.get_data_length_bytes(),
        "data_segment_length mismatch"
    );

    assert_eq!(
        builder.header_view()?.get_opcode()?,
        parsed_hdr_view.get_opcode()?,
        "opcode mismatch"
    );

    Ok(())
}

#[test]
fn test_text_response() -> Result<()> {
    let bytes = load_fixture("tests/unit_tests/fixtures/text/text_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    // Parse fixture into PDUWithData with header_buf.
    let mut header_buf = [0u8; HEADER_LEN];
    header_buf.copy_from_slice(&bytes[..HEADER_LEN]);
    let mut parsed = PDUWithData::<TextResponse>::from_header_slice(header_buf);
    parsed.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;

    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    // Zerocopy view for header fields.
    let hdr = <TextResponse as ZFromBytes>::ref_from_bytes(&parsed.header_buf)
        .expect("valid BHS");

    // Check opcode.
    let op = BhsOpcode::try_from(hdr.opcode.raw())?;
    assert_eq!(op.opcode, Opcode::TextResp, "expected TextResp opcode");

    // Check sizes and sequence numbers.
    let data_size = hdr.get_data_length_bytes();
    assert_eq!(data_size, parsed.data.len());

    assert_eq!(hdr.stat_sn.get(), 1939077135);
    assert_eq!(hdr.exp_cmd_sn.get(), 2);

    // Check payload contents.
    let expected =
        "TargetName=iqn.2025-07.com.example:target0\0TargetAddress=127.0.0.1:3260,1\0";
    let actual = String::from_utf8(parsed.data).context("Failed to decode TEXT data")?;
    assert_eq!(expected.to_string(), actual);

    Ok(())
}
