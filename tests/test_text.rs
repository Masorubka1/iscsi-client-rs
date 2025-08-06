use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::PDUWithData,
        nop::request::NopOutRequest,
        opcode::{BhsOpcode, IfFlags, Opcode},
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
    },
};

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

    let bytes = load_fixture("tests/fixtures/text_request.hex")?;
    assert!(bytes.len() > HEADER_LEN);

    let header_parsed = TextRequest::from_bhs_bytes(&bytes[..HEADER_LEN])?;
    let parsed_fixture =
        PDUWithData::<TextRequest>::parse(header_parsed, &bytes, false, false)?;

    let lun = [0u8; 8];
    let itt = 1;
    let ttt = NopOutRequest::DEFAULT_TAG;
    let cmd_sn = 1;
    let exp_sn = 1939077135;

    let header_builder = TextRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn);

    let mut built = PDUWithData::<TextRequest>::from_header(header_builder.header);
    built.append_data(parsed_fixture.data.clone());

    let chunks = built.build(&cfg)?;
    assert_eq!(chunks.len(), 1);
    let (hdr_bytes, body_bytes) = &chunks[0];

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

    assert_eq!(
        built.header.get_data_length_bytes(),
        parsed_fixture.header.get_data_length_bytes(),
        "data_segment_length mismatch"
    );
    assert_eq!(
        built.header.get_opcode(),
        parsed_fixture.header.get_opcode(),
        "opcode mismatch"
    );

    Ok(())
}

#[test]
fn test_text_response() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/text_response.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let hdr_only = TextResponse::from_bhs_bytes(&bytes[..HEADER_LEN])?;
    let parsed = PDUWithData::<TextResponse>::parse(hdr_only, &bytes, false, false)?;

    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    assert_eq!(
        parsed.header.opcode,
        BhsOpcode {
            flags: IfFlags::empty(),
            opcode: Opcode::TextResp
        },
        "expected TextResp opcode"
    );

    let data_size = parsed.header.get_data_length_bytes();
    assert_eq!(data_size, parsed.data.len());

    assert_eq!(parsed.header.stat_sn, 1939077135);
    assert_eq!(parsed.header.exp_cmd_sn, 2);

    let expected =
        "TargetName=iqn.2025-07.com.example:target0\0TargetAddress=127.0.0.1:3260,1\0";
    let actual = String::from_utf8(parsed.data).context("Failed to decode TEXT data")?;
    assert_eq!(expected.to_string(), actual);

    Ok(())
}
