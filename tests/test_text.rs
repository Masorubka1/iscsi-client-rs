use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::pdu_connection::ToBytes,
    models::{
        common::BasicHeaderSegment,
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
    assert!(bytes.len() > TextRequest::HEADER_LEN);

    let lun = [0u8; 8];
    let itt = 1;
    let ttt = NopOutRequest::DEFAULT_TAG;
    let cmd_sn = 1;
    let exp_sn = 1939077135;

    let mut builder = TextRequestBuilder::new()
        .lun(&lun)
        .initiator_task_tag(itt)
        .target_task_tag(ttt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_sn);

    let expected = TextRequest::from_bhs_bytes(&bytes)?;
    builder.header.data_segment_length = [0u8; 3];
    builder.header.data_segment_length[2] = 16;

    assert_eq!(&builder.header, &expected, "PDU bytes do not match fixture");

    let (hdr, data) = builder.to_bytes(&cfg).expect("failed to serialize");
    assert!(data.is_empty());

    //println!("Header: {}", hdr.encode_hex::<String>());
    //println!("Body:   {}", data.encode_hex::<String>());

    assert_eq!(
        &hdr[..],
        &bytes[..TextRequest::HEADER_LEN],
        "TextRequest header mismatch"
    );
    Ok(())
}

#[test]
fn test_text_response() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/text_response.hex")?;
    assert!(bytes.len() >= TextResponse::HEADER_LEN);

    let (parsed, data, digest) = TextResponse::parse(&bytes)?;
    assert!(!data.is_empty());
    assert!(digest.is_none());

    assert_eq!(
        parsed.opcode,
        BhsOpcode {
            flags: IfFlags::empty(),
            opcode: Opcode::TextResp,
        },
        "expected NOP-IN opcode 0x20"
    );
    let data_size = parsed.data_length_bytes();
    assert_eq!(data_size, data.len());
    assert_eq!(parsed.stat_sn, 1939077135);
    assert_eq!(parsed.exp_cmd_sn, 2);
    let expected = "TargetName=iqn.2025-07.com.example:target0\0TargetAddress=127.0.0.1:\
                    3260,1\0\0\0";
    assert_eq!(
        expected.to_string(),
        String::from_utf8(data).context("Failed to serialize")?
    );

    Ok(())
}
