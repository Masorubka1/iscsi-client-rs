use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{Config, ToLoginKeys},
    },
    client::pdu_connection::ToBytes,
    login::{
        common::Stage,
        request::{LoginRequest, LoginRequestBuilder},
    },
};

#[test]
fn test_login_request_builder_minimal() -> Result<()> {
    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let hex_str = fs::read_to_string("tests/fixtures/login_minimal.hex")?
        .trim()
        .replace(|c: char| c.is_whitespace(), "");

    let bytes: Vec<u8> = Vec::from_hex(&hex_str).expect("Failed to decode hex fixture");
    assert_eq!(bytes.len(), 48, "fixture should decode to 48 bytes");
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;

    let tsih: u16 = 0x00;

    let mut builder = LoginRequestBuilder::new(config.initiator.isid, tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            config.negotiation.version_min,
            config.negotiation.version_max,
        );

    for key in config
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(config.target.to_login_keys())
        .chain(config.negotiation.to_login_keys())
        .chain(config.auth.to_login_keys())
    {
        builder = builder.with_data(key.into_bytes());
    }

    assert_eq!(builder.header, expected, "PDU bytes do not match fixture");

    Ok(())
}

#[test]
fn test_login_request_builder_full() -> Result<()> {
    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let hex_str = fs::read_to_string("tests/fixtures/login_pdu.bin")?
        .trim()
        .replace(char::is_whitespace, "");
    let bytes: Vec<u8> =
        Vec::from_hex(&hex_str).expect("Failed to decode full-login fixture");

    let expected_header = &bytes[..48];
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;
    let expected_body = &bytes[48..];

    let tsih: u16 = 0;
    let mut builder = LoginRequestBuilder::new(config.initiator.isid, tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            config.negotiation.version_min,
            config.negotiation.version_max,
        );

    for key in config
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(config.target.to_login_keys())
        .chain(config.negotiation.to_login_keys())
        .chain(config.auth.to_login_keys())
        .chain(config.performance.to_login_keys())
    {
        builder = builder.with_data(key.into_bytes());
    }

    builder = builder.with_data(config.extra_text.into_bytes());

    assert_eq!(&builder.header, &expected, "PDU bytes do not match fixture");

    let (hdr, body) = builder.to_bytes();

    //println!("Header: {}", hdr.encode_hex::<String>());
    //println!("Body:   {}", body.encode_hex::<String>());

    assert_eq!(&hdr[..], expected_header, "BHS different header dumps");
    assert_eq!(&body[..], expected_body, "DataSegment+pad unequal dump");

    Ok(())
}
