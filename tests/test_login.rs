use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{Config, ToLoginKeys},
    },
    client::pdu_connection::ToBytes,
    models::{
        common::Builder,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
};

const ISID: [u8; 6] = [0, 2, 61, 0, 0, 9];

#[test]
fn test_login_request() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let hex_str = fs::read_to_string("tests/fixtures/login_request.hex")?
        .trim()
        .replace(|c: char| c.is_whitespace(), "");

    let bytes: Vec<u8> = Vec::from_hex(&hex_str).expect("Failed to decode hex fixture");
    assert_eq!(bytes.len(), 524, "fixture should decode to 48 bytes");
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;

    let mut builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg.login.to_login_keys().into_iter() {
        builder = builder.append_data(key.into_bytes());
    }

    assert_eq!(builder.header, expected, "PDU bytes do not match fixture");
    Ok(())
}

#[test]
fn test_login_body_only() -> Result<()> {
    let cfg =
        resolve_config_path("tests/config.yaml").and_then(Config::load_from_file)?;
    let hex_str = fs::read_to_string("tests/fixtures/login_request.hex")?
        .trim()
        .replace(char::is_whitespace, "");
    let bytes: Vec<u8> = Vec::from_hex(&hex_str)?;
    let expected_body = &bytes[LoginRequest::HEADER_LEN..];

    let mut builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg.login.to_login_keys().into_iter() {
        builder = builder.append_data(key.into_bytes());
    }

    let (_hdr, body) = builder.to_bytes(&cfg).expect("failed to serialize");
    assert_eq!(&body[..], expected_body);
    Ok(())
}

#[test]
fn test_login_response_echo() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let mut builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg.login.to_login_keys().into_iter() {
        builder = builder.append_data(key.into_bytes());
    }

    let hex_str = fs::read_to_string("tests/fixtures/login_response.hex")?
        .trim()
        .replace(char::is_whitespace, "");
    let resp_bytes: Vec<u8> =
        Vec::from_hex(&hex_str).context("failed to decode login_response.hex")?;

    let (resp_hdr, _resp_data, resp_digest) = LoginResponse::parse(&resp_bytes)?;

    assert!(resp_digest.is_none());
    assert_eq!(
        resp_hdr.flags.bits(),
        builder.header.flags.bits(),
        "flags should match what we sent"
    );
    assert_eq!(
        resp_hdr.version_max, builder.header.version_max,
        "version_max should match what we sent"
    );
    Ok(())
}
