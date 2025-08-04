use std::{collections::BTreeSet, fs};

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

const ISID: [u8; 6] = [0, 2, 61, 0, 0, 14];

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_login_request() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let bytes = load_fixture("tests/fixtures/login_request.hex")?;
    let mut parsed = LoginRequest::parse(&bytes)?;
    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let mut builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    for key in cfg.to_login_keys().into_iter() {
        builder = builder.append_data(key.into_bytes());
    }

    let data = parsed.data.clone();
    parsed.data = vec![];
    let new_data = builder.header.data;
    builder.header.data = vec![];

    assert_eq!(builder.header, parsed, "PDU bytes do not match fixture");

    parsed.data = data;
    builder.header.data = new_data;

    let (_hdr, body) = builder.to_bytes(&cfg).expect("failed to serialize");

    //println!("Header: {}", hdr.encode_hex::<String>());
    //println!("ParsedHeader: {}", parsed.encode_hex::<String>());
    println!(
        "Body (decoded):\n{}",
        String::from_utf8_lossy(&body).replace('\0', "\n")
    );
    println!(
        "ParsedBody (decoded):\n{}",
        String::from_utf8_lossy(&parsed.data).replace('\0', "\n")
    );

    let left: BTreeSet<_> = body.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
    let right: BTreeSet<_> = parsed
        .data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(left, right);
    Ok(())
}

#[test]
fn test_login_response_echo() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let hex_str = fs::read_to_string("tests/fixtures/login_response.hex")?
        .trim()
        .replace(char::is_whitespace, "");
    let resp_bytes: Vec<u8> =
        Vec::from_hex(&hex_str).context("failed to decode login_response.hex")?;

    let parsed = LoginResponse::parse(&resp_bytes)?;
    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

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

    assert_eq!(
        parsed.flags.bits(),
        builder.header.flags.bits(),
        "flags should match what we sent"
    );
    assert_eq!(
        parsed.version_max, builder.header.version_max,
        "version_max should match what we sent"
    );
    Ok(())
}
