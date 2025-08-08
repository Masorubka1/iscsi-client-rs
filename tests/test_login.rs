use std::{collections::BTreeSet, fs};

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{Config, ToLoginKeys},
    },
    models::{
        common::{Builder, HEADER_LEN},
        data_fromat::PDUWithData,
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

    let header_parsed = LoginRequest::from_bhs_bytes(&bytes[..HEADER_LEN])?;

    let parsed = PDUWithData::<LoginRequest>::parse(
        header_parsed,
        &bytes[HEADER_LEN..],
        false,
        false,
    )?;
    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let header_builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    let mut builder = PDUWithData::<LoginRequest>::from_header(header_builder.header);

    for key in cfg.to_login_keys() {
        builder.append_data(key.into_bytes());
    }

    assert_eq!(builder.header, parsed.header, "BHS differs from fixture");

    let chunks = builder.build(&cfg)?;
    assert_eq!(chunks.len(), 1, "login request must be a single chunk");
    let (_hdr, body) = &chunks[0];

    let left: BTreeSet<_> = body.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
    let right: BTreeSet<_> = parsed
        .data
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(left, right, "data segment key set differs");

    Ok(())
}

#[test]
fn test_login_response_echo() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let resp_bytes = load_fixture("tests/fixtures/login_response.hex")?;

    let resp_hdr = LoginResponse::from_bhs_bytes(&resp_bytes[..HEADER_LEN])?;
    let parsed =
        PDUWithData::<LoginResponse>::parse(resp_hdr, &resp_bytes, false, false)?;

    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    let builder = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(
            cfg.login.negotiation.version_min,
            cfg.login.negotiation.version_max,
        );

    assert_eq!(
        parsed.header.version_max, builder.header.version_max,
        "version_max should match what we sent"
    );
    assert_eq!(
        parsed.header.flags.bits(),
        builder.header.flags.bits(),
        "flags should match what we sent"
    );

    Ok(())
}
