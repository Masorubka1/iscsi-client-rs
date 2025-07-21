use std::fs;

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{Config, ToLoginKeys},
    },
    client::pdu_connection::ToBytes,
    models::login::{
        common::Stage,
        request::{LoginRequest, LoginRequestBuilder},
        response::LoginResponse,
    },
};

#[test]
fn test_login_request() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let hex_str = fs::read_to_string("tests/fixtures/login_request.hex")?
        .trim()
        .replace(|c: char| c.is_whitespace(), "");

    let bytes: Vec<u8> = Vec::from_hex(&hex_str).expect("Failed to decode hex fixture");
    assert_eq!(bytes.len(), 572, "fixture should decode to 48 bytes");
    let expected = LoginRequest::from_bhs_bytes(&bytes)?;

    let mut builder = LoginRequestBuilder::new(cfg.initiator.isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(cfg.negotiation.version_min, cfg.negotiation.version_max);

    for key in cfg
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(cfg.target.to_login_keys())
        .chain(cfg.negotiation.to_login_keys())
        .chain(cfg.auth.to_login_keys())
        .chain(cfg.performance.to_login_keys())
    {
        builder = builder.with_data(key.into_bytes());
    }
    builder = builder.with_data(cfg.extra_text.into_bytes());

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
    let expected_body = &bytes[48..];

    let mut builder = LoginRequestBuilder::new(cfg.initiator.isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(cfg.negotiation.version_min, cfg.negotiation.version_max)
        .connection_id(0)
        .cmd_sn(0)
        .exp_stat_sn(0);

    for key in cfg
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(cfg.target.to_login_keys())
        .chain(cfg.negotiation.to_login_keys())
        .chain(cfg.auth.to_login_keys())
        .chain(cfg.performance.to_login_keys())
    {
        builder = builder.with_data(key.into_bytes());
    }
    builder = builder.with_data(cfg.extra_text.into_bytes());

    let (_hdr, body) = builder.to_bytes();
    assert_eq!(&body[..], expected_body);
    Ok(())
}

#[test]
fn test_login_response_echo() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let mut req_builder = LoginRequestBuilder::new(cfg.initiator.isid, 0)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .connection_id(1)
        .versions(cfg.negotiation.version_min, cfg.negotiation.version_max);
    for key in cfg
        .initiator
        .to_login_keys()
        .into_iter()
        .chain(cfg.target.to_login_keys())
        .chain(cfg.negotiation.to_login_keys())
        .chain(cfg.auth.to_login_keys())
        .chain(cfg.performance.to_login_keys())
    {
        req_builder = req_builder.with_data(key.into_bytes());
    }
    req_builder = req_builder.with_data(cfg.extra_text.into_bytes());

    let hex_str = fs::read_to_string("tests/fixtures/login_response.hex")?
        .trim()
        .replace(char::is_whitespace, "");
    let resp_bytes: Vec<u8> =
        Vec::from_hex(&hex_str).context("failed to decode login_response.hex")?;

    let (resp_hdr, _resp_data, _resp_digest) = LoginResponse::parse(&resp_bytes)?;

    assert_eq!(
        resp_hdr.flags.bits(),
        req_builder.header.flags.bits(),
        "flags should match what we sent"
    );
    assert_eq!(
        resp_hdr.version_max, req_builder.header.version_max,
        "version_max should match what we sent"
    );
    Ok(())
}
