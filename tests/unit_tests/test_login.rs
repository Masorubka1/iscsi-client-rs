// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{
            AuthConfig, Config, ToLoginKeys, login_keys_chap_response,
            login_keys_operational, login_keys_security,
        },
        enums::Digest,
    },
    models::{
        common::{Builder, HEADER_LEN},
        data_fromat::{PduRequest, PduResponse},
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
};

use crate::unit_tests::{load_fixture, parse_imm, parse_mut};

const ISID: [u8; 6] = [0, 2, 61, 0, 0, 14];

fn parse_chap_challenge_tlv(tlv: &[u8]) -> Result<(u8, Vec<u8>)> {
    let s = String::from_utf8_lossy(tlv);
    let mut id: Option<u8> = None;
    let mut c_hex: Option<String> = None;
    for kv in s.split('\x00') {
        if kv.is_empty() {
            continue;
        }
        if let Some(rest) = kv.strip_prefix("CHAP_I=") {
            id = Some(rest.trim().parse()?);
        } else if let Some(rest) = kv.strip_prefix("CHAP_C=") {
            let rest = rest.trim();
            let rest = rest
                .strip_prefix("0x")
                .or_else(|| rest.strip_prefix("0X"))
                .unwrap_or(rest);
            c_hex = Some(rest.to_string());
        }
    }
    let id = id.context("missing CHAP_I")?;
    let c_hex = c_hex.context("missing CHAP_C")?;
    if c_hex.len() % 2 != 0 {
        bail!("CHAP_C hex length must be even, got {}", c_hex.len());
    }
    let chal = hex::decode(c_hex)?;
    Ok((id, chal))
}

/// CHAP_R = MD5( id || secret || challenge ) -> "0x" + UPPER HEX
fn calc_chap_r_hex(id: u8, secret: &[u8], challenge: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update([id]);
    h.update(secret);
    h.update(challenge);
    let d = h.finalize();
    let mut s = String::with_capacity(2 + d.len() * 2);
    s.push_str("0x");
    for b in d {
        use core::fmt::Write;
        write!(&mut s, "{b:02X}").expect("WTF");
    }
    s
}

fn split_zeroes(buf: &[u8]) -> BTreeSet<String> {
    buf.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[test]
fn test_login_request() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let bytes = load_fixture("tests/unit_tests/fixtures/login/login_request.hex")?;

    let parsed: PduRequest<LoginRequest> = parse_mut(&bytes, &cfg)?;
    assert!(!parsed.data()?.is_empty());
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

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PduRequest::<LoginRequest>::new_request(header_buf, &cfg);

    for key in cfg.to_login_keys() {
        builder.append_data(key.into_bytes().as_slice());
    }

    assert_eq!(
        builder.header_buf, parsed.header_buf,
        "BHS differs from fixture"
    );

    let (_hdr, body) = &builder.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;

    let left: BTreeSet<_> = split_zeroes(body);
    let right: BTreeSet<_> = split_zeroes(&parsed.data()?);
    assert_eq!(left, right, "data segment key set differs");

    Ok(())
}

#[test]
fn test_login_response_echo() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let resp_bytes = load_fixture("tests/unit_tests/fixtures/login/login_response.hex")?;
    let parsed: PduResponse<LoginResponse> = parse_imm(&resp_bytes, &cfg)?;

    assert!(!parsed.data()?.is_empty());
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
        parsed.header_view()?.version_max,
        builder.header.version_max,
        "version_max should match what we sent"
    );
    assert_eq!(
        parsed.header_view()?.flags,
        builder.header.flags,
        "flags should match what we sent"
    );

    Ok(())
}

#[test]
fn chap_step1_security_only() -> Result<()> {
    let cfg = resolve_config_path("tests/config_chap.yaml")
        .and_then(Config::load_from_file)
        .context("failed to load tests/config_chap.yaml")?;

    let req_exp = load_fixture("tests/unit_tests/fixtures/login/step1_req.hex")?;
    let resp_bytes = load_fixture("tests/unit_tests/fixtures/login/step1_resp.hex")?;
    let _r1: PduResponse<LoginResponse> = parse_imm(&resp_bytes, &cfg)?;

    let s1_hdr = LoginRequestBuilder::new(ISID, 0)
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(0)
        .connection_id(1)
        .cmd_sn(0)
        .exp_stat_sn(0);

    let mut header_buf = [0u8; HEADER_LEN];
    s1_hdr.header.to_bhs_bytes(&mut header_buf)?;

    let mut s1 = PduRequest::<LoginRequest>::new_request(header_buf, &cfg);
    s1.append_data(login_keys_security(&cfg).as_slice());

    let (hdr_bytes, data_bytes) = &s1.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;
    let mut got = hdr_bytes.to_vec();
    got.extend_from_slice(data_bytes);

    let exp_pdu: PduRequest<LoginRequest> = parse_mut(&req_exp, &cfg)?;
    let got_pdu: PduRequest<LoginRequest> = parse_mut(&got, &cfg)?;
    assert_eq!(got_pdu.header_buf, exp_pdu.header_buf, "step1 BHS differs");
    assert_eq!(
        split_zeroes(&got_pdu.data()?),
        split_zeroes(&exp_pdu.data()?),
        "step1 TLV set differs"
    );
    Ok(())
}

#[test]
fn chap_step2_chap_a() -> Result<()> {
    let cfg = resolve_config_path("tests/config_chap.yaml")
        .and_then(Config::load_from_file)
        .context("failed to load tests/unit_tests/config_chap.yaml")?;

    let r1: PduResponse<LoginResponse> = parse_imm(
        &load_fixture("tests/unit_tests/fixtures/login/step1_resp.hex")?,
        &cfg,
    )?;
    let req_exp: PduRequest<LoginRequest> = parse_mut(
        &load_fixture("tests/unit_tests/fixtures/login/step2_req.hex")?,
        &cfg,
    )?;

    let r1_header = r1.header_view()?;

    let s2_hdr = LoginRequestBuilder::new(ISID, r1_header.tsih.get())
        .csg(Stage::Security)
        .nsg(Stage::Security)
        .initiator_task_tag(r1_header.initiator_task_tag.get())
        .connection_id(1)
        .cmd_sn(r1_header.exp_cmd_sn.get())
        .exp_stat_sn(r1_header.exp_cmd_sn.get().wrapping_add(1));

    let mut header_buf = [0u8; HEADER_LEN];
    s2_hdr.header.to_bhs_bytes(&mut header_buf)?;

    let mut s2 = PduRequest::<LoginRequest>::new_request(header_buf, &cfg);
    s2.append_data(b"CHAP_A=5\x00".as_slice());

    assert_eq!(s2.header_buf, req_exp.header_buf, "step2 BHS differs");
    assert_eq!(
        s2.data()?,
        req_exp.data()?,
        "step2 request bytes differ from fixture"
    );
    Ok(())
}

#[test]
fn chap_step3_chap_response() -> Result<()> {
    let cfg = resolve_config_path("tests/config_chap.yaml")
        .and_then(Config::load_from_file)
        .context("failed to load tests/config_chap.yaml")?;

    let r2: PduResponse<LoginResponse> = parse_imm(
        &load_fixture("tests/unit_tests/fixtures/login/step2_resp.hex")?,
        &cfg,
    )?;
    let (chap_i, chap_c) = parse_chap_challenge_tlv(&r2.data()?)?;
    let (user, secret) = match &cfg.login.auth {
        AuthConfig::Chap(c) => (c.username.as_str(), c.secret.as_bytes()),
        _ => bail!("tests/config_chap.yaml must provide CHAP credentials"),
    };
    let chap_r = calc_chap_r_hex(chap_i, secret, &chap_c);

    let req_exp = load_fixture("tests/unit_tests/fixtures/login/step3_req.hex")?;

    let r2_header = r2.header_view()?;

    let s3_hdr = LoginRequestBuilder::new(ISID, r2_header.tsih.get())
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(r2_header.initiator_task_tag.get())
        .connection_id(1)
        .cmd_sn(r2_header.exp_cmd_sn.get())
        .exp_stat_sn(r2_header.stat_sn.get().wrapping_add(1));

    let mut header_buf = [0u8; HEADER_LEN];
    s3_hdr.header.to_bhs_bytes(&mut header_buf)?;

    let mut s3 = PduRequest::<LoginRequest>::new_request(header_buf, &cfg);
    s3.append_data(login_keys_chap_response(user, &chap_r).as_slice());

    let (hdr_bytes, data_bytes) = &s3.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;
    let mut got = hdr_bytes.to_vec();
    got.extend_from_slice(data_bytes);

    let exp_pdu: PduRequest<LoginRequest> = parse_mut(&req_exp, &cfg)?;
    let got_pdu: PduRequest<LoginRequest> = parse_mut(&got, &cfg)?;
    assert_eq!(got_pdu.header_buf, exp_pdu.header_buf, "step3 BHS differs");
    assert_eq!(
        split_zeroes(&got_pdu.data()?),
        split_zeroes(&exp_pdu.data()?),
        "step3 TLV set differs"
    );
    Ok(())
}

#[test]
fn chap_step4_oper_to_ff_with_ops() -> Result<()> {
    let cfg = resolve_config_path("tests/config_chap.yaml")
        .and_then(Config::load_from_file)
        .context("failed to load tests/config_chap.yaml")?;

    let r2: PduResponse<LoginResponse> = parse_imm(
        &load_fixture("tests/unit_tests/fixtures/login/step3_resp.hex")?,
        &cfg,
    )?;
    let req_exp = load_fixture("tests/unit_tests/fixtures/login/step4_req.hex")?;

    let r2_header = r2.header_view()?;

    let s4_hdr = LoginRequestBuilder::new(ISID, r2_header.tsih.get())
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(r2_header.version_max, r2_header.version_active)
        .connection_id(1)
        .cmd_sn(r2_header.exp_cmd_sn.get())
        .exp_stat_sn(r2_header.stat_sn.get().wrapping_add(1));

    let mut header_buf = [0u8; HEADER_LEN];
    s4_hdr.header.to_bhs_bytes(&mut header_buf)?;

    let mut s4 = PduRequest::<LoginRequest>::new_request(header_buf, &cfg);
    s4.append_data(login_keys_operational(&cfg).as_slice());

    let (hdr_bytes, data_bytes) = &s4.build(
        cfg.login.negotiation.max_recv_data_segment_length as usize,
        cfg.login.negotiation.header_digest == Digest::CRC32C,
        cfg.login.negotiation.data_digest == Digest::CRC32C,
    )?;
    let mut got = hdr_bytes.to_vec();
    got.extend_from_slice(data_bytes);

    let exp_pdu: PduRequest<LoginRequest> = parse_mut(&req_exp, &cfg)?;
    let got_pdu: PduRequest<LoginRequest> = parse_mut(&got, &cfg)?;
    assert_eq!(got_pdu.header_buf, exp_pdu.header_buf, "step4 BHS differs");
    assert_eq!(
        split_zeroes(&got_pdu.data()?),
        split_zeroes(&exp_pdu.data()?),
        "step4 TLV set differs"
    );
    Ok(())
}
