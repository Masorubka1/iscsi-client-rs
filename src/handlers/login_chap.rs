// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};

use crate::{
    cfg::config::{
        AuthConfig, Config, login_keys_chap_response, login_keys_operational,
        login_keys_security,
    },
    client::client::Connection,
    models::{
        common::Builder as _,
        data_fromat::PDUWithData,
        login::{common::Stage, request::LoginRequestBuilder, response::LoginResponse},
    },
};

fn calc_chap_r_hex(id: u8, secret: &[u8], challenge: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update([id]);
    hasher.update(secret);
    hasher.update(challenge);
    let d = hasher.finalize();
    let mut s = String::with_capacity(2 + d.len() * 2);
    s.push_str("0x");
    for b in d {
        use core::fmt::Write;
        write!(&mut s, "{b:02X}").unwrap();
    }
    s
}

fn parse_chap_challenge(txt_bytes: &[u8]) -> Result<(u8, Vec<u8>)> {
    let txt = String::from_utf8(txt_bytes.to_vec())?;
    let mut chap_i: Option<u8> = None;
    let mut chap_c_hex: Option<String> = None;

    for kv in txt.split_terminator('\x00') {
        let mut parts = kv.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("CHAP_I"), Some(v)) => chap_i = Some(v.trim().parse()?),
            (Some("CHAP_C"), Some(s)) => {
                let s = s.trim();
                let s = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                chap_c_hex = Some(s.to_string());
            },
            _ => {},
        }
    }

    let id = chap_i.context("missing CHAP_I")?;
    let hex = chap_c_hex.context("missing CHAP_C")?;
    if hex.len() % 2 != 0 {
        bail!("CHAP_C hex length must be even, got {}", hex.len());
    }
    let chal =
        hex::decode(&hex).with_context(|| format!("failed to decode CHAP_C: {hex}"))?;
    Ok((id, chal))
}

async fn step_security(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    itt: u32,
    cid: u16,
) -> Result<PDUWithData<LoginResponse>> {
    let req = LoginRequestBuilder::new(isid, 0)
        .csg(Stage::Security)
        .nsg(Stage::Security)
        .initiator_task_tag(itt)
        .connection_id(cid)
        .cmd_sn(0)
        .exp_stat_sn(0)
        .header;

    let mut pdu = PDUWithData::from_header(req);
    pdu.append_data(login_keys_security(cfg));
    conn.send_request(itt, pdu).await?;
    conn.read_response::<LoginResponse>(itt).await
}

async fn step_chap_a(
    conn: &Connection,
    isid: [u8; 6],
    prev: &PDUWithData<LoginResponse>,
    cid: u16,
) -> Result<PDUWithData<LoginResponse>> {
    let req = LoginRequestBuilder::new(isid, prev.header.tsih)
        .csg(Stage::Security)
        .nsg(Stage::Security)
        .initiator_task_tag(prev.header.initiator_task_tag)
        .connection_id(cid)
        .cmd_sn(prev.header.exp_cmd_sn)
        .exp_stat_sn(prev.header.stat_sn.wrapping_add(1))
        .header;

    let mut pdu = PDUWithData::from_header(req);
    pdu.append_data(b"CHAP_A=5\x00".to_vec());
    conn.send_request(prev.header.initiator_task_tag, pdu)
        .await?;
    conn.read_response::<LoginResponse>(prev.header.initiator_task_tag)
        .await
}

async fn step_chap_answer(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    prev: &PDUWithData<LoginResponse>,
    cid: u16,
) -> Result<PDUWithData<LoginResponse>> {
    let (id, chal) = parse_chap_challenge(&prev.data)?;
    let (user, secret) = match &cfg.login.auth {
        AuthConfig::Chap(c) => (c.username.as_str(), c.secret.as_bytes()),
        AuthConfig::None => bail!("Target requires CHAP but config has no credentials"),
    };
    let chap_r = calc_chap_r_hex(id, secret, &chal);

    let req = LoginRequestBuilder::new(isid, prev.header.tsih)
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(prev.header.initiator_task_tag)
        .connection_id(cid)
        .cmd_sn(prev.header.exp_cmd_sn)
        .exp_stat_sn(prev.header.stat_sn.wrapping_add(1))
        .header;

    let mut pdu = PDUWithData::from_header(req);
    pdu.append_data(login_keys_chap_response(user, &chap_r));
    conn.send_request(prev.header.initiator_task_tag, pdu)
        .await?;
    conn.read_response::<LoginResponse>(prev.header.initiator_task_tag)
        .await
}

async fn step_operational_to_ff(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    cid: u16,
    prev: &PDUWithData<LoginResponse>,
) -> Result<PDUWithData<LoginResponse>> {
    let req = LoginRequestBuilder::new(isid, prev.header.tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(prev.header.version_max, prev.header.version_active)
        .initiator_task_tag(prev.header.initiator_task_tag)
        .connection_id(cid)
        .cmd_sn(prev.header.exp_cmd_sn)
        .exp_stat_sn(prev.header.stat_sn.wrapping_add(1))
        .header;

    let mut pdu = PDUWithData::from_header(req);
    pdu.append_data(login_keys_operational(cfg));
    conn.send_request(prev.header.initiator_task_tag, pdu)
        .await?;
    conn.read_response::<LoginResponse>(prev.header.initiator_task_tag)
        .await
}

pub async fn login_chap(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
) -> Result<PDUWithData<LoginResponse>> {
    let itt = 0u32;
    let cid = 1u16;

    let r1 = step_security(conn, cfg, isid, itt, cid).await?;
    let r1b = step_chap_a(conn, isid, &r1, cid).await?;
    let r2 = step_chap_answer(conn, cfg, isid, &r1b, cid).await?;
    let r4 = step_operational_to_ff(conn, cfg, isid, cid, &r2).await?;
    Ok(r4)
}
