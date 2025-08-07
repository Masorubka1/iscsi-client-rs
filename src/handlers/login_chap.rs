//! CHAP login helper (RFC 1994) for the new PDU / connection layer.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use md5::Md5;

use crate::{
    cfg::config::{AuthConfig, Config, ToLoginKeys},
    client::client::Connection,
    models::{
        common::{Builder as _, SendingData},
        data_fromat::PDUWithData,
        login::{common::Stage, request::LoginRequestBuilder, response::LoginResponse},
    },
};

type HmacMd5 = Hmac<Md5>;

/// ---------------------------------------------------------------------------
/// Helper – parse the target’s CHAP challenge
/// ---------------------------------------------------------------------------
fn parse_chap_challenge(challenge_data: &[u8]) -> Result<(u8, Vec<u8>)> {
    let txt = String::from_utf8(challenge_data.to_vec())?;

    let mut chap_i = None;
    let mut chap_c = None; // ← **C**, not Cyrillic «С»

    for kv in txt.split('\x00') {
        let mut parts = kv.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("CHAP_I"), Some(v)) => chap_i = Some(v.parse()?),
            (Some("CHAP_C"), Some(hex)) => chap_c = Some(hex::decode(hex)?),
            _ => {},
        }
    }

    Ok((
        chap_i.context("missing CHAP_I")?,
        chap_c.context("missing CHAP_C")?,
    ))
}

/// ---------------------------------------------------------------------------
/// Step 1 – request a CHAP challenge
/// ---------------------------------------------------------------------------
async fn chap_step1(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    tsih: u16,
    task_tag: u32,
    cmd_sn: u32,
    exp_stat_sn: u32,
) -> Result<(LoginResponse, Vec<u8>)> {
    // --- build PDU ----------------------------------------------------------
    let log_req = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .header;

    let mut pdu = PDUWithData::from_header(log_req);
    pdu.append_data(b"AuthMethod=CHAP,None\x00".to_vec());

    for key in cfg
        .login
        .to_login_keys()
        .into_iter()
        .chain(cfg.extra_data.to_login_keys())
    {
        pdu.append_data(key.into_bytes());
    }

    // --- send / receive -----------------------------------------------------
    conn.send_request(task_tag, pdu).await?;
    let rsp = conn.read_response::<LoginResponse>(task_tag).await?;

    Ok((rsp.header, rsp.data))
}

/// ---------------------------------------------------------------------------
/// Step 2 – send the CHAP challenge response
/// ---------------------------------------------------------------------------
async fn chap_step2(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    hdr1: &LoginResponse,
    chap_i: u8,
    chap_c: &[u8],
) -> Result<LoginResponse> {
    // --- prepare CHAP_R -----------------------------------------------------
    let (secret_key, username) = match &cfg.login.auth {
        AuthConfig::Chap(chap) => (chap.secret.as_bytes(), chap.username.clone()),
        AuthConfig::None => bail!("CHAP authentication required but not configured"),
    };

    let mut mac = HmacMd5::new_from_slice(secret_key)?;
    mac.update(&[chap_i]);
    mac.update(chap_c);
    let chap_r = mac.finalize().into_bytes();

    // --- build PDU ----------------------------------------------------------
    let mut log_req = LoginRequestBuilder::new(isid, hdr1.tsih)
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(hdr1.initiator_task_tag)
        .connection_id(1)
        .cmd_sn(hdr1.max_cmd_sn)
        .exp_stat_sn(hdr1.exp_cmd_sn)
        .header;

    log_req.set_continue_bit();

    let mut pdu = PDUWithData::from_header(log_req);
    pdu.append_data(b"CHAP_A=5\x00".to_vec());
    pdu.append_data(format!("CHAP_N={username}\x00").into_bytes());
    pdu.append_data(format!("CHAP_R={}\x00", hex::encode(chap_r)).into_bytes());

    // --- send / receive -----------------------------------------------------
    conn.send_request(hdr1.initiator_task_tag, pdu).await?;
    let rsp = conn
        .read_response::<LoginResponse>(hdr1.initiator_task_tag)
        .await?;
    Ok(rsp.header)
}

/// ---------------------------------------------------------------------------
/// Step 3 – transition to Full-Feature phase
/// ---------------------------------------------------------------------------
async fn chap_step3(
    conn: &Connection,
    isid: [u8; 6],
    hdr2: &LoginResponse,
) -> Result<LoginResponse> {
    let log_req = LoginRequestBuilder::new(isid, hdr2.tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(hdr2.version_max, hdr2.version_active)
        .initiator_task_tag(hdr2.initiator_task_tag)
        .connection_id(1)
        .cmd_sn(hdr2.exp_cmd_sn)
        .exp_stat_sn(hdr2.max_cmd_sn)
        .header;

    let pdu = PDUWithData::from_header(log_req);

    conn.send_request(hdr2.initiator_task_tag, pdu).await?;
    let rsp = conn
        .read_response::<LoginResponse>(hdr2.initiator_task_tag)
        .await?;
    Ok(rsp.header)
}

/// ---------------------------------------------------------------------------
/// Public helper – full CHAP login flow
/// ---------------------------------------------------------------------------
pub async fn login_chap(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
) -> Result<LoginResponse> {
    // ---- Step 1 ------------------------------------------------------------
    let (hdr1, raw1) = chap_step1(conn, cfg, isid, 0, 0, 0, 0).await?;

    // ---- extract I/C from the target’s challenge --------------------------
    let (chap_i, chap_c) = parse_chap_challenge(&raw1)?;

    // ---- Step 2 ------------------------------------------------------------
    let hdr2 = chap_step2(conn, cfg, isid, &hdr1, chap_i, &chap_c).await?;

    // ---- Step 3 ------------------------------------------------------------
    chap_step3(conn, isid, &hdr2).await
}
