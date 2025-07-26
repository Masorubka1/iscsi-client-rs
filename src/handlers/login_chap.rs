use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use md5::Md5;

use crate::{
    cfg::config::{AuthConfig, Config, ToLoginKeys},
    client::client::{Connection, PduResponse},
    models::{
        common::Builder,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
};

type HmacMd5 = Hmac<Md5>;

/// Performs the first CHAP authentication step by sending the initiator name
/// and requesting a CHAP challenge from the target.
async fn chap_step1(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    tsih: u16,
    task_tag: u32,
    cmd_sn: u32,
    exp_stat_sn: u32,
) -> Result<(LoginResponse, Vec<u8>)> {
    let mut req = LoginRequestBuilder::new(isid, tsih)
        .transit()
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .initiator_task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .append_data(b"AuthMethod=CHAP,None\x00".to_vec());

    for key in cfg
        .login
        .to_login_keys()
        .into_iter()
        .chain(cfg.extra_data.to_login_keys())
    {
        req = req.append_data(key.into_bytes());
    }

    let (hdr, data, _dig) = match conn
        .call::<{ LoginRequest::HEADER_LEN }, LoginResponse>(req)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };
    Ok((hdr, data))
}

/// Extract CHAP_I and CHAP_N values from the target’s challenge string
fn parse_chap_challenge(challenge_data: &[u8]) -> Result<(u8, Vec<u8>)> {
    let txt = String::from_utf8(challenge_data.to_vec())?;
    let mut chap_i = None;
    let mut chap_n = None;
    for kv in txt.split('\x00') {
        let mut parts = kv.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("CHAP_I"), Some(v)) => chap_i = Some(v.parse()?),
            (Some("CHAP_С"), Some(hex)) => chap_n = Some(hex::decode(hex)?),
            _ => {},
        }
    }
    let i = chap_i.context("missing CHAP_I")?;
    let n = chap_n.context("missing CHAP_N")?;
    Ok((i, n))
}

/// Step 2: send CHAP response (CHAP_A, CHAP_I, CHAP_R, UserName), return header
async fn chap_step2(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
    tsih: u16,
    task_tag: u32,
    cmd_sn: u32,
    exp_stat_sn: u32,
) -> Result<LoginResponse> {
    let req = LoginRequestBuilder::new(isid, tsih)
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .cont()
        .initiator_task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .append_data(b"CHAP_A=5\x00".to_vec());
    let (_hdr, data, _dig) = match conn
        .call::<{ LoginRequest::HEADER_LEN }, LoginResponse>(req)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };

    let (chap_i, chap_n) = parse_chap_challenge(&data)?;

    let (secret_key, username) = match &cfg.login.auth {
        AuthConfig::Chap(chap) => (chap.secret.as_bytes(), chap.username.clone()),
        AuthConfig::None => bail!("CHAP authentication required but none configured"),
    };

    let mut mac = HmacMd5::new_from_slice(secret_key)?;
    mac.update(&[chap_i]);
    mac.update(&chap_n);
    let chap_r = mac.finalize().into_bytes();

    let req = LoginRequestBuilder::new(isid, tsih)
        .csg(Stage::Security)
        .nsg(Stage::Operational)
        .cont()
        .initiator_task_tag(task_tag)
        .connection_id(1)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .append_data(format!("CHAP_N={username}\x00").as_bytes().to_vec())
        .append_data(
            format!("CHAP_R={}\x00", hex::encode(chap_r))
                .as_bytes()
                .to_vec(),
        );
    let (hdr, _data, _dig) = match conn
        .call::<{ LoginRequest::HEADER_LEN }, LoginResponse>(req)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };
    Ok(hdr)
}

/// Step 3: complete login → FullFeature
async fn chap_step3(
    conn: &Connection,
    isid: [u8; 6],
    hdr2: &LoginResponse,
) -> Result<LoginResponse> {
    let req = LoginRequestBuilder::new(isid, hdr2.tsih)
        .transit()
        .csg(Stage::Operational)
        .nsg(Stage::FullFeature)
        .versions(hdr2.version_max, hdr2.version_active)
        .initiator_task_tag(hdr2.initiator_task_tag)
        .connection_id(1)
        .cmd_sn(hdr2.exp_cmd_sn)
        .exp_stat_sn(hdr2.max_cmd_sn);
    let (hdr, _data, _dig) = match conn
        .call::<{ LoginRequest::HEADER_LEN }, LoginResponse>(req)
        .await?
    {
        PduResponse::Normal((hdr, data, _dig)) => (hdr, data, _dig),
        PduResponse::Reject((hdr, data, _dig)) => {
            bail!("Error_resp: {:?}\n Data: {:?}", hdr, data)
        },
    };
    Ok(hdr)
}

/// High‐level CHAP login flow
pub async fn login_chap(
    conn: &Connection,
    cfg: &Config,
    isid: [u8; 6],
) -> Result<LoginResponse> {
    let (hdr1, _raw1) = chap_step1(conn, cfg, isid, 0, 0, 0, 0).await?;

    let hdr2 = chap_step2(
        conn,
        cfg,
        isid,
        hdr1.tsih,
        hdr1.initiator_task_tag,
        hdr1.max_cmd_sn,
        hdr1.exp_cmd_sn,
    )
    .await?;

    let hdr3 = chap_step3(conn, isid, &hdr2).await?;
    Ok(hdr3)
}
