// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{Context, Result, anyhow};
use md5::{Digest, Md5};
use tracing::debug;

use crate::{
    cfg::config::{
        AuthConfig, Config, ToLoginKeys, login_keys_chap_response,
        login_keys_operational, login_keys_security,
    },
    client::client::ClientConnection,
    models::{
        common::{Builder as _, HEADER_LEN},
        data_fromat::PDUWithData,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct LoginCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub cfg: &'a Config,
    pub isid: [u8; 6],
    pub cid: u16,
    pub itt: u32,
    pub buf: [u8; HEADER_LEN],
}

impl<'a> LoginCtx<'a> {
    pub fn new(
        conn: Arc<ClientConnection>,
        cfg: &'a Config,
        isid: [u8; 6],
        cid: u16,
        itt: u32,
    ) -> Self {
        Self {
            conn,
            cfg,
            isid,
            cid,
            itt,
            buf: [0u8; HEADER_LEN],
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginStatus {
    pub itt: u32,
    pub tsih: u16,
    pub exp_cmd_sn: u32,
    pub stat_sn: u32,
    pub version_max: u8,
    pub version_active: u8,
}

impl From<&PDUWithData<LoginResponse>> for LoginStatus {
    fn from(r: &PDUWithData<LoginResponse>) -> Self {
        let header = r.header_view().expect("failed to parse header");

        Self {
            itt: header.initiator_task_tag,
            tsih: header.tsih.get(),
            exp_cmd_sn: header.exp_cmd_sn.get(),
            stat_sn: header.stat_sn.get(),
            version_max: header.version_max,
            version_active: header.version_active,
        }
    }
}

type LoginStepOut = Transition<LoginStates, Result<LoginStatus>>;

pub enum LoginStates {
    // Plain (1 Step)
    PlainStart(PlainStart),

    // CHAP (4 Steps)
    ChapSecurity(ChapSecurity),
    ChapA(ChapA),
    ChapAnswer(ChapAnswer),
    ChapOpToFull(ChapOpToFull),
}

#[derive(Debug, Clone)]
pub struct LastHdr {
    pub tsih: u16,
    pub itt: u32,
    pub exp_cmd_sn: u32,
    pub stat_sn: u32,
    pub ver_max: u8,
    pub ver_active: u8,
    pub data: Vec<u8>,
}

impl From<&PDUWithData<LoginResponse>> for LastHdr {
    fn from(r: &PDUWithData<LoginResponse>) -> Self {
        let header = r.header_view().expect("failder to parse header");

        Self {
            tsih: header.tsih.get(),
            itt: header.initiator_task_tag,
            exp_cmd_sn: header.exp_cmd_sn.get(),
            stat_sn: header.stat_sn.get(),
            ver_max: header.version_max,
            ver_active: header.version_active,
            data: r.data.clone(),
        }
    }
}

/* -------------------- helpers (CHAP) -------------------- */

/// CHAP_R = MD5( one-octet CHAP_ID || secret || challenge ), HEX uppercase with
/// prefix 0x
fn calc_chap_r_hex(id: u8, secret: &[u8], challenge: &[u8]) -> String {
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

/// split CHAP_I/CHAP_C
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
        anyhow::bail!("CHAP_C hex length must be even, got {}", hex.len());
    }
    let chal =
        hex::decode(&hex).with_context(|| format!("failed to decode CHAP_C: {hex}"))?;
    Ok((id, chal))
}

/* -------------------- PLAIN -------------------- */

#[derive(Debug)]
pub struct PlainStart;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for PlainStart {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let header = LoginRequestBuilder::new(ctx.isid, 0)
                .transit()
                .csg(Stage::Operational)
                .nsg(Stage::FullFeature)
                .versions(
                    ctx.cfg.login.negotiation.version_min,
                    ctx.cfg.login.negotiation.version_max,
                )
                .initiator_task_tag(ctx.itt)
                .connection_id(ctx.cid)
                .cmd_sn(0)
                .exp_stat_sn(0);

            let _ = header
                .header
                .to_bhs_bytes(ctx.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<LoginResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu = PDUWithData::<LoginRequest>::from_header_slice(ctx.buf);
            for key in ctx.cfg.to_login_keys() {
                pdu.append_data(key.into_bytes());
            }

            match ctx.conn.send_request(ctx.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(ctx.itt).await {
                    Ok(rsp) => Transition::Done(Ok(LoginStatus::from(&rsp))),
                    Err(other) => Transition::Done(Err(anyhow::anyhow!(
                        "got unexpected PDU: {}",
                        other
                    ))),
                },
            }
        })
    }
}

/* -------------------- CHAP (4 steps) -------------------- */
#[derive(Debug)]
pub struct ChapSecurity;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapSecurity {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            // Step1: Security → Security (without CHAP_A)
            let header = LoginRequestBuilder::new(ctx.isid, 0)
                .csg(Stage::Security)
                .nsg(Stage::Security)
                .initiator_task_tag(ctx.itt)
                .connection_id(ctx.cid)
                .cmd_sn(0)
                .exp_stat_sn(0);

            let _ = header
                .header
                .to_bhs_bytes(ctx.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<LoginResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu = PDUWithData::<LoginRequest>::from_header_slice(ctx.buf);
            pdu.append_data(login_keys_security(ctx.cfg));

            match ctx.conn.send_request(ctx.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(ctx.itt).await {
                    Ok(rsp) => {
                        let last = LastHdr::from(&rsp);
                        Transition::Next(
                            LoginStates::ChapA(ChapA { last }),
                            Ok(LoginStatus::from(&rsp)),
                        )
                    },
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapA {
    pub last: LastHdr,
}

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapA {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        let last = self.last.clone();
        Box::pin(async move {
            // Step2: Security → Security, CHAP_A=5
            let header = LoginRequestBuilder::new(ctx.isid, last.tsih)
                .csg(Stage::Security)
                .nsg(Stage::Security)
                .initiator_task_tag(last.itt)
                .connection_id(ctx.cid)
                .cmd_sn(last.exp_cmd_sn)
                .exp_stat_sn(last.stat_sn.wrapping_add(1));

            let _ = header
                .header
                .to_bhs_bytes(ctx.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<LoginResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu = PDUWithData::<LoginRequest>::from_header_slice(ctx.buf);
            pdu.append_data(b"CHAP_A=5\x00".to_vec());

            match ctx.conn.send_request(last.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(last.itt).await {
                    Ok(rsp) => {
                        let next_last = LastHdr::from(&rsp);
                        Transition::Next(
                            LoginStates::ChapAnswer(ChapAnswer { last: next_last }),
                            Ok(LoginStatus::from(&rsp)),
                        )
                    },
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapAnswer {
    pub last: LastHdr,
}

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapAnswer {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        let last = self.last.clone();
        Box::pin(async move {
            let (id, chal) = match parse_chap_challenge(&last.data) {
                Ok(v) => v,
                Err(e) => return Transition::Done(Err(e)),
            };

            let (user, secret) = match &ctx.cfg.login.auth {
                AuthConfig::Chap(c) => (c.username.as_str(), c.secret.as_bytes()),
                AuthConfig::None => {
                    return Transition::Done(Err(anyhow!(
                        "Target requires CHAP but config has no credentials"
                    )));
                },
            };

            let chap_r = calc_chap_r_hex(id, secret, &chal);

            // Step3: (Security -> Operational, Transit=1)
            let header = LoginRequestBuilder::new(ctx.isid, last.tsih)
                .transit()
                .csg(Stage::Security)
                .nsg(Stage::Operational)
                .initiator_task_tag(last.itt)
                .connection_id(ctx.cid)
                .cmd_sn(last.exp_cmd_sn)
                .exp_stat_sn(last.stat_sn.wrapping_add(1));

            let _ = header
                .header
                .to_bhs_bytes(ctx.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<LoginResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu = PDUWithData::<LoginRequest>::from_header_slice(ctx.buf);
            pdu.append_data(login_keys_chap_response(user, &chap_r));

            if let Err(e) = ctx.conn.send_request(last.itt, pdu).await {
                return Transition::Done(Err(e));
            }

            match ctx.conn.read_response::<LoginResponse>(last.itt).await {
                Ok(rsp) => {
                    let next_last = LastHdr::from(&rsp);
                    Transition::Next(
                        LoginStates::ChapOpToFull(ChapOpToFull { last: next_last }),
                        Ok(LoginStatus::from(&rsp)),
                    )
                },
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapOpToFull {
    pub last: LastHdr,
}

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapOpToFull {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        let last = self.last.clone();
        Box::pin(async move {
            // Step4: Operational (Transit) → FullFeature + operational keys
            let header = LoginRequestBuilder::new(ctx.isid, last.tsih)
                .transit()
                .csg(Stage::Operational)
                .nsg(Stage::FullFeature)
                .versions(last.ver_max, last.ver_active)
                .initiator_task_tag(last.itt)
                .connection_id(ctx.cid)
                .cmd_sn(last.exp_cmd_sn)
                .exp_stat_sn(last.stat_sn.wrapping_add(1));

            let _ = header
                .header
                .to_bhs_bytes(ctx.buf.as_mut_slice())
                .map_err(|e| {
                    Transition::<PDUWithData<LoginResponse>, anyhow::Error>::Done(e)
                });

            let mut pdu = PDUWithData::<LoginRequest>::from_header_slice(ctx.buf);
            pdu.append_data(login_keys_operational(ctx.cfg));

            match ctx.conn.send_request(last.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(last.itt).await {
                    Ok(rsp) => Transition::Done(Ok(LoginStatus::from(&rsp))),
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}

pub async fn run_login(
    mut state: LoginStates,
    ctx: &mut LoginCtx<'_>,
) -> Result<LoginStatus> {
    debug!("Loop login");
    loop {
        let tr = match &mut state {
            LoginStates::PlainStart(s) => s.step(ctx).await,
            LoginStates::ChapSecurity(s) => s.step(ctx).await,
            LoginStates::ChapA(s) => s.step(ctx).await,
            LoginStates::ChapAnswer(s) => s.step(ctx).await,
            LoginStates::ChapOpToFull(s) => s.step(ctx).await,
        };

        match tr {
            Transition::Next(next_state, _r) => {
                state = next_state;
            },
            Transition::Stay(Ok(_)) => {},
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(r) => return r,
        }
    }
}

pub fn start_plain() -> LoginStates {
    LoginStates::PlainStart(PlainStart)
}

pub fn start_chap() -> LoginStates {
    LoginStates::ChapSecurity(ChapSecurity)
}
