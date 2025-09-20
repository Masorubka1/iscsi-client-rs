use std::pin::Pin;

use anyhow::{Context, Result, anyhow};
use md5::{Digest, Md5};

use crate::{
    cfg::config::{
        AuthConfig, login_keys_chap_response, login_keys_operational, login_keys_security,
    },
    models::{
        common::Builder,
        data_fromat::PDUWithData,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
    state_machine::{
        common::{StateMachine, Transition},
        login::common::{LoginCtx, LoginStates, LoginStepOut},
    },
};

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

#[derive(Debug)]
pub struct ChapSecurity;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapSecurity {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            // Step1: Security → Security (without CHAP_A)
            let header = LoginRequestBuilder::new(ctx.isid, ctx.tsih)
                .csg(Stage::Security)
                .nsg(Stage::Security)
                .initiator_task_tag(ctx.itt)
                .connection_id(ctx.cid)
                .cmd_sn(0)
                .exp_stat_sn(0);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu =
                PDUWithData::<LoginRequest>::from_header_slice(ctx.buf, &ctx.conn.cfg);
            pdu.append_data(login_keys_security(&ctx.conn.cfg).as_slice());

            match ctx.conn.send_request(ctx.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(ctx.itt).await {
                    Ok(rsp) => {
                        ctx.last_response = Some(rsp);
                        Transition::Next(LoginStates::ChapA(ChapA), Ok(()))
                    },
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapA;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapA {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            // Step2: Security → Security, CHAP_A=5
            let (header, itt) = {
                let last = match ctx.validate_last_response_header() {
                    Ok(last) => last,
                    Err(e) => {
                        return Transition::Done(Err(e));
                    },
                };

                let header = LoginRequestBuilder::new(ctx.isid, last.tsih.get())
                    .csg(Stage::Security)
                    .nsg(Stage::Security)
                    .initiator_task_tag(last.initiator_task_tag.get())
                    .connection_id(ctx.cid)
                    .cmd_sn(last.exp_cmd_sn.get())
                    .exp_stat_sn(last.stat_sn.get().wrapping_add(1));

                (header, last.initiator_task_tag.get())
            };

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu =
                PDUWithData::<LoginRequest>::from_header_slice(ctx.buf, &ctx.conn.cfg);
            pdu.append_data(b"CHAP_A=5\x00".as_slice());

            match ctx.conn.send_request(itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(itt).await {
                    Ok(rsp) => {
                        ctx.last_response = Some(rsp);
                        Transition::Next(LoginStates::ChapAnswer(ChapAnswer), Ok(()))
                    },
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapAnswer;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapAnswer {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let (header, itt, user, chap_r) = {
                let last = match ctx.validate_last_response_pdu() {
                    Ok(last) => last,
                    Err(e) => return Transition::Done(Err(e)),
                };

                let last_header = match ctx.validate_last_response_header() {
                    Ok(last) => last,
                    Err(e) => return Transition::Done(Err(e)),
                };

                let data = match last.data() {
                    Ok(data) => data,
                    Err(e) => return Transition::Done(Err(e)),
                };

                let (id, chal) = match parse_chap_challenge(data) {
                    Ok(v) => v,
                    Err(e) => return Transition::Done(Err(e)),
                };

                let (user, secret) = match &ctx.conn.cfg.login.auth {
                    AuthConfig::Chap(c) => (c.username.as_str(), c.secret.as_bytes()),
                    AuthConfig::None => {
                        return Transition::Done(Err(anyhow!(
                            "Target requires CHAP but config has no credentials"
                        )));
                    },
                };

                let chap_r = calc_chap_r_hex(id, secret, &chal);

                // Step3: (Security -> Operational, Transit=1)
                let header = LoginRequestBuilder::new(ctx.isid, last_header.tsih.get())
                    .transit()
                    .csg(Stage::Security)
                    .nsg(Stage::Operational)
                    .initiator_task_tag(last_header.initiator_task_tag.get())
                    .connection_id(ctx.cid)
                    .cmd_sn(last_header.exp_cmd_sn.get())
                    .exp_stat_sn(last_header.stat_sn.get().wrapping_add(1));

                (header, last_header.initiator_task_tag.get(), user, chap_r)
            };

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu =
                PDUWithData::<LoginRequest>::from_header_slice(ctx.buf, &ctx.conn.cfg);
            pdu.append_data(login_keys_chap_response(user, &chap_r).as_slice());

            if let Err(e) = ctx.conn.send_request(itt, pdu).await {
                return Transition::Done(Err(e));
            }

            match ctx.conn.read_response::<LoginResponse>(itt).await {
                Ok(rsp) => {
                    ctx.last_response = Some(rsp);
                    Transition::Next(LoginStates::ChapOpToFull(ChapOpToFull), Ok(()))
                },
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

#[derive(Debug)]
pub struct ChapOpToFull;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for ChapOpToFull {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            // Step4: Operational (Transit) → FullFeature + operational keys
            let (header, itt) = {
                let last = match ctx.validate_last_response_header() {
                    Ok(last) => last,
                    Err(e) => return Transition::Done(Err(e)),
                };

                let header = LoginRequestBuilder::new(ctx.isid, last.tsih.get())
                    .transit()
                    .csg(Stage::Operational)
                    .nsg(Stage::FullFeature)
                    .versions(last.version_max, last.version_active)
                    .initiator_task_tag(last.initiator_task_tag.get())
                    .connection_id(ctx.cid)
                    .cmd_sn(last.exp_cmd_sn.get())
                    .exp_stat_sn(last.stat_sn.get().wrapping_add(1));
                (header, last.initiator_task_tag.get())
            };

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu =
                PDUWithData::<LoginRequest>::from_header_slice(ctx.buf, &ctx.conn.cfg);
            pdu.append_data(login_keys_operational(&ctx.conn.cfg).as_slice());

            match ctx.conn.send_request(itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(itt).await {
                    Ok(rsp) => {
                        ctx.last_response = Some(rsp);
                        Transition::Done(Ok(()))
                    },
                    Err(e) => Transition::Done(Err(e)),
                },
            }
        })
    }
}
