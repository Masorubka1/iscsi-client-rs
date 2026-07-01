//! This module defines the state machine for iSCSI SendTargets discovery.
//! It connects to a target portal, performs a Discovery-session login,
//! issues `SendTargets=All` via Text Request, and parses the list of
//! available targets from the response.
//!
//! # RFC 3720 / RFC 7143 references
//! - § 4.2  SendTargets operation
//! - § 9.1  Text Request / Text Response opcodes
//! - § 10.10 Text negotiation (F/C stage bits)

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{marker::PhantomData, pin::Pin, sync::Arc};

use anyhow::{Context, Result, anyhow};
use rand::RngExt;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    cfg::config::{Config, login_keys_security},
    client::client::ClientConnection,
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data_fromat::{PduRequest, PduResponse},
        identifiers::Itt,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
        logout::{
            common::LogoutReason,
            request::{LogoutRequest, LogoutRequestBuilder},
            response::LogoutResponse,
        },
        text::{
            request::{TextRequest, TextRequestBuilder},
            response::TextResponse,
        },
    },
    state_machine::common::{StateMachine, StateMachineCtx, Transition},
};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single iSCSI target discovered via SendTargets.
///
/// Each `DiscoveredTarget` pairs a `TargetName` (IQN) with one or more
/// `TargetAddress` entries, as returned by the target in the Text response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredTarget {
    /// The iSCSI Qualified Name of the target (e.g. `iqn.2003-01.org…`).
    pub target_name: String,
    /// One or more `TargetAddress` strings in the form
    /// `IP:port,tpgt` (e.g. `192.168.1.10:3260,1`).
    pub target_addresses: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery state machine context
// ─────────────────────────────────────────────────────────────────────────────

/// Holds all state for a SendTargets discovery operation.
///
/// The state machine progresses through:
/// 1. `Connect`     — open a TCP connection to the portal
/// 2. `Login`       — authenticate with a Discovery session
/// 3. `SendTargets` — issue `SendTargets=All` Text Request
/// 4. `Collect`     — read all Text Response PDUs (handle F/C fragmentation)
/// 5. `Logout`      — gracefully close the session
/// 6. `Finish`      — return parsed targets
#[derive(Debug)]
pub struct DiscoveryCtx<'a> {
    _lt: PhantomData<&'a ()>,

    /// The TCP connection (set after `Connect`).
    pub conn: Option<Arc<ClientConnection>>,
    /// Configuration — same `Config` as for normal sessions, but the
    /// `SessionType` is interpreted as Discovery during login.
    pub cfg: Config,
    /// Cancellation token for the whole discovery flow.
    pub cancel: CancellationToken,
    /// Accumulated list of discovered targets.
    pub results: Vec<DiscoveredTarget>,
    /// Initiator Task Tag (ITT), incremented per request.
    pub itt: Itt,
    /// Command Sequence Number (bumped after login, used for Text/Logout).
    pub cmd_sn: u32,
    /// Expected Status Sequence Number (from target's StatSN + 1).
    pub exp_stat_sn: u32,
    /// Scratch buffer for BHS serialization.
    pub buf: [u8; HEADER_LEN],
    /// Last login response (preserved for logout parameters).
    pub last_login_response: Option<PduResponse<LoginResponse>>,
    /// Initiator Session ID, generated randomly per discovery attempt.
    pub isid: [u8; 6],
    /// Target-assigned TSIH (populated after login).
    pub tsih: u16,

    state: Option<DiscoveryStates>,
}

impl<'a> DiscoveryCtx<'a> {
    /// Creates a new discovery context in the `Connect` state.
    pub fn new(cfg: Config, cancel: CancellationToken) -> Self {
        let isid = {
            let mut rng = rand::rng();
            let mut buf = [0u8; 6];
            rng.fill(&mut buf);
            // RFC 7143 § 9.10: ISID top 2 bits describe the generator type.
            // `0b01` = vendor-assigned (safe default for ad-hoc discovery).
            buf[0] = (buf[0] & 0x3F) | 0x40;
            buf
        };

        Self {
            conn: None,
            cfg,
            cancel,
            results: Vec::new(),
            itt: Itt::new_unchecked(0),
            cmd_sn: 0,
            exp_stat_sn: 0,
            buf: [0u8; HEADER_LEN],
            last_login_response: None,
            isid,
            tsih: 0,
            state: Some(DiscoveryStates::Connect(Connect)),
            _lt: PhantomData,
        }
    }

    /// One-shot convenience: run the full discovery flow and return
    /// the list of targets.
    pub async fn discover(
        cfg: Config,
        cancel: CancellationToken,
    ) -> Result<Vec<DiscoveredTarget>> {
        let mut ctx = DiscoveryCtx::new(cfg, cancel);
        ctx.execute(&CancellationToken::new()).await
    }

    /// Parse the raw key=value bytes from Text Response data segments into
    /// `DiscoveredTarget` structs.
    pub fn parse_send_targets_response(data: &[u8]) -> Vec<DiscoveredTarget> {
        let mut map: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();

        for entry in data.split(|b| *b == 0) {
            if entry.is_empty() {
                continue;
            }
            let entry_str = match std::str::from_utf8(entry) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (key, value) = match entry_str.split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            map.entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }

        // Group by TargetName: each entry may have multiple TargetAddress keys.
        let mut targets: Vec<DiscoveredTarget> = Vec::new();
        if let Some(names) = map.remove("TargetName") {
            for name in names {
                targets.push(DiscoveredTarget {
                    target_name: name,
                    target_addresses: Vec::new(),
                });
            }
        }

        if let Some(addrs) = map.remove("TargetAddress") {
            for (i, addr_str) in addrs.iter().enumerate() {
                let idx = i.min(targets.len().saturating_sub(1));
                if let Some(t) = targets.get_mut(idx) {
                    for sub in addr_str.split('\0').filter(|s| !s.is_empty()) {
                        t.target_addresses.push(sub.to_string());
                    }
                }
            }
        }

        targets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// States
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Connect;

#[derive(Debug)]
pub struct Login;

#[derive(Debug)]
pub struct SendTargets;

#[derive(Debug)]
pub struct Collect;

#[derive(Debug)]
pub struct Logout;

#[derive(Debug)]
pub struct Finish;

#[derive(Debug)]
pub enum DiscoveryStates {
    Connect(Connect),
    Login(Login),
    SendTargets(SendTargets),
    Collect(Collect),
    Logout(Logout),
    Finish(Finish),
}

type DiscoveryStep = Transition<DiscoveryStates, Result<()>>;

// ═════════════════════════════════════════════════════════════════════════════
// Connect
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for Connect {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            debug!(
                "Discovery: connecting to {}",
                ctx.cfg.login.transport.target_address
            );
            let conn = match ClientConnection::connect(
                ctx.cfg.clone(),
                ctx.cancel.clone(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    return Transition::Done(Err(anyhow!(
                        "discovery connect failed: {e}"
                    )));
                },
            };
            ctx.conn = Some(conn);
            Transition::Next(DiscoveryStates::Login(Login), Ok(()))
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Login
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for Login {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let conn = match ctx.conn.as_ref() {
                Some(c) => Arc::clone(c),
                None => {
                    return Transition::Done(Err(anyhow!(
                        "no connection in discovery ctx"
                    )));
                },
            };

            let header = LoginRequestBuilder::new(ctx.isid, /* tsih hint */ 0)
                .transit()
                .csg(Stage::Security)
                .nsg(Stage::FullFeature)
                .versions(0, 0)
                .initiator_task_tag(ctx.itt)
                .connection_id(0);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu = PduRequest::<LoginRequest>::new_request(ctx.buf, &conn.cfg);
            pdu.append_data(login_keys_security(&ctx.cfg).as_slice());

            if let Err(e) = conn.send_request(ctx.itt, pdu).await {
                return Transition::Done(Err(e));
            }

            let rsp = match conn.read_response::<LoginResponse>(ctx.itt).await {
                Ok(r) => r,
                Err(e) => {
                    return Transition::Done(Err(anyhow!(
                        "discovery login response: {e}"
                    )));
                },
            };

            let hdr = match rsp.header_view() {
                Ok(h) => h,
                Err(e) => return Transition::Done(Err(e)),
            };

            match hdr.flags.nsg() {
                Some(Stage::FullFeature) => {
                    debug!("Discovery login complete — TSIH={}", hdr.tsih.get());
                },
                other => {
                    return Transition::Done(Err(anyhow!(
                        "discovery login: unexpected NSG={other:?} (expected \
                         FullFeature)"
                    )));
                },
            }

            ctx.tsih = hdr.tsih.get();
            // RFC 7143 § 6.4: Discovery sessions do NOT advance CmdSN
            // during login.  CmdSN=0 and ExpStatSN=0 for all subsequent PDUs.
            ctx.cmd_sn = 0;
            ctx.exp_stat_sn = 0;
            let next = ctx.itt.get().wrapping_add(1);
            ctx.itt = Itt::new_unchecked(next);
            ctx.last_login_response = Some(rsp);

            Transition::Next(DiscoveryStates::SendTargets(SendTargets), Ok(()))
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SendTargets
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for SendTargets {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let conn = match ctx.conn.as_ref() {
                Some(c) => Arc::clone(c),
                None => return Transition::Done(Err(anyhow!("no connection"))),
            };

            let header = TextRequestBuilder::new()
                .immediate()
                .lun(0)
                .initiator_task_tag(ctx.itt)
                .target_task_tag(TextRequest::DEFAULT_TAG)
                .cmd_sn(ctx.cmd_sn)
                .exp_stat_sn(ctx.exp_stat_sn);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut builder = PduRequest::<TextRequest>::new_request(ctx.buf, &conn.cfg);
            builder.append_data(b"SendTargets=All\0".as_slice());

            let itt = ctx.itt;
            if let Err(e) = conn.send_request(itt, builder).await {
                return Transition::Done(Err(e));
            }

            debug!("Discovery: sent SendTargets=All (ITT={itt})");

            Transition::Next(DiscoveryStates::Collect(Collect), Ok(()))
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Collect
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for Collect {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let conn = match ctx.conn.as_ref() {
                Some(c) => Arc::clone(c),
                None => return Transition::Done(Err(anyhow!("no connection"))),
            };

            let mut all_data: Vec<u8> = Vec::new();

            loop {
                let (mut pdu, data) =
                    match conn.read_response_raw::<TextResponse>(ctx.itt).await {
                        Ok((p, d)) => (p, d),
                        Err(e) => {
                            return Transition::Done(Err(anyhow!(
                                "discovery text response read: {e}"
                            )));
                        },
                    };

                let is_final = pdu
                    .header_view()
                    .map(|h| h.flags.get_final_bit())
                    .unwrap_or(false);

                let _ = pdu.parse_with_buff(&data);

                if let Ok(view) = pdu.header_view() {
                    debug!(
                        "Discovery TextResponse: data_len={}, final={}, data={:?}",
                        view.get_data_length_bytes(),
                        is_final,
                        String::from_utf8_lossy(pdu.data().unwrap_or(&[])),
                    );
                }

                all_data.extend_from_slice(data.as_ref());

                if is_final {
                    break;
                }
            }

            debug!(
                "Discovery: received {} bytes of SendTargets response",
                all_data.len()
            );

            ctx.results = DiscoveryCtx::parse_send_targets_response(&all_data);

            debug!("Discovery: parsed {} target(s)", ctx.results.len());

            let next = ctx.itt.get().wrapping_add(1);
            ctx.itt = Itt::new_unchecked(next);

            Transition::Next(DiscoveryStates::Logout(Logout), Ok(()))
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Logout
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for Logout {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let conn = match ctx.conn.as_ref() {
                Some(c) => Arc::clone(c),
                None => return Transition::Done(Err(anyhow!("no connection"))),
            };

            let header =
                LogoutRequestBuilder::new(LogoutReason::CloseSession, ctx.itt, 0)
                    .cmd_sn(ctx.cmd_sn)
                    .exp_stat_sn(ctx.exp_stat_sn);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let builder = PduRequest::<LogoutRequest>::new_request(ctx.buf, &conn.cfg);

            if let Err(e) = conn.send_request(ctx.itt, builder).await {
                return Transition::Done(Err(e));
            }

            match conn.read_response::<LogoutResponse>(ctx.itt).await {
                Ok(_) => {
                    debug!("Discovery logout complete");
                },
                Err(e) => {
                    debug!("Discovery logout response: {e} (ignored)");
                },
            }

            conn.kill_now();

            Transition::Next(DiscoveryStates::Finish(Finish), Ok(()))
        })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Finish
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachine<DiscoveryCtx<'ctx>, DiscoveryStep> for Finish {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = DiscoveryStep> + Send + 'a>>
    where
        Self: 'a,
        DiscoveryCtx<'ctx>: 'a;

    fn step<'a>(&'a self, _ctx: &'a mut DiscoveryCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move { Transition::Done(Ok(())) })
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// StateMachineCtx impl — drives the machine to completion
// ═════════════════════════════════════════════════════════════════════════════

impl<'ctx> StateMachineCtx<DiscoveryCtx<'ctx>, Vec<DiscoveredTarget>>
    for DiscoveryCtx<'ctx>
{
    async fn execute(
        &mut self,
        _cancel: &CancellationToken,
    ) -> Result<Vec<DiscoveredTarget>> {
        debug!("Discovery loop start");
        loop {
            let state = self
                .state
                .take()
                .context("state must be set in DiscoveryCtx")?;
            let tr = match state {
                DiscoveryStates::Connect(s) => s.step(self).await,
                DiscoveryStates::Login(s) => s.step(self).await,
                DiscoveryStates::SendTargets(s) => s.step(self).await,
                DiscoveryStates::Collect(s) => s.step(self).await,
                DiscoveryStates::Logout(s) => s.step(self).await,
                DiscoveryStates::Finish(s) => s.step(self).await,
            };

            match tr {
                Transition::Next(next, r) => {
                    r?;
                    self.state = Some(next);
                },
                Transition::Stay(Ok(_)) => {},
                Transition::Stay(Err(e)) => return Err(e),
                Transition::Done(r) => {
                    r?;
                    return Ok(std::mem::take(&mut self.results));
                },
            }
        }
    }
}
