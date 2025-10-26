//! This module defines common structures and enums for the iSCSI Login state
//! machine. It provides the context and state definitions for handling the
//! login process.

use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    cfg::config::{Config, login_keys_operational},
    client::client::ClientConnection,
    models::{
        common::HEADER_LEN,
        data_fromat::PduResponse,
        login::{common::Stage, response::LoginResponse},
    },
    state_machine::{
        common::{StateMachine, StateMachineCtx, Transition},
        login::{
            login_chap::{ChapA, ChapAnswer, ChapOpToFull, ChapSecurity},
            login_plain::PlainStart,
        },
    },
};

/// This structure represents the context for a Login command.
#[derive(Debug)]
pub struct LoginCtx<'a> {
    _lt: PhantomData<&'a ()>,

    /// The client connection.
    pub conn: Arc<ClientConnection>,
    /// The Initiator Session ID.
    pub isid: [u8; 6],
    /// The Connection ID.
    pub cid: u16,
    /// The Target Session Identifying Handle.
    pub tsih: u16,
    /// The Initiator Task Tag.
    pub itt: u32,
    /// A buffer for the BHS.
    pub buf: [u8; HEADER_LEN],

    /// The last received login response.
    pub last_response: Option<PduResponse<LoginResponse>>,

    state: Option<LoginStates>,
}

impl<'a> LoginCtx<'a> {
    /// Creates a new `LoginCtx` for a login operation.
    pub fn new(conn: Arc<ClientConnection>, isid: [u8; 6], cid: u16, tsih: u16) -> Self {
        Self {
            conn,
            isid,
            cid,
            tsih,
            itt: 0,
            buf: [0u8; HEADER_LEN],
            last_response: None,
            state: None,
            _lt: PhantomData,
        }
    }

    /// Sets the login state to use plain authentication.
    pub fn set_plain_login(&mut self) {
        self.state = Some(LoginStates::PlainStart(PlainStart));
    }

    /// Sets the login state to use CHAP authentication.
    pub fn set_chap_login(&mut self) {
        self.state = Some(LoginStates::ChapSecurity(ChapSecurity));
    }

    /// Validates and returns the header of the last login response.
    pub fn validate_last_response_header(&self) -> Result<&LoginResponse> {
        match &self.last_response {
            Some(l) => match l.header_view() {
                Ok(last) => Ok(last),
                Err(e) => Err(e),
            },
            None => Err(anyhow!("no last response in ctx")),
        }
    }

    /// Validates and returns the last login response PDU.
    pub fn validate_last_response_pdu(&self) -> Result<&PduResponse<LoginResponse>> {
        match &self.last_response {
            Some(l) => Ok(l),
            None => Err(anyhow!("no last response in ctx")),
        }
    }
}

/// A type alias for the output of a login state machine step.
pub type LoginStepOut = Transition<LoginStates, Result<()>>;

/// Defines the possible states for a Login operation state machine.
#[derive(Debug)]
pub enum LoginStates {
    /// The initial state for plain authentication.
    PlainStart(PlainStart),
    /// The initial state for CHAP authentication.
    ChapSecurity(ChapSecurity),
    /// The state for sending the CHAP algorithm.
    ChapA(ChapA),
    /// The state for sending the CHAP answer.
    ChapAnswer(ChapAnswer),
    /// The state for transitioning from operational to full feature phase.
    ChapOpToFull(ChapOpToFull),
}

impl<'ctx> StateMachineCtx<LoginCtx<'ctx>, PduResponse<LoginResponse>>
    for LoginCtx<'ctx>
{
    async fn execute(
        &mut self,
        _cancel: &CancellationToken,
    ) -> Result<PduResponse<LoginResponse>> {
        debug!("Loop login");
        loop {
            let state = self.state.take().context("state must be set LoginCtx")?;
            let tr = match state {
                LoginStates::PlainStart(s) => s.step(self).await,
                LoginStates::ChapSecurity(s) => s.step(self).await,
                LoginStates::ChapA(s) => s.step(self).await,
                LoginStates::ChapAnswer(s) => s.step(self).await,
                LoginStates::ChapOpToFull(s) => s.step(self).await,
            };

            match tr {
                Transition::Next(next_state, _r) => {
                    self.state = Some(next_state);
                },
                Transition::Stay(Ok(_)) => {},
                Transition::Stay(Err(e)) => return Err(e),
                Transition::Done(r) => {
                    r?;
                    return self
                        .last_response
                        .take()
                        .ok_or_else(|| anyhow!("no last response in ctx"));
                },
            }
        }
    }
}

fn parse_login_text_map(data: &[u8]) -> Result<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for entry in data.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let entry_str = std::str::from_utf8(entry)
            .context("login response contains invalid UTF-8 text")?;
        let (key, value) = entry_str.split_once('=').ok_or_else(|| {
            anyhow!("login response entry '{entry_str}' is missing '=' separator")
        })?;
        let value = value.trim().to_string();
        if value == "NotUnderstood" {
            warn!("{}={}", key.to_string(), value);
            continue;
        }

        map.entry(key.to_string())
            .or_default()
            .push(value.trim().to_string());
    }
    Ok(map)
}

/// Ensures that the target accepted every operational key/value requested in
/// the configuration.
pub(crate) fn verify_operational_negotiation(
    cfg: &Config,
    rsp: &PduResponse<LoginResponse>,
) -> Result<()> {
    let header = rsp.header_view()?;
    match header.flags.nsg() {
        Some(Stage::FullFeature) => {},
        other => bail!(
            "login response NSG={other:?} (expected {:?})",
            Stage::FullFeature
        ),
    }

    let data = rsp
        .data()
        .context("login response missing negotiation payload")?;
    if data.is_empty() {
        bail!("login response negotiation payload is empty");
    }

    let server = parse_login_text_map(data)?;
    let expected_bytes = login_keys_operational(cfg);
    let expected = parse_login_text_map(expected_bytes.as_slice())?;

    let mut mismatches = Vec::new();
    for (key, exp_values) in expected {
        for expected_value in exp_values {
            match server.get(&key) {
                Some(values) if values.iter().any(|v| v == &expected_value) => {},
                Some(values) => mismatches.push(format!(
                    "{key}: expected '{expected_value}' but target replied '{}'",
                    values.join(", ")
                )),
                None => {},
            }
        }
    }

    if mismatches.is_empty() {
        Ok(())
    } else {
        bail!("login negotiation mismatch: {}", mismatches.join("; "))
    }
}
