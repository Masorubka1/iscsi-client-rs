use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tracing::debug;

use crate::{
    cfg::config::Config,
    client::client::ClientConnection,
    models::{
        common::HEADER_LEN, data_fromat::PDUWithData, login::response::LoginResponse,
    },
    state_machine::{
        common::{StateMachine, StateMachineCtx, Transition},
        login::{
            login_chap::{ChapA, ChapAnswer, ChapOpToFull, ChapSecurity},
            login_plain::PlainStart,
        },
    },
};

#[derive(Debug)]
pub struct LoginCtx<'a> {
    pub conn: Arc<ClientConnection>,
    pub cfg: &'a Config,
    pub isid: [u8; 6],
    pub cid: u16,
    pub itt: u32,
    pub buf: [u8; HEADER_LEN],

    pub last_response: Option<PDUWithData<LoginResponse>>,

    state: Option<LoginStates>,
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
            last_response: None,
            state: None,
        }
    }

    pub fn set_plain_login(&mut self) {
        self.state = Some(LoginStates::PlainStart(PlainStart));
    }

    pub fn set_chap_login(&mut self) {
        self.state = Some(LoginStates::ChapSecurity(ChapSecurity));
    }

    pub fn validate_last_response_header(&self) -> Result<&LoginResponse> {
        match &self.last_response {
            Some(l) => match l.header_view() {
                Ok(last) => Ok(last),
                Err(e) => Err(e),
            },
            None => Err(anyhow!("no last response in ctx")),
        }
    }

    pub fn validate_last_response_pdu(&self) -> Result<&PDUWithData<LoginResponse>> {
        match &self.last_response {
            Some(l) => Ok(l),
            None => Err(anyhow!("no last response in ctx")),
        }
    }
}

pub type LoginStepOut = Transition<LoginStates, Result<()>>;

#[derive(Debug)]
pub enum LoginStates {
    // Plain (1 Step)
    PlainStart(PlainStart),
    // CHAP (4 Steps)
    ChapSecurity(ChapSecurity),
    ChapA(ChapA),
    ChapAnswer(ChapAnswer),
    ChapOpToFull(ChapOpToFull),
}

impl<'ctx> StateMachineCtx<LoginCtx<'ctx>> for LoginCtx<'ctx> {
    async fn execute(&mut self) -> Result<()> {
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
                Transition::Done(err) => {
                    return err;
                },
            }
        }
    }
}
