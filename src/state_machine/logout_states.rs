use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Result, bail};

use crate::{
    client::client::Connection,
    models::{
        data_fromat::PDUWithData,
        logout::{
            request::{LogoutReason, LogoutRequest, LogoutRequestBuilder},
            response::{LogoutResponse, LogoutResponseCode},
        },
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct LogoutCtx<'a> {
    pub conn: Arc<Connection>,
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub cid: u16,
    pub reason: LogoutReason,
}

impl<'a> LogoutCtx<'a> {
    pub fn new(
        conn: Arc<Connection>,
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        cid: u16,
        reason: LogoutReason,
    ) -> Self {
        Self {
            conn,
            itt,
            cmd_sn,
            exp_stat_sn,
            cid,
            reason,
        }
    }

    async fn send_logout(&self) -> Result<LogoutStatus> {
        let cmd_sn = self.cmd_sn.load(Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.fetch_add(1, Ordering::SeqCst);
        let itt = self.itt.fetch_add(1, Ordering::SeqCst);

        let header = LogoutRequestBuilder::new(self.reason.clone(), itt, self.cid)
            .cmd_sn(cmd_sn)
            .exp_stat_sn(exp_stat_sn)
            .build();

        let builder: PDUWithData<LogoutRequest> = PDUWithData::from_header(header);
        self.conn.send_request(itt, builder).await?;

        Ok(LogoutStatus {
            itt,
            cmd_sn,
            exp_stat_sn,
        })
    }

    async fn receive_logout_resp(&self, expected: LogoutStatus) -> Result<()> {
        let LogoutStatus { itt, .. } = expected;

        match self.conn.read_response::<LogoutResponse>(itt).await {
            Ok(rsp) => {
                if rsp.header.response != LogoutResponseCode::Success {
                    bail!("LogoutResp: target returned {:?}", rsp.header);
                }
                Ok(())
            },
            Err(other) => bail!("got unexpected PDU: {}", other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogoutStatus {
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

pub struct Idle;
pub struct Wait {
    pending: LogoutStatus,
}

pub enum LogoutStates {
    Idle(Idle),
    Wait(Wait),
}

type LogoutStepOut = Transition<LogoutStates, Result<LogoutStatus>>;

impl<'ctx> StateMachine<LogoutCtx<'ctx>, LogoutStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = LogoutStepOut> + Send + 'a>>
    where
        Self: 'a,
        LogoutCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LogoutCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_logout().await {
                Ok(st) => Transition::Next(
                    LogoutStates::Wait(Wait {
                        pending: st.clone(),
                    }),
                    Ok(st),
                ),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<LogoutCtx<'ctx>, LogoutStepOut> for Wait {
    type StepResult<'a>
        = Pin<Box<dyn std::future::Future<Output = LogoutStepOut> + Send + 'a>>
    where
        Self: 'a,
        LogoutCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut LogoutCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.receive_logout_resp(self.pending.clone()).await {
                Ok(()) => Transition::Done(Ok(self.pending.clone())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

pub async fn run_logout(
    mut state: LogoutStates,
    ctx: &mut LogoutCtx<'_>,
) -> Result<LogoutStatus> {
    loop {
        let trans = match &mut state {
            LogoutStates::Idle(s) => s.step(ctx).await,
            LogoutStates::Wait(s) => s.step(ctx).await,
        };

        match trans {
            Transition::Next(next_state, _r) => state = next_state,
            Transition::Stay(Ok(_)) => {},
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(r) => return r,
        }
    }
}
