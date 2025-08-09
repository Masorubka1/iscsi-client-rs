use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Result, bail};
use tracing::info;

use crate::{
    client::client::Connection,
    models::{
        data_fromat::PDUWithData,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
    },
    state_machine::common::{StateMachine, Transition},
};

#[derive(Debug)]
pub struct NopCtx<'a> {
    pub conn: Arc<Connection>,
    pub lun: [u8; 8],
    pub itt: &'a AtomicU32,
    pub cmd_sn: &'a AtomicU32,
    pub exp_stat_sn: &'a AtomicU32,
    pub ttt: u32,
}

#[derive(Debug, Clone)]
pub struct NopStatus {
    pub itt: u32,
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
}

impl<'a> NopCtx<'a> {
    pub fn new(
        conn: Arc<Connection>,
        lun: [u8; 8],
        itt: &'a AtomicU32,
        cmd_sn: &'a AtomicU32,
        exp_stat_sn: &'a AtomicU32,
        ttt: u32,
    ) -> Self {
        Self {
            conn,
            lun,
            itt,
            cmd_sn,
            exp_stat_sn,
            ttt,
        }
    }

    async fn send_nop_out(&self) -> Result<NopStatus> {
        let cmd_sn = self.cmd_sn.load(Ordering::SeqCst);
        let exp_stat_sn = self.exp_stat_sn.fetch_add(1, Ordering::SeqCst);
        let itt = self.itt.fetch_add(1, Ordering::SeqCst);

        let header = NopOutRequestBuilder::new()
            .cmd_sn(cmd_sn)
            .lun(&self.lun)
            .initiator_task_tag(itt)
            .target_task_tag(self.ttt)
            .exp_stat_sn(exp_stat_sn)
            .immediate();

        let builder: PDUWithData<NopOutRequest> = PDUWithData::from_header(header.header);
        info!("[NopOut]: {builder:?}");
        self.conn.send_request(itt, builder).await?;
        Ok(NopStatus {
            itt,
            cmd_sn,
            exp_stat_sn,
        })
    }

    async fn recieve_nop_in(&self, exp_status: NopStatus) -> Result<()> {
        let NopStatus {
            itt,
            cmd_sn: _,
            exp_stat_sn: _,
        } = exp_status;
        match self.conn.read_response::<NopInResponse>(itt).await {
            Ok(rsp) => {
                info!("[NopIn]: {rsp:?}");
                Ok(())
            },
            Err(other) => bail!("got unexpected PDU: {:?}", other.to_string()),
        }
    }
}

pub struct Idle;
pub struct Wait {
    pending: NopStatus,
}

pub enum NopStates {
    Idle(Idle),
    Wait(Wait),
}

type NopStepOut = Transition<NopStates, Result<NopStatus>>;

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Idle {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.send_nop_out().await {
                Ok(st) => Transition::Next(
                    NopStates::Wait(Wait {
                        pending: st.clone(),
                    }),
                    Ok(st),
                ),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

impl<'ctx> StateMachine<NopCtx<'ctx>, NopStepOut> for Wait {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = NopStepOut> + Send + 'a>>
    where
        Self: 'a,
        NopCtx<'ctx>: 'a;

    fn step<'a>(&'a mut self, ctx: &'a mut NopCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            match ctx.recieve_nop_in(self.pending.clone()).await {
                Ok(()) => Transition::Done(Ok(self.pending.clone())),
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}

pub async fn run_nop(mut state: NopStates, ctx: &mut NopCtx<'_>) -> Result<NopStatus> {
    loop {
        let trans = match &mut state {
            NopStates::Idle(s) => s.step(ctx).await,
            NopStates::Wait(s) => s.step(ctx).await,
        };

        match trans {
            Transition::Next(next_state, _r) => {
                state = next_state;
            },
            Transition::Stay(Ok(_)) => {},
            Transition::Stay(Err(e)) => return Err(e),
            Transition::Done(r) => return r,
        }
    }
}
