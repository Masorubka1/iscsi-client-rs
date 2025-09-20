use std::pin::Pin;

use crate::{
    cfg::config::ToLoginKeys,
    models::{
        common::Builder,
        data_fromat::PduRequest,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
    state_machine::{
        common::{StateMachine, Transition},
        login::common::{LoginCtx, LoginStepOut},
    },
};

#[derive(Debug)]
pub struct PlainStart;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for PlainStart {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
            let header = LoginRequestBuilder::new(ctx.isid, ctx.tsih)
                .transit()
                .csg(Stage::Operational)
                .nsg(Stage::FullFeature)
                .versions(
                    ctx.conn.cfg.login.negotiation.version_min,
                    ctx.conn.cfg.login.negotiation.version_max,
                )
                .initiator_task_tag(ctx.itt)
                .connection_id(ctx.cid)
                .cmd_sn(0)
                .exp_stat_sn(0);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu = PduRequest::<LoginRequest>::new_request(ctx.buf, &ctx.conn.cfg);
            for key in ctx.conn.cfg.to_login_keys() {
                pdu.append_data(key.into_bytes().as_slice());
            }

            match ctx.conn.send_request(ctx.itt, pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx.conn.read_response::<LoginResponse>(ctx.itt).await {
                    Ok(rsp) => {
                        ctx.last_response = Some(rsp);
                        Transition::Done(Ok(()))
                    },
                    Err(other) => Transition::Done(Err(anyhow::anyhow!(
                        "got unexpected PDU: {}",
                        other
                    ))),
                },
            }
        })
    }
}
