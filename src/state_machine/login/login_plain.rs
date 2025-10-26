//! This module defines the state machine for the iSCSI plain login process.
//! It includes the state and transitions for handling an unauthenticated login.

use std::pin::Pin;

use crate::{
    cfg::config::{login_keys_operational, login_keys_security},
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

/// Represents the initial state for a plain (unauthenticated) login.
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
                .versions(0, 0)
                .initiator_task_tag(ctx.itt)
                .connection_id(ctx.cid);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu = PduRequest::<LoginRequest>::new_request(ctx.buf, &ctx.conn.cfg);
            let mut sec_bytes = login_keys_security(&ctx.conn.cfg);
            sec_bytes.extend_from_slice(&login_keys_operational(&ctx.conn.cfg));
            pdu.append_data(&sec_bytes);

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
