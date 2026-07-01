//! This module defines the state machine for the iSCSI plain login process.
//! It includes the state and transitions for handling an unauthenticated login.

use std::pin::Pin;

use anyhow::anyhow;

use crate::{
    cfg::config::{login_keys_operational, login_keys_security},
    models::{
        common::{BasicHeaderSegment, Builder},
        data_fromat::PduRequest,
        identifiers::Itt,
        login::{
            common::Stage,
            request::{LoginRequest, LoginRequestBuilder},
            response::LoginResponse,
        },
    },
    state_machine::{
        common::{StateMachine, Transition},
        login::common::{
            verify_operational_negotiation, LoginCtx, LoginStates, LoginStepOut,
        },
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
                .initiator_task_tag(Itt::default())
                .connection_id(ctx.cid);

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu = PduRequest::<LoginRequest>::new_request(ctx.buf, &ctx.conn.cfg);
            let mut sec_bytes = login_keys_security(&ctx.conn.cfg);
            sec_bytes.extend_from_slice(&login_keys_operational(&ctx.conn.cfg));
            if let Err(e) = pdu.append_data(&sec_bytes) {
                return Transition::Done(Err(e));
            }

            match ctx.conn.send_request(Itt::default(), pdu).await {
                Err(e) => Transition::Done(Err(e)),
                Ok(()) => match ctx
                    .conn
                    .read_response::<LoginResponse>(Itt::default())
                    .await
                {
                    Ok(rsp) => {
                        let nsg = match rsp.header_view() {
                            Ok(header) => header.flags.nsg(),
                            Err(e) => return Transition::Done(Err(e)),
                        };

                        match nsg {
                            Some(Stage::FullFeature) => {
                                if let Err(e) =
                                    verify_operational_negotiation(&ctx.conn.cfg, &rsp)
                                {
                                    return Transition::Done(Err(e));
                                }
                                ctx.last_response = Some(rsp);
                                Transition::Done(Ok(()))
                            },
                            Some(Stage::Operational) => {
                                ctx.last_response = Some(rsp);
                                Transition::Next(
                                    LoginStates::PlainOpToFull(PlainOpToFull),
                                    Ok(()),
                                )
                            },
                            other => Transition::Done(Err(anyhow!(
                                "plain login unexpected NSG={other:?}"
                            ))),
                        }
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

/// Represents the follow-up operational step for targets that don't accept a
/// one-shot plain transition to Full Feature.
#[derive(Debug)]
pub struct PlainOpToFull;

impl<'ctx> StateMachine<LoginCtx<'ctx>, LoginStepOut> for PlainOpToFull {
    type StepResult<'a>
        = Pin<Box<dyn Future<Output = LoginStepOut> + Send + 'a>>
    where
        Self: 'a,
        LoginCtx<'ctx>: 'a;

    fn step<'a>(&'a self, ctx: &'a mut LoginCtx<'ctx>) -> Self::StepResult<'a> {
        Box::pin(async move {
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
                    .initiator_task_tag(last.get_initiator_task_tag())
                    .connection_id(ctx.cid)
                    .cmd_sn(last.exp_cmd_sn.get())
                    .exp_stat_sn(last.stat_sn.get().wrapping_add(1));

                (header, last.get_initiator_task_tag())
            };

            if let Err(e) = header.header.to_bhs_bytes(ctx.buf.as_mut_slice()) {
                return Transition::Done(Err(e));
            }

            let mut pdu = PduRequest::<LoginRequest>::new_request(ctx.buf, &ctx.conn.cfg);
            if let Err(e) =
                pdu.append_data(login_keys_operational(&ctx.conn.cfg).as_slice())
            {
                return Transition::Done(Err(e));
            }

            if let Err(e) = ctx.conn.send_request(itt, pdu).await {
                return Transition::Done(Err(e));
            }

            match ctx.conn.read_response::<LoginResponse>(itt).await {
                Ok(rsp) => {
                    if let Err(e) = verify_operational_negotiation(&ctx.conn.cfg, &rsp) {
                        return Transition::Done(Err(e));
                    }
                    ctx.last_response = Some(rsp);
                    Transition::Done(Ok(()))
                },
                Err(e) => Transition::Done(Err(e)),
            }
        })
    }
}
