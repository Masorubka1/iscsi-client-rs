// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use enum_dispatch::enum_dispatch;

use crate::models::{
    command::{request::ScsiCommandRequest, response::ScsiCommandResponse},
    common::{BasicHeaderSegment, SendingData},
    data::{request::ScsiDataOut, response::ScsiDataIn},
    login::{request::LoginRequest, response::LoginResponse},
    logout::{request::LogoutRequest, response::LogoutResponse},
    nop::{request::NopOutRequest, response::NopInResponse},
    opcode::{BhsOpcode, Opcode},
    ready_2_transfer::response::ReadyToTransfer,
    reject::response::RejectPdu,
    text::{request::TextRequest, response::TextResponse},
};

#[enum_dispatch(BasicHeaderSegment, SendingData)]
#[derive(Debug)]
pub enum Pdu<'a> {
    NopOutRequest(&'a mut NopOutRequest),
    ScsiCommandRequest(&'a mut ScsiCommandRequest),
    TextRequest(&'a mut TextRequest),
    LoginRequest(&'a mut LoginRequest),
    ScsiDataOut(&'a mut ScsiDataOut),
    NopInResponse(&'a mut NopInResponse),
    ScsiCommandResponse(&'a mut ScsiCommandResponse),
    TextResponse(&'a mut TextResponse),
    LoginResponse(&'a mut LoginResponse),
    ScsiDataIn(&'a mut ScsiDataIn),
    RejectPdu(&'a mut RejectPdu),
    ReadyToTransfer(&'a mut ReadyToTransfer),
    LogoutRequest(&'a mut LogoutRequest),
    LogoutResponse(&'a mut LogoutResponse),
}

impl<'a> Pdu<'a> {
    pub fn from_bhs_bytes(bytes: &'a mut [u8]) -> Result<Self> {
        let bhs = BhsOpcode::try_from(bytes[0])
            .map_err(|e| anyhow::anyhow!("invalid opcode: {}", e))?;
        match bhs.opcode {
            Opcode::NopOut => {
                let req = NopOutRequest::from_bhs_bytes(bytes)?;
                Ok(Pdu::NopOutRequest(req))
            },
            Opcode::NopIn => {
                let req = NopInResponse::from_bhs_bytes(bytes)?;
                Ok(Pdu::NopInResponse(req))
            },
            Opcode::ScsiCommandReq => {
                let req = ScsiCommandRequest::from_bhs_bytes(bytes)?;
                Ok(Pdu::ScsiCommandRequest(req))
            },
            Opcode::ScsiCommandResp => {
                let req = ScsiCommandResponse::from_bhs_bytes(bytes)?;
                Ok(Pdu::ScsiCommandResponse(req))
            },
            Opcode::TextReq => {
                let req = TextRequest::from_bhs_bytes(bytes)?;
                Ok(Pdu::TextRequest(req))
            },
            Opcode::LoginReq => {
                let req = LoginRequest::from_bhs_bytes(bytes)?;
                Ok(Pdu::LoginRequest(req))
            },
            Opcode::ScsiDataOut => {
                let req = ScsiDataOut::from_bhs_bytes(bytes)?;
                Ok(Pdu::ScsiDataOut(req))
            },
            Opcode::LoginResp => {
                let rsp = LoginResponse::from_bhs_bytes(bytes)?;
                Ok(Pdu::LoginResponse(rsp))
            },
            Opcode::Reject => {
                let rsp = RejectPdu::from_bhs_bytes(bytes)?;
                Ok(Pdu::RejectPdu(rsp))
            },
            Opcode::ScsiDataIn => {
                let req = ScsiDataIn::from_bhs_bytes(bytes)?;
                Ok(Pdu::ScsiDataIn(req))
            },
            Opcode::ReadyToTransfer => {
                let req = ReadyToTransfer::from_bhs_bytes(bytes)?;
                Ok(Pdu::ReadyToTransfer(req))
            },
            Opcode::LogoutReq => {
                let req = LogoutRequest::from_bhs_bytes(bytes)?;
                Ok(Pdu::LogoutRequest(req))
            },
            Opcode::LogoutResp => {
                let req = LogoutResponse::from_bhs_bytes(bytes)?;
                Ok(Pdu::LogoutResponse(req))
            },
            other => bail!("unsupported opcode: {:?}", other),
        }
    }
}
