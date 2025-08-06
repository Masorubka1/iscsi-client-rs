use anyhow::{Result, bail};
use enum_dispatch::enum_dispatch;

use crate::models::{
    command::{request::ScsiCommandRequest, response::ScsiCommandResponse},
    common::{BasicHeaderSegment, HEADER_LEN},
    login::{request::LoginRequest, response::LoginResponse},
    nop::{request::NopOutRequest, response::NopInResponse},
    opcode::{BhsOpcode, Opcode},
    reject::response::RejectPdu,
    text::{request::TextRequest, response::TextResponse},
};

#[enum_dispatch(BasicHeaderSegment)]
pub enum Pdu {
    NopOutRequest,
    ScsiCommandRequest,
    TextRequest,
    LoginRequest,
    NopInResponse,
    ScsiCommandResponse,
    TextResponse,
    LoginResponse,
    RejectPdu,
}

impl Pdu {
    pub fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
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
            Opcode::LoginResp => {
                let rsp = LoginResponse::from_bhs_bytes(bytes)?;
                Ok(Pdu::LoginResponse(rsp))
            },
            Opcode::Reject => {
                let rsp = RejectPdu::from_bhs_bytes(bytes)?;
                Ok(Pdu::RejectPdu(rsp))
            },
            other => bail!("unsupported opcode: {:?}", other),
        }
    }
}
