use anyhow::{Result, bail};
use enum_dispatch::enum_dispatch;

use crate::models::{
    command::{request::ScsiCommandRequest, response::ScsiCommandResponse},
    common::BasicHeaderSegment,
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

    #[allow(dead_code)]
    fn total_length_bytes(&self) -> usize {
        match self {
            Pdu::NopOutRequest(req) => req.total_length_bytes(),
            Pdu::NopInResponse(res) => res.total_length_bytes(),
            Pdu::ScsiCommandRequest(req) => req.total_length_bytes(),
            Pdu::ScsiCommandResponse(res) => res.total_length_bytes(),
            Pdu::TextRequest(req) => req.total_length_bytes(),
            Pdu::TextResponse(res) => res.total_length_bytes(),
            Pdu::LoginRequest(req) => req.total_length_bytes(),
            Pdu::LoginResponse(res) => res.total_length_bytes(),
            Pdu::RejectPdu(res) => res.total_length_bytes(),
        }
    }

    /// Parse a PDU from raw bytes (header + data segment + padding).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bhs = BhsOpcode::try_from(bytes[0])
            .map_err(|e| anyhow::anyhow!("invalid opcode: {}", e))?;
        match bhs.opcode {
            Opcode::NopOut => {
                let req = NopOutRequest::parse(bytes)?;
                Ok(Pdu::NopOutRequest(req))
            },
            Opcode::NopIn => {
                let req = NopInResponse::parse(bytes)?;
                Ok(Pdu::NopInResponse(req))
            },
            Opcode::ScsiCommandReq => {
                let req = ScsiCommandRequest::parse(bytes)?;
                Ok(Pdu::ScsiCommandRequest(req))
            },
            Opcode::ScsiCommandResp => {
                let req = ScsiCommandResponse::parse(bytes)?;
                Ok(Pdu::ScsiCommandResponse(req))
            },
            Opcode::TextReq => {
                let req = TextRequest::parse(bytes)?;
                Ok(Pdu::TextRequest(req))
            },
            Opcode::LoginReq => {
                let req = LoginRequest::parse(bytes)?;
                Ok(Pdu::LoginRequest(req))
            },
            Opcode::LoginResp => {
                let rsp = LoginResponse::parse(bytes)?;
                Ok(Pdu::LoginResponse(rsp))
            },
            Opcode::Reject => {
                let rsp = RejectPdu::parse(bytes)?;
                Ok(Pdu::RejectPdu(rsp))
            },
            other => bail!("unsupported opcode: {:?}", other),
        }
    }

    /// Serialize the full PDU (header + data segment + padding) to raw bytes.
    pub fn to_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Pdu::NopOutRequest(req) => req.encode(),
            Pdu::ScsiCommandRequest(req) => req.encode(),
            Pdu::TextRequest(req) => req.encode(),
            Pdu::LoginRequest(req) => req.encode(),
            _ => bail!(
                "serialisation not supported for {:?}",
                self.get_opcode().opcode
            ),
        }
    }

    /// Encode the full PDU into a continuous hex string (no spaces).
    #[allow(dead_code)]
    fn to_hex(&self) -> Result<String> {
        let ans = self.to_bytes()?;
        let mut tmp = ans.0;
        tmp.extend_from_slice(&ans.1);
        Ok(hex::encode(tmp))
    }

    /// Decode a hex string (ignoring any whitespace) and parse into the PDU.
    #[allow(dead_code)]
    fn from_hex(hex_str: &str) -> Result<Self> {
        let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = hex::decode(&cleaned)
            .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
        Self::from_bytes(&bytes)
    }
}
