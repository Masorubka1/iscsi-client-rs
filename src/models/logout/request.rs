use std::fmt;

use anyhow::{Result, anyhow, bail};
use tracing::{error, warn};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

/// iSCSI Logout Reason Code (Byte 1)
#[derive(Debug, Default, PartialEq, Clone)]
#[repr(u8)]
pub enum LogoutReason {
    /// Close the entire session (all connections)
    #[default]
    CloseSession = 0x01,
    /// Close a specific connection identified by CID
    CloseConnection = 0x02,
    /// Remove a connection for recovery purposes
    RemoveConnectionForRecovery = 0x03,
}

impl LogoutReason {
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            LogoutReason::CloseSession => 0x01,
            LogoutReason::CloseConnection => 0x02,
            LogoutReason::RemoveConnectionForRecovery => 0x03,
        }
    }
}

impl TryFrom<u8> for LogoutReason {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0x01 => LogoutReason::CloseSession,
            0x02 => LogoutReason::CloseConnection,
            0x03 => LogoutReason::RemoveConnectionForRecovery,
            other => bail!("unexpected logout code {other}"),
        })
    }
}

impl fmt::Display for LogoutReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogoutReason::*;
        let s = match self {
            CloseSession => "CloseSession",
            CloseConnection => "CloseConnection",
            RemoveConnectionForRecovery => "RemoveConnectionForRecovery",
        };
        f.write_str(s)
    }
}

/// BHS structure for **Logout Request** (opcode `LogoutReq`)
///
/// Fits into 48-byte Basic Header Segment.
/// Data Segment length must always be zero for Logout Request.
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct LogoutRequest {
    pub opcode: BhsOpcode,            // byte 0: I|0x06
    pub reason: LogoutReason,         // byte 1: Reason Code
    reserved0: [u8; 2],               // bytes 2..4: Reserved
    pub total_ahs_length: u8,         // byte 4: normally 0
    pub data_segment_length: [u8; 3], // bytes 5..8: must be zero
    reserved1: [u8; 8],               /* bytes 8..16: Reserved (no ISID/Tsih in
                                       * LogoutReq) */
    pub initiator_task_tag: u32, // bytes 16..20: ITT
    pub cid: u16,                // bytes 20..22: CID (if closing a specific connection)
    reserved2: [u8; 2],          // bytes 22..24: Reserved
    pub cmd_sn: u32,             // bytes 24..28
    pub exp_stat_sn: u32,        // bytes 28..32
    reserved3: [u8; 16],         // bytes 32..48: Reserved
}

impl LogoutRequest {
    /// Serialize the BHS to 48 bytes.
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.reason.as_u8();
        // buf[2..4] reserved
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        // buf[8..16] reserved
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..22].copy_from_slice(&self.cid.to_be_bytes());
        // buf[22..24] reserved
        buf[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        // buf[32..48] reserved
        buf
    }

    /// Parse a LogoutRequest from a 48-byte BHS buffer.
    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!("buffer too small"));
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        if opcode.opcode != Opcode::LogoutReq {
            bail!("LogoutReq invalid opcode: {:?}", opcode.opcode);
        }

        let reason = LogoutReason::try_from(buf[1])?;

        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        if total_ahs_length != 0 {
            bail!(
                "LogoutReq: total_ahs_length must be 0, got {}",
                total_ahs_length
            );
        }
        if data_segment_length != [0, 0, 0] {
            bail!(
                "LogoutReq: data_segment_length must be 0, got [{}, {}, {}]",
                data_segment_length[0],
                data_segment_length[1],
                data_segment_length[2]
            );
        }

        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let cid = u16::from_be_bytes(buf[20..22].try_into()?);
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);

        Ok(LogoutRequest {
            opcode,
            reason,
            reserved0: [0; 2],
            total_ahs_length,
            data_segment_length,
            reserved1: [0; 8],
            initiator_task_tag,
            cid,
            reserved2: [0; 2],
            cmd_sn,
            exp_stat_sn,
            reserved3: [0; 16],
        })
    }
}

/// Builder for **Logout Request**
///
/// Defaults to an Immediate Logout (`I` bit) with empty AHS and zero Data
/// Segment length.
#[derive(Debug, Default)]
pub struct LogoutRequestBuilder {
    header: LogoutRequest,
}

impl LogoutRequestBuilder {
    pub fn new(reason: LogoutReason, itt: u32, cid: u16) -> Self {
        let hdr = LogoutRequest {
            opcode: BhsOpcode {
                flags: IfFlags::I,
                opcode: Opcode::LogoutReq,
            },
            reason,
            total_ahs_length: 0,
            data_segment_length: [0, 0, 0],
            initiator_task_tag: itt,
            cid,
            ..Default::default()
        };

        Self { header: hdr }
    }

    /// Set the Connection ID (CID) — required when closing a specific
    /// connection.
    pub fn connection_id(mut self, cid: u16) -> Self {
        self.header.cid = cid;
        self
    }

    /// Set the command sequence number (CmdSN).
    pub fn cmd_sn(mut self, sn: u32) -> Self {
        self.header.cmd_sn = sn;
        self
    }

    /// Set the expected StatSN from the target.
    pub fn exp_stat_sn(mut self, sn: u32) -> Self {
        self.header.exp_stat_sn = sn;
        self
    }

    pub fn build(self) -> LogoutRequest {
        self.header
    }
}

impl SendingData for LogoutRequest {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("Logout Request cannot be marked as Final");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("Logout Request cannot be marked as Contine");
    }
}

impl FromBytes for LogoutRequest {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LogoutRequest {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    fn set_data_length_bytes(&mut self, len: u32) {
        error!("LogoutReq must have zero DataSegmentLength");
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}
