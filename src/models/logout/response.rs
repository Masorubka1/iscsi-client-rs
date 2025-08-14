use std::fmt;

use anyhow::{Result, anyhow, bail};
use tracing::{error, warn};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::{BhsOpcode, Opcode},
    },
};

/// iSCSI Logout Response Code (RFC 3720 §10.15.1)
#[derive(Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutResponseCode {
    /// 0 - connection or session closed successfully
    #[default]
    Success = 0x00,
    /// 1 - CID not found
    CidNotFound = 0x01,
    /// 2 - connection recovery is not supported
    RecoveryNotSupported = 0x02,
    /// 3 - cleanup failed for various reasons
    CleanupFailed = 0x03,
}

impl LogoutResponseCode {
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            LogoutResponseCode::Success => 0x00,
            LogoutResponseCode::CidNotFound => 0x01,
            LogoutResponseCode::RecoveryNotSupported => 0x02,
            LogoutResponseCode::CleanupFailed => 0x03,
        }
    }
}

impl TryFrom<u8> for LogoutResponseCode {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0x00 => LogoutResponseCode::Success,
            0x01 => LogoutResponseCode::CidNotFound,
            0x02 => LogoutResponseCode::RecoveryNotSupported,
            0x03 => LogoutResponseCode::CleanupFailed,
            other => bail!("invalid LogoutResponseCode: {other:#04x}"),
        })
    }
}

impl fmt::Display for LogoutResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogoutResponseCode::*;
        let s = match self {
            Success => "Success",
            CidNotFound => "CidNotFound",
            RecoveryNotSupported => "RecoveryNotSupported",
            CleanupFailed => "CleanupFailed",
        };
        f.write_str(s)
    }
}

/// BHS structure for **Logout Response** (opcode `LogoutResp` = 0x26)
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct LogoutResponse {
    pub opcode: BhsOpcode,            // byte 0: 0x26
    pub flags: u8,                    // byte 1: F-bit at bit7, others reserved
    pub response: LogoutResponseCode, // byte 2: response code
    reserved0: u8,                    // byte 3: reserved
    pub total_ahs_length: u8,         // byte 4: must be 0
    pub data_segment_length: [u8; 3], // bytes 5..8: must be [0,0,0]
    reserved1: [u8; 8],               // bytes 8..16: reserved
    pub initiator_task_tag: u32,      // bytes 16..20: ITT
    reserved2: [u8; 4],               // bytes 20..24: reserved
    pub stat_sn: u32,                 // bytes 24..28
    pub exp_cmd_sn: u32,              // bytes 28..32
    pub max_cmd_sn: u32,              // bytes 32..36
    reserved3: [u8; 4],               // bytes 36..40: reserved
    pub time2wait: u16,               // bytes 40..42
    pub time2retain: u16,             // bytes 42..44
    reserved4: [u8; 4],               // bytes 44..48: reserved
}

impl LogoutResponse {
    /// Serialize BHS to 48 bytes.
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into(); // 0x26
        buf[1] = self.flags; // F|reserved
        buf[2] = self.response.as_u8(); // response code
        buf[3] = self.reserved0;
        buf[4] = self.total_ahs_length; // must be 0
        buf[5..8].copy_from_slice(&self.data_segment_length); // must be [0,0,0]
        buf[8..16].copy_from_slice(&self.reserved1);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.reserved2);
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.reserved3);
        buf[40..42].copy_from_slice(&self.time2wait.to_be_bytes());
        buf[42..44].copy_from_slice(&self.time2retain.to_be_bytes());
        buf[44..48].copy_from_slice(&self.reserved4);
        buf
    }

    /// Parse a 48-byte Logout Response BHS.
    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!("buffer too small"));
        }

        let opcode = BhsOpcode::try_from(buf[0])?;
        if opcode.opcode != Opcode::LogoutResp {
            bail!("LogoutResp invalid opcode: {:?}", opcode.opcode);
        }

        // Flags: bit7 is Final (F=1), others reserved. We keep `flags` raw.
        let flags = buf[1];

        let response = LogoutResponseCode::try_from(buf[2])?;
        let reserved0 = buf[3];

        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        if total_ahs_length != 0 {
            bail!(
                "LogoutResp: total_ahs_length must be 0, got {}",
                total_ahs_length
            );
        }
        if data_segment_length != [0, 0, 0] {
            bail!(
                "LogoutResp: data_segment_length must be 0, got [{}, {}, {}]",
                data_segment_length[0],
                data_segment_length[1],
                data_segment_length[2]
            );
        }

        let mut reserved1 = [0u8; 8];
        reserved1.copy_from_slice(&buf[8..16]);

        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);

        let mut reserved2 = [0u8; 4];
        reserved2.copy_from_slice(&buf[20..24]);

        let stat_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_cmd_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let max_cmd_sn = u32::from_be_bytes(buf[32..36].try_into()?);

        let mut reserved3 = [0u8; 4];
        reserved3.copy_from_slice(&buf[36..40]);

        let time2wait = u16::from_be_bytes([buf[40], buf[41]]);
        let time2retain = u16::from_be_bytes([buf[42], buf[43]]);

        let mut reserved4 = [0u8; 4];
        reserved4.copy_from_slice(&buf[44..48]);

        Ok(LogoutResponse {
            opcode,
            flags,
            response,
            reserved0,
            total_ahs_length,
            data_segment_length,
            reserved1,
            initiator_task_tag,
            reserved2,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            reserved3,
            time2wait,
            time2retain,
            reserved4,
        })
    }

    /// Helper: check if Final (F) bit is set in `flags`.
    #[inline]
    pub fn is_final(&self) -> bool {
        (self.flags & 0b1000_0000) != 0
    }

    /// Helper: set Final (F) bit in `flags`.
    #[inline]
    pub fn set_final(&mut self) {
        self.flags |= 0b1000_0000;
    }
}

impl SendingData for LogoutResponse {
    fn get_final_bit(&self) -> bool {
        self.is_final()
    }

    fn set_final_bit(&mut self) {
        self.set_final();
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("Logout Response cannot be marked as Contine");
    }
}

impl FromBytes for LogoutResponse {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LogoutResponse {
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
        error!("LogoutResp must have zero DataSegmentLength");
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}
