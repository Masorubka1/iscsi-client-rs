// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::{error, warn};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U16, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        logout::common::RawLogoutResponseCode,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS structure for **Logout Response** (opcode `LogoutResp` = 0x26)
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LogoutResponse {
    pub opcode: RawBhsOpcode,            // byte 0: 0x26
    pub flags: u8,                       // byte 1: F-bit at bit7, others reserved
    pub response: RawLogoutResponseCode, // byte 2: response code
    reserved0: u8,                       // byte 3: reserved
    pub total_ahs_length: u8,            // byte 4: must be 0
    pub data_segment_length: [u8; 3],    // bytes 5..8: must be [0,0,0]
    reserved1: [u8; 8],                  // bytes 8..16: reserved
    pub initiator_task_tag: u32,         // bytes 16..20: ITT
    reserved2: [u8; 4],                  // bytes 20..24: reserved
    pub stat_sn: U32<BigEndian>,         // bytes 24..28
    pub exp_cmd_sn: U32<BigEndian>,      // bytes 28..32
    pub max_cmd_sn: U32<BigEndian>,      // bytes 32..36
    reserved3: [u8; 4],                  // bytes 36..40: reserved
    pub time2wait: U16<BigEndian>,       // bytes 40..42
    pub time2retain: U16<BigEndian>,     // bytes 42..44
    reserved4: [u8; 4],                  // bytes 44..48: reserved
}

impl LogoutResponse {
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = <Self as zerocopy::FromBytes>::mut_from_bytes(buf)
            .map_err(|e| anyhow::anyhow!("failed convert buffer LogoutResponse: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::LogoutResp) {
            anyhow::bail!(
                "LogoutResponse: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
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
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        LogoutResponse::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LogoutResponse {
    #[inline]
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        self.to_bhs_bytes(buf)
    }

    #[inline]
    fn get_opcode(&self) -> Result<BhsOpcode> {
        BhsOpcode::try_from(self.opcode.raw())
    }

    #[inline]
    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    #[inline]
    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    #[inline]
    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    #[inline]
    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    #[inline]
    fn set_data_length_bytes(&mut self, len: u32) {
        error!("LogoutResp must have zero DataSegmentLength");
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }

    #[inline]
    fn get_header_diggest(&self, _: bool) -> usize {
        0
    }

    #[inline]
    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for LogoutResponse {}
