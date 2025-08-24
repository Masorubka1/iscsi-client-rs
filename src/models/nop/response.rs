// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow, bail};
use tracing::warn;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32, U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct NopInResponse {
    pub opcode: RawBhsOpcode,            // 0
    reserved1: [u8; 3],                  // 1..4
    pub total_ahs_length: u8,            // 4
    pub data_segment_length: [u8; 3],    // 5..8
    pub lun: U64<BigEndian>,             // 8..16
    pub initiator_task_tag: u32,         // 16..20
    pub target_task_tag: U32<BigEndian>, // 20..24
    pub stat_sn: U32<BigEndian>,         // 24..28
    pub exp_cmd_sn: U32<BigEndian>,      // 28..32
    pub max_cmd_sn: U32<BigEndian>,      // 32..36
    reserved2: [u8; 12],                 // 36..48
}

impl NopInResponse {
    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = <Self as zerocopy::FromBytes>::mut_from_bytes(buf)
            .map_err(|e| anyhow!("failed convert buffer NopInResponse: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::NopIn) {
            bail!(
                "NopInResponse: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

impl SendingData for NopInResponse {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("NopIn Response cannot be marked as Final");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("NopIn Response cannot be marked as Contine");
    }
}

impl FromBytes for NopInResponse {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        NopInResponse::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for NopInResponse {
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
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}

impl ZeroCopyType for NopInResponse {}
