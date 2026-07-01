//! This module defines the structures for iSCSI Login Response PDUs.
//! It includes the `LoginResponse` header and related methods for handling the
//! login process.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U16, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        identifiers::Itt,
        login::{
            common::RawLoginFlags,
            status::{RawStatusClass, RawStatusDetail},
        },
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Represents the Basic Header Segment (BHS) for a Login Response PDU.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LoginResponse {
    pub opcode: RawBhsOpcode,         // Byte 0: `Opcode::LoginResp`
    pub flags: RawLoginFlags,         // Byte 1: login transit/continue/stage flags
    pub version_max: u8,              // Byte 2: maximum supported iSCSI version
    pub version_active: u8,           // Byte 3: negotiated active iSCSI version
    pub total_ahs_length: u8,         // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3], // Bytes 5..8: login text payload length
    /// Initiator Session Identifier echoed from the login request.
    pub isid: [u8; 6],
    /// Target Session Identifying Handle assigned by the target.
    pub tsih: U16<BigEndian>,
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    reserved1: [u8; 4],                     // Bytes 20..24: reserved
    pub stat_sn: U32<BigEndian>,            // Bytes 24..28: StatSN
    pub exp_cmd_sn: U32<BigEndian>,         // Bytes 28..32: ExpCmdSN
    pub max_cmd_sn: U32<BigEndian>,         // Bytes 32..36: MaxCmdSN
    pub status_class: RawStatusClass,       // Byte 36: login status class
    pub status_detail: RawStatusDetail,     // Byte 37: login status detail
    reserved2: [u8; 10],                    // Bytes 38..48: reserved
}

impl LoginResponse {
    /// Serializes the BHS into a byte buffer.
    #[inline]
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    /// Deserializes the BHS from a byte buffer.
    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = <Self as zerocopy::FromBytes>::mut_from_bytes(buf)
            .map_err(|e| anyhow::anyhow!("failed convert buffer LoginResponse: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::LoginResp) {
            anyhow::bail!(
                "LoginResponse: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

impl SendingData for LoginResponse {
    #[inline]
    fn get_final_bit(&self) -> bool {
        !self.flags.cont()
    }

    #[inline]
    fn set_final_bit(&mut self) {
        self.flags.set_cont(false)
    }

    #[inline]
    fn get_continue_bit(&self) -> bool {
        self.flags.cont()
    }

    #[inline]
    fn set_continue_bit(&mut self) {
        self.flags.set_cont(true)
    }
}

impl FromBytes for LoginResponse {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        LoginResponse::from_bhs_bytes(bytes)
    }
}
impl BasicHeaderSegment for LoginResponse {
    #[inline]
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        self.to_bhs_bytes(buf)
    }

    #[inline]
    fn get_opcode(&self) -> Result<BhsOpcode> {
        BhsOpcode::try_from(self.opcode.raw())
    }

    #[inline]
    fn get_initiator_task_tag(&self) -> Itt {
        self.initiator_task_tag.get().into()
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

    #[inline]
    fn get_header_diggest(&self, _: bool) -> usize {
        0
    }

    #[inline]
    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for LoginResponse {}
