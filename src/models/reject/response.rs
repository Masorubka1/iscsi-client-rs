//! This module defines the structures for iSCSI Reject PDUs.
//! It includes the `RejectPdu` header and related methods for handling rejected
//! PDUs.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::warn;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32, U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        identifiers::Itt,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
        reject::reject_description::RawRejectReason,
    },
};

/// Represents the Basic Header Segment (BHS) for a Reject PDU.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RejectPdu {
    pub opcode: RawBhsOpcode,               // Byte 0: `Opcode::Reject`
    reserved1: u8,                          // Byte 1: reserved
    pub reason: RawRejectReason,            // Byte 2: reject reason
    pub reserved2: u8,                      // Byte 3: reserved
    pub total_ahs_length: u8,               // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3],       /* Bytes 5..8: rejected header+payload
                                             * snapshot length */
    pub reserved3: U64<BigEndian>, // Bytes 8..16: reserved
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    pub reserved4: U32<BigEndian>, // Bytes 20..24: reserved
    pub stat_sn: U32<BigEndian>,   // Bytes 24..28: StatSN
    pub exp_cmd_sn: U32<BigEndian>, // Bytes 28..32: ExpCmdSN
    pub max_cmd_sn: U32<BigEndian>, // Bytes 32..36: MaxCmdSN
    pub data_sn_or_r2_sn: U32<BigEndian>, // Bytes 36..40: DataSN or R2TSN of rejected PDU
    pub reserved5: U64<BigEndian>, // Bytes 40..48: reserved
}

impl RejectPdu {
    /// Serializes the BHS into a byte buffer.
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
            .map_err(|e| anyhow::anyhow!("failed convert buffer RejectPdu: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::Reject) {
            anyhow::bail!(
                "RejectPdu: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

impl SendingData for RejectPdu {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("RejectPdu Response cannot be marked as Final");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("RejectPdu Response cannot be marked as Contine");
    }
}

impl FromBytes for RejectPdu {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        RejectPdu::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for RejectPdu {
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
}

impl ZeroCopyType for RejectPdu {}
