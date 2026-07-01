//! This module defines the structures for iSCSI SCSI Command Response PDUs.
//! It includes the `ScsiCommandResponse` header and related methods.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::warn;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        command::zero_copy::{RawResponseCode, RawScsiCmdRespFlags, RawScsiStatus},
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        identifiers::Itt,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Basic Header Segment for iSCSI SCSI Command Response PDU
///
/// Represents the 48-byte header structure for SCSI Command Response PDU as
/// defined in RFC 7143. Contains response status, sequence numbers, residual
/// counts, and other information returned by the target after executing a SCSI
/// command.
#[repr(C)]
#[derive(Debug, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ScsiCommandResponse {
    pub opcode: RawBhsOpcode, // Byte 0: `Opcode::ScsiCommandResp`
    pub flags: RawScsiCmdRespFlags, // Byte 1: Final/residual-status flags
    pub response: RawResponseCode, // Byte 2: iSCSI response code
    pub status: RawScsiStatus, // Byte 3: SCSI status
    pub total_ahs_length: u8, // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3], // Bytes 5..8: sense/response payload length
    reserved: [u8; 8],        // Bytes 8..16: reserved
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    pub snack_tag: U32<BigEndian>, // Bytes 20..24: SNACK tag
    pub stat_sn: U32<BigEndian>, // Bytes 24..28: StatSN
    pub exp_cmd_sn: U32<BigEndian>, // Bytes 28..32: ExpCmdSN
    pub max_cmd_sn: U32<BigEndian>, // Bytes 32..36: MaxCmdSN
    pub exp_data_sn: U32<BigEndian>, // Bytes 36..40: ExpDataSN
    pub bidirectional_read_residual_count: U32<BigEndian>, /* Bytes 40..44: bidi
                               * residual count */
    pub residual_count: U32<BigEndian>, // Bytes 44..48: residual count
}

impl ScsiCommandResponse {
    /// Serializes the BHS into a byte buffer.
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        buf.fill(0);
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    /// Deserializes the BHS from a byte buffer.
    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = <Self as zerocopy::FromBytes>::mut_from_bytes(buf).map_err(|e| {
            anyhow::anyhow!("failed convert buffer ScsiCommandResponse: {e}")
        })?;
        if hdr.opcode.opcode_known() != Some(Opcode::ScsiCommandResp) {
            anyhow::bail!(
                "ScsiCommandResponse: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }

    /// Checks if the residual count is valid.
    #[inline]
    pub fn residual_valid(&self) -> bool {
        self.flags.u_big() || self.flags.o_big()
    }

    /// Returns the effective residual count.
    #[inline]
    pub fn residual_effective(&self) -> u32 {
        if self.residual_valid() {
            self.residual_count.get()
        } else {
            0
        }
    }

    /// Checks if the bidirectional read residual count is valid.
    #[inline]
    pub fn bidi_read_residual_valid(&self) -> bool {
        self.flags.u_small() || self.flags.o_small()
    }

    /// Returns the effective bidirectional read residual count.
    #[inline]
    pub fn bidi_read_residual_effective(&self) -> u32 {
        if self.bidi_read_residual_valid() {
            self.bidirectional_read_residual_count.get()
        } else {
            0
        }
    }
}

impl SendingData for ScsiCommandResponse {
    fn get_final_bit(&self) -> bool {
        self.flags.fin()
    }

    fn set_final_bit(&mut self) {
        warn!("ScsiCommand Response must contain Final");
        self.flags.set_fin(true);
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("ScsiCommand Response don`t support Continue");
    }
}

impl FromBytes for ScsiCommandResponse {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        ScsiCommandResponse::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiCommandResponse {
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

impl ZeroCopyType for ScsiCommandResponse {}
