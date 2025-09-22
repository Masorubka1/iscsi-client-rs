//! This module defines the structures for iSCSI SCSI Data-In PDUs.
//! It includes the `ScsiDataIn` header and related methods for handling data
//! transfer from target to initiator.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow, bail};
use tracing::debug;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32, U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        command::{common::ScsiStatus, zero_copy::RawScsiStatus},
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data::common::RawDataInFlags,
        data_fromat::ZeroCopyType,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Represents the Basic Header Segment (BHS) for a SCSI Data-In PDU (opcode
/// 0x25).
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ScsiDataIn {
    pub opcode: RawBhsOpcode,          // 0  (0x25)
    pub flags: RawDataInFlags,         // 1  (F,A,0,0,0,O,U,S)
    pub reserved2: u8,                 // 2  (reserved)
    pub status_or_rsvd: RawScsiStatus, // 3  (SCSI Status, if S=1; else 0)
    pub total_ahs_length: u8,          // 4
    pub data_segment_length: [u8; 3],  // 5..7
    pub lun: U64<BigEndian>,           /* 8..15  (LUN or reserved; if A=1 must
                                        * present) */
    pub initiator_task_tag: U32<BigEndian>, // 16..19
    pub target_transfer_tag: U32<BigEndian>, // 20..23 (TTT or 0xffffffff)
    pub stat_sn_or_rsvd: U32<BigEndian>,    // 24..27 (StatSN, if S=1; else 0)
    pub exp_cmd_sn: U32<BigEndian>,         // 28..31
    pub max_cmd_sn: U32<BigEndian>,         // 32..35
    pub data_sn: U32<BigEndian>,            // 36..39
    pub buffer_offset: U32<BigEndian>,      // 40..43
    pub residual_count: U32<BigEndian>,     // 44..47 (valid only if S=1; else 0)
}

impl ScsiDataIn {
    /// Returns the decoded SCSI status if the Status (S) bit is set.
    #[inline]
    pub fn scsi_status(&self) -> Option<ScsiStatus> {
        if self.flags.s() {
            self.status_or_rsvd.decode().ok()
        } else {
            None
        }
    }

    /// Checks if the residual count is valid.
    #[inline]
    pub fn residual_valid(&self) -> bool {
        self.flags.u() || self.flags.o()
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

    /// Sets the SCSI status and updates the S and F flags accordingly.
    #[inline]
    pub fn set_scsi_status(&mut self, st: Option<ScsiStatus>) {
        match st {
            Some(s) => {
                self.flags.set_s(true); // S = 1
                self.flags.set_fin(true); // S ⇒ F
                self.status_or_rsvd.encode(s);
            },
            None => {
                self.flags.set_s(false); // S = 0
                self.status_or_rsvd.encode(ScsiStatus::Good);
                self.stat_sn_or_rsvd.set(0);
                self.residual_count.set(0);
            },
        }
    }

    /// Serializes the BHS into a byte buffer, zeroing out fields as required.
    #[inline]
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        if !self.flags.s() {
            buf[3] = 0; // status
            buf[24..28].fill(0); // StatSN
            buf[44..48].fill(0); // ResidualCount
        }
        Ok(())
    }

    /// Deserializes the BHS from a byte buffer.
    #[inline]
    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        if buf.len() < HEADER_LEN {
            return Err(anyhow!(
                "buffer too small for SCSI Data-In BHS: {}",
                buf.len()
            ));
        }
        let hdr = Self::mut_from_bytes(buf)
            .map_err(|_| anyhow!("SCSI Data-In: zerocopy prefix error"))?;
        // opcode check
        if hdr.opcode.opcode_known() != Some(Opcode::ScsiDataIn) {
            bail!(
                "ScsiDataIn invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        // flags validation (U/O mutual exclusion, S => F, reserved bits clear)
        hdr.flags.validate()?;
        Ok(hdr)
    }

    /// Returns the actual value of the Final (F) bit.
    #[inline]
    pub fn get_real_final_bit(&self) -> bool {
        self.flags.fin()
    }

    /// Returns the value of the Status (S) bit.
    #[inline]
    pub fn get_status_bit(&self) -> bool {
        self.flags.s()
    }
}

impl SendingData for ScsiDataIn {
    fn get_final_bit(&self) -> bool {
        // In practice Data-In can be followed by a separate SCSI Response.
        // Keep your previous semantics: final only when F=1 and either S not set,
        // or status is Good.
        let f = self.flags.fin();
        let s = self.flags.s();
        let is_final = f && s;
        debug!(
            "DataIn get_final_bit (channel): F={} S={} status={:?} => {}",
            f,
            s,
            self.scsi_status(),
            is_final
        );
        is_final
    }

    fn set_final_bit(&mut self) {
        self.flags.set_fin(true);
    }

    fn get_continue_bit(&self) -> bool {
        !self.flags.fin()
    }

    fn set_continue_bit(&mut self) {
        // Clear F; and to keep S ⇒ F invariant, also clear S.
        self.flags.set_fin(false);
        self.flags.set_s(false);
    }
}

impl FromBytes for ScsiDataIn {
    #[inline]
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        ScsiDataIn::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiDataIn {
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
        self.initiator_task_tag.get()
    }

    #[inline]
    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    #[inline]
    fn set_ahs_length_bytes(&mut self, len_bytes: u8) {
        self.total_ahs_length = len_bytes >> 2;
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

impl ZeroCopyType for ScsiDataIn {}
