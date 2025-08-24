// SPDX-License-Identifier: GPL-3.0-or-later
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

/// BHS for SCSI Data-In (opcode 0x25)
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
    pub initiator_task_tag: u32,             // 16..19
    pub target_transfer_tag: U32<BigEndian>, // 20..23 (TTT or 0xffffffff)
    pub stat_sn_or_rsvd: U32<BigEndian>,     // 24..27 (StatSN, if S=1; else 0)
    pub exp_cmd_sn: U32<BigEndian>,          // 28..31
    pub max_cmd_sn: U32<BigEndian>,          // 32..35
    pub data_sn: U32<BigEndian>,             // 36..39
    pub buffer_offset: U32<BigEndian>,       // 40..43
    pub residual_count: U32<BigEndian>,      // 44..47 (valid only if S=1; else 0)
}

impl ScsiDataIn {
    /// Returns decoded SCSI status iff `S=1` (otherwise `None`).
    #[inline]
    pub fn scsi_status(&self) -> Option<ScsiStatus> {
        if self.flags.s() {
            self.status_or_rsvd.decode().ok()
        } else {
            None
        }
    }

    /// Sets/clears SCSI status and enforces `S ⇒ F`.
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

    /// Serialize BHS into the provided 48-byte buffer.
    ///
    /// If `S=0`, zeroes out the Status/StatSN/ResidualCount bytes
    /// as required by the spec.
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

    /// Parse BHS in-place (backed by the caller's buffer).
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

    #[inline]
    pub fn get_real_final_bit(&self) -> bool {
        self.flags.fin()
    }

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
        debug!(
            "DataIn is finnal:{} status:{}",
            self.flags.fin(),
            !matches!(self.scsi_status(), None | Some(ScsiStatus::Good))
        );
        self.flags.fin() && !matches!(self.scsi_status(), None | Some(ScsiStatus::Good))
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
        self.initiator_task_tag
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
