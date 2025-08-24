// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32, U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data::common::RawDataOutFlags,
        data_fromat::ZeroCopyType,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS for SCSI Data-Out (opcode 0x26)
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ScsiDataOut {
    pub opcode: RawBhsOpcode,                // 0 (0x26)
    pub flags: RawDataOutFlags,              // 1 (F, rest 0)
    pub reserved2: [u8; 2],                  // 2..4
    pub total_ahs_length: u8,                // 4
    pub data_segment_length: [u8; 3],        // 5..8
    pub lun: U64<BigEndian>,                 // 8..16
    pub initiator_task_tag: u32,             // 16..20
    pub target_transfer_tag: U32<BigEndian>, // 20..23
    pub exp_stat_sn: U32<BigEndian>,         // 24..28
    pub reserved3: [u8; 8],                  // 28..36
    pub data_sn: U32<BigEndian>,             // 36..40
    pub buffer_offset: U32<BigEndian>,       // 40..44
    pub reserved4: u32,                      // 44..48
}

impl ScsiDataOut {
    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        buf.fill(0);
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = Self::mut_from_bytes(buf)
            .map_err(|e| anyhow::anyhow!("failed convert buffer ScsiDataOut: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::ScsiDataOut) {
            anyhow::bail!(
                "ScsiDataOut: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

impl SendingData for ScsiDataOut {
    fn get_final_bit(&self) -> bool {
        self.flags.fin()
    }

    fn set_final_bit(&mut self) {
        self.flags.set_fin(true);
    }

    fn get_continue_bit(&self) -> bool {
        !self.flags.fin()
    }

    fn set_continue_bit(&mut self) {
        self.flags.set_fin(false);
    }
}

impl FromBytes for ScsiDataOut {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        ScsiDataOut::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiDataOut {
    #[inline]
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        self.to_bhs_bytes(buf)
    }

    #[inline]
    fn get_opcode(&self) -> Result<BhsOpcode> {
        BhsOpcode::try_from(self.opcode.raw())
    }

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

/// Builder for **SCSI Data-Out** PDUs (opcode `0x26`).
///
/// This helper prepares the Basic Header Segment (BHS) for Data-Out and
/// lets the higher layer stream an arbitrary payload split into chunks
/// that respect the negotiated **MaxRecvDataSegmentLength (MRDSL)**.
///
/// When the payload is later converted into wire frames (by your
/// `ToBytes`/`Builder` implementation), each chunk will be emitted as a
/// separate Data-Out PDU with:
/// - **F (Final) = 1** only on the **last** chunk,
/// - **DataSN** increasing sequentially per PDU,
/// - **BufferOffset** set to the cumulative number of bytes already sent,
/// - **DataSegmentLength** equal to the current chunk size (without padding).
///
/// Target Transfer Tag (**TTT**) semantics:
/// - For **unsolicited / initial burst** Data-Out PDUs, use `DEFAULT_TTT =
///   0xFFFF_FFFF`.
/// - For **R2T-driven** transfers, set the TTT received in the R2T PDU.
///
/// You can also request HeaderDigest and/or DataDigest emission; these
/// flags only affect how the final frames are serialized (they do not
/// modify the BHS fields directly).
#[derive(Debug, Default)]
pub struct ScsiDataOutBuilder {
    pub header: ScsiDataOut,

    enable_header_digest: bool,
    enable_data_digest: bool,
}

impl ScsiDataOutBuilder {
    /// Default Target Transfer Tag for unsolicited/initial-burst Data-Out.
    pub const DEFAULT_TTT: u32 = 0xFFFF_FFFF;

    pub fn new() -> Self {
        Self {
            header: ScsiDataOut {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::ScsiDataOut);
                    tmp
                },
                ..Default::default()
            },
            enable_header_digest: false,
            enable_data_digest: false,
        }
    }

    /// Set the 8-byte LUN to which data is written.
    pub fn lun(mut self, lun: u64) -> Self {
        self.header.lun.set(lun);
        self
    }

    /// Set Initiator Task Tag (ITT) identifying this stream.
    pub fn initiator_task_tag(mut self, itt: u32) -> Self {
        self.header.initiator_task_tag = itt;
        self
    }

    /// Set Target Transfer Tag (TTT). Use `DEFAULT_TTT` for unsolicited
    /// bursts, or the TTT provided in an R2T for solicited transfers.
    pub fn target_transfer_tag(mut self, ttt: u32) -> Self {
        self.header.target_transfer_tag.set(ttt);
        self
    }

    /// Set the expected StatusSN (ExpStatSN).
    pub fn exp_stat_sn(mut self, sn: u32) -> Self {
        self.header.exp_stat_sn.set(sn);
        self
    }

    /// Set the **DataSN** for this Data-Out PDU.
    pub fn data_sn(mut self, data_sn: u32) -> Self {
        self.header.data_sn.set(data_sn);
        self
    }

    /// Set the **BufferOffset** (in **bytes**) of the first byte carried by
    /// this Data-Out PDU within the overall WRITE command payload.
    pub fn buffer_offset(mut self, buffer_offset: u32) -> Self {
        self.header.buffer_offset.set(buffer_offset);
        self
    }

    /// Request emission of a HeaderDigest (e.g., CRC32C) after the header.
    pub fn with_header_digest(mut self) -> Self {
        self.enable_header_digest = true;
        self
    }

    /// Request emission of a DataDigest after each Data Segment.
    pub fn with_data_digest(mut self) -> Self {
        self.enable_data_digest = true;
        self
    }
}

impl ZeroCopyType for ScsiDataOut {}
