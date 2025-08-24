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
        data_fromat::ZeroCopyType,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
        text::common::RawStageFlags,
    },
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Default, Debug, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct TextRequest {
    /// Byte 0: F/I + 6-bit opcode (should be `Opcode::TextReq`).
    pub opcode: RawBhsOpcode,
    /// Byte 1: stage flags (F/C); interpretation is Text-PDU specific.
    pub flags: RawStageFlags,
    reserved1: [u8; 2],
    /// Byte 4
    pub total_ahs_length: u8,
    /// Bytes 5..7
    pub data_segment_length: [u8; 3],
    /// Bytes 8..15
    pub lun: U64<BigEndian>,
    /// Bytes 16..19
    pub initiator_task_tag: u32,
    /// Bytes 20..23
    pub target_task_tag: U32<BigEndian>,
    /// Bytes 24..27
    pub cmd_sn: U32<BigEndian>,
    /// Bytes 28..31
    pub exp_stat_sn: U32<BigEndian>,
    reserved2: [u8; 16],
}

impl TextRequest {
    pub const DEFAULT_TAG: u32 = 0xFFFF_FFFF;

    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        buf.fill(0);
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let hdr = <Self as zerocopy::FromBytes>::mut_from_bytes(buf)
            .map_err(|e| anyhow::anyhow!("failed convert buffer TextRequest: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::TextReq) {
            anyhow::bail!(
                "TextRequest: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

/// Builder for an iSCSI **Text Request** PDU (`Opcode::TextReq`).
///
/// Text PDUs carry key–value negotiation (e.g., `HeaderDigest=None`,
/// `MaxRecvDataSegmentLength=…`) and other textual exchanges defined by the
/// iSCSI spec. This builder initializes a 48-byte BHS with sensible defaults
/// (opcode set to `TextReq`, `StageFlags::FINAL` by default, `CmdSN = 1`),
/// and lets you fill in the sequence numbers, tags, LUN, and (optionally)
/// enable digests.
///
/// # What you can set
/// - **Immediate bit**: `immediate()` sets the *I* flag in byte 0.
/// - **Sequencing**: `cmd_sn(..)` and `exp_stat_sn(..)` as usual for the
///   session.
/// - **Tags**: `initiator_task_tag(..)` and `target_task_tag(..)`.
/// - **LUN**: `lun(..)` accepts an 8-byte encoded LUN (often zero for TEXT).
/// - **Digests**: `with_header_digest()` / `with_data_digest()` opt into
///   including CRC32C digests when your connection logic honors negotiated
///   `HeaderDigest` / `DataDigest`.
///
/// # F/C (Final/Continue)
/// By default the builder sets `StageFlags::FINAL`, meaning the message is
/// complete. If you intend to split a long key/value payload across multiple
/// Text PDUs, toggle the stage flags on `header.flags` (see `StageFlags`) so
/// that intermediate PDUs have **CONTINUE** set and the last one has **FINAL**.
#[derive(Debug, Default)]
pub struct TextRequestBuilder {
    pub header: TextRequest,
    enable_header_digest: bool,
    enable_data_digest: bool,
}

impl TextRequestBuilder {
    pub fn new() -> Self {
        TextRequestBuilder {
            header: TextRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::TextReq);
                    tmp
                },
                ..Default::default()
            },
            enable_data_digest: false,
            enable_header_digest: false,
        }
    }

    /// Set Immediate bit (Immediate = bit6)
    pub fn immediate(mut self) -> Self {
        self.header.opcode.set_i();
        self
    }

    /// Enable HeaderDigest in NOP-Out.
    pub fn with_header_digest(mut self) -> Self {
        self.enable_header_digest = true;
        self
    }

    /// Enable DataDigest in NOP-Out.
    pub fn with_data_digest(mut self) -> Self {
        self.enable_data_digest = true;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag = tag;
        self
    }

    /// Sets the target task tag, a unique identifier for this command.
    pub fn target_task_tag(mut self, tag: u32) -> Self {
        self.header.target_task_tag.set(tag);
        self
    }

    /// Sets the command sequence number (CmdSN) for this request.
    pub fn cmd_sn(mut self, sn: u32) -> Self {
        self.header.cmd_sn.set(sn);
        self
    }

    /// Sets the expected status sequence number (ExpStatSN) from the target.
    pub fn exp_stat_sn(mut self, sn: u32) -> Self {
        self.header.exp_stat_sn.set(sn);
        self
    }

    /// Set the 8-byte Logical Unit Number (LUN) in the BHS header.
    pub fn lun(mut self, lun: u64) -> Self {
        self.header.lun.set(lun);
        self
    }
}

impl SendingData for TextRequest {
    fn get_final_bit(&self) -> bool {
        self.flags.get_final_bit()
    }

    fn set_final_bit(&mut self) {
        // F ← 1,  C ← 0
        self.flags.set_final_bit();
        if self.get_continue_bit() {
            self.flags.set_continue_bit();
        }
    }

    fn get_continue_bit(&self) -> bool {
        self.flags.get_continue_bit()
    }

    fn set_continue_bit(&mut self) {
        // C ← 1,  F ← 0
        self.flags.set_continue_bit();
        if self.get_final_bit() {
            self.flags.set_final_bit();
        }
    }
}

impl FromBytes for TextRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        TextRequest::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for TextRequest {
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

impl ZeroCopyType for TextRequest {}
