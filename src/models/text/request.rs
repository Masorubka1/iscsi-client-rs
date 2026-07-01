//! This module defines the structures for iSCSI Text Request PDUs.
//! It includes the `TextRequest` header and a builder for constructing it.

// SPDX-License-Identifier: AGPL-3.0-or-later
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
        identifiers::{CmdSn, Itt, Lun, StatSn, Ttt},
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
        text::common::RawStageFlags,
    },
};

/// Represents the Basic Header Segment (BHS) for a Text Request PDU.
#[repr(C)]
#[derive(Default, Debug, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct TextRequest {
    pub opcode: RawBhsOpcode, // Byte 0: I/F flags + `Opcode::TextReq`
    pub flags: RawStageFlags, // Byte 1: Text stage flags (F/C)
    reserved1: [u8; 2],       // Bytes 2..4: reserved
    pub total_ahs_length: u8, // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3], // Bytes 5..8: text payload length
    pub lun: U64<BigEndian>,  // Bytes 8..16: LUN
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    pub target_task_tag: U32<BigEndian>, // Bytes 20..24: TTT
    pub cmd_sn: U32<BigEndian>, // Bytes 24..28: CmdSN
    pub exp_stat_sn: U32<BigEndian>, // Bytes 28..32: ExpStatSN
    reserved2: [u8; 16],      // Bytes 32..48: reserved
}

impl TextRequest {
    /// The default task tag value for Text requests.
    pub const DEFAULT_TAG: u32 = 0xFFFF_FFFF;

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
    /// Creates a new `TextRequestBuilder` with default values.
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

    /// Sets the Immediate bit in the PDU header.
    pub fn immediate(mut self) -> Self {
        self.header.opcode.set_i();
        self
    }

    /// Enables header digest for the PDU.
    pub fn with_header_digest(mut self) -> Self {
        self.enable_header_digest = true;
        self
    }

    /// Enables data digest for the PDU.
    pub fn with_data_digest(mut self) -> Self {
        self.enable_data_digest = true;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: impl Into<Itt>) -> Self {
        self.header.initiator_task_tag.set(tag.into().get());
        self
    }

    /// Sets the target task tag, used to identify a command to which this is a
    /// response.
    pub fn target_task_tag(mut self, tag: impl Into<Ttt>) -> Self {
        self.header.target_task_tag.set(tag.into().get());
        self
    }

    /// Sets the command sequence number (CmdSN) for this request.
    pub fn cmd_sn(mut self, sn: impl Into<CmdSn>) -> Self {
        self.header.cmd_sn.set(sn.into().get());
        self
    }

    /// Sets the expected status sequence number (ExpStatSN) from the target.
    pub fn exp_stat_sn(mut self, sn: impl Into<StatSn>) -> Self {
        self.header.exp_stat_sn.set(sn.into().get());
        self
    }

    /// Sets the Logical Unit Number (LUN) for the command.
    pub fn lun(mut self, lun: impl Into<Lun>) -> Self {
        self.header.lun.set(lun.into().get());
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

impl ZeroCopyType for TextRequest {}
