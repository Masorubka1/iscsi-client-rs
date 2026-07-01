//! This module defines the structures for iSCSI NOP-Out PDUs.
//! It includes the `NopOutRequest` header and a builder for constructing it.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::{debug, warn};
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
    },
};

/// Represents the Basic Header Segment (BHS) for a NOP-Out PDU.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct NopOutRequest {
    pub opcode: RawBhsOpcode, // Byte 0: I flag + `Opcode::NopOut`
    reserved1: [u8; 3],       // Bytes 1..4: reserved
    pub total_ahs_length: u8, // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3], // Bytes 5..8: optional payload length
    pub lun: U64<BigEndian>,  // Bytes 8..16: LUN
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    pub target_task_tag: U32<BigEndian>, // Bytes 20..24: TTT
    pub cmd_sn: U32<BigEndian>, // Bytes 24..28: CmdSN
    pub exp_stat_sn: U32<BigEndian>, // Bytes 28..32: ExpStatSN
    reserved2: [u8; 16],      // Bytes 32..48: reserved
}

impl NopOutRequest {
    /// The default task tag value for NOP-Out requests.
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;

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
            .map_err(|e| anyhow::anyhow!("failed convert buffer NopOutRequest: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::NopOut) {
            anyhow::bail!(
                "NopOutRequest: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

/// Builder for an iSCSI **NOP-Out** PDU (opcode `NopOut`).
///
/// NOP-Out is a lightweight “ping/keep-alive” PDU used to verify liveness,
/// measure round-trip time, or provoke a NOP-In from the target. It carries
/// no SCSI semantics and **does not use F/C (Final/Continue) bits**.
///
/// This builder prepares the 48-byte BHS; if you want to attach an optional
/// data segment (rare for NOPs), wrap the header with `PDUWithData` and call
/// `append_data(...)`.
///
/// # What you can set
/// - **Immediate bit**: `immediate()` sets the *I* flag in byte 0.
/// - **Initiator/Target Task Tags**:
///   - `initiator_task_tag(..)` sets **ITT** (used to match the reply).
///   - `target_task_tag(..)` sets **TTT**:
///     - For a *solicited ping*, use `NopOutRequest::DEFAULT_TAG`
///       (`0xFFFF_FFFF`) to ask the target to generate a NOP-In.
///     - For a *response to a target’s NOP-In*, copy the TTT you received.
/// - **Sequencing**: `cmd_sn(..)` and `exp_stat_sn(..)` as usual for the
///   session.
/// - **LUN**: `lun(..)` accepts an 8-byte encoded LUN (often zero for NOPs).
/// - **Digests**: `with_header_digest()` / `with_data_digest()` opt into
///   including CRC32C digests when your connection logic honors negotiated
///   `HeaderDigest` / `DataDigest` settings.
///
/// # Typical patterns
/// - **Initiator ping** (solicit a NOP-In):
///   - Set `TTT = 0xFFFF_FFFF`, pick a fresh ITT, send NOP-Out, wait for NOP-In
///     with the same ITT.
/// - **Reply to target’s NOP-In**:
///   - Echo back the **TTT** you received in NOP-In, send NOP-Out.
#[derive(Debug, Default)]
pub struct NopOutRequestBuilder {
    pub header: NopOutRequest,
    want_header_digest: bool,
    want_data_digest: bool,
}

impl NopOutRequestBuilder {
    /// Creates a new `NopOutRequestBuilder` with default values.
    pub fn new() -> Self {
        NopOutRequestBuilder {
            header: NopOutRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::NopOut);
                    tmp
                },
                reserved1: {
                    let mut tmp = [0; 3];
                    tmp[0] = 0b1000_0000;
                    tmp
                },
                ..Default::default()
            },
            want_data_digest: false,
            want_header_digest: false,
        }
    }

    /// Sets the Immediate bit in the PDU header.
    pub fn immediate(mut self) -> Self {
        self.header.opcode.set_i();
        self
    }

    /// Enables header digest for the PDU.
    pub fn with_header_digest(mut self) -> Self {
        self.want_header_digest = true;
        self
    }

    /// Enables data digest for the PDU.
    pub fn with_data_digest(mut self) -> Self {
        self.want_data_digest = true;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: impl Into<Itt>) -> Self {
        self.header.initiator_task_tag.set(tag.into().get());
        self
    }

    /// Sets the target task tag, used to match a response to a NOP-In.
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

impl SendingData for NopOutRequest {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        debug!("NopOut Request cannot be marked as Final")
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("NopOut Request cannot be marked as Contine");
    }
}

impl FromBytes for NopOutRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        NopOutRequest::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for NopOutRequest {
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

impl ZeroCopyType for NopOutRequest {}
