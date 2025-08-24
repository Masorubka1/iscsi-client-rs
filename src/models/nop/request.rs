// SPDX-License-Identifier: GPL-3.0-or-later
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
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct NopOutRequest {
    pub opcode: RawBhsOpcode,            // 0
    reserved1: [u8; 3],                  // 1..4
    pub total_ahs_length: u8,            // 4
    pub data_segment_length: [u8; 3],    // 5..8
    pub lun: U64<BigEndian>,             // 8..16
    pub initiator_task_tag: u32,         // 16..20
    pub target_task_tag: U32<BigEndian>, // 20..24
    pub cmd_sn: U32<BigEndian>,          // 24..28
    pub exp_stat_sn: U32<BigEndian>,     // 28..32
    reserved2: [u8; 16],                 // 32..48
}

impl NopOutRequest {
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;

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

    /// Set Immediate bit (Immediate = bit6)
    pub fn immediate(mut self) -> Self {
        self.header.opcode.set_i();
        self
    }

    /// Enable HeaderDigest in NOP-Out.
    pub fn with_header_digest(mut self) -> Self {
        self.want_header_digest = true;
        self
    }

    /// Enable DataDigest in NOP-Out.
    pub fn with_data_digest(mut self) -> Self {
        self.want_data_digest = true;
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

impl SendingData for NopOutRequest {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("NopOut Request cannot be marked as Final");
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

impl ZeroCopyType for NopOutRequest {}
