// SPDX-License-Identifier: GPL-3.0-or-later
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
        login::common::{RawLoginFlags, Stage},
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS form LoginRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LoginRequest {
    pub opcode: RawBhsOpcode,         // 0
    pub flags: RawLoginFlags,         // 1
    pub version_max: u8,              // 2
    pub version_min: u8,              // 3
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub isid: [u8; 6],                // 8..14
    pub tsih: U16<BigEndian>,         // 14..16
    pub initiator_task_tag: u32,      // 16..20
    pub cid: U16<BigEndian>,          // 20..22
    reserved1: [u8; 2],               // 22..24
    pub cmd_sn: U32<BigEndian>,       // 24..28
    pub exp_stat_sn: U32<BigEndian>,  // 28..32
    reserved2: [u8; 16],              // 32..48
}

impl LoginRequest {
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
            .map_err(|e| anyhow::anyhow!("failed convert buffer LoginRequest: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::LoginReq) {
            anyhow::bail!(
                "LoginRequest: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

/// Builder for an iSCSI **Login Request** PDU (opcode `LoginReq` / BHS byte0 =
/// I|0x03).
///
/// This helper constructs the 48-byte Login BHS and lets you set the
/// connection stage flags, version fields, and sequence counters. The actual
/// login key–value pairs (e.g. `AuthMethod=…\0`, `HeaderDigest=…\0`, …) go
/// into the **Data Segment** and should be appended separately via
/// `PDUWithData::append_data(...)`.
///
/// # What it sets
/// - **Opcode/Immediate**: `new()` creates a LoginReq with the **I**
///   (Immediate) bit set.
/// - **Transit/Stages**:
///   - `transit()` sets the **T** bit (request a stage transition).
///   - `csg(Stage)` selects the **current stage** (CSG bits).
///   - `nsg(Stage)` selects the **next stage** (NSG bits).
/// - **Versions**: `versions(max, min)` set *VersionMax*/*VersionMin*.
/// - **Session/Conn IDs**: `initiator_task_tag(…)`, `connection_id(…)`,
///   `isid(…)`.
/// - **Sequencing**: `cmd_sn(…)`, `exp_stat_sn(…)`.
///
/// # Typical flow
/// 1. **Security → Operational** with authentication keys in Data Segment
/// 2. (Optionally continue within Security for CHAP exchange)
/// 3. **Operational → FullFeature** to finish login
#[derive(Debug)]
pub struct LoginRequestBuilder {
    pub header: LoginRequest,
}

impl LoginRequestBuilder {
    pub fn new(isid: [u8; 6], tsih: u16) -> Self {
        LoginRequestBuilder {
            header: LoginRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::LoginReq);
                    tmp.set_i();
                    tmp
                },
                isid,
                tsih: tsih.into(),
                ..Default::default()
            },
        }
    }

    /// Set Transit (T = bit7)
    pub fn transit(mut self) -> Self {
        self.header.flags.set_transit(true);
        self
    }

    /// Set CSG (connection-stage: bits 3–4)
    pub fn csg(mut self, stage: Stage) -> Self {
        self.header.flags.set_csg(stage);
        self
    }

    /// Set NSG (next-stage: bits 0–1)
    pub fn nsg(mut self, stage: Stage) -> Self {
        self.header.flags.set_nsg(stage);
        self
    }

    /// Minimal and maximum version of protocol
    pub fn versions(mut self, max: u8, min: u8) -> Self {
        self.header.version_max = max;
        self.header.version_min = min;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag = tag;
        self
    }

    /// Sets the connection ID (CID) for multiplexing sessions.
    pub fn connection_id(mut self, cid: u16) -> Self {
        self.header.cid.set(cid);
        self
    }

    /// Sets the command sequence number (CmdSN) for this request.
    pub fn cmd_sn(mut self, cmd_sn: u32) -> Self {
        self.header.cmd_sn.set(cmd_sn);
        self
    }

    /// Sets the expected status sequence number (ExpStatSN) from the target.
    pub fn exp_stat_sn(mut self, exp_stat_sn: u32) -> Self {
        self.header.exp_stat_sn.set(exp_stat_sn);
        self
    }

    pub fn isid(mut self, isid: &[u8; 6]) -> Self {
        self.header.isid.clone_from_slice(isid);
        self
    }
}

impl SendingData for LoginRequest {
    fn get_final_bit(&self) -> bool {
        !self.flags.cont()
    }

    fn set_final_bit(&mut self) {
        self.flags.set_cont(false);
    }

    fn get_continue_bit(&self) -> bool {
        self.flags.cont()
    }

    fn set_continue_bit(&mut self) {
        self.flags.set_cont(true);
    }
}

impl FromBytes for LoginRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        LoginRequest::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LoginRequest {
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

    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    fn set_data_length_bytes(&mut self, len: u32) {
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }

    fn get_header_diggest(&self, _: bool) -> usize {
        0
    }

    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for LoginRequest {}
