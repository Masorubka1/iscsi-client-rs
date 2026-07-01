//! This module defines the structures for iSCSI Login Request PDUs.
//! It includes the `LoginRequest` header and a builder for constructing it.

// SPDX-License-Identifier: AGPL-3.0-or-later
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
        identifiers::{Cid, CmdSn, Isid, Itt, StatSn, Tsih},
        login::common::{RawLoginFlags, Stage},
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Basic Header Segment for iSCSI Login Request PDU
///
/// Represents the 48-byte header structure for Login Request PDU as defined in
/// RFC 7143. Contains session establishment parameters including version
/// negotiation, session IDs, and connection information used during the iSCSI
/// login process.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LoginRequest {
    pub opcode: RawBhsOpcode, // Byte 0: I flag + `Opcode::LoginReq`
    pub flags: RawLoginFlags, // Byte 1: login transit/continue/stage flags
    pub version_max: u8,      // Byte 2: maximum supported iSCSI version
    pub version_min: u8,      // Byte 3: minimum supported iSCSI version
    pub total_ahs_length: u8, // Byte 4: AHS length in 4-byte words
    pub data_segment_length: [u8; 3], // Bytes 5..8: login text payload length
    /// Initiator Session Identifier encoded in bytes 8..14.
    pub isid: [u8; 6],
    /// Target Session Identifying Handle, or zero for a new session.
    pub tsih: U16<BigEndian>,
    pub initiator_task_tag: U32<BigEndian>, // Bytes 16..20: ITT
    /// Connection Identifier assigned by the initiator.
    pub cid: U16<BigEndian>,
    reserved1: [u8; 2],              // Bytes 22..24: reserved
    pub cmd_sn: U32<BigEndian>,      // Bytes 24..28: CmdSN
    pub exp_stat_sn: U32<BigEndian>, // Bytes 28..32: ExpStatSN
    reserved2: [u8; 16],             // Bytes 32..48: reserved
}

impl LoginRequest {
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
    /// Creates a new `LoginRequestBuilder` with the given ISID and TSIH.
    pub fn new(isid: Isid, tsih: Tsih) -> Self {
        LoginRequestBuilder {
            header: LoginRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::LoginReq);
                    tmp.set_i();
                    tmp
                },
                isid: isid.get(),
                tsih: tsih.get().into(),
                ..Default::default()
            },
        }
    }

    /// Sets the Transit (T) bit, indicating a stage transition request.
    pub fn transit(mut self) -> Self {
        self.header.flags.set_transit(true);
        self
    }

    /// Sets the Current Stage (CSG) of the login phase.
    pub fn csg(mut self, stage: Stage) -> Self {
        self.header.flags.set_csg(stage);
        self
    }

    /// Sets the Next Stage (NSG) of the login phase.
    pub fn nsg(mut self, stage: Stage) -> Self {
        self.header.flags.set_nsg(stage);
        self
    }

    /// Sets the minimum and maximum iSCSI versions supported by the initiator.
    pub fn versions(mut self, max: u8, min: u8) -> Self {
        self.header.version_max = max;
        self.header.version_min = min;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: impl Into<Itt>) -> Self {
        self.header.initiator_task_tag.set(tag.into().get());
        self
    }

    /// Sets the connection ID (CID) for this login request.
    pub fn connection_id(mut self, cid: Cid) -> Self {
        self.header.cid.set(cid.get());
        self
    }

    /// Sets the command sequence number (CmdSN) for this request.
    pub fn cmd_sn(mut self, cmd_sn: impl Into<CmdSn>) -> Self {
        self.header.cmd_sn.set(cmd_sn.into().get());
        self
    }

    /// Sets the expected status sequence number (ExpStatSN) from the target.
    pub fn exp_stat_sn(mut self, exp_stat_sn: impl Into<StatSn>) -> Self {
        self.header.exp_stat_sn.set(exp_stat_sn.into().get());
        self
    }

    /// Sets the Initiator Session ID (ISID) for the login request.
    pub fn isid(mut self, isid: Isid) -> Self {
        self.header.isid = isid.get();
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

    fn get_initiator_task_tag(&self) -> Itt {
        self.initiator_task_tag.get().into()
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
