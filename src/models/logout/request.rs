// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::{error, warn};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U16, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        logout::common::{LogoutReason, RawLogoutReason},
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS structure for **Logout Request** (opcode `LogoutReq`)
///
/// Fits into 48-byte Basic Header Segment.
/// Data Segment length must always be zero for Logout Request.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct LogoutRequest {
    pub opcode: RawBhsOpcode,         // byte 0: I|0x06
    pub reason: RawLogoutReason,      // byte 1: Reason Code
    reserved0: [u8; 2],               // bytes 2..4: Reserved
    pub total_ahs_length: u8,         // byte 4: normally 0
    pub data_segment_length: [u8; 3], // bytes 5..8: must be zero
    reserved1: [u8; 8],               /* bytes 8..16: Reserved (no ISID/Tsih in
                                       * LogoutReq) */
    pub initiator_task_tag: u32, // bytes 16..20: ITT
    pub cid: U16<BigEndian>,     /* bytes 20..22: CID (if closing a
                                  * specific connection) */
    reserved2: [u8; 2],              // bytes 22..24: Reserved
    pub cmd_sn: U32<BigEndian>,      // bytes 24..28
    pub exp_stat_sn: U32<BigEndian>, // bytes 28..32
    reserved3: [u8; 16],             // bytes 32..48: Reserved
}

impl LogoutRequest {
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
            .map_err(|e| anyhow::anyhow!("failed convert buffer LogoutRequest: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::LogoutReq) {
            anyhow::bail!(
                "LogoutRequest: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

/// Builder for **Logout Request**
///
/// Defaults to an Immediate Logout (`I` bit) with empty AHS and zero Data
/// Segment length.
#[derive(Debug, Default)]
pub struct LogoutRequestBuilder {
    pub header: LogoutRequest,
}

impl LogoutRequestBuilder {
    pub fn new(reason: LogoutReason, itt: u32, cid: u16) -> Self {
        Self {
            header: LogoutRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::LogoutReq);
                    tmp.set_i();
                    tmp
                },
                reason: reason.into(),
                total_ahs_length: 0,
                data_segment_length: [0, 0, 0],
                initiator_task_tag: itt,
                cid: cid.into(),
                ..Default::default()
            },
        }
    }

    /// Set the Connection ID (CID) — required when closing a specific
    /// connection.
    pub fn connection_id(mut self, cid: u16) -> Self {
        self.header.cid.set(cid);
        self
    }

    /// Set the command sequence number (CmdSN).
    pub fn cmd_sn(mut self, cmd_sn: u32) -> Self {
        self.header.cmd_sn.set(cmd_sn);
        self
    }

    /// Set the expected StatSN from the target.
    pub fn exp_stat_sn(mut self, exp_stat_sn: u32) -> Self {
        self.header.exp_stat_sn.set(exp_stat_sn);
        self
    }
}

impl SendingData for LogoutRequest {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("Logout Request cannot be marked as Final");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("Logout Request cannot be marked as Contine");
    }
}

impl FromBytes for LogoutRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        LogoutRequest::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LogoutRequest {
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
        error!("LogoutReq must have zero DataSegmentLength");
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }

    #[inline]
    fn get_header_diggest(&self, _: bool) -> usize {
        0
    }

    #[inline]
    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for LogoutRequest {}
