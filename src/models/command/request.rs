// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow, bail};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32, U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        command::{common::TaskAttribute, zero_copy::RawScsiCmdReqFlags},
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// BHS for ScsiCommandRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ScsiCommandRequest {
    pub opcode: RawBhsOpcode,                          // 0
    pub flags: RawScsiCmdReqFlags,                     // 1
    reserved1: [u8; 2],                                // 2..4
    pub total_ahs_length: u8,                          // 4
    pub data_segment_length: [u8; 3],                  // 5..8
    pub lun: U64<BigEndian>,                           // 8..16
    pub initiator_task_tag: u32,                       // 16..20
    pub expected_data_transfer_length: U32<BigEndian>, // 20..24
    pub cmd_sn: U32<BigEndian>,                        // 24..28
    pub exp_stat_sn: U32<BigEndian>,                   // 28..32
    pub scsi_descriptor_block: [u8; 16],               // 32..48
}

impl ScsiCommandRequest {
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
            .map_err(|e| anyhow!("failed convert buffer ScsiCommandRequest: {e}"))?;
        if hdr.opcode.opcode_known() != Some(Opcode::ScsiCommandReq) {
            anyhow::bail!(
                "ScsiCommandRequest: invalid opcode 0x{:02x}",
                hdr.opcode.opcode_raw()
            );
        }
        Ok(hdr)
    }
}

/// Builder for **SCSI Command** PDUs (opcode `0x01`).
///
/// This helper constructs the Basic Header Segment (BHS) for a SCSI command
/// sent over iSCSI. It lets you set the common fields (LUN, ITT, CmdSN,
/// ExpStatSN, 16-byte CDB, task attributes, and READ/WRITE/Immediate flags)
/// and, when needed, request header/data digests for serialization.
///
/// Notes & conventions:
/// - The 16-byte **CDB** is copied verbatim into the header. For READ(10) or
///   WRITE(10) you typically pad your 10-byte CDB to 16 bytes.
/// - **expected_data_transfer_length** is the total payload you expect to move:
///   * For **Data-Out** (WRITE) it should match the number of bytes you will
///     actually send in subsequent Data-Out PDUs (unsolicited or per R2T).
///   * For **Data-In** (READ) it announces how many bytes you expect to receive
///     and is used for residual accounting by the target.
/// - **Immediate (I)** sets bit 6 in the opcode byte. Whether the target
///   processes immediate commands depends on negotiated parameters.
/// - **TaskAttribute** encodes SIMPLE/ORDERED/HEAD_OF_QUEUE/ACA into the low
///   bits of the flags field (per SPC/SAM).
/// - Enabling **Header/Data Digest** here only toggles intent for the
///   serialization layer; it does not modify BHS fields directly.
#[derive(Debug, Default, PartialEq)]
pub struct ScsiCommandRequestBuilder {
    pub header: ScsiCommandRequest,
    enable_header_digest: bool,
    enable_data_digest: bool,
}

impl ScsiCommandRequestBuilder {
    pub fn new() -> Self {
        ScsiCommandRequestBuilder {
            header: ScsiCommandRequest {
                opcode: {
                    let mut tmp = RawBhsOpcode::default();
                    tmp.set_opcode_known(Opcode::ScsiCommandReq);
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

    /// Set Read bit
    pub fn read(mut self) -> Self {
        self.header.flags.set_read(true);
        self
    }

    /// Set Read bit
    pub fn write(mut self) -> Self {
        self.header.flags.set_write(true);
        self
    }

    /// Set TaskTag bits
    pub fn task_attribute(mut self, task: TaskAttribute) -> Self {
        self.header.flags.set_task_attr(task);
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

    /// Sets the expected_data_length, a length off all parts of data.
    pub fn expected_data_transfer_length(mut self, expected_data_length: u32) -> Self {
        self.header
            .expected_data_transfer_length
            .set(expected_data_length);
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

    /// Set the 16-byte SCSI Command Descriptor Block (CDB) in the BHS header.
    pub fn scsi_descriptor_block(mut self, scsi_descriptor_block: &[u8; 16]) -> Self {
        self.header
            .scsi_descriptor_block
            .clone_from_slice(scsi_descriptor_block);
        self
    }
}

impl SendingData for ScsiCommandRequest {
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

impl FromBytes for ScsiCommandRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        ScsiCommandRequest::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiCommandRequest {
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

impl ZeroCopyType for ScsiCommandRequest {}
