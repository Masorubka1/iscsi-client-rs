//! This module defines the structures for iSCSI SCSI Command Request PDUs.
//! It includes the `ScsiCommandRequest` header and a builder for constructing it.

// SPDX-License-Identifier: AGPL-3.0-or-later
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

/// Basic Header Segment for iSCSI SCSI Command Request PDU
///
/// Represents the 48-byte header structure for SCSI Command PDU as defined in RFC 7143.
/// Contains all the fields necessary to send a SCSI command over iSCSI including
/// task tags, sequence numbers, LUN, and the embedded SCSI CDB.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ScsiCommandRequest {
    /// PDU opcode (byte 0) - should be 0x01 for SCSI Command
    pub opcode: RawBhsOpcode,
    /// Command flags (byte 1) - Final, Read, Write bits and task attributes
    pub flags: RawScsiCmdReqFlags,
    /// Reserved bytes (2-3)
    reserved1: [u8; 2],
    /// Total Additional Header Segments length (byte 4)
    pub total_ahs_length: u8,
    /// Data Segment Length (bytes 5-7) - length of immediate data
    pub data_segment_length: [u8; 3],
    /// Logical Unit Number (bytes 8-15)
    pub lun: U64<BigEndian>,
    /// Initiator Task Tag (bytes 16-19) - unique command identifier
    pub initiator_task_tag: U32<BigEndian>,
    /// Expected Data Transfer Length (bytes 20-23) - total data expected
    pub expected_data_transfer_length: U32<BigEndian>,
    /// Command Sequence Number (bytes 24-27) - for ordering
    pub cmd_sn: U32<BigEndian>,
    /// Expected Status Sequence Number (bytes 28-31) - acknowledgment
    pub exp_stat_sn: U32<BigEndian>,
    /// SCSI Command Descriptor Block (bytes 32-47) - the actual SCSI command
    pub scsi_descriptor_block: [u8; 16],
}

impl ScsiCommandRequest {
    /// The default initiator task tag value.
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

/// Builder for constructing iSCSI SCSI Command Request PDUs
///
/// Provides methods to build and serialize SCSI Command Request PDUs with proper
/// digest handling and data segment management.
#[derive(Debug, Default, PartialEq)]
pub struct ScsiCommandRequestBuilder {
    /// The SCSI command request header structure
    pub header: ScsiCommandRequest,
    /// Whether to calculate and include header digest
    enable_header_digest: bool,
    /// Whether to calculate and include data digest
    enable_data_digest: bool,
}

impl ScsiCommandRequestBuilder {
    /// Creates a new `ScsiCommandRequestBuilder` with default values.
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

    /// Sets the Immediate bit in the PDU header.
    pub fn immediate(mut self) -> Self {
        self.header.opcode.set_i();
        self
    }

    /// Sets the Read bit in the PDU header.
    pub fn read(mut self) -> Self {
        self.header.flags.set_read(true);
        self
    }

    /// Sets the Write bit in the PDU header.
    pub fn write(mut self) -> Self {
        self.header.flags.set_write(true);
        self
    }

    /// Sets the task attribute for the SCSI command.
    pub fn task_attribute(mut self, task: TaskAttribute) -> Self {
        self.header.flags.set_task_attr(task);
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
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag.set(tag);
        self
    }

    /// Sets the expected data transfer length for the command.
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

    /// Sets the Logical Unit Number (LUN) for the command.
    pub fn lun(mut self, lun: u64) -> Self {
        self.header.lun.set(lun);
        self
    }

    /// Sets the SCSI Command Descriptor Block (CDB).
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
        self.initiator_task_tag.get()
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
