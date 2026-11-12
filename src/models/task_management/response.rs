//! SCSI Task Management Function Response PDU.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::{error, warn};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        identifiers::Itt,
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Target result for a task management function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskManagementResponseCode {
    FunctionComplete,
    TaskDoesNotExist,
    LunDoesNotExist,
    TaskStillAllegiant,
    FailoverNotSupported,
    FunctionNotSupported,
    FunctionNotAuthorized,
    FunctionRejected,
}

impl TryFrom<u8> for TaskManagementResponseCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::FunctionComplete,
            1 => Self::TaskDoesNotExist,
            2 => Self::LunDoesNotExist,
            3 => Self::TaskStillAllegiant,
            4 => Self::FailoverNotSupported,
            5 => Self::FunctionNotSupported,
            6 => Self::FunctionNotAuthorized,
            255 => Self::FunctionRejected,
            _ => bail!("unknown TMF response code {value}"),
        })
    }
}

/// 48-byte Task Management Function Response BHS.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct TaskManagementResponse {
    pub opcode: RawBhsOpcode,
    pub flags: u8,
    pub response: u8,
    reserved0: u8,
    pub total_ahs_length: u8,
    pub data_segment_length: [u8; 3],
    reserved1: [u8; 8],
    pub initiator_task_tag: U32<BigEndian>,
    reserved2: [u8; 4],
    pub stat_sn: U32<BigEndian>,
    pub exp_cmd_sn: U32<BigEndian>,
    pub max_cmd_sn: U32<BigEndian>,
    reserved3: [u8; 12],
}

impl TaskManagementResponse {
    const FINAL: u8 = 0x80;

    pub fn response_code(&self) -> Result<TaskManagementResponseCode> {
        self.response.try_into()
    }

    pub fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() != HEADER_LEN {
            bail!("buffer length must be {HEADER_LEN}, got {}", buf.len());
        }
        buf.copy_from_slice(self.as_bytes());
        Ok(())
    }

    pub fn from_bhs_bytes(buf: &mut [u8]) -> Result<&mut Self> {
        let header = <Self as zerocopy::FromBytes>::mut_from_bytes(buf)
            .map_err(|error| anyhow::anyhow!("invalid TMF response BHS: {error}"))?;
        if header.opcode.opcode_known() != Some(Opcode::ScsiTaskMgmtResp) {
            bail!("invalid TMF response opcode");
        }
        header.response_code()?;
        if !header.get_final_bit() {
            bail!("TMF response must set Final");
        }
        if header.total_ahs_length != 0 || header.get_data_length_bytes() != 0 {
            bail!("TMF response must not contain AHS or data");
        }
        Ok(header)
    }
}

impl SendingData for TaskManagementResponse {
    fn get_final_bit(&self) -> bool {
        self.flags & Self::FINAL != 0
    }

    fn set_final_bit(&mut self) {
        self.flags |= Self::FINAL;
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("TMF Response has no Continue bit");
    }
}

impl FromBytes for TaskManagementResponse {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for TaskManagementResponse {
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()> {
        self.to_bhs_bytes(buf)
    }

    fn get_opcode(&self) -> Result<BhsOpcode> {
        BhsOpcode::try_from(self.opcode.raw())
    }

    fn get_initiator_task_tag(&self) -> Itt {
        self.initiator_task_tag.get().into()
    }

    fn get_ahs_length_bytes(&self) -> usize {
        self.total_ahs_length as usize * 4
    }

    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([0, self.data_segment_length[0], self.data_segment_length[1], self.data_segment_length[2]]) as usize
    }

    fn set_data_length_bytes(&mut self, _: u32) {
        error!("TMF Response must not contain a data segment");
    }

    fn get_header_diggest(&self, enabled: bool) -> usize {
        4 * enabled as usize
    }

    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for TaskManagementResponse {}
