//! SCSI Task Management Function Request PDU.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, bail};
use tracing::{error, warn};
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32,
    U64,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::ZeroCopyType,
        identifiers::{CmdSn, Itt, Lun, StatSn},
        opcode::{BhsOpcode, Opcode, RawBhsOpcode},
    },
};

/// Supported task management functions.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskManagementFunction {
    /// Abort the task identified by the referenced ITT.
    AbortTask = 1,
    /// Reset all tasks and SCSI state for the addressed logical unit.
    LogicalUnitReset = 5,
}

/// 48-byte Task Management Function Request BHS.
#[repr(C)]
#[derive(Debug, Default, PartialEq, ZFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct TaskManagementRequest {
    pub opcode: RawBhsOpcode,
    /// Final bit and task management function.
    pub function: u8,
    reserved0: [u8; 2],
    pub total_ahs_length: u8,
    pub data_segment_length: [u8; 3],
    pub lun: U64<BigEndian>,
    pub initiator_task_tag: U32<BigEndian>,
    pub referenced_task_tag: U32<BigEndian>,
    pub cmd_sn: U32<BigEndian>,
    pub exp_stat_sn: U32<BigEndian>,
    pub referenced_cmd_sn: U32<BigEndian>,
    pub exp_data_sn: U32<BigEndian>,
    reserved1: [u8; 8],
}

impl TaskManagementRequest {
    const FINAL: u8 = 0x80;
    const FUNCTION_MASK: u8 = 0x7f;

    pub fn function(&self) -> Result<TaskManagementFunction> {
        match self.function & Self::FUNCTION_MASK {
            1 => Ok(TaskManagementFunction::AbortTask),
            5 => Ok(TaskManagementFunction::LogicalUnitReset),
            value => bail!("unsupported task management function {value}"),
        }
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
            .map_err(|error| anyhow::anyhow!("invalid TMF request BHS: {error}"))?;
        if header.opcode.opcode_known() != Some(Opcode::ScsiTaskMgmtReq) {
            bail!("invalid TMF request opcode");
        }
        header.function()?;
        if !header.get_final_bit() {
            bail!("TMF request must set Final");
        }
        if header.total_ahs_length != 0 || header.get_data_length_bytes() != 0 {
            bail!("TMF request must not contain AHS or data");
        }
        Ok(header)
    }
}

/// Builder for the supported task management requests.
#[derive(Debug)]
pub struct TaskManagementRequestBuilder {
    pub header: TaskManagementRequest,
}

impl TaskManagementRequestBuilder {
    fn new(function: TaskManagementFunction, lun: Lun, itt: Itt) -> Self {
        let mut opcode = RawBhsOpcode::default();
        opcode.set_opcode_known(Opcode::ScsiTaskMgmtReq);
        opcode.set_i();
        Self {
            header: TaskManagementRequest {
                opcode,
                function: TaskManagementRequest::FINAL | function as u8,
                lun: lun.get().into(),
                initiator_task_tag: itt.get().into(),
                referenced_task_tag: u32::MAX.into(),
                ..Default::default()
            },
        }
    }

    /// Builds an ABORT TASK request.
    pub fn abort_task(
        lun: Lun,
        itt: Itt,
        referenced_itt: Itt,
        referenced_cmd_sn: CmdSn,
    ) -> Self {
        let mut builder = Self::new(TaskManagementFunction::AbortTask, lun, itt);
        builder
            .header
            .referenced_task_tag
            .set(referenced_itt.get());
        builder.header.referenced_cmd_sn.set(referenced_cmd_sn.get());
        builder
    }

    /// Builds a LOGICAL UNIT RESET request.
    pub fn logical_unit_reset(lun: Lun, itt: Itt) -> Self {
        Self::new(TaskManagementFunction::LogicalUnitReset, lun, itt)
    }

    pub fn cmd_sn(mut self, value: CmdSn) -> Self {
        self.header.cmd_sn.set(value.get());
        self
    }

    pub fn exp_stat_sn(mut self, value: StatSn) -> Self {
        self.header.exp_stat_sn.set(value.get());
        self
    }

}

impl SendingData for TaskManagementRequest {
    fn get_final_bit(&self) -> bool {
        self.function & Self::FINAL != 0
    }

    fn set_final_bit(&mut self) {
        self.function |= Self::FINAL;
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("TMF Request has no Continue bit");
    }
}

impl FromBytes for TaskManagementRequest {
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for TaskManagementRequest {
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
        error!("TMF Request must not contain a data segment");
    }

    fn get_header_diggest(&self, enabled: bool) -> usize {
        4 * enabled as usize
    }

    fn get_data_diggest(&self, _: bool) -> usize {
        0
    }
}

impl ZeroCopyType for TaskManagementRequest {}
