use anyhow::{Result, bail};
use tracing::warn;

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::{BhsOpcode, Opcode},
    },
};

/// BHS for **Ready To Transfer (R2T)** – RFC 7143 §10.7.
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct ReadyToTransfer {
    pub opcode: BhsOpcode,                 // 0
    pub reserved1: [u8; 3],                // 1..4
    pub total_ahs_length: u8,              // 4
    pub data_segment_length: [u8; 3],      // 5..8  (должно быть 0)
    pub lun: [u8; 8],                      // 8..16
    pub initiator_task_tag: u32,           // 16..20
    pub target_transfer_tag: u32,          // 20..24
    pub stat_sn: u32,                      // 24..28
    pub exp_cmd_sn: u32,                   // 28..32
    pub max_cmd_sn: u32,                   // 32..36
    pub r2t_sn: u32,                       // 36..40
    pub buffer_offset: u32,                // 40..44
    pub desired_data_transfer_length: u32, // 44..48
}

impl ReadyToTransfer {
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1..4].copy_from_slice(&self.reserved1);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.r2t_sn.to_be_bytes());
        buf[40..44].copy_from_slice(&self.buffer_offset.to_be_bytes());
        buf[44..48].copy_from_slice(&self.desired_data_transfer_length.to_be_bytes());
        buf
    }

    pub fn from_bhs_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            bail!("buffer too small for R2T BHS");
        }
        let opcode = BhsOpcode::try_from(b[0])?;
        if opcode.opcode != Opcode::ReadyToTransfer {
            bail!("R2T invalid opcode: {:?}", opcode.opcode);
        }
        let total_ahs_length = b[4];
        let data_segment_length = [b[5], b[6], b[7]];
        if data_segment_length != [0, 0, 0] {
            bail!("R2T must carry zero DataSegmentLength");
        }

        let mut lun = [0u8; 8];
        lun.copy_from_slice(&b[8..16]);

        Ok(Self {
            opcode,
            reserved1: b[1..4].try_into()?,
            total_ahs_length,
            data_segment_length,
            lun,
            initiator_task_tag: u32::from_be_bytes(b[16..20].try_into()?),
            target_transfer_tag: u32::from_be_bytes(b[20..24].try_into()?),
            stat_sn: u32::from_be_bytes(b[24..28].try_into()?),
            exp_cmd_sn: u32::from_be_bytes(b[28..32].try_into()?),
            max_cmd_sn: u32::from_be_bytes(b[32..36].try_into()?),
            r2t_sn: u32::from_be_bytes(b[36..40].try_into()?),
            buffer_offset: u32::from_be_bytes(b[40..44].try_into()?),
            desired_data_transfer_length: u32::from_be_bytes(b[44..48].try_into()?),
        })
    }
}

impl SendingData for ReadyToTransfer {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("R2T is header-only; Final flag in opcode byte is not used");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("R2T cannot be marked as Continue");
    }
}

impl FromBytes for ReadyToTransfer {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ReadyToTransfer {
    #[inline]
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    #[inline]
    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
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
