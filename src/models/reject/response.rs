use anyhow::{Result, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN},
        opcode::BhsOpcode,
        reject::reject_description::RejectReason,
    },
};

/// BHS for a Reject PDU (always 52 bytes)
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct RejectPdu {
    pub opcode: BhsOpcode,            // 0
    reserved1: u8,                    // 1
    pub reason: RejectReason,         // 2
    pub reserved2: u8,                // 3
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub reserved3: [u8; 4 * 2],       // 8..16
    pub initiator_task_tag: u32,      // 16..20
    pub reserved4: [u8; 4],           // 20..24
    pub stat_sn: u32,                 // 24..28
    pub exp_cmd_sn: u32,              // 28..32
    pub max_cmd_sn: u32,              // 32..36
    pub data_sn_or_r2_sn: u32,        // 36..40
    pub reserved5: [u8; 4 * 2],       // 40..48
}

impl RejectPdu {
    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("buffer too small");
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        let reserved1 = buf[1];
        let reason = RejectReason::try_from(buf[2])?;
        let reserved2 = buf[3];
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut reserved3 = [0u8; 8];
        reserved3.copy_from_slice(&buf[8..16]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let mut reserved4 = [0u8; 4];
        reserved4.copy_from_slice(&buf[20..24]);
        let stat_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_cmd_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let max_cmd_sn = u32::from_be_bytes(buf[32..36].try_into()?);
        let data_sn_or_r2_sn = u32::from_be_bytes(buf[36..40].try_into()?);

        Ok(RejectPdu {
            opcode,
            reserved1,
            reason,
            reserved2,
            total_ahs_length,
            data_segment_length,
            reserved3,
            initiator_task_tag,
            reserved4,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            data_sn_or_r2_sn,
            reserved5: [0u8; 8],
        })
    }

    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.reserved1;
        buf[2] = (&self.reason).into();
        buf[3] = self.reserved2;
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.reserved3);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.reserved4);
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.data_sn_or_r2_sn.to_be_bytes());
        //buf[40..48].copy_from_slice(&self.reserved5);
        buf
    }

    pub fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    pub fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    pub fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    pub fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    pub fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    pub fn set_data_length_bytes(&mut self, len: u32) {
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}

impl FromBytes for RejectPdu {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for RejectPdu {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
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
}
