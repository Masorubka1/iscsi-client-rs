use anyhow::{Result, bail};
use tracing::warn;

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        command::common::{ResponseCode, ScsiCommandResponseFlags, ScsiStatus},
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::{BhsOpcode, Opcode},
    },
};

/// BHS for ScsiCommandResponse PDU
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct ScsiCommandResponse {
    pub opcode: BhsOpcode,                      // 0
    pub flags: ScsiCommandResponseFlags,        // 1
    pub response: ResponseCode,                 // 2
    pub status: ScsiStatus,                     // 3
    pub total_ahs_length: u8,                   // 4
    pub data_segment_length: [u8; 3],           // 5..8
    reserved: [u8; 8],                          // 8..16
    pub initiator_task_tag: u32,                // 16..20
    pub snack_tag: u32,                         // 20..24
    pub stat_sn: u32,                           // 24..28
    pub exp_cmd_sn: u32,                        // 28..32
    pub max_cmd_sn: u32,                        // 32..36
    pub exp_data_sn: u32,                       // 36..40
    pub bidirectional_read_residual_count: u32, // 40..44
    pub residual_count: u32,                    // 44..48
}

impl ScsiCommandResponse {
    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2] = (&self.response).into();
        buf[3] = (&self.status).into();
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.reserved);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.snack_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.exp_data_sn.to_be_bytes());
        buf[40..44]
            .copy_from_slice(&self.bidirectional_read_residual_count.to_be_bytes());
        buf[44..48].copy_from_slice(&self.residual_count.to_be_bytes());
        buf
    }

    /// Deserialize BHS from 48 bytes
    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("buffer too small: {} < {}", buf.len(), HEADER_LEN);
        }

        let opcode = BhsOpcode::try_from(buf[0])?;
        if opcode.opcode != Opcode::ScsiCommandResp {
            bail!("ScsiCommandResp invalid opcode: {:?}", opcode.opcode);
        }
        let flags = ScsiCommandResponseFlags::try_from(buf[1])?;
        let response = ResponseCode::try_from(buf[2])?;
        let status = ScsiStatus::try_from(buf[3])?;
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[8..16]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let snack_tag = u32::from_be_bytes(buf[20..24].try_into()?);
        let stat_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_cmd_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let max_cmd_sn = u32::from_be_bytes(buf[32..36].try_into()?);
        let exp_data_sn = u32::from_be_bytes(buf[36..40].try_into()?);
        let bidirectional_read_residual_count =
            u32::from_be_bytes(buf[40..44].try_into()?);
        let residual_count = u32::from_be_bytes(buf[44..48].try_into()?);

        Ok(ScsiCommandResponse {
            opcode,
            flags,
            response,
            status,
            total_ahs_length,
            data_segment_length,
            reserved,
            initiator_task_tag,
            snack_tag,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            exp_data_sn,
            bidirectional_read_residual_count,
            residual_count,
        })
    }
}

impl SendingData for ScsiCommandResponse {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("ScsiCommand Response must contain Final");
        self.flags.insert(ScsiCommandResponseFlags::FINAL);
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("ScsiCommand Response don`t support Continue");
    }
}

impl FromBytes for ScsiCommandResponse {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiCommandResponse {
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
