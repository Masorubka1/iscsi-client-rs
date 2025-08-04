use anyhow::{Context, Result, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        command::common::{ResponseCode, ScsiCommandResponseFlags, ScsiStatus},
        common::BasicHeaderSegment,
        opcode::BhsOpcode,
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
    pub header_digest: Option<u32>,             // 48..52

    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl ScsiCommandResponse {
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2] = (&self.response).into();
        buf[3] = (&self.status).into();
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        // 8..16 reserved
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.snack_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.exp_data_sn.to_be_bytes());
        buf[40..44]
            .copy_from_slice(&self.bidirectional_read_residual_count.to_be_bytes());
        buf[44..48].copy_from_slice(&self.residual_count.to_be_bytes());
        // TODO: fix header_diggest
        //buf[48..52].copy_from_slice(&self.header_digest.to_be_bytes());
        buf
    }

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            bail!("buffer too small: {} < {}", buf.len(), Self::HEADER_LEN);
        }

        let opcode = BhsOpcode::try_from(buf[0])?;
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
        // TODO: fix residual_count
        //let residual_count = u32::from_be_bytes(buf[44..48].try_into()?);
        // TODO: fix header_diggest
        //let header_digest = u32::from_be_bytes(buf[48..52].try_into()?);

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
            residual_count: 0,
            header_digest: None,
            data: vec![],
            data_digest: None,
        })
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            bail!(
                "Buffer {} too small for ScsiCommandResponse BHS {}",
                buf.len(),
                Self::HEADER_LEN
            );
        }
        let mut response = Self::from_bhs_bytes(&buf[..Self::HEADER_LEN])?;

        let ahs_len = response.ahs_length_bytes();
        let data_len = response.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            bail!(
                "NopInResponse Buffer {} too small for DataSegment {}",
                buf.len(),
                offset + data_len
            );
        }
        response.data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        response.header_digest = if buf.len() >= offset + 4 {
            println!("HEADER DIGEST {}, {}", buf.len(), offset + 4);
            Some(u32::from_be_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .context("Failed to get offset from buf")?,
            ))
        } else {
            None
        };

        Ok(response)
    }
}

impl BasicHeaderSegment for ScsiCommandResponse {
    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    fn ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    fn data_length_bytes(&self) -> usize {
        let data_size = u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize;

        let pad = (4 - (data_size % 4)) % 4;
        data_size + pad
    }

    fn total_length_bytes(&self) -> usize {
        Self::HEADER_LEN + self.ahs_length_bytes() + self.data_length_bytes()
    }
}

impl FromBytes for ScsiCommandResponse {
    const HEADER_LEN: usize = ScsiCommandResponse::HEADER_LEN;

    fn from_bytes(buf: &[u8]) -> Result<Self> {
        Self::parse(buf)
    }
}
