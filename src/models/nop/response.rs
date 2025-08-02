use anyhow::{Context, Result, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::BasicHeaderSegment,
        opcode::{BhsOpcode, IfFlags},
    },
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct NopInResponse {
    pub opcode: BhsOpcode,            // 0
    reserved1: [u8; 3],               // 1..4
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub lun: [u8; 8],                 // 8..16
    pub initiator_task_tag: u32,      // 16..20
    pub target_task_tag: u32,         // 20..24
    pub stat_sn: u32,                 // 24..28
    pub exp_cmd_sn: u32,              // 28..32
    pub max_cmd_sn: u32,              // 32..36
    reserved2: [u8; 8],               // 36..44
    pub header_digest: Option<u32>,   // 44..48

    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl NopInResponse {
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = (&self.opcode).into();
        // finnal bit
        buf[1..4].copy_from_slice(&self.reserved1);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_task_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        // buf[36..44] -- reserved
        //buf[44..48].copy_from_slice(&self.header_digest.to_be_bytes());
        buf
    }

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self, anyhow::Error> {
        if buf.len() < Self::HEADER_LEN {
            bail!("buffer too small");
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        // buf[1..4] -- reserved
        let reserved1 = {
            let mut tmp = [0u8; 3];
            tmp[0] = IfFlags::I.bits();
            tmp
        };
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut lun = [0u8; 8];
        lun.clone_from_slice(&buf[8..16]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let target_task_tag = u32::from_be_bytes(buf[20..24].try_into()?);
        let stat_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_cmd_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let max_cmd_sn = u32::from_be_bytes(buf[32..36].try_into()?);
        // buf[36..44] -- reserved
        // let header_digest = u32::from_be_bytes(buf[44..48].try_into()?);
        Ok(NopInResponse {
            opcode,
            reserved1,
            total_ahs_length,
            lun,
            data_segment_length,
            initiator_task_tag,
            target_task_tag,
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            reserved2: [0u8; 8],
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

impl BasicHeaderSegment for NopInResponse {
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

impl FromBytes for NopInResponse {
    const HEADER_LEN: usize = NopInResponse::HEADER_LEN;

    fn from_bytes(buf: &[u8]) -> Result<Self> {
        Self::parse(buf)
    }
}
