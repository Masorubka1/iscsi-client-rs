use anyhow::{Context, Result, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::BasicHeaderSegment, opcode::BhsOpcode,
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
    pub header_digest: Option<u32>,   // 48..52

    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl RejectPdu {
    pub const HEADER_LEN: usize = 44;

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
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
        //let mut reserved5 = [0u8; 4 * 2];
        //reserved5.copy_from_slice(&buf[40..48]);
        // TODO: fix header_diggest
        //let header_diggest = u32::from_be_bytes(buf[48..52].try_into()?);

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
            header_digest: None,
            data: vec![],
            data_digest: None,
        })
    }

    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
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
        //buf[40..44].copy_from_slice(&self.reserved5);
        // TODO: fix header_diggest
        // buf[48..52].copy_from_slice(&self.header_diggest.to_be_bytes());
        buf
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

impl BasicHeaderSegment for RejectPdu {
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

impl FromBytes for RejectPdu {
    const HEADER_LEN: usize = Self::HEADER_LEN;

    fn from_bytes(buf: &[u8]) -> Result<Self> {
        Self::parse(buf)
    }
}
