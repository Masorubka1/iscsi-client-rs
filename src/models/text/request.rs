use anyhow::{Context, Result, bail};

use crate::models::opcode::{BhsOpcode, IfFlags};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct TextRequest {
    pub opcode: BhsOpcode, // always 0x04(Request) && 0x24(Response) by RFC
    reserved1: [u8; 3],
    pub total_ahs_length: u8,
    pub data_segment_length: [u8; 3],
    pub lun: [u8; 8],
    pub initiator_task_tag: u32, // tag or 0xffffffff
    pub target_task_tag: u32,    // tag or 0xffffffff
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    reserved2: [u8; 16],
    pub header_digest: u32,
}

impl TextRequest {
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = self.opcode.clone().into();
        // finnal bit
        buf[1..4].copy_from_slice(&self.reserved1);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_task_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        // buf[32..44] -- reserved
        buf[44..48].copy_from_slice(&self.header_digest.to_be_bytes());
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
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        // buf[32..44] -- reserved
        let header_digest = u32::from_be_bytes(buf[44..48].try_into()?);
        Ok(TextRequest {
            opcode,
            reserved1,
            total_ahs_length,
            lun,
            data_segment_length,
            initiator_task_tag,
            target_task_tag,
            cmd_sn,
            exp_stat_sn,
            reserved2: [0u8; 16],
            header_digest,
        })
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)> {
        if buf.len() < Self::HEADER_LEN {
            bail!("Buffer too small for LoginResponse BHS");
        }

        let mut bhs = [0u8; Self::HEADER_LEN];
        bhs.copy_from_slice(&buf[..Self::HEADER_LEN]);
        let header = Self::from_bhs_bytes(&bhs)?;

        let ahs_len = header.ahs_length_bytes();
        let data_len = header.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            bail!("Buffer too small for DataSegment");
        }
        let data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        let hd = if buf.len() >= offset + 4 {
            Some(u32::from_be_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .context("Failed to get offset from buf")?,
            ))
        } else {
            None
        };

        Ok((header, data, hd))
    }
}
