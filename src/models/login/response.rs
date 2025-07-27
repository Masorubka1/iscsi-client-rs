use anyhow::{Context, Result, anyhow, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::BasicHeaderSegment,
        login::{
            common::LoginFlags,
            status::{StatusClass, StatusDetail},
        },
        opcode::BhsOpcode,
    },
};

/// Header LoginResponse PDU
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct LoginResponse {
    pub opcode: BhsOpcode,            // 0
    pub flags: LoginFlags,            // 1
    pub version_max: u8,              // 2
    pub version_active: u8,           // 3
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub isid: [u8; 6],                // 8..14
    pub tsih: u16,                    // 14..16
    pub initiator_task_tag: u32,      // 16..20
    reserved1: [u8; 4],               // 20..24
    pub stat_sn: u32,                 // 24..28
    pub exp_cmd_sn: u32,              // 28..32
    pub max_cmd_sn: u32,              // 32..36
    pub status_class: StatusClass,    // 36
    pub status_detail: StatusDetail,  // 37
    reserved2: [u8; 14],              // 38..48
}

impl LoginResponse {
    pub const DATA_DIGEST: u8 = 0x01;
    pub const HEADER_DIGEST: u8 = 0x02;
    pub const HEADER_LEN: usize = 48;

    /// Parsing only BHS LoginResponse (48 bytes)
    pub fn from_bhs_bytes(buf: &[u8; Self::HEADER_LEN]) -> Result<Self> {
        let raw_flags = buf[1];
        let flags = LoginFlags::from_bits(raw_flags)
            .ok_or_else(|| anyhow!("invalid LoginFlags: {}", raw_flags))?;

        let mut data_segment_length = [0u8; 3];
        data_segment_length.copy_from_slice(&buf[5..8]);

        let mut isid = [0u8; 6];
        isid.copy_from_slice(&buf[8..14]);

        let status_class = StatusClass::from(buf[36]);
        let status_detail =
            StatusDetail::try_from((status_class, buf[37])).map_err(|e| {
                anyhow!("invalid StatusDetail for class {:?}: {}", status_class, e)
            })?;

        Ok(LoginResponse {
            opcode: buf[0].try_into()?,
            flags,
            version_max: buf[2],
            version_active: buf[3],
            total_ahs_length: buf[4],
            data_segment_length,
            isid,
            tsih: u16::from_be_bytes([buf[14], buf[15]]),
            initiator_task_tag: u32::from_be_bytes(
                buf[16..20]
                    .try_into()
                    .context("failed to get initiator_task_tag")?,
            ),
            reserved1: buf[20..24]
                .try_into()
                .context("failed to get reserved data")?,
            stat_sn: u32::from_be_bytes(
                buf[24..28].try_into().context("failed to get stat_sn")?,
            ),
            exp_cmd_sn: u32::from_be_bytes(
                buf[28..32].try_into().context("failed to get exp_cmd_sn")?,
            ),
            max_cmd_sn: u32::from_be_bytes(
                buf[32..36].try_into().context("failed to get max_cmd_sn")?,
            ),
            status_class,
            status_detail,
            reserved2: [0u8; 14],
        })
    }

    /// Serialize only the BHS (48 bytes) of this LoginResponse
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2] = self.version_max;
        buf[3] = self.version_active;
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..14].copy_from_slice(&self.isid);
        buf[14..16].copy_from_slice(&self.tsih.to_be_bytes());
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        // reserved1 (20..24)
        buf[20..24].copy_from_slice(&self.reserved1);
        buf[24..28].copy_from_slice(&self.stat_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36] = self.status_class.into();
        buf[37] = self.status_detail.clone().into();
        // reserved2 (38..48)
        buf
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)> {
        if buf.len() < Self::HEADER_LEN {
            bail!(
                "Buffer {} too small for LoginResponse BHS {}",
                buf.len(),
                Self::HEADER_LEN
            );
        }

        let mut bhs = [0u8; Self::HEADER_LEN];
        bhs.copy_from_slice(&buf[..Self::HEADER_LEN]);
        let header = Self::from_bhs_bytes(&bhs)?;

        let ahs_len = header.ahs_length_bytes();
        let data_len = header.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            bail!(
                "LoginResponse Buffer {} too small for DataSegment {}",
                buf.len(),
                offset + data_len
            );
        }
        let data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        let header_digest = if buf.len() >= offset + 4 {
            let h = u32::from_be_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .context("failed to parse header digest")?,
            );
            Some(h)
        } else {
            None
        };

        Ok((header, data, header_digest))
    }
}

impl BasicHeaderSegment for LoginResponse {
    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
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

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut new_buf = [0u8; LoginResponse::HEADER_LEN];
        new_buf.clone_from_slice(buf);
        Self::from_bhs_bytes(&new_buf)
    }
}

impl FromBytes for LoginResponse {
    const HEADER_LEN: usize = LoginResponse::HEADER_LEN;

    fn peek_total_len(buf: &[u8]) -> Result<usize> {
        if buf.len() < Self::HEADER_LEN {
            bail!(
                "Buffer {} too small for LoginResponse BHS {}",
                buf.len(),
                Self::HEADER_LEN
            );
        }

        let mut b = [0u8; Self::HEADER_LEN];
        b.copy_from_slice(&buf[..Self::HEADER_LEN]);
        let hdr = LoginResponse::from_bhs_bytes(&b)?;

        let ahs_len = hdr.ahs_length_bytes();
        let data_len = hdr.data_length_bytes();

        Ok(Self::HEADER_LEN + ahs_len + data_len)
    }

    fn from_bytes(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)> {
        let (hdr, data, digest) = LoginResponse::parse(buf)?;
        Ok((hdr, data, digest))
    }
}
