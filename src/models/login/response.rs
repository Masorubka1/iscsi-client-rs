use anyhow::{Context, Result, anyhow};

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
    reserved2: [u8; 10],              // 38..48
}

impl LoginResponse {
    pub const DATA_DIGEST: u8 = 0x01;
    pub const HEADER_DIGEST: u8 = 0x02;
    pub const HEADER_LEN: usize = 48;

    /// Parsing only BHS LoginResponse (48 bytes)
    pub fn parse_bhs(buf: &[u8; Self::HEADER_LEN]) -> Result<Self> {
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
            reserved2: buf[38..48]
                .try_into()
                .context("failed to get reserved data")?,
        })
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)> {
        if buf.len() < Self::HEADER_LEN {
            return Err(anyhow!("Buffer too small for LoginResponse BHS"));
        }

        let mut bhs = [0u8; Self::HEADER_LEN];
        bhs.copy_from_slice(&buf[..Self::HEADER_LEN]);
        let header = Self::parse_bhs(&bhs)?;

        let ahs_len = header.ahs_length_bytes();
        let data_len = header.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            return Err(anyhow!("Buffer too small for DataSegment"));
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
    fn get_opcode(&self) -> BhsOpcode {
        self.opcode.clone()
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
}

impl FromBytes for LoginResponse {
    const HEADER_LEN: usize = LoginResponse::HEADER_LEN;

    fn peek_total_len(header: &[u8]) -> Result<usize> {
        if header.len() < Self::HEADER_LEN {
            return Err(anyhow!("to small header"));
        }

        let mut b = [0u8; 48];
        b.copy_from_slice(&header[..48]);
        let hdr = LoginResponse::parse_bhs(&b)?;

        let ahs_len = hdr.ahs_length_bytes();
        let data_len = hdr.data_length_bytes();

        Ok(Self::HEADER_LEN + ahs_len + data_len)
    }

    fn from_bytes(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)> {
        let (hdr, data, digest) = LoginResponse::parse(buf)?;
        Ok((hdr, data, digest))
    }
}
