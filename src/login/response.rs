use anyhow::{Result, anyhow};

use crate::{
    client::pdu_connection::FromBytes,
    login::{
        common::LoginFlags,
        status::{StatusClass, StatusDetail},
    },
};

/// Структура для Login Response PDU
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct LoginResponse {
    pub opcode: u8, // 0x23
    pub flags: LoginFlags,
    pub version_max: u8,
    pub version_active: u8,
    pub total_ahs_length: u8,
    pub data_segment_length: [u8; 3],
    pub isid: [u8; 6], // Initiator Session ID
    pub tsih: u16,     // Target Session ID Handle
    pub initiator_task_tag: u32,
    // 4 байта RESERVED
    reserved1: [u8; 4],
    pub stat_sn: u32,
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub status_class: StatusClass,
    pub status_detail: StatusDetail,
    // (38..48) байта RESERVED
    reserved2: [u8; 10],
    // далее DataSegment (login parameters) и Digest — парсим отдельно
}

impl LoginResponse {
    pub const DATA_DIGEST: u8 = 0x01;
    pub const HEADER_DIGEST: u8 = 0x02;
    pub const HEADER_LEN: usize = 48;

    /// Парсит только BHS Login Response (48 байт)
    pub fn parse_bhs(buf: &[u8; 48]) -> Result<Self> {
        // 1) flags
        let raw_flags = buf[1];
        let flags = LoginFlags::from_bits(raw_flags)
            .ok_or_else(|| anyhow!("invalid LoginFlags: {:#02x}", raw_flags))?;

        // 2) data-length etc.
        let mut data_segment_length = [0u8; 3];
        data_segment_length.copy_from_slice(&buf[5..8]);

        let mut isid = [0u8; 6];
        isid.copy_from_slice(&buf[8..14]);

        let tsih = u16::from_be_bytes([buf[14], buf[15]]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into().unwrap());

        let stat_sn = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        let exp_cmd_sn = u32::from_be_bytes(buf[28..32].try_into().unwrap());
        let max_cmd_sn = u32::from_be_bytes(buf[32..36].try_into().unwrap());

        // 3) status class & detail
        let raw_status_class = buf[36];
        let raw_status_detail = buf[37];
        let status_class = StatusClass::from(raw_status_class);
        let status_detail = StatusDetail::try_from((status_class, raw_status_detail))
            .map_err(|e| {
                anyhow!("invalid StatusDetail for class {:?}: {}", status_class, e)
            })?;

        Ok(LoginResponse {
            opcode: buf[0],
            flags,
            version_max: buf[2],
            version_active: buf[3],
            total_ahs_length: buf[4],
            data_segment_length,
            isid,
            tsih,
            initiator_task_tag,
            reserved1: buf[20..24].try_into().unwrap(),
            stat_sn,
            exp_cmd_sn,
            max_cmd_sn,
            status_class,
            status_detail,
            reserved2: buf[38..48].try_into().unwrap(),
        })
    }

    pub fn ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    pub fn data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    /// Полный парсинг PDU включая DataSegment и Digest
    pub fn parse(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<usize>)> {
        // Must have at least the 48‐byte BHS.
        if buf.len() < Self::HEADER_LEN {
            return Err(anyhow!("Buffer too small for LoginResponse BHS"));
        }

        // 1) Copy out the BHS and parse it
        let mut bhs = [0u8; Self::HEADER_LEN];
        bhs.copy_from_slice(&buf[..Self::HEADER_LEN]);
        let header = Self::parse_bhs(&bhs)?; // <-- now returns Result

        // 2) Compute offsets
        let ahs_len = header.ahs_length_bytes();
        let data_len = header.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        // 3) Extract DataSegment
        if buf.len() < offset + data_len {
            return Err(anyhow!("Buffer too small for DataSegment"));
        }
        let data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        // 4) Optionally extract a 4‐byte header digest
        let hd = if buf.len() >= offset + 4 {
            Some(usize::from_be_bytes(
                buf[offset..offset + 4].try_into().unwrap(),
            ))
        } else {
            None
        };

        Ok((header, data, hd))
    }
}

impl FromBytes for LoginResponse {
    type Response = (Self, Vec<u8>, Option<usize>);

    const HEADER_LEN: usize = LoginResponse::HEADER_LEN;

    fn peek_total_len(header: &[u8]) -> Result<usize> {
        if header.len() < Self::HEADER_LEN {
            return Err(anyhow!("to small header"));
        }

        let mut b = [0u8; 48];
        b.copy_from_slice(&header[..48]);
        let hdr = LoginResponse::parse_bhs(&b)?;

        let ahs_len = hdr.total_ahs_length as usize;
        let data_len = u32::from_be_bytes([
            0,
            hdr.data_segment_length[0],
            hdr.data_segment_length[1],
            hdr.data_segment_length[2],
        ]) as usize;

        Ok(Self::HEADER_LEN + ahs_len + data_len)
    }

    fn from_bytes(buf: &[u8]) -> Result<Self::Response> {
        let (hdr, data, digest) = LoginResponse::parse(buf)?;
        Ok((hdr, data, digest))
    }
}
