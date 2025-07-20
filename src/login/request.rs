use anyhow::{Context, Result, anyhow};

use crate::{
    client::pdu_connection::ToBytes,
    login::common::{LoginFlags, Stage},
};

/// BHS form LoginRequest PDU
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct LoginRequest {
    pub opcode: u8, // always 0x03 by RFC
    pub flags: LoginFlags,
    pub version_max: u8,
    pub version_min: u8,
    pub total_ahs_length: u8,
    pub data_segment_length: [u8; 3],
    pub isid: [u8; 6],
    pub tsih: u16,
    pub initiator_task_tag: u32,
    pub cid: u16,
    // 2 bytes RESERVED
    reserved1: [u8; 2],
    pub cmd_sn: u32,
    pub exp_stat_sn: u32,
    // rest (bytes 32..48) RESERVED
    reserved2: [u8; 16],
}

impl LoginRequest {
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = self.opcode;
        buf[1] = self.flags.bits();
        buf[2] = self.version_max;
        buf[3] = self.version_min;
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..14].copy_from_slice(&self.isid);
        buf[14..16].copy_from_slice(&self.tsih.to_be_bytes());
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..22].copy_from_slice(&self.cid.to_be_bytes());
        // buf[22..24] -- reserved
        buf[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        // buf[32..48] -- reserved
        buf
    }

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self, anyhow::Error> {
        if buf.len() < Self::HEADER_LEN {
            return Err(anyhow!("buffer too small"));
        }
        let opcode = buf[0];
        let flags = LoginFlags::from_bits(buf[1])
            .context(format!("failed to set all bits {}", buf[1]))?;
        let version_max = buf[2];
        let version_min = buf[3];
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut isid = [0u8; 6];
        isid.copy_from_slice(&buf[8..14]);
        let tsih = u16::from_be_bytes([buf[14], buf[15]]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let cid = u16::from_be_bytes(buf[20..22].try_into()?);
        let mut reserved1 = [0u8; 2];
        reserved1.copy_from_slice(&buf[22..24]);
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let mut reserved2 = [0u8; 16];
        reserved2.copy_from_slice(&buf[32..48]);
        Ok(LoginRequest {
            opcode,
            flags,
            version_max,
            version_min,
            total_ahs_length,
            data_segment_length,
            isid,
            tsih,
            initiator_task_tag,
            cid,
            reserved1,
            cmd_sn,
            exp_stat_sn,
            reserved2,
        })
    }
}

/// Builder Login Request
pub struct LoginRequestBuilder {
    pub header: LoginRequest,
    pub data: Vec<u8>,
}

impl LoginRequestBuilder {
    pub fn new(isid: [u8; 6], tsih: u16) -> Self {
        let header = LoginRequest {
            opcode: 0x43,
            flags: LoginFlags::empty(),
            version_max: 0x00,
            version_min: 0x00,
            total_ahs_length: 0,
            data_segment_length: [0; 3],
            isid,
            tsih,
            initiator_task_tag: 0,
            cid: 0,
            cmd_sn: 0,
            exp_stat_sn: 0,
            reserved1: [0; 2],
            reserved2: [0; 16],
        };
        LoginRequestBuilder {
            header,
            data: Vec::new(),
        }
    }

    /// Set Transit (T = bit7)
    pub fn transit(mut self) -> Self {
        self.header.flags.insert(LoginFlags::TRANSIT);
        self
    }

    /// Set Continue (C = bit6)
    pub fn cont(mut self) -> Self {
        self.header.flags.insert(LoginFlags::CONTINUE);
        self
    }

    /// Set CSG (connection-stage: bits 3–4)
    pub fn csg(mut self, stage: Stage) -> Self {
        let bits = (stage as u8 & 0b11) << 2;
        self.header.flags.remove(LoginFlags::CSG_MASK);
        self.header
            .flags
            .insert(LoginFlags::from_bits_truncate(bits));
        self
    }

    /// Set NSG (next-stage: bits 0–1)
    pub fn nsg(mut self, stage: Stage) -> Self {
        let bits = stage as u8 & 0b11;
        self.header.flags.remove(LoginFlags::NSG_MASK);
        self.header
            .flags
            .insert(LoginFlags::from_bits_truncate(bits));
        self
    }

    /// Minimal and maximum version of protocol
    pub fn versions(mut self, max: u8, min: u8) -> Self {
        self.header.version_max = max;
        self.header.version_min = min;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag = tag;
        self
    }

    /// Sets the connection ID (CID) for multiplexing sessions.
    pub fn connection_id(mut self, cid: u16) -> Self {
        self.header.cid = cid;
        self
    }

    /// Sets the command sequence number (CmdSN) for this request.
    pub fn cmd_sn(mut self, sn: u32) -> Self {
        self.header.cmd_sn = sn;
        self
    }

    /// Sets the expected status sequence number (ExpStatSN) from the target.
    pub fn exp_stat_sn(mut self, sn: u32) -> Self {
        self.header.exp_stat_sn = sn;
        self
    }

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(mut self, more: Vec<u8>) -> Self {
        self.data.extend_from_slice(&more);
        let len = self.data.len() as u32;
        let be = len.to_be_bytes();
        self.header.data_segment_length = [be[1], be[2], be[3]];

        self
    }

    /// Adds a null-terminated ASCII key=value string to the Data Segment.
    pub fn with_login_parameters(self, kv: &str) -> Self {
        self.append_data(kv.as_bytes().to_vec())
    }

    /// Adds arbitrary binary data to the Data Segment.
    pub fn with_data(self, data: Vec<u8>) -> Self {
        self.append_data(data)
    }

    /// Build finnal PDU (BHS + DataSegment)
    fn build(mut self) -> ([u8; 48], Vec<u8>) {
        let pad = (4 - (self.data.len() % 4)) % 4;
        self.data.extend(std::iter::repeat_n(0, pad));

        (self.header.to_bhs_bytes(), self.data)
    }
}

impl ToBytes<48> for LoginRequestBuilder {
    fn to_bytes(self) -> ([u8; 48], Vec<u8>) {
        self.build()
    }
}
