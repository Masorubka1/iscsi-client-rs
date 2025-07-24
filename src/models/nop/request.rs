use anyhow::{Context, Result, bail};

use crate::models::{
    common::{BasicHeaderSegment, Builder},
    opcode::{BhsOpcode, IfFlags, Opcode},
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct NopOutRequest {
    pub opcode: BhsOpcode,            // 0
    reserved1: [u8; 3],               // 1..4
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub lun: [u8; 8],                 // 8..16
    pub initiator_task_tag: u32,      // 16..20
    pub target_task_tag: u32,         // 20..24
    pub cmd_sn: u32,                  // 24..28
    pub exp_stat_sn: u32,             // 28..32
    reserved2: [u8; 16],              // 32..48
    pub header_digest: u32,           // 48..52
}

impl NopOutRequest {
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;
    pub const HEADER_LEN: usize = 52;

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

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
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
        Ok(NopOutRequest {
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

impl BasicHeaderSegment for NopOutRequest {
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

/// Builder Login Request
pub struct NopOutRequestBuilder {
    pub header: NopOutRequest,
    pub data: Vec<u8>,
    want_header_digest: bool,
    want_data_digest: bool,
}

impl NopOutRequestBuilder {
    pub fn new(
        lun: [u8; 8],
        initiator_task_tag: u32,
        target_task_tag: u32,
        exp_stat_sn: u32,
    ) -> Self {
        let header = NopOutRequest {
            opcode: BhsOpcode {
                flags: IfFlags::empty(),
                opcode: Opcode::NopOut,
            },
            reserved1: {
                let mut tmp = [0; 3];
                tmp[0] = IfFlags::I.bits();
                tmp
            },
            total_ahs_length: 0,
            data_segment_length: [0; 3],
            lun,
            initiator_task_tag,
            target_task_tag,
            cmd_sn: 0,
            exp_stat_sn,
            reserved2: [0; 16],
            header_digest: 0,
        };
        NopOutRequestBuilder {
            header,
            data: Vec::new(),
            want_data_digest: false,
            want_header_digest: false,
        }
    }

    /// Set Ping bit (Ping = bit6)
    pub fn ping(mut self) -> Self {
        self.header.opcode.flags.insert(IfFlags::F);
        self
    }

    /// Enable HeaderDigest in NOP-Out.
    pub fn with_header_digest(mut self) -> Self {
        self.want_header_digest = true;
        self
    }

    /// Enable DataDigest in NOP-Out.
    pub fn with_data_digest(mut self) -> Self {
        self.want_data_digest = true;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag = tag;
        self
    }

    /// Sets the target task tag, a unique identifier for this command.
    pub fn target_task_tag(mut self, tag: u32) -> Self {
        self.header.target_task_tag = tag;
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
}

impl Builder for NopOutRequestBuilder {
    type Header = [u8; NopOutRequest::HEADER_LEN];

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(mut self, more: Vec<u8>) -> Self {
        self.data.extend_from_slice(&more);
        let len = self.data.len() as u32;
        let be = len.to_be_bytes();
        self.header.data_segment_length = [be[1], be[2], be[3]];

        self
    }

    /// Build finnal PDU (BHS + DataSegment)
    fn build(mut self) -> ([u8; NopOutRequest::HEADER_LEN], Vec<u8>) {
        let pad = (4 - (self.data.len() % 4)) % 4;
        self.data.extend(std::iter::repeat_n(0, pad));

        (self.header.to_bhs_bytes(), self.data)
    }
}
