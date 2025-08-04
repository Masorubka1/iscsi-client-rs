use anyhow::{Context, Result, anyhow, bail};
use tracing::info;

use crate::{
    cfg::config::Config,
    models::{
        common::{BasicHeaderSegment, Builder},
        login::common::{LoginFlags, Stage},
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

/// BHS form LoginRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct LoginRequest {
    pub opcode: BhsOpcode,            // 0
    pub flags: LoginFlags,            // 1
    pub version_max: u8,              // 2
    pub version_min: u8,              // 3
    pub total_ahs_length: u8,         // 4
    pub data_segment_length: [u8; 3], // 5..8
    pub isid: [u8; 6],                // 8..14
    pub tsih: u16,                    // 14..16
    pub initiator_task_tag: u32,      // 16..20
    pub cid: u16,                     // 20..22
    reserved1: [u8; 2],               // 22..24
    pub cmd_sn: u32,                  // 24..28
    pub exp_stat_sn: u32,             // 28..32
    reserved2: [u8; 16],              // 32..44
    pub header_digest: Option<u32>,

    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl LoginRequest {
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = (&self.opcode).into();
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

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            return Err(anyhow!("buffer too small"));
        }
        let opcode = buf[0].try_into()?;
        let flags = LoginFlags::try_from(buf[1])?;
        let version_max = buf[2];
        let version_min = buf[3];
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut isid = [0u8; 6];
        isid.copy_from_slice(&buf[8..14]);
        let tsih = u16::from_be_bytes([buf[14], buf[15]]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let cid = u16::from_be_bytes(buf[20..22].try_into()?);
        // buf[22..24] -- reserved
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        // buf[32..48] -- reserved
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
            reserved1: [0u8; 2],
            cmd_sn,
            exp_stat_sn,
            reserved2: [0u8; 16],
            header_digest: None,
            data: vec![],
            data_digest: None,
        })
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            bail!(
                "Buffer {} too small for LoginRequest BHS {}",
                buf.len(),
                Self::HEADER_LEN
            );
        }

        let mut request = Self::from_bhs_bytes(&buf[..Self::HEADER_LEN])?;

        let ahs_len = request.ahs_length_bytes();
        let data_len = request.data_length_bytes();
        let mut offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            bail!(
                "LoginRequest Buffer {} too small for DataSegment {}",
                buf.len(),
                offset + data_len
            );
        }
        request.data = buf[offset..offset + data_len].to_vec();
        offset += data_len;

        request.header_digest = if buf.len() >= offset + 4 {
            info!("HEADER DIGEST");
            Some(u32::from_be_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .context("Failed to get offset from buf")?,
            ))
        } else {
            None
        };

        Ok(request)
    }

    pub fn encode(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pad = (4 - (self.data.len() % 4)) % 4;
        self.data.extend(std::iter::repeat_n(0, pad));

        let len = self.data.len() as u32;
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];

        Ok((self.to_bhs_bytes().to_vec(), self.data.clone()))
    }
}

impl BasicHeaderSegment for LoginRequest {
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

/// Builder Login Request
#[derive(Debug)]
pub struct LoginRequestBuilder {
    pub header: LoginRequest,
}

impl LoginRequestBuilder {
    pub fn new(isid: [u8; 6], tsih: u16) -> Self {
        LoginRequestBuilder {
            header: LoginRequest {
                opcode: BhsOpcode {
                    flags: IfFlags::F,
                    opcode: Opcode::LoginReq,
                },
                isid,
                tsih,
                ..Default::default()
            },
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
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
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

    pub fn isid(mut self, isid: &[u8; 8]) -> Self {
        self.header.isid.clone_from_slice(isid);
        self
    }
}

impl Builder for LoginRequestBuilder {
    type Header = Vec<u8>;

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(mut self, more: Vec<u8>) -> Self {
        self.header.data.extend_from_slice(&more);
        let len = self.header.data.len() as u32;
        let be = len.to_be_bytes();
        self.header.data_segment_length = [be[1], be[2], be[3]];

        self
    }

    /// Build finnal PDU (BHS + DataSegment)
    fn build(mut self, cfg: &Config) -> Result<(Self::Header, Vec<u8>)> {
        let encoded = LoginRequest::encode(&mut self.header)?;

        if (cfg.login.negotiation.max_recv_data_segment_length as usize) < encoded.1.len()
        {
            bail!(
                "ScsiCommandRequest data size: {} reached out of limit {}",
                encoded.1.len(),
                cfg.login.negotiation.max_recv_data_segment_length
            );
        }

        Ok(encoded)
    }
}
