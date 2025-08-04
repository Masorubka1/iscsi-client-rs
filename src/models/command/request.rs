use anyhow::{Result, bail};

use crate::{
    cfg::config::Config,
    models::{
        command::common::{ScsiCommandRequestFlags, TaskAttribute},
        common::{BasicHeaderSegment, Builder},
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

/// BHS for ScsiCommandRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct ScsiCommandRequest {
    pub opcode: BhsOpcode,                  // 0
    pub flags: ScsiCommandRequestFlags,     // 1
    reserved1: [u8; 2],                     // 2..4
    pub total_ahs_length: u8,               // 4
    pub data_segment_length: [u8; 3],       // 5..8
    pub lun: [u8; 8],                       // 8..16
    pub initiator_task_tag: u32,            // 16..20
    pub expected_data_transfer_length: u32, // 20..24
    pub cmd_sn: u32,                        // 24..28
    pub exp_stat_sn: u32,                   // 28..32
    pub scsi_descriptor_block: [u8; 16],    // 32..48
    // TODO: fix ash length
    pub header_digest: Option<u32>, // 44 + total_ahs..48 + total_ahs

    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl ScsiCommandRequest {
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;
    pub const HEADER_LEN: usize = 48;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; Self::HEADER_LEN] {
        let mut buf = [0u8; Self::HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2..4].copy_from_slice(&self.reserved1);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.expected_data_transfer_length.to_be_bytes());
        buf[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        buf[32..48].copy_from_slice(&self.scsi_descriptor_block);
        buf
    }

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            bail!("buffer too small");
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        let flags = ScsiCommandRequestFlags::try_from(buf[1])?;
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut lun = [0u8; 8];
        lun.clone_from_slice(&buf[8..16]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let expected_data_transfer_length = u32::from_be_bytes(buf[20..24].try_into()?);
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);
        let mut scsi_descriptor_block = [0u8; 16];
        scsi_descriptor_block.clone_from_slice(&buf[32..48]);
        // TODO: fix header_diggest
        // TODO: fix additional_header_segment copy
        // let header_digest = u32::from_be_bytes(buf[48..52].try_into()?);
        Ok(ScsiCommandRequest {
            opcode,
            flags,
            reserved1: [0u8; 2],
            total_ahs_length,
            lun,
            data_segment_length,
            initiator_task_tag,
            expected_data_transfer_length,
            cmd_sn,
            exp_stat_sn,
            scsi_descriptor_block,
            //additional_header_segment: [0u8; 4],
            header_digest: None,
            data: vec![],
            data_digest: None,
        })
    }

    /// Parsing PDU with DataSegment and Digest
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::HEADER_LEN {
            bail!(
                "Buffer {} too small for ScsiCommandRequest BHS {}",
                buf.len(),
                Self::HEADER_LEN
            );
        }

        let mut request = Self::from_bhs_bytes(&buf[..Self::HEADER_LEN])?;

        let ahs_len = request.ahs_length_bytes();
        let data_len = request.data_length_bytes();
        let offset = Self::HEADER_LEN + ahs_len;

        if buf.len() < offset + data_len {
            bail!(
                "ScsiCommandRequest Buffer {} too small for DataSegment {}",
                buf.len(),
                offset + data_len
            );
        }
        request.data = buf[offset..offset + data_len].to_vec();
        /*offset += data_len;

        request.header_digest = if buf.len() >= offset + 4 {
            info!("HEADER DIGEST");
            Some(u32::from_be_bytes(
                buf[offset..offset + 4]
                    .try_into()
                    .context("Failed to get offset from buf")?,
            ))
        } else {
            None
        };*/

        Ok(request)
    }

    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pad = (4 - (self.data.len() % 4)) % 4;
        let mut body = self.data.clone();
        body.extend(std::iter::repeat_n(0, pad));

        Ok((self.to_bhs_bytes().to_vec(), body))
    }
}

impl BasicHeaderSegment for ScsiCommandRequest {
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
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    fn total_length_bytes(&self) -> usize {
        Self::HEADER_LEN + self.ahs_length_bytes() + self.data_length_bytes()
    }
}

/// Builder Login Request
#[derive(Debug, Default, PartialEq)]
pub struct ScsiCommandRequestBuilder {
    pub header: ScsiCommandRequest,
    enable_header_digest: bool,
    enable_data_digest: bool,
}

impl ScsiCommandRequestBuilder {
    pub fn new() -> Self {
        ScsiCommandRequestBuilder {
            header: ScsiCommandRequest {
                opcode: BhsOpcode {
                    flags: IfFlags::empty(),
                    opcode: Opcode::ScsiCommandReq,
                },
                ..Default::default()
            },
            enable_data_digest: false,
            enable_header_digest: false,
        }
    }

    /// Set Ping bit (Ping = bit6)
    pub fn ping(mut self) -> Self {
        self.header.opcode.flags.insert(IfFlags::F);
        self
    }

    /// Set Finall bit
    pub fn finall(mut self) -> Self {
        self.header.flags.insert(ScsiCommandRequestFlags::FINAL);
        self
    }

    /// Set Read bit
    pub fn read(mut self) -> Self {
        self.header.flags.insert(ScsiCommandRequestFlags::READ);
        self
    }

    /// Set Read bit
    pub fn write(mut self) -> Self {
        self.header.flags.insert(ScsiCommandRequestFlags::WRITE);
        self
    }

    /// Set TaskTag bits
    pub fn task_attribute(mut self, task: TaskAttribute) -> Self {
        let raw_attr: u8 = task.into();
        let old = self.header.flags.bits();
        let cleared = old & !ScsiCommandRequestFlags::ATTR_MASK.bits();
        let new_bits = cleared | (raw_attr & ScsiCommandRequestFlags::ATTR_MASK.bits());
        self.header.flags = ScsiCommandRequestFlags::from_bits_truncate(new_bits);
        self
    }

    /// Enable HeaderDigest in NOP-Out.
    pub fn with_header_digest(mut self) -> Self {
        self.enable_header_digest = true;
        self
    }

    /// Enable DataDigest in NOP-Out.
    pub fn with_data_digest(mut self) -> Self {
        self.enable_data_digest = true;
        self
    }

    /// Sets the initiator task tag, a unique identifier for this command.
    pub fn initiator_task_tag(mut self, tag: u32) -> Self {
        self.header.initiator_task_tag = tag;
        self
    }

    /// Sets the expected_data_length, a length off all parts of data.
    pub fn expected_data_transfer_length(mut self, expected_data_length: u32) -> Self {
        self.header.expected_data_transfer_length = expected_data_length;
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

    /// Set the 8-byte Logical Unit Number (LUN) in the BHS header.
    pub fn lun(mut self, lun: &[u8; 8]) -> Self {
        self.header.lun.clone_from_slice(lun);
        self
    }

    /// Set the 16-byte SCSI Command Descriptor Block (CDB) in the BHS header.
    pub fn scsi_descriptor_block(mut self, scsi_descriptor_block: &[u8; 16]) -> Self {
        self.header
            .scsi_descriptor_block
            .clone_from_slice(scsi_descriptor_block);
        self
    }
}

impl Builder for ScsiCommandRequestBuilder {
    type Header = Vec<u8>;

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(mut self, more: Vec<u8>) -> Self {
        self.header.data.extend_from_slice(&more);
        let len = self.header.data.len() as u32;
        let be = len.to_be_bytes();
        self.header.data_segment_length = [be[1], be[2], be[3]];

        self
    }

    /// Build final PDU (BHS + DataSegment)
    fn build(self, cfg: &Config) -> Result<(Self::Header, Vec<u8>)> {
        let encoded = ScsiCommandRequest::encode(&self.header)?;

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
