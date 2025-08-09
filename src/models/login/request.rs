use anyhow::{Result, anyhow, bail};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
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
    reserved2: [u8; 16],              // 32..48
}

impl LoginRequest {
    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
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
        if buf.len() < HEADER_LEN {
            return Err(anyhow!("buffer too small"));
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        if opcode.opcode != Opcode::LoginReq {
            bail!("LoginReq invalid opcode: {:?}", opcode.opcode);
        }

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
        })
    }
}

/// Builder for an iSCSI **Login Request** PDU (opcode `LoginReq` / BHS byte0 =
/// I|0x03).
///
/// This helper constructs the 48-byte Login BHS and lets you set the
/// connection stage flags, version fields, and sequence counters. The actual
/// login key–value pairs (e.g. `AuthMethod=…\0`, `HeaderDigest=…\0`, …) go
/// into the **Data Segment** and should be appended separately via
/// `PDUWithData::append_data(...)`.
///
/// # What it sets
/// - **Opcode/Immediate**: `new()` creates a LoginReq with the **I**
///   (Immediate) bit set.
/// - **Transit/Stages**:
///   - `transit()` sets the **T** bit (request a stage transition).
///   - `csg(Stage)` selects the **current stage** (CSG bits).
///   - `nsg(Stage)` selects the **next stage** (NSG bits).
/// - **Versions**: `versions(max, min)` set *VersionMax*/*VersionMin*.
/// - **Session/Conn IDs**: `initiator_task_tag(…)`, `connection_id(…)`,
///   `isid(…)`.
/// - **Sequencing**: `cmd_sn(…)`, `exp_stat_sn(…)`.
///
/// # Typical flow
/// 1. **Security → Operational** with authentication keys in Data Segment
/// 2. (Optionally continue within Security for CHAP exchange)
/// 3. **Operational → FullFeature** to finish login
#[derive(Debug)]
pub struct LoginRequestBuilder {
    pub header: LoginRequest,
}

impl LoginRequestBuilder {
    pub fn new(isid: [u8; 6], tsih: u16) -> Self {
        LoginRequestBuilder {
            header: LoginRequest {
                opcode: BhsOpcode {
                    flags: IfFlags::I,
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

impl SendingData for LoginRequest {
    fn get_final_bit(&self) -> bool {
        !self.flags.contains(LoginFlags::CONTINUE)
    }

    fn set_final_bit(&mut self) {
        self.flags.remove(LoginFlags::CONTINUE);
    }

    fn get_continue_bit(&self) -> bool {
        self.flags.contains(LoginFlags::CONTINUE)
    }

    fn set_continue_bit(&mut self) {
        self.flags.insert(LoginFlags::CONTINUE);
    }
}

impl FromBytes for LoginRequest {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for LoginRequest {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    fn set_data_length_bytes(&mut self, len: u32) {
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}
