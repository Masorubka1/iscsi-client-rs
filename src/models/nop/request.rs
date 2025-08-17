use anyhow::{Result, bail};
use tracing::warn;

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

/// BHS for NopOutRequest PDU
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
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
}

impl NopOutRequest {
    pub const DEFAULT_TAG: u32 = 0xffffffff_u32;

    /// Serialize BHS in 48 bytes
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1..4].copy_from_slice(&self.reserved1);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_task_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.cmd_sn.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        // buf[32..48] -- reserved
        buf
    }

    pub fn from_bhs_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("buffer too small");
        }
        let opcode = BhsOpcode::try_from(buf[0])?;
        if opcode.opcode != Opcode::NopOut {
            bail!("NopOut invalid opcode: {:?}", opcode.opcode);
        }
        let reserved1 = buf[1..4].try_into()?;
        let total_ahs_length = buf[4];
        let data_segment_length = [buf[5], buf[6], buf[7]];
        let mut lun = [0u8; 8];
        lun.clone_from_slice(&buf[8..16]);
        let initiator_task_tag = u32::from_be_bytes(buf[16..20].try_into()?);
        let target_task_tag = u32::from_be_bytes(buf[20..24].try_into()?);
        let cmd_sn = u32::from_be_bytes(buf[24..28].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(buf[28..32].try_into()?);
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
        })
    }
}

/// Builder for an iSCSI **NOP-Out** PDU (opcode `NopOut`).
///
/// NOP-Out is a lightweight “ping/keep-alive” PDU used to verify liveness,
/// measure round-trip time, or provoke a NOP-In from the target. It carries
/// no SCSI semantics and **does not use F/C (Final/Continue) bits**.
///
/// This builder prepares the 48-byte BHS; if you want to attach an optional
/// data segment (rare for NOPs), wrap the header with `PDUWithData` and call
/// `append_data(...)`.
///
/// # What you can set
/// - **Immediate bit**: `immediate()` sets the *I* flag in byte 0.
/// - **Initiator/Target Task Tags**:
///   - `initiator_task_tag(..)` sets **ITT** (used to match the reply).
///   - `target_task_tag(..)` sets **TTT**:
///     - For a *solicited ping*, use `NopOutRequest::DEFAULT_TAG`
///       (`0xFFFF_FFFF`) to ask the target to generate a NOP-In.
///     - For a *response to a target’s NOP-In*, copy the TTT you received.
/// - **Sequencing**: `cmd_sn(..)` and `exp_stat_sn(..)` as usual for the
///   session.
/// - **LUN**: `lun(..)` accepts an 8-byte encoded LUN (often zero for NOPs).
/// - **Digests**: `with_header_digest()` / `with_data_digest()` opt into
///   including CRC32C digests when your connection logic honors negotiated
///   `HeaderDigest` / `DataDigest` settings.
///
/// # Typical patterns
/// - **Initiator ping** (solicit a NOP-In):
///   - Set `TTT = 0xFFFF_FFFF`, pick a fresh ITT, send NOP-Out, wait for NOP-In
///     with the same ITT.
/// - **Reply to target’s NOP-In**:
///   - Echo back the **TTT** you received in NOP-In, send NOP-Out.
#[derive(Debug, Default)]
pub struct NopOutRequestBuilder {
    pub header: NopOutRequest,
    want_header_digest: bool,
    want_data_digest: bool,
}

impl NopOutRequestBuilder {
    pub fn new() -> Self {
        NopOutRequestBuilder {
            header: NopOutRequest {
                opcode: BhsOpcode {
                    flags: IfFlags::empty(),
                    opcode: Opcode::NopOut,
                },
                reserved1: {
                    let mut tmp = [0; 3];
                    tmp[0] = 0b1000_0000;
                    tmp
                },
                ..Default::default()
            },
            want_data_digest: false,
            want_header_digest: false,
        }
    }

    /// Set Immediate bit (Immediate = bit6)
    pub fn immediate(mut self) -> Self {
        self.header.opcode.flags.insert(IfFlags::I);
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

    /// Set the 8-byte Logical Unit Number (LUN) in the BHS header.
    pub fn lun(mut self, lun: &[u8; 8]) -> Self {
        self.header.lun.clone_from_slice(lun);
        self
    }
}

impl SendingData for NopOutRequest {
    fn get_final_bit(&self) -> bool {
        true
    }

    fn set_final_bit(&mut self) {
        warn!("NopOut Request cannot be marked as Final");
    }

    fn get_continue_bit(&self) -> bool {
        false
    }

    fn set_continue_bit(&mut self) {
        warn!("NopOut Request cannot be marked as Contine");
    }
}

impl FromBytes for NopOutRequest {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for NopOutRequest {
    #[inline]
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    #[inline]
    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    #[inline]
    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    #[inline]
    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    #[inline]
    fn set_ahs_length_bytes(&mut self, len: u8) {
        self.total_ahs_length = len >> 2;
    }

    #[inline]
    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    #[inline]
    fn set_data_length_bytes(&mut self, len: u32) {
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}
