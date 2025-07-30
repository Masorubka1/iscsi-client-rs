use std::{convert::TryFrom, ptr};

use thiserror::Error;

/// Mask out the low 6 bits for opcode
const OPCODE_MASK: u8 = 0x3F;
/// Top two bits are I (bit7) and F (bit6)
const FLAGS_MASK: u8 = 0xC0;

bitflags::bitflags! {
    /// I and F bits from the first byte of every BHS
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct IfFlags: u8 {
        /// NOP-Out “I” (Immediate/ping) bit
        const I      = 0b1000_0000;
        /// “Final”/Continuation bit (e.g. last chunk of text/login)
        const F      = 0b0100_0000;
    }
}

/// All defined iSCSI opcodes (RFC 3720 § 9.1).
#[repr(u8)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Opcode {
    #[default]
    NopOut = 0x00,
    ScsiCommandReq = 0x01,
    ScsiTaskMgmtReq = 0x02,
    LoginReq = 0x03,
    TextReq = 0x04,
    ScsiDataOut = 0x05,
    LogoutReq = 0x06,
    // 0x07–0x1F reserved
    ScsiTaskMgmtResp = 0x22,
    LoginResp = 0x23,
    TextResp = 0x24,
    ScsiDataIn = 0x25,
    LogoutResp = 0x26,
    // 0x27–0x3E reserved
    Reject = 0x3F,
    ScsiCommandResp = 0x21,
    NopIn = 0x20,
    // add other data-digest / header-digest opcodes as needed
}

#[derive(Debug, Error)]
#[error("invalid opcode: 0x{0:02x}")]
pub struct UnknownOpcode(pub u8);

#[derive(Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BhsOpcode {
    pub flags: IfFlags,
    pub opcode: Opcode,
}

impl TryFrom<u8> for BhsOpcode {
    type Error = UnknownOpcode;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        // we use here from_bits_truncate cause all bits covered
        let flags = IfFlags::from_bits_truncate(byte & FLAGS_MASK);
        let code = byte & OPCODE_MASK;
        let opcode = match code {
            0x00 => Opcode::NopOut,
            0x01 => Opcode::ScsiCommandReq,
            0x02 => Opcode::ScsiTaskMgmtReq,
            0x03 => Opcode::LoginReq,
            0x04 => Opcode::TextReq,
            0x05 => Opcode::ScsiDataOut,
            0x06 => Opcode::LogoutReq,
            0x20 => Opcode::NopIn,
            0x21 => Opcode::ScsiCommandResp,
            0x22 => Opcode::ScsiTaskMgmtResp,
            0x23 => Opcode::LoginResp,
            0x24 => Opcode::TextResp,
            0x25 => Opcode::ScsiDataIn,
            0x26 => Opcode::LogoutResp,
            0x3F => Opcode::Reject,
            other => return Err(UnknownOpcode(other)),
        };
        Ok(BhsOpcode { flags, opcode })
    }
}

impl From<&BhsOpcode> for u8 {
    fn from(b: &BhsOpcode) -> u8 {
        let f = b.flags.bits();

        let op_byte = unsafe {
            // &b.opcode is a *const Opcode, but repr(u8) means its first byte is the
            // discriminant. Cast that pointer to *const u8 and read it.
            ptr::read_unaligned(&b.opcode as *const Opcode as *const u8)
        };
        f | op_byte
    }
}
