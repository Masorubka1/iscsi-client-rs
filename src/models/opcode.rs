//! Helpers for encoding / decoding the very first byte of every iSCSI
//! **Basic-Header-Segment** (BHS).
//!
//! The byte layout is defined by RFC 7143 § 5.3:
//!
//! ```text
//!  7   6   5   4   3   2   1   0      bit position
//! +---+---+---------------------------+
//! | I | F |        OPCODE (6 bits)    |  ← first BHS octet
//! +---+---+---------------------------+
//! ```
//!
//! * **I** – *Immediate* flag.  When set, the PDU is processed by the target
//!   before any queued commands.
//! * **F** – *Final* flag.  Present on some PDUs but **not** interpreted
//!   uniformly across all op-codes; therefore this helper only exposes the *I*
//!   bit.  (See individual PDU structs for their own F/C logic.)
//! * **OPCODE** – 6-bit operation code identifying the PDU type.
//!
//! The utilities below allow you to
//!
//! * split the raw byte into a pair `(IfFlags, Opcode)` (`TryFrom<u8>`)
//! * merge a pair back into the raw byte (`From<&BhsOpcode> for u8`).

use std::{convert::TryFrom, ptr};

use thiserror::Error;

/// Mask that selects the lower 6 bits (**OPCODE**) from the first BHS byte.
const OPCODE_MASK: u8 = 0x3F;
/// Mask that selects the upper 2 bits (**I/F**) from the first BHS byte.
const FLAGS_MASK: u8 = 0b1100_0000;

bitflags::bitflags! {
    /// Bit-flags occupying the top two bits of the first BHS byte.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct IfFlags: u8 {
        /// **I** – *Immediate / Ping* flag (bit 7).
        /// The flag is meaningful for *NOP-Out* PDUs and any PDU that a
        /// SCSI initiator wants processed ahead of the normal command
        /// queue.
        const I = 0b0100_0000;
        //
        // NOTE: We purposely do **not** expose the F-bit here because its
        // semantics differ between PDU types.  Each concrete BHS struct
        // encodes its own notion of *Final* / *Continue*.
    }
}

/// All op-codes defined by RFC 3720 & RFC 7143 (§ 9.1).
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
    /* 0x07–0x1F reserved */
    NopIn = 0x20,
    ScsiCommandResp = 0x21,
    ScsiTaskMgmtResp = 0x22,
    LoginResp = 0x23,
    TextResp = 0x24,
    ScsiDataIn = 0x25,
    LogoutResp = 0x26,
    /* 0x27–0x3E reserved */
    Reject = 0x3F,
}

/// Returned when the lower six bits contain an undefined op-code.
#[derive(Debug, Error)]
#[error("invalid opcode: 0x{0:02x}")]
pub struct UnknownOpcode(pub u8);

/// Typed representation of the very first BHS byte.
///
/// * `flags`  – high-order **I/F** bits.
/// * `opcode` – 6-bit op-code.
#[derive(Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BhsOpcode {
    pub flags: IfFlags,
    pub opcode: Opcode,
}

impl TryFrom<u8> for BhsOpcode {
    type Error = UnknownOpcode;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        // Extract the I/F bits and truncate unknown ones.
        let flags = IfFlags::from_bits_truncate(byte & FLAGS_MASK);
        // Extract the 6-bit opcode.
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
        Ok(Self { flags, opcode })
    }
}

impl From<&BhsOpcode> for u8 {
    fn from(b: &BhsOpcode) -> u8 {
        let flag_bits = b.flags.bits();

        // Because `Opcode` is `#[repr(u8)]`, the first byte of the enum
        // value is its numeric discriminant. We use `read_unaligned`
        // instead of a plain deref to avoid alignment pitfalls in a
        // portable way.
        let opcode_byte =
            unsafe { ptr::read_unaligned(&b.opcode as *const Opcode as *const u8) };
        flag_bits | opcode_byte
    }
}
