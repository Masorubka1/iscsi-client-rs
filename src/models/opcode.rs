// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! Helpers for encoding / decoding the very first byte of every iSCSI
//! **Basic-Header-Segment** (BHS).
//!
//! The byte layout is defined by RFC 7143 § 5.3:
//!
//! ```text
//!  7   6   5   4   3   2   1   0      bit position
//! +---+---+---------------------------+
//! | . | I |        OPCODE (6 bits)    |  ← first BHS octet
//! +---+---+---------------------------+
//! ```
//!
//! * **I** – *Immediate* flag.  When set, the PDU is processed by the target
//!   before any queued commands.
//! * **OPCODE** – 6-bit operation code identifying the PDU type.
//!
//! The utilities below allow you to
//!
//! * split the raw byte into a pair `(IfFlags, Opcode)` (`TryFrom<u8>`)
//! * merge a pair back into the raw byte (`From<&BhsOpcode> for u8`).

use core::fmt;
use std::convert::TryFrom;

use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Mask that selects the lower 6 bits (**OPCODE**) from the first BHS byte.
const OPCODE_MASK: u8 = 0b0011_1111;
/// Mask that selects the upper 1 bits (**I**) from the first BHS byte.
const I_MASK: u8 = 0b0100_0000;

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
    ReadyToTransfer = 0x31,
    /* 0x27–0x3E reserved */
    Reject = 0x3F,
}

impl Opcode {
    #[inline]
    pub fn from_u6(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => Self::NopOut,
            0x01 => Self::ScsiCommandReq,
            0x02 => Self::ScsiTaskMgmtReq,
            0x03 => Self::LoginReq,
            0x04 => Self::TextReq,
            0x05 => Self::ScsiDataOut,
            0x06 => Self::LogoutReq,
            0x20 => Self::NopIn,
            0x21 => Self::ScsiCommandResp,
            0x22 => Self::ScsiTaskMgmtResp,
            0x23 => Self::LoginResp,
            0x24 => Self::TextResp,
            0x25 => Self::ScsiDataIn,
            0x26 => Self::LogoutResp,
            0x31 => Self::ReadyToTransfer,
            0x3F => Self::Reject,
            _ => return None,
        })
    }
}

/// Returned when the lower six bits contain an undefined op-code.
#[derive(Debug, Error)]
#[error("invalid opcode: 0x{0:02x}")]
pub struct UnknownOpcode(pub u8);

/// Typed representation of the very first BHS byte.
///
/// * `flags`  – high-order **I** bit.
/// * `opcode` – 6-bit op-code.
#[derive(Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BhsOpcode {
    pub flags: bool,
    pub opcode: Opcode,
}

impl TryFrom<u8> for BhsOpcode {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        let flags = (byte & I_MASK) != 0;
        let code = byte & OPCODE_MASK;
        let opcode = Opcode::from_u6(code).ok_or(UnknownOpcode(code))?;
        Ok(Self { flags, opcode })
    }
}

impl From<&BhsOpcode> for u8 {
    fn from(b: &BhsOpcode) -> u8 {
        let mut raw = b.opcode.clone() as u8;
        if b.flags {
            raw |= I_MASK;
        }
        raw
    }
}

/// Wire-safe, zero-copy first BHS octet.
/// Transparent over `u8`, so it can live inside a zerocopy BHS struct.
#[repr(transparent)]
#[derive(Clone, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawBhsOpcode(u8);

impl RawBhsOpcode {
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    // Flags
    #[inline]
    pub const fn i(&self) -> bool {
        (self.0 & I_MASK) != 0
    }

    #[inline]
    pub fn set_i(&mut self) {
        self.0 |= I_MASK
    }

    // Opcode (lower 6 bits)
    #[inline]
    pub const fn opcode_raw(&self) -> u8 {
        self.0 & OPCODE_MASK
    }

    #[inline]
    pub fn set_opcode_raw(&mut self, v: u8) {
        self.0 = (self.0 & !OPCODE_MASK) | (v & OPCODE_MASK)
    }

    #[inline]
    pub fn opcode_known(&self) -> Option<Opcode> {
        Opcode::from_u6(self.opcode_raw())
    }

    #[inline]
    pub fn set_opcode_known(&mut self, k: Opcode) {
        self.set_opcode_raw(k as u8);
    }
}

impl fmt::Debug for RawBhsOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match BhsOpcode::try_from(self.0) {
            Ok(bhs) => {
                let mut tmp = f.debug_struct("RawBhsOpcode");
                if bhs.flags {
                    tmp.field("I", &bhs.flags);
                }
                tmp.field("opcode", &bhs.opcode).finish()
            },
            Err(_) => {
                let mut tmp = f.debug_struct("RawBhsOpcode");
                if self.i() {
                    tmp.field("I", &self.i());
                }
                tmp.field("opcode_raw", &format_args!("0x{:02X}", self.opcode_raw()))
                    .finish()
            },
        }
    }
}
