//! This module defines common structures and flags for iSCSI Data-In and Data-Out PDUs.
//! It includes flag definitions and zero-copy wrappers for efficient PDU handling.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use anyhow::{Result, bail};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

bitflags::bitflags! {
    #[derive(Default, Debug, PartialEq)]
    /// Flags for iSCSI SCSI Data-Out PDU
    ///
    /// Contains control flags for Data-Out PDUs that carry SCSI write data
    /// from initiator to target.
    pub struct DataOutFlags: u8 {
        /// Final bit (F) - indicates this is the last Data-Out PDU for the command
        const FINAL = 0b1000_0000;
    }
}

impl TryFrom<u8> for DataOutFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        DataOutFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#08b}", value))
    }
}

/// Wire view for **Data-OUT flags** (byte 1 of the PDU).
///
/// Transparent wrapper over a single `u8` with zerocopy semantics.
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawDataOutFlags(u8);

impl RawDataOutFlags {
    /// Bitmask for the Final flag.
    pub const FINAL: u8 = 0b1000_0000;

    /// Returns the raw 8-bit value of the flags.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    /// Creates a new `RawDataOutFlags` from a raw 8-bit value.
    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    /// Checks if the Final (F) bit is set.
    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    /// Sets or clears the Final (F) bit.
    #[inline]
    pub fn set_fin(&mut self, on: bool) {
        if on {
            self.0 |= Self::FINAL;
        } else {
            self.0 &= !Self::FINAL;
        }
    }
}

/* Optional: interop with the bitflags type */

impl From<DataOutFlags> for RawDataOutFlags {
    #[inline]
    fn from(f: DataOutFlags) -> Self {
        Self(f.bits())
    }
}

impl TryFrom<RawDataOutFlags> for DataOutFlags {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(r: RawDataOutFlags) -> Result<Self> {
        DataOutFlags::from_bits(r.raw())
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#010b}", r.raw()))
    }
}

bitflags::bitflags! {
    #[derive(Default, Debug, PartialEq)]
    /// Flags for iSCSI SCSI Data-In PDU
    ///
    /// Contains control flags for Data-In PDUs that carry SCSI read data
    /// from target to initiator, including status and residual information.
    pub struct DataInFlags: u8 {
        /// Final bit (F) - indicates this is the last Data-In PDU for the command
        const FINAL = 1 << 7;
        /// Acknowledge bit (A) - requests DataACK SNACK for error recovery (ERL>0)
        const A = 1 << 6;
        // bits 5..3 reserved (0)
        /// Residual Overflow bit (O) - valid only when S=1
        const O = 1 << 2;
        /// Residual Underflow bit (U) - valid only when S=1
        const U = 1 << 1;
        /// Status present bit (S) - when set, F must also be set
        const S = 1 << 0;
    }
}

impl TryFrom<u8> for DataInFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let tmp = DataInFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#08b}", value))?;

        if tmp.contains(DataInFlags::U) && tmp.contains(DataInFlags::O) {
            bail!("Protocol error cause U && O both presented")
        }

        Ok(tmp)
    }
}

/// Wire format representation of Data-In PDU flags
///
/// Zero-copy wrapper around the flags byte in Data-In PDU header.
/// Provides direct access to the raw byte value for serialization.
#[repr(transparent)]
#[derive(Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawDataInFlags(u8);

impl RawDataInFlags {
    /// Bitmask for the Acknowledge (A) flag.
    pub const A: u8 = 1 << 6;
    /// Bitmask for the Final (F) flag.
    pub const FINAL: u8 = 1 << 7;
    /// Bitmask for the Residual Overflow (O) flag.
    pub const O: u8 = 1 << 2;
    const RESERVED_MASK: u8 = 0b0011_1000;
    /// Bitmask for the Status Present (S) flag.
    pub const S: u8 = 1 << 0;
    /// Bitmask for the Residual Underflow (U) flag.
    pub const U: u8 = 1 << 1;

    /// Returns the raw 8-bit value of the flags.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    /// Creates a new `RawDataInFlags` from a raw 8-bit value.
    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    /// Checks if the Final (F) bit is set.
    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    /// Checks if the Acknowledge (A) bit is set.
    #[inline]
    pub fn ack(&self) -> bool {
        self.0 & Self::A != 0
    }

    /// Checks if the Residual Overflow (O) bit is set.
    #[inline]
    pub fn o(&self) -> bool {
        self.0 & Self::O != 0
    }

    /// Checks if the Residual Underflow (U) bit is set.
    #[inline]
    pub fn u(&self) -> bool {
        self.0 & Self::U != 0
    }

    /// Checks if the Status Present (S) bit is set.
    #[inline]
    pub fn s(&self) -> bool {
        self.0 & Self::S != 0
    }

    /// Sets or clears the Final (F) bit.
    #[inline]
    pub fn set_fin(&mut self, on: bool) {
        Self::set_bit(&mut self.0, Self::FINAL, on)
    }

    /// Sets or clears the Acknowledge (A) bit.
    #[inline]
    pub fn set_ack(&mut self, on: bool) {
        Self::set_bit(&mut self.0, Self::A, on)
    }

    /// Sets or clears the Residual Overflow (O) bit.
    #[inline]
    pub fn set_o(&mut self, on: bool) {
        Self::set_pair(&mut self.0, Self::O, Self::U, on)
    }

    /// Sets or clears the Residual Underflow (U) bit.
    #[inline]
    pub fn set_u(&mut self, on: bool) {
        Self::set_pair(&mut self.0, Self::U, Self::O, on)
    }

    /// Sets or clears the Status Present (S) bit.
    #[inline]
    pub fn set_s(&mut self, on: bool) {
        Self::set_bit(&mut self.0, Self::S, on);
        if on {
            self.set_fin(true);
        } // enforce S => F
    }

    #[inline]
    fn set_bit(v: &mut u8, bit: u8, on: bool) {
        if on {
            *v |= bit;
        } else {
            *v &= !bit;
        }
    }

    // keep mutual exclusion for U/O pair
    #[inline]
    fn set_pair(v: &mut u8, set_bit: u8, clear_bit: u8, on: bool) {
        if on {
            *v |= set_bit;
            *v &= !clear_bit;
        } else {
            *v &= !set_bit;
        }
    }

    /// Validates the protocol constraints of the flags.
    #[inline]
    pub fn validate(&self) -> Result<()> {
        if self.0 & Self::RESERVED_MASK != 0 {
            bail!(
                "protocol error: reserved bits set in DataInFlags: {:#010b}",
                self.0
            );
        }
        if self.u() && self.o() {
            bail!("protocol error: both U and O set");
        }
        if self.s() && !self.fin() {
            bail!("protocol error: S=1 requires F=1");
        }
        Ok(())
    }
}

/* Optional: interop с bitflags-типом */

impl From<DataInFlags> for RawDataInFlags {
    #[inline]
    fn from(f: DataInFlags) -> Self {
        Self(f.bits())
    }
}

impl TryFrom<RawDataInFlags> for DataInFlags {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(r: RawDataInFlags) -> Result<Self> {
        r.validate()?;
        DataInFlags::from_bits(r.raw())
            .ok_or_else(|| anyhow::anyhow!("invalid DataInFlags: {:#010b}", r.raw()))
    }
}

// ---------- RawDataOutFlags ----------
impl fmt::Debug for RawDataOutFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawDataOutFlags {{ ")?;
        if self.fin() {
            write!(f, "FIN")?;
        }
        write!(f, " }}")
    }
}

impl fmt::Debug for RawDataInFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw();
        let reserved_bits = (raw & Self::RESERVED_MASK) >> 3;

        write!(f, "RawDataInFlags {{ ")?;

        if self.fin() {
            write!(f, "FIN|")?;
        }
        if self.ack() {
            write!(f, "A|")?;
        }
        if self.o() {
            write!(f, "O|")?;
        }
        if self.u() {
            write!(f, "U|")?;
        }
        if self.s() {
            write!(f, "S|")?;
        }

        if reserved_bits != 0 {
            write!(f, "reserved_bits=0b{:03b}|", reserved_bits)?;
        }
        if self.u() && self.o() {
            write!(f, "INVALID:U&O|")?;
        }
        if self.s() && !self.fin() {
            write!(f, "INVALID:S_without_F|")?;
        }

        write!(f, " }}")
    }
}
