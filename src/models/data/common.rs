// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use anyhow::{Result, bail};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

bitflags::bitflags! {
    #[derive(Default, Debug, PartialEq)]
    pub struct DataOutFlags: u8 {
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
    pub const FINAL: u8 = 0b1000_0000;

    /// Get raw flags byte as-is.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    /// Construct from a raw byte (no validation).
    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    /// Check Final (F) bit.
    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    /// Set/clear Final (F) bit.
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
    pub struct DataInFlags: u8 {
        const FINAL = 1 << 7; // Final
        const A = 1 << 6; // Acknowledge (DataACK SNACK, ERL>0)
        // bits 5..3 reserved (0)
        const O = 1 << 2; // Residual Overflow (валиден только при S=1)
        const U = 1 << 1; // Residual Underflow (валиден только при S=1)
        const S = 1 << 0; // Status present (если 1, то F тоже обязан быть 1)
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

/// Wire view for **Data-IN flags** (byte 1 of the PDU).
#[repr(transparent)]
#[derive(Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawDataInFlags(u8);

impl RawDataInFlags {
    pub const A: u8 = 1 << 6;
    pub const FINAL: u8 = 1 << 7;
    // reserved: bits 5..3
    pub const O: u8 = 1 << 2;
    const RESERVED_MASK: u8 = 0b0011_1000;
    pub const S: u8 = 1 << 0;
    pub const U: u8 = 1 << 1;

    /// Get raw flags byte.
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    /// Construct from raw (no validation).
    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    // Getters
    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    #[inline]
    pub fn ack(&self) -> bool {
        self.0 & Self::A != 0
    }

    #[inline]
    pub fn o(&self) -> bool {
        self.0 & Self::O != 0
    }

    #[inline]
    pub fn u(&self) -> bool {
        self.0 & Self::U != 0
    }

    #[inline]
    pub fn s(&self) -> bool {
        self.0 & Self::S != 0
    }

    // Setters
    #[inline]
    pub fn set_fin(&mut self, on: bool) {
        Self::set_bit(&mut self.0, Self::FINAL, on)
    }

    #[inline]
    pub fn set_ack(&mut self, on: bool) {
        Self::set_bit(&mut self.0, Self::A, on)
    }

    #[inline]
    pub fn set_o(&mut self, on: bool) {
        Self::set_pair(&mut self.0, Self::O, Self::U, on)
    }

    #[inline]
    pub fn set_u(&mut self, on: bool) {
        Self::set_pair(&mut self.0, Self::U, Self::O, on)
    }

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

    /// Validate protocol constraints:
    /// - reserved bits (5..3) must be zero
    /// - not both U and O
    /// - S => F
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
