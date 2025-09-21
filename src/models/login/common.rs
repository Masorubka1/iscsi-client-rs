//! This module defines common structures and enums for iSCSI Login PDUs.
//! It includes flags and stage definitions for the login process.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fmt;

use anyhow::Result;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

bitflags::bitflags! {
    #[derive(Default, PartialEq)]
    pub struct LoginFlags: u8 {
        /// Transit bit (next stage)
        const TRANSIT = 0x80;
        /// Continue bit (more text)
        const CONTINUE = 0x40;
        /// Current Stage bits (bits 3-4)
        const CSG_MASK = 0b0000_1100;
        /// Next Stage bits (bits 0-1)
        const NSG_MASK = 0b0000_0011;
    }
}

impl TryFrom<u8> for LoginFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        LoginFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid LoginFlags: {:#08b}", value))
    }
}

impl fmt::Debug for LoginFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if self.contains(LoginFlags::TRANSIT) {
            parts.push("TRANSIT");
        }
        if self.contains(LoginFlags::CONTINUE) {
            parts.push("CONTINUE");
        }

        match (self.bits() & LoginFlags::CSG_MASK.bits()) >> 2 {
            0 => {},
            1 => parts.push("CSG=Operational"),
            3 => parts.push("CSG=FullFeature"),
            _ => parts.push("CSG=Unknown"),
        }

        match self.bits() & LoginFlags::NSG_MASK.bits() {
            0 => {},
            1 => parts.push("NSG=Operational"),
            3 => parts.push("NSG=FullFeature"),
            _ => parts.push("NSG=Unknown"),
        }

        write!(f, "LoginFlags({})", parts.join("|"))
    }
}

/// Represents the stages of the iSCSI login phase.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Stage {
    /// Security negotiation stage.
    #[default]
    Security = 0,
    /// Operational negotiation stage.
    Operational = 1,
    /// Full feature phase.
    FullFeature = 3,
}

impl Stage {
    /// Creates a `Stage` from a 2-bit value.
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0 => Some(Stage::Security),
            1 => Some(Stage::Operational),
            3 => Some(Stage::FullFeature),
            _ => None,
        }
    }
}

/// Wire-safe, zero-copy wrapper for iSCSI Login Flags (one byte on the wire).
///
/// Layout (RFC 3720/7143):
///   bit7: TRANSIT
///   bit6: CONTINUE
///   bits3..2: CSG (Current Stage)  [values: 0=Security, 1=Operational,
/// 3=FullFeature]   bits1..0: NSG (Next Stage)     [values: 0=Security,
/// 1=Operational, 3=FullFeature]
#[repr(transparent)]
#[derive(
    Copy, Clone, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct RawLoginFlags(u8);

impl RawLoginFlags {
    /// Returns the raw 8-bit value of the flags.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Creates a new `RawLoginFlags` from a raw 8-bit value.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Converts the raw flags to a `LoginFlags` bitflags struct.
    #[inline]
    pub fn flags(self) -> Result<LoginFlags> {
        LoginFlags::try_from(self.0)
    }

    /// Sets the raw flags from a `LoginFlags` bitflags struct.
    #[inline]
    pub fn set_flags(&mut self, f: LoginFlags) {
        self.0 = f.bits();
    }

    /// Checks if the Transit (T) bit is set.
    #[inline]
    pub fn transit(self) -> bool {
        (self.0 & LoginFlags::TRANSIT.bits()) != 0
    }

    /// Sets or clears the Transit (T) bit.
    #[inline]
    pub fn set_transit(&mut self, on: bool) {
        if on {
            self.0 |= LoginFlags::TRANSIT.bits();
        } else {
            self.0 &= !LoginFlags::TRANSIT.bits();
        }
    }

    /// Checks if the Continue (C) bit is set.
    #[inline]
    pub fn cont(self) -> bool {
        (self.0 & LoginFlags::CONTINUE.bits()) != 0
    }

    /// Sets or clears the Continue (C) bit.
    #[inline]
    pub fn set_cont(&mut self, on: bool) {
        if on {
            self.0 |= LoginFlags::CONTINUE.bits();
        } else {
            self.0 &= !LoginFlags::CONTINUE.bits();
        }
    }

    // --- CSG / NSG (Stage) ---

    /// Gets the Current Stage (CSG) from the flags.
    #[inline]
    pub fn csg(self) -> Option<Stage> {
        Stage::from_bits((self.0 & LoginFlags::CSG_MASK.bits()) >> 2)
    }

    /// Sets the Current Stage (CSG) in the flags.
    #[inline]
    pub fn set_csg(&mut self, s: Stage) {
        self.0 = (self.0 & !LoginFlags::CSG_MASK.bits())
            | (((s as u8) & LoginFlags::NSG_MASK.bits()) << 2);
    }

    /// Gets the Next Stage (NSG) from the flags.
    #[inline]
    pub fn nsg(self) -> Option<Stage> {
        Stage::from_bits(self.0 & LoginFlags::NSG_MASK.bits())
    }

    /// Sets the Next Stage (NSG) in the flags.
    #[inline]
    pub fn set_nsg(&mut self, s: Stage) {
        self.0 = (self.0 & !LoginFlags::NSG_MASK.bits())
            | ((s as u8) & LoginFlags::NSG_MASK.bits());
    }
}

impl TryFrom<RawLoginFlags> for LoginFlags {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(r: RawLoginFlags) -> Result<Self> {
        LoginFlags::try_from(r.raw())
    }
}

impl From<LoginFlags> for RawLoginFlags {
    #[inline]
    fn from(f: LoginFlags) -> Self {
        Self(f.bits())
    }
}

/// Pretty-print using your custom `Debug` for `LoginFlags`.
impl fmt::Debug for RawLoginFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawLoginFlags({:?})", LoginFlags::try_from(self.0))
    }
}
