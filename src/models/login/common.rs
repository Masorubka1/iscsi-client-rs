// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
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

#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Stage {
    #[default]
    Security = 0,
    Operational = 1,
    FullFeature = 3,
}

impl Stage {
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
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Lossy conversion into your `LoginFlags` bitflags (unknown bits are
    /// kept).
    #[inline]
    pub fn flags(self) -> Result<LoginFlags> {
        LoginFlags::try_from(self.0)
    }

    /// Overwrite all bits from a `LoginFlags` value.
    #[inline]
    pub fn set_flags(&mut self, f: LoginFlags) {
        self.0 = f.bits();
    }

    #[inline]
    pub fn transit(self) -> bool {
        (self.0 & LoginFlags::TRANSIT.bits()) != 0
    }

    #[inline]
    pub fn set_transit(&mut self, on: bool) {
        if on {
            self.0 |= LoginFlags::TRANSIT.bits();
        } else {
            self.0 &= !LoginFlags::TRANSIT.bits();
        }
    }

    #[inline]
    pub fn cont(self) -> bool {
        (self.0 & LoginFlags::CONTINUE.bits()) != 0
    }

    #[inline]
    pub fn set_cont(&mut self, on: bool) {
        if on {
            self.0 |= LoginFlags::CONTINUE.bits();
        } else {
            self.0 &= !LoginFlags::CONTINUE.bits();
        }
    }

    // --- CSG / NSG (Stage) ---

    /// Get Current Stage (bits 3..2). Returns `None` if the encoded value is
    /// reserved (2).
    #[inline]
    pub fn csg(self) -> Option<Stage> {
        Stage::from_bits((self.0 & LoginFlags::CSG_MASK.bits()) >> 2)
    }

    /// Set Current Stage (bits 3..2).
    #[inline]
    pub fn set_csg(&mut self, s: Stage) {
        self.0 = (self.0 & !LoginFlags::CSG_MASK.bits())
            | (((s as u8) & LoginFlags::NSG_MASK.bits()) << 2);
    }

    /// Get Next Stage (bits 1..0). Returns `None` if the encoded value is
    /// reserved (2).
    #[inline]
    pub fn nsg(self) -> Option<Stage> {
        Stage::from_bits(self.0 & LoginFlags::NSG_MASK.bits())
    }

    /// Set Next Stage (bits 1..0).
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
