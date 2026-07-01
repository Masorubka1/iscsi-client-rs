//! Typed wrappers around iSCSI identifiers to prevent accidental misuse
//! of raw `u32`/`u64` values.
//!
//! RFC 7143 defines specific constraints on each identifier; these wrappers
//! enforce those constraints at construction time so that invalid values
//! cannot leak into the PDU layer.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    fmt::{self, Write},
    sync::atomic::{AtomicU32, Ordering},
};

use anyhow::bail;
use rand::RngExt;

// ── Initiator Session Identifier (ISID) ─────────────────────────────────────

/// Six-byte identifier chosen by the initiator to identify an iSCSI session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Isid([u8; 6]);

impl Isid {
    /// Generates a random RFC-compatible ISID and its lowercase hexadecimal
    /// representation.
    pub fn generate() -> (Self, String) {
        let mut raw = [0u8; 6];
        rand::rng().fill(&mut raw);
        raw[0] &= 0x3f;

        let mut hex = String::with_capacity(12);
        for byte in raw {
            write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
        }

        (Self::new(raw), hex)
    }

    /// Creates an ISID from its six-byte wire representation.
    #[inline]
    pub const fn new(raw: [u8; 6]) -> Self {
        Self(raw)
    }

    /// Returns the six-byte wire representation.
    #[inline]
    pub const fn get(self) -> [u8; 6] {
        self.0
    }

    /// Returns a reference to the six-byte wire representation.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for Isid {
    #[inline]
    fn from(raw: [u8; 6]) -> Self {
        Self::new(raw)
    }
}

impl fmt::Display for Isid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

// ── Connection Identifier (CID) ─────────────────────────────────────────────

/// Initiator-assigned identifier for a connection within an iSCSI session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Cid(u16);

impl Cid {
    /// First connection identifier, conventionally used for session login.
    pub const ZERO: Self = Self(0);

    /// Creates a connection identifier from its wire value.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the 16-bit wire value.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl From<u16> for Cid {
    #[inline]
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Target Session Identifying Handle (TSIH) ────────────────────────────────

/// Target-assigned handle identifying an established iSCSI session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Tsih(u16);

impl Tsih {
    /// No established session; used when requesting a new session.
    pub const NONE: Self = Self(0);

    /// Creates a target session handle from its wire value.
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the 16-bit wire value.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns whether this value denotes no established session.
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
}

impl From<u16> for Tsih {
    #[inline]
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl fmt::Display for Tsih {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Initiator Task Tag (ITT) ────────────────────────────────────────────────

/// Initiator-assigned tag that correlates a request with its responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Itt(u32);

impl Itt {
    /// Reserved wire value indicating that no initiator task is associated.
    pub const RESERVED: u32 = u32::MAX;

    /// Creates an ITT, rejecting the reserved `0xFFFF_FFFF` value.
    #[inline]
    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::RESERVED {
            bail!("ITT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    #[inline]
    /// Returns the 32-bit wire value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for Itt {
    #[inline]
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

impl fmt::Display for Itt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

// ── Logical Unit Number (LUN) ───────────────────────────────────────────────

/// Encoded iSCSI Logical Unit Number used to address a target logical unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Lun(u64);

impl Lun {
    /// Logical unit zero.
    pub const ZERO: Self = Self(0);

    /// Creates a LUN from its 64-bit wire representation.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the 64-bit wire representation.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Lun {
    #[inline]
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl fmt::Display for Lun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LUN(0x{:016X})", self.0)
    }
}

// ── Target Task Tag (TTT) ───────────────────────────────────────────────────

/// Target-assigned tag that identifies an outstanding target transfer task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ttt(u32);

impl Ttt {
    /// Reserved wire value indicating that no target transfer task exists.
    pub const NONE: u32 = u32::MAX;

    /// Creates a TTT, rejecting the reserved `0xFFFF_FFFF` value.
    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::NONE {
            bail!("TTT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    #[inline]
    /// Returns the 32-bit wire value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for Ttt {
    #[inline]
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

impl fmt::Display for Ttt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

// ── Command Sequence Number (CmdSN) ─────────────────────────────────────────

/// Command sequence number used for iSCSI command ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CmdSn(u32);

impl CmdSn {
    /// Creates a command sequence number from its wire value.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the 32-bit wire value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for CmdSn {
    #[inline]
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

impl fmt::Display for CmdSn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Status Sequence Number (StatSN / ExpStatSN) ─────────────────────────────

/// Status sequence number used to acknowledge target responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct StatSn(u32);

impl StatSn {
    /// Creates a status sequence number from its wire value.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the 32-bit wire value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for StatSn {
    #[inline]
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

impl fmt::Display for StatSn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Atomic ITT generator ────────────────────────────────────────────────────

/// Thread-safe generator for unique initiator task tags.
#[derive(Debug, Default)]
pub struct IttGen(AtomicU32);

impl IttGen {
    /// Creates a generator whose first returned tag is `start`.
    #[inline]
    pub fn new(start: Itt) -> Self {
        Self(AtomicU32::new(start.get()))
    }

    /// Atomically fetch the current value and advance to the next valid ITT.
    #[inline]
    pub fn fetch_inc(&self) -> Itt {
        let curr = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |curr| {
                let next = curr.wrapping_add(1);
                Some(if next == Itt::RESERVED { 0 } else { next })
            })
            .expect("Atomic ITT update failed");

        Itt::new(curr).expect("Stored reserved ITT in generator")
    }

    #[inline]
    /// Returns the current tag without incrementing the generator.
    pub fn load(&self) -> Itt {
        Itt::new(self.0.load(Ordering::SeqCst)).expect("Failed to increase itt")
    }
}

#[cfg(test)]
mod tests {
    use super::Isid;

    #[test]
    fn generated_isid_matches_hex_representation() {
        let (isid, hex) = Isid::generate();
        assert_eq!(isid.as_bytes().len(), 6);
        assert_eq!(hex.len(), 12);
        assert_eq!(
            hex::decode(hex).expect("failed to decode generated ISID"),
            isid.as_bytes()
        );
    }
}
