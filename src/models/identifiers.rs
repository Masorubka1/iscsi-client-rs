//! Typed wrappers around iSCSI identifiers to prevent accidental misuse
//! of raw `u32`/`u64` values.
//!
//! RFC 7143 defines specific constraints on each identifier; these wrappers
//! enforce those constraints at construction time so that invalid values
//! cannot leak into the PDU layer.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};

use anyhow::bail;

// ── Initiator Task Tag (ITT) ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Itt(u32);

impl Itt {
    /// Reserved value — "no task".
    pub const RESERVED: u32 = u32::MAX;

    /// Validated constructor (fails on `0xFFFF_FFFF`).
    #[inline]
    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::RESERVED {
            bail!("ITT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    #[inline]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Lun(u64);

impl Lun {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ttt(u32);

impl Ttt {
    pub const NONE: u32 = u32::MAX;

    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::NONE {
            bail!("TTT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    #[inline]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CmdSn(u32);

impl CmdSn {
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct StatSn(u32);

impl StatSn {
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

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

#[derive(Debug, Default)]
pub struct IttGen(AtomicU32);

impl IttGen {
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
    pub fn load(&self) -> Itt {
        Itt::new(self.0.load(Ordering::SeqCst)).expect("Failed to increase itt")
    }
}
