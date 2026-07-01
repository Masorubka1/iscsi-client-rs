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

// ─────────────────────────────────────────────────────────────────────────────
// Initiator Task Tag (ITT)
// ─────────────────────────────────────────────────────────────────────────────

/// An iSCSI Initiator Task Tag.
///
/// RFC 7143 § 9.1: ITT is the initiator-assigned identifier for a task.
/// A value of `0xFFFF_FFFF` is reserved (meaning "no task" or "unused").
///
/// Valid user-assigned ITTs: `0x0000_0000` .. `0xFFFF_FFFE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Itt(u32);

impl Itt {
    /// The reserved ITT value (`0xFFFF_FFFF`), used for PDUs that are not
    /// associated with any task (e.g. unsolicited NOP-In).
    pub const RESERVED: u32 = u32::MAX;

    /// Create an `Itt` from a raw `u32`. Returns an error when the value
    /// equals the reserved sentinel.
    #[inline]
    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::RESERVED {
            bail!("ITT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    /// Unchecked constructor — only valid when the caller can prove the value
    /// is not `0xFFFF_FFFF`.
    #[inline]
    pub const fn new_unchecked(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Increment by 1 with wrapping (used for ITT generator in sessions).
    #[inline]
    pub fn inc(self) -> Self {
        let next = self.0.wrapping_add(1);
        // Skip the reserved value
        if next == Self::RESERVED {
            Self(0)
        } else {
            Self(next)
        }
    }
}

impl fmt::Display for Itt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Logical Unit Number (LUN)
// ─────────────────────────────────────────────────────────────────────────────

/// An iSCSI Logical Unit Number.
///
/// RFC 7143 § 9.1.13: LUN is an 8-byte field.  The addressing method is
/// encoded in the upper two bits.  LUN `0` is valid (e.g. for Text commands).
///
/// The most common value for single-LUN targets is `0x0001_0000_0000_0000`
/// (address method `00`b, LUN 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Lun(u64, [u8; 2]);

impl Lun {
    /// LUN 0 — often used for discovery / Text operations.
    pub const ZERO: Self = Self(0, [0u8; 2]);

    /// Construct a LUN from a 64-bit raw value (the full 8-byte field as it
    /// appears on the wire).
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        let bytes = raw.to_be_bytes();
        // Extract address method (top 2 bits of byte 0)
        let addr_method = bytes[0] >> 6;
        Self(raw, [addr_method, bytes[1]])
    }

    /// Convenience: single-level addressing, LUN within `0..=16383`.
    /// Produces address-method `00`b.
    #[inline]
    pub const fn single(lun_number: u16) -> Self {
        let raw = (lun_number as u64) << 48;
        Self(raw, [0u8; 2])
    }

    /// Return the raw 64-bit value as it appears on the wire.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Address method (top 2 bits of the first byte).  `0b00` = single-level.
    #[inline]
    pub const fn addr_method(self) -> u8 {
        self.1[0]
    }

    /// The LUN number extracted from single-level addressing.
    /// Returns `None` for other addressing methods.
    #[inline]
    pub const fn lun_number(self) -> Option<u16> {
        if self.1[0] == 0 {
            Some((self.0 >> 48) as u16)
        } else {
            None
        }
    }
}

impl fmt::Display for Lun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = self.lun_number() {
            write!(f, "LUN({n})")
        } else {
            write!(f, "LUN(0x{:016X})", self.0)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Target Task Tag (TTT)
// ─────────────────────────────────────────────────────────────────────────────

/// An iSCSI Target Task Tag.
///
/// `0xFFFF_FFFF` is the reserved value meaning "no TTT" / "unused".
/// All other values are valid TTTs assigned by the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ttt(u32);

impl Ttt {
    /// The reserved / unused TTT value.
    pub const NONE: u32 = u32::MAX;

    /// Create a `Ttt`. Returns an error for the reserved value.
    #[inline]
    pub fn new(raw: u32) -> anyhow::Result<Self> {
        if raw == Self::NONE {
            bail!("TTT 0xFFFFFFFF is reserved");
        }
        Ok(Self(raw))
    }

    /// Unchecked constructor (caller guarantees `raw != NONE`).
    #[inline]
    pub const fn new_unchecked(raw: u32) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Ttt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic ITT generator (for session-wide ITT allocation)
// ─────────────────────────────────────────────────────────────────────────────

/// A session-scoped atomic ITT counter.
///
/// Calling `fetch_inc()` returns the current value and atomically increments
/// the counter, automatically skipping the reserved `0xFFFF_FFFF` sentinel.
#[derive(Debug, Default)]
pub struct IttGen(AtomicU32);

impl IttGen {
    /// Create a new generator starting at the given ITT value.
    #[inline]
    pub fn new(start: Itt) -> Self {
        Self(AtomicU32::new(start.get()))
    }

    /// Atomically fetch the current ITT and advance to the next.
    /// Skips `0xFFFF_FFFF`.
    #[inline]
    pub fn fetch_inc(&self) -> Itt {
        loop {
            let prev = self.0.fetch_add(1, Ordering::SeqCst);
            if prev != Itt::RESERVED {
                return Itt::new_unchecked(prev);
            }
            // wrapped around to 0xFFFF_FFFF — advance again
        }
    }

    /// Return the current value without advancing.
    #[inline]
    pub fn load(&self) -> Itt {
        let raw = self.0.load(Ordering::SeqCst);
        Itt::new_unchecked(raw)
    }
}
