// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! REPORT LUNS — CDB filler (12-byte CDB written into a 16-byte buffer).
//!
//! CDB layout (SPC):
//!   [0]  = 0xA0 (REPORT LUNS)
//!   [1]  = Service Action (0x00 for REPORT LUNS)
//!   [2]  = SELECT REPORT
//!   [3]  = reserved
//!   [4]  = reserved
//!   [5]  = reserved
//!   [6..9]  = ALLOCATION LENGTH (big-endian u32)
//!   [10] = reserved
//!   [11] = CONTROL
//!
//! Response starts with:
//!   [0..3] = LUN LIST LENGTH (big-endian u32, multiple of 8)
//!   [4..7] = reserved
//!   [8..]  = LUN entries (8 bytes each)
//!
//! This module only builds the CDB.

pub const REPORT_LUNS: u8 = 0xA0;

/// Common SELECT REPORT values (byte 2).
pub mod select_report {
    /// All logical unit addresses.
    pub const ALL: u8 = 0x00;
    /// Well known logical unit addresses.
    pub const WELL_KNOWN: u8 = 0x01;
    /// All logical unit addresses (excluding well known) — commonly used.
    pub const ALL_MAPPED: u8 = 0x02;
}

/// Fill a REPORT LUNS CDB into `cdb[0..12]`.
#[inline]
pub fn fill_report_luns(
    cdb: &mut [u8; 16],
    select: u8,
    allocation_len: u32,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = REPORT_LUNS;
    cdb[1] = 0x00; // Service Action = REPORT LUNS
    cdb[2] = select;
    let [b6, b7, b8, b9] = allocation_len.to_be_bytes();
    cdb[6] = b6;
    cdb[7] = b7;
    cdb[8] = b8;
    cdb[9] = b9;
    cdb[11] = control;
}

/// Convenience: select=ALL, control=0.
#[inline]
pub fn fill_report_luns_simple(cdb: &mut [u8; 16], allocation_len: u32) {
    fill_report_luns(cdb, select_report::ALL, allocation_len, 0x00)
}
