// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! REQUEST SENSE — 6-byte CDB filler written into a provided 16-byte buffer.
//!
//! CDB layout (SPC):
//!   [0] = 0x03 (REQUEST SENSE)
//!   [1] = DESC (bit 0), other bits reserved=0
////! [2]..[3] = reserved (0)
//!   [4] = ALLOCATION LENGTH (number of bytes to return)
//!   [5] = CONTROL
//!
//! Notes:
//! - `desc=false` requests Fixed sense format; `desc=true` requests Descriptor
//!   format. The target may still choose format per its mode settings.

pub const REQUEST_SENSE: u8 = 0x03;

/// Fill a REQUEST SENSE (6) CDB into `cdb[0..6]`.
#[inline]
pub fn fill_request_sense(
    cdb: &mut [u8; 16],
    desc: bool,
    allocation_len: u8,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = REQUEST_SENSE;
    cdb[1] = (desc as u8) & 0x01; // DESC bit (bit 0)
    cdb[4] = allocation_len;
    cdb[5] = control;
}

/// Convenience: DESC=0 (fixed format), CONTROL=0.
#[inline]
pub fn fill_request_sense_simple(cdb: &mut [u8; 16], allocation_len: u8) {
    fill_request_sense(cdb, false, allocation_len, 0x00)
}
