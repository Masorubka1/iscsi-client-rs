// src/control_block/mode_sense.rs
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! MODE SENSE (6 / 10) — CDB fillers that write into a provided 16-byte buffer.
//! Returns the CDB length actually used (6 or 10).

pub const MODE_SENSE_6: u8 = 0x1A;
pub const MODE_SENSE_10: u8 = 0x5A;

/// Page Control (PC) for MODE SENSE byte 2 (bits 7..6).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PageControl {
    Current = 0b00,
    Changeable = 0b01,
    Default = 0b10,
    Saved = 0b11,
}

#[inline]
fn pc_bits(pc: PageControl) -> u8 {
    (pc as u8) << 6
}

/// Fill a MODE SENSE(6) CDB into `cdb[0..6]`.
/// Layout:
///   [0]=0x1A, [1]=DBD<<3, [2]=PC(7..6)|PAGE(5..0), [3]=SUBPAGE, [4]=ALLOC_LEN,
/// [5]=CONTROL
#[inline]
pub fn fill_mode_sense6(
    cdb: &mut [u8; 16],
    dbd: bool,
    pc: PageControl,
    page_code: u8,
    subpage_code: u8,
    allocation_len: u8,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = MODE_SENSE_6;
    cdb[1] = ((dbd as u8) << 3) & 0b0000_1000;
    cdb[2] = pc_bits(pc) | (page_code & 0x3F);
    cdb[3] = subpage_code;
    cdb[4] = allocation_len;
    cdb[5] = control;
}

/// Convenience: MODE SENSE(6) with PC=Current, DBD=1, subpage=0, control=0.
#[inline]
pub fn fill_mode_sense6_simple(cdb: &mut [u8; 16], page_code: u8, allocation_len: u8) {
    fill_mode_sense6(
        cdb,
        true,
        PageControl::Current,
        page_code,
        0x00,
        allocation_len,
        0x00,
    )
}

/// Fill a MODE SENSE(10) CDB into `cdb[0..10]`.
/// Layout:
///   [0]=0x5A, [1]=LLBAA<<4 | DBD<<3, [2]=PC(7..6)|PAGE(5..0), [3]=SUBPAGE,
///   [4..6]=0, [7..8]=ALLOC_LEN(be), [9]=CONTROL
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn fill_mode_sense10(
    cdb: &mut [u8; 16],
    dbd: bool,
    llbaa: bool,
    pc: PageControl,
    page_code: u8,
    subpage_code: u8,
    allocation_len: u16,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = MODE_SENSE_10;
    cdb[1] = ((llbaa as u8) << 4) | ((dbd as u8) << 3);
    cdb[2] = pc_bits(pc) | (page_code & 0x3F);
    cdb[3] = subpage_code;
    let [msb, lsb] = allocation_len.to_be_bytes();
    cdb[7] = msb;
    cdb[8] = lsb;
    cdb[9] = control;
}

/// Convenience: MODE SENSE(10) with PC=Current, DBD=1, LLBAA=0, subpage=0,
/// control=0.
#[inline]
pub fn fill_mode_sense10_simple(cdb: &mut [u8; 16], page_code: u8, allocation_len: u16) {
    fill_mode_sense10(
        cdb,
        true,
        false,
        PageControl::Current,
        page_code,
        0x00,
        allocation_len,
        0x00,
    )
}
