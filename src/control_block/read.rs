// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Build a padded 16-byte **SCSI READ(10)** CDB.
///
/// Parameters:
/// - `cdb`     : output buffer (will be zeroed; only 10 bytes are used, we keep
///   16 for alignment)
/// - `lba`     : 32-bit Logical Block Address to start reading from
/// - `blocks`  : number of logical blocks to transfer (big-endian, 0 =>
///   **65,536** blocks)
/// - `flags`   : RDPROTECT[7:5] | DPO[4] | FUA[3] (other bits must be zero)
/// - `control` : CONTROL byte
///
/// Layout (SBC):
/// - byte 0      : OPERATION CODE = 0x28
/// - byte 1      : flags (masked to RDPROTECT/DPO/FUA)
/// - bytes 2..5  : LBA (big-endian, 32-bit)
/// - byte 6      : GROUP NUMBER (low 5 bits) — leave 0 unless you need it
/// - bytes 7..8  : TRANSFER LENGTH (big-endian, 16-bit; **0 => 65,536 blocks**)
/// - byte 9      : CONTROL
#[inline]
pub fn build_read10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x28; // READ(10)
    cdb[1] = flags & 0b1111_1000; // allow RDPROTECT[7:5], DPO[4], FUA[3]
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // group number (0 unless used)
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control;
}

/// Build a 16-byte **SCSI READ(16)** CDB.
///
/// Parameters:
/// - `cdb`     : output buffer (will be zeroed; full 16 bytes used)
/// - `lba`     : 64-bit Logical Block Address
/// - `blocks`  : number of logical blocks to transfer (big-endian, 32-bit; **0
///   => 0 blocks**)
/// - `flags`   : RDPROTECT[7:5] | DPO[4] | FUA[3] (other bits must be zero)
/// - `control` : CONTROL byte
///
/// Layout (SBC):
/// - byte  0      : OPERATION CODE = 0x88
/// - byte  1      : flags (masked to RDPROTECT/DPO/FUA)
/// - bytes 2..9   : LBA (big-endian, 64-bit)
/// - bytes 10..13 : TRANSFER LENGTH (big-endian, 32-bit; **0 => 0 blocks**)
/// - byte  14     : GROUP NUMBER (low 5 bits) — leave 0 unless you need it
/// - byte  15     : CONTROL
#[inline]
pub fn build_read16(cdb: &mut [u8; 16], lba: u64, blocks: u32, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x88; // READ(16)
    cdb[1] = flags & 0b1111_1000; // allow RDPROTECT[7:5], DPO[4], FUA[3]
    cdb[2..10].copy_from_slice(&lba.to_be_bytes());
    cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
    // cdb[14] = group number (0 unless used)
    cdb[15] = control;
}
