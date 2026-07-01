// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Build a 16-byte SCSI **XDWRITEREAD(10)** CDB (opcode 0x53).
///
/// XDWRITEREAD atomically writes data to the device and reads data back
/// from the same LBA range in a single bidirectional command.  It requires
/// `BidirectionalInitialR2T` AHS (RFC 7146 § 4) when used with iSCSI.
///
/// Parameters:
/// - `cdb`       : output buffer (will be zeroed; full 16 bytes, only 10 used)
/// - `lba`       : 32-bit Logical Block Address
/// - `write_blocks` : number of blocks to write (0 → 65536)
/// - `read_blocks`  : number of blocks to read back (0 → 65536)
/// - `flags`     : WRPROTECT[7:5] | DISABLE_WRITE[4] (others must be 0)
/// - `control`   : CONTROL byte
///
/// Layout (SBC-4):
/// - byte 0  : OPERATION CODE = 0x53
/// - byte 1  : flags
/// - bytes 2..5  : LBA (big-endian, 32-bit)
/// - byte 6  : GROUP NUMBER
/// - bytes 7..8  : TRANSFER LENGTH (write blocks, big-endian, 16-bit)
/// - byte 9  : CONTROL
/// - bytes 10..15 : SERVICE ACTION (for XDWRITEREAD(32)) — unused here
#[inline]
pub fn build_xdwrite_read10(
    cdb: &mut [u8; 16],
    lba: u32,
    write_blocks: u16,
    read_blocks: u16,
    flags: u8,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = 0x53; // XDWRITEREAD(10)
    cdb[1] = flags & 0b1111_0000; // WRPROTECT[7:5], DISABLE_WRITE[4]
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    // cdb[6] = group number (0)
    cdb[7..9].copy_from_slice(&write_blocks.to_be_bytes());
    cdb[9] = control;
    // bytes 10..15 remain zero (not used for 10-byte variant)

    // The number of blocks to **read back** is communicated via the
    // Expected Data Transfer Length in the SCSI Command PDU, NOT in
    // the CDB itself.  For iSCSI, the read data length goes into the
    // BidirectionalInitialR2T AHS.
    let _ = read_blocks; // used only for documentation
}
