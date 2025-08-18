/// Build a 16-byte SCSI **WRITE(10)** CDB.
///
/// Parameters:
/// - `cdb`     : output buffer (will be zeroed; only 10 bytes are used, we keep
///   16 for alignment)
/// - `lba`     : 32-bit Logical Block Address
/// - `blocks`  : number of logical blocks to transfer (0 means **65,536** for
///   WRITE(10))
/// - `flags`   : WRPROTECT[7:5] | DPO[4] | FUA[3] | FUA_NV[1] (others must be
///   0)
/// - `control` : CONTROL byte
///
/// Layout (SBC):
/// - byte 0  : OPERATION CODE = 0x2A
/// - byte 1  : flags (reserved bits must be 0)
/// - bytes 2..5  : LBA (big-endian, 32-bit)
/// - byte 6  : GROUP NUMBER (low 5 bits) — leave 0 unless you need it
/// - bytes 7..8  : TRANSFER LENGTH (big-endian, 16-bit; **0 => 65,536 blocks**)
/// - byte 9  : CONTROL
#[inline]
pub fn build_write10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x2A; // WRITE(10)
    cdb[1] = flags & 0b1111_1010; // allow WRPROTECT[7:5], DPO[4], FUA[3], FUA_NV[1]
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // group number (0 unless used)
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control;
}

/// Build a 16-byte SCSI **WRITE(16)** CDB.
///
/// Parameters:
/// - `cdb`     : output buffer (will be zeroed; full 16 bytes used)
/// - `lba`     : 64-bit Logical Block Address
/// - `blocks`  : number of logical blocks to transfer (0 means **0 blocks** for
///   WRITE(16))
/// - `flags`   : WRPROTECT[7:5] | DPO[4] | FUA[3] (others must be 0)
/// - `control` : CONTROL byte
///
/// Layout (SBC):
/// - byte  0  : OPERATION CODE = 0x8A
/// - byte  1  : flags (reserved bits must be 0)
/// - bytes 2..9   : LBA (big-endian, 64-bit)
/// - bytes 10..13 : TRANSFER LENGTH (big-endian, 32-bit; **0 => 0 blocks**)
/// - byte  14 : GROUP NUMBER (low 5 bits) — leave 0 unless you need it
/// - byte  15 : CONTROL
#[inline]
pub fn build_write16(cdb: &mut [u8; 16], lba: u64, blocks: u32, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x8A; // WRITE(16)
    cdb[1] = flags & 0b1111_1000; // allow WRPROTECT[7:5], DPO[4], FUA[3]
    cdb[2..10].copy_from_slice(&lba.to_be_bytes());
    cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
    // cdb[14] = group number (0 unless used)
    cdb[15] = control;
}
