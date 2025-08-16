/// Build a padded 16-byte SCSI WRITE(10) CDB.
///
/// * `lba`     – 32-bit Logical-Block Address
/// * `blocks`  – amount sequenced numbers (u16)
/// * `flags`   – WRPROTECT/DPO/FUA (bits 6:4,3,1)
/// * `control` – control bit
#[inline]
pub fn build_write10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x2A; // WRITE(10)
    cdb[1] = flags;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // group number
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control;
}

/// Build a padded 16-byte **SCSI READ (10)** CDB.
///
/// * `lba`     – 32-bit Logical-Block Address to start reading from
/// * `blocks`  – number of contiguous blocks to transfer (max 65 535)
/// * `flags`   – RDPROTECT / DPO / FUA bits (6:4 Protection, 3 = DPO, 1 = FUA)
/// * `control` – Control byte
///
/// The first 10 bytes follow SPC-4 §6.13; the remaining six bytes are
/// zero-padding because iSCSI always carries a 16-byte CDB field.
#[inline]
pub fn build_read10(cdb: &mut [u8; 16], lba: u32, blocks: u16, flags: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x28; // READ(10) opcode
    cdb[1] = flags;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[6] = 0; // Group Number (usually 0)
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb[9] = control; // Control
}

#[inline]
pub fn build_write16(cdb: &mut [u8; 16], lba: u64, blocks: u32, flags: u8, control: u8) {
    // WRITE(16) — SBC-4: op=0x8A, byte1 flags (wrprotect/dpo/fua), LBA[8], xfer
    // len[4], group, control
    cdb.fill(0);
    cdb[0] = 0x8A;
    cdb[1] = flags; // use 0 unless you need DPO/FUA/WRPROTECT
    cdb[2..10].copy_from_slice(&lba.to_be_bytes());
    cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
    cdb[15] = control;
}

#[inline]
pub fn build_read16(cdb: &mut [u8; 16], lba: u64, blocks: u32, flags: u8, control: u8) {
    // READ(16) — op=0x88
    cdb.fill(0);
    cdb[0] = 0x88;
    cdb[1] = flags; // rdprotect/dpo/fua if needed
    cdb[2..10].copy_from_slice(&lba.to_be_bytes());
    cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
    cdb[15] = control;
}
