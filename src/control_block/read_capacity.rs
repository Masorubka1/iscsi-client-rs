// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Result, anyhow};
use zerocopy::{
    FromBytes, Immutable, KnownLayout,
    byteorder::{BigEndian, U32, U64},
};

/// Build a padded 16-byte **SCSI READ CAPACITY(10)** CDB (opcode 0x25).
///
/// Parameters:
/// - `cdb`     : output buffer (zeroed; first 10 bytes used, kept as 16 for
///   iSCSI alignment)
/// - `lba`     : 32-bit LBA hint (meaningful only when `pmi` = true; else set
///   0)
/// - `pmi`     : Partial Medium Indicator (true => return info for `lba`)
/// - `control` : CONTROL byte
///
/// Notes:
/// - With `pmi = false`, targets return the **maximum LBA** (last logical
///   block) and the **logical block length** (8-byte response).
/// - If the device is larger than 2 TB, the Max LBA will be `0xFFFF_FFFF`,
///   which is a hint to issue **READ CAPACITY(16)** instead.
#[inline]
pub fn build_read_capacity10(cdb: &mut [u8; 16], lba: u32, pmi: bool, control: u8) {
    cdb.fill(0);
    cdb[0] = 0x25; // READ CAPACITY(10)
    cdb[1] = 0x00; // obsolete/reserved in SBC; keep zero
    cdb[2..6].copy_from_slice(&lba.to_be_bytes()); // only used if PMI=1
    // bytes 6..7 reserved (kept 0)
    cdb[8] = if pmi { 0x01 } else { 0x00 }; // PMI bit (bit 0)
    cdb[9] = control;
}

/// Build a 16-byte **SCSI READ CAPACITY(16)** CDB via SERVICE ACTION IN(16)
/// (opcode 0x9E, SA=0x10).
///
/// Parameters:
/// - `cdb`       : output buffer (zeroed)
/// - `lba`       : 64-bit LBA hint (meaningful only when `pmi` = true; else set
///   0)
/// - `pmi`       : Partial Medium Indicator (true => return info for/after
///   `lba`)
/// - `alloc_len` : Allocation length for the parameter data (big-endian). Use
///   **32** to get full data.
/// - `control`   : CONTROL byte
///
/// Typical use:
/// - For full device capacity: `lba = 0`, `pmi = false`, `alloc_len = 32`.
#[inline]
pub fn build_read_capacity16(
    cdb: &mut [u8; 16],
    lba: u64,
    pmi: bool,
    alloc_len: u32,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = 0x9E; // SERVICE ACTION IN(16)
    cdb[1] = 0x10; // Service Action = READ CAPACITY(16)
    cdb[2..10].copy_from_slice(&lba.to_be_bytes()); // only used if PMI=1
    cdb[10..14].copy_from_slice(&alloc_len.to_be_bytes()); // recommended 32
    cdb[14] = if pmi { 0x01 } else { 0x00 }; // PMI bit (bit 0)
    cdb[15] = control;
}

/// Raw 8-byte parameter data returned by READ CAPACITY(10) command
///
/// Contains the basic capacity information for a SCSI block device.
/// All fields are stored in big-endian format as per SCSI specification.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
pub struct Rc10Raw {
    /// Maximum logical block address (bytes 0-3) - highest valid LBA on the device
    pub max_lba: U32<BigEndian>,
    /// Block length in bytes (bytes 4-7) - size of each logical block
    pub block_len: U32<BigEndian>,
}

/// Raw header (first 12 bytes) of READ CAPACITY(16) parameter data
///
/// Contains extended capacity information for large SCSI block devices.
/// The specification may return up to 32 bytes, but this structure covers
/// the essential first 12 bytes. All fields are in big-endian format.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable, Debug)]
pub struct Rc16Raw {
    /// Maximum logical block address (bytes 0-7) - 64-bit LBA for large devices
    pub max_lba: U64<BigEndian>,
    /// Block length in bytes (bytes 8-11) - size of each logical block
    pub block_len: U32<BigEndian>,
}

impl Rc10Raw {
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        (self.max_lba.get() as u64 + 1) * self.block_len.get() as u64
    }

    /// If true, target likely needs READ CAPACITY(16).
    #[inline]
    pub fn indicates_overflow(&self) -> bool {
        self.max_lba == u32::MAX
    }
}

impl Rc16Raw {
    #[inline]
    pub fn total_bytes(&self) -> u128 {
        (self.max_lba.get() as u128 + 1) * self.block_len.get() as u128
    }
}

/// Parse READ CAPACITY(10) parameter data (needs ≥ 8 bytes).
#[inline]
pub fn parse_read_capacity10_zerocopy(buf: &[u8]) -> Result<&Rc10Raw> {
    let (raw, _rest) = Rc10Raw::ref_from_prefix(buf)
        .map_err(|_| anyhow!("READ CAPACITY(10): need ≥ 8 bytes, got {}", buf.len()))?;
    Ok(raw)
}

/// Parse READ CAPACITY(16) parameter data head (needs ≥ 12 bytes).
#[inline]
pub fn parse_read_capacity16_zerocopy(buf: &[u8]) -> Result<&Rc16Raw> {
    let (raw, _rest) = Rc16Raw::ref_from_prefix(buf)
        .map_err(|_| anyhow!("READ CAPACITY(16): need ≥ 12 bytes, got {}", buf.len()))?;
    Ok(raw)
}
