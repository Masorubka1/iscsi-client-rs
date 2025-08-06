use anyhow::{Result, anyhow};
use bitflags::bitflags;

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN},
        opcode::{BhsOpcode, IfFlags, Opcode},
    },
};

bitflags! {
    #[derive(Default, Debug, PartialEq)]
    pub struct DataOutFlags: u8 {
        const F = 1 << 7; // Final
        // bits 6..0 зарезервированы (0)
    }
}

impl TryFrom<u8> for DataOutFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        DataOutFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#08b}", value))
    }
}

/// BHS для SCSI Data-Out (opcode 0x26)
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct ScsiDataOut {
    pub opcode: BhsOpcode,            // byte 0 (должен быть 0x26)
    pub flags: DataOutFlags,          // byte 1 (F, остальное 0)
    pub reserved2: [u8; 2],           // bytes 2..3 (reserved)
    pub total_ahs_length: u8,         // byte 4  (в 4-байтных словах)
    pub data_segment_length: [u8; 3], // bytes 5..7
    pub lun: [u8; 8],                 // bytes 8..15
    pub initiator_task_tag: u32,      // bytes 16..19
    pub target_transfer_tag: u32,     // bytes 20..23 (TTT, либо 0xffffffff)
    pub exp_stat_sn: u32,             // bytes 24..27 (от инициатора)
    pub reserved3: [u8; 8],           // bytes 28..35 (reserved)
    pub data_sn: u32,                 // bytes 36..39
    pub buffer_offset: u32,           // bytes 40..43
    pub reserved4: u32,               // bytes 44..47 (reserved, 0)
}

impl ScsiDataOut {
    #[inline]
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2..4].copy_from_slice(&self.reserved2);
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        buf[24..28].copy_from_slice(&self.exp_stat_sn.to_be_bytes());
        buf[28..36].copy_from_slice(&self.reserved3);
        buf[36..40].copy_from_slice(&self.data_sn.to_be_bytes());
        buf[40..44].copy_from_slice(&self.buffer_offset.to_be_bytes());
        buf[44..48].copy_from_slice(&self.reserved4.to_be_bytes());

        buf
    }

    pub fn from_bhs_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(anyhow!("buffer too small for SCSI Data-Out BHS"));
        }
        let opcode: BhsOpcode = b[0].try_into()?;

        let flags = DataOutFlags::try_from(b[1])?;
        let mut reserved2 = [0u8; 2];
        reserved2.copy_from_slice(&b[2..4]);
        let total_ahs_length = b[4];
        let data_segment_length = [b[5], b[6], b[7]];
        let mut lun = [0u8; 8];
        lun.copy_from_slice(&b[8..16]);
        let initiator_task_tag = u32::from_be_bytes(b[16..20].try_into()?);
        let target_transfer_tag = u32::from_be_bytes(b[20..24].try_into()?);
        let exp_stat_sn = u32::from_be_bytes(b[24..28].try_into()?);
        let mut reserved3 = [0u8; 8];
        reserved3.copy_from_slice(&b[28..36]);
        let data_sn = u32::from_be_bytes(b[36..40].try_into()?);
        let buffer_offset = u32::from_be_bytes(b[40..44].try_into()?);
        let reserved4 = u32::from_be_bytes(b[44..48].try_into()?);

        Ok(Self {
            opcode,
            flags,
            reserved2,
            total_ahs_length,
            data_segment_length,
            lun,
            initiator_task_tag,
            target_transfer_tag,
            exp_stat_sn,
            reserved3,
            data_sn,
            buffer_offset,
            reserved4,
        })
    }
}

impl FromBytes for ScsiDataOut {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiDataOut {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]> {
        Ok(self.to_bhs_bytes())
    }

    fn get_opcode(&self) -> &BhsOpcode {
        &self.opcode
    }

    fn get_initiator_task_tag(&self) -> u32 {
        self.initiator_task_tag
    }

    fn get_ahs_length_bytes(&self) -> usize {
        (self.total_ahs_length as usize) * 4
    }

    fn set_ahs_length_bytes(&mut self, len_bytes: u8) {
        self.total_ahs_length = len_bytes >> 2;
    }

    fn get_data_length_bytes(&self) -> usize {
        u32::from_be_bytes([
            0,
            self.data_segment_length[0],
            self.data_segment_length[1],
            self.data_segment_length[2],
        ]) as usize
    }

    fn set_data_length_bytes(&mut self, len: u32) {
        let be = len.to_be_bytes();
        self.data_segment_length = [be[1], be[2], be[3]];
    }
}

/// Билдер для SCSI Data-Out (opcode 0x26).
///
/// Делит payload на чанки по MaxRecvDataSegmentLength (MRDSL) и для каждого
/// чанка:
/// - выставляет F=1 только на последнем чанке,
/// - задаёт DataSN по порядку (start_data_sn + i),
/// - ставит BufferOffset как суммарный размер уже отправленных чанков,
/// - DataSegmentLength = размер текущего чанка (без padding).
#[derive(Debug, Default)]
pub struct ScsiDataOutBuilder {
    pub header: ScsiDataOut,

    enable_header_digest: bool,
    enable_data_digest: bool,
}

impl ScsiDataOutBuilder {
    pub const DEFAULT_TTT: u32 = 0xFFFF_FFFF;

    pub fn new() -> Self {
        Self {
            header: ScsiDataOut {
                opcode: BhsOpcode {
                    flags: IfFlags::empty(),
                    opcode: Opcode::ScsiDataOut,
                },
                ..Default::default()
            },
            enable_header_digest: false,
            enable_data_digest: false,
        }
    }

    /// (обычно не трогаем вручную — выставляется в `to_bytes` на последнем
    /// чанке)
    pub fn final_flag(mut self, set: bool) -> Self {
        if set {
            self.header.flags.insert(DataOutFlags::F);
        } else {
            self.header.flags.remove(DataOutFlags::F);
        }
        self
    }

    pub fn lun(mut self, lun: &[u8; 8]) -> Self {
        self.header.lun.copy_from_slice(lun);
        self
    }

    pub fn initiator_task_tag(mut self, itt: u32) -> Self {
        self.header.initiator_task_tag = itt;
        self
    }

    /// Для unsolicited/initial burst — обычно 0xFFFF_FFFF.
    /// Для R2T — ставим TTT из R2T.
    pub fn target_transfer_tag(mut self, ttt: u32) -> Self {
        self.header.target_transfer_tag = ttt;
        self
    }

    pub fn exp_stat_sn(mut self, sn: u32) -> Self {
        self.header.exp_stat_sn = sn;
        self
    }

    pub fn with_header_digest(mut self) -> Self {
        self.enable_header_digest = true;
        self
    }

    pub fn with_data_digest(mut self) -> Self {
        self.enable_data_digest = true;
        self
    }
}
