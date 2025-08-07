use anyhow::{Result, anyhow};
use bitflags::bitflags;

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        opcode::BhsOpcode,
    },
};

bitflags! {
    #[derive(Default, Debug, PartialEq)]
    pub struct DataInFlags: u8 {
        const FINAL = 1 << 7; // Final
        const A = 1 << 6; // Acknowledge (DataACK SNACK, ERL>0)
        // bits 5..3 reserved (0)
        const O = 1 << 2; // Residual Overflow (валиден только при S=1)
        const U = 1 << 1; // Residual Underflow (валиден только при S=1)
        const S = 1 << 0; // Status present (если 1, то F тоже обязан быть 1)
    }
}

impl TryFrom<u8> for DataInFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        DataInFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid DataOutFlags: {:#08b}", value))
    }
}

/// BHS for SCSI Data-In (opcode 0x25)
#[repr(C)]
#[derive(Debug, Default, PartialEq)]
pub struct ScsiDataIn {
    pub opcode: BhsOpcode,            // byte 0  (должен быть 0x25)
    pub flags: DataInFlags,           // byte 1  (F,A,0,0,0,O,U,S)
    pub reserved2: u8,                // byte 2  (reserved)
    pub status_or_rsvd: u8,           // byte 3  (SCSI Status, если S=1; иначе 0)
    pub total_ahs_length: u8,         // byte 4  (кол-во 4-байтных слов AHS)
    pub data_segment_length: [u8; 3], // bytes 5..7
    pub lun: [u8; 8],                 /* bytes 8..15  (LUN или reserved; при A=1
                                       * обязателен) */
    pub initiator_task_tag: u32,  // bytes 16..19
    pub target_transfer_tag: u32, // bytes 20..23 (TTT или 0xffffffff)
    pub stat_sn_or_rsvd: u32,     // bytes 24..27 (StatSN, если S=1; иначе 0)
    pub exp_cmd_sn: u32,          // bytes 28..31
    pub max_cmd_sn: u32,          // bytes 32..35
    pub data_sn: u32,             // bytes 36..39
    pub buffer_offset: u32,       // bytes 40..43
    pub residual_count: u32,      // bytes 44..47 (валиден только при S=1; иначе 0)
}

impl ScsiDataIn {
    #[inline]
    pub fn scsi_status(&self) -> Option<u8> {
        if self.flags.contains(DataInFlags::S) {
            Some(self.status_or_rsvd)
        } else {
            None
        }
    }

    #[inline]
    pub fn set_scsi_status(&mut self, st: Option<u8>) {
        match st {
            Some(s) => {
                self.flags.insert(DataInFlags::S);
                self.flags.insert(DataInFlags::FINAL); // S=1 ⇒ F=1
                self.status_or_rsvd = s;
            },
            None => {
                self.flags.remove(DataInFlags::S);
                self.status_or_rsvd = 0;
                self.stat_sn_or_rsvd = 0;
                self.residual_count = 0;
            },
        }
    }

    #[inline]
    pub fn to_bhs_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = (&self.opcode).into();
        buf[1] = self.flags.bits();
        buf[2] = self.reserved2;
        buf[3] = if self.flags.contains(DataInFlags::S) {
            self.status_or_rsvd
        } else {
            0
        };
        buf[4] = self.total_ahs_length;
        buf[5..8].copy_from_slice(&self.data_segment_length);
        buf[8..16].copy_from_slice(&self.lun);
        buf[16..20].copy_from_slice(&self.initiator_task_tag.to_be_bytes());
        buf[20..24].copy_from_slice(&self.target_transfer_tag.to_be_bytes());
        let stat = if self.flags.contains(DataInFlags::S) {
            self.stat_sn_or_rsvd
        } else {
            0
        };
        buf[24..28].copy_from_slice(&stat.to_be_bytes());
        buf[28..32].copy_from_slice(&self.exp_cmd_sn.to_be_bytes());
        buf[32..36].copy_from_slice(&self.max_cmd_sn.to_be_bytes());
        buf[36..40].copy_from_slice(&self.data_sn.to_be_bytes());
        buf[40..44].copy_from_slice(&self.buffer_offset.to_be_bytes());
        let res = if self.flags.contains(DataInFlags::S) {
            self.residual_count
        } else {
            0
        };
        buf[44..48].copy_from_slice(&res.to_be_bytes());

        buf
    }

    pub fn from_bhs_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(anyhow!("buffer too small for SCSI Data-In BHS"));
        }
        let opcode: BhsOpcode = b[0].try_into()?;
        let flags = DataInFlags::try_from(b[1])?;
        let reserved2 = b[2];
        let status_or_rsvd = b[3];
        let total_ahs_length = b[4];
        let data_segment_length = [b[5], b[6], b[7]];
        let mut lun = [0u8; 8];
        lun.copy_from_slice(&b[8..16]);
        let initiator_task_tag = u32::from_be_bytes(b[16..20].try_into()?);
        let target_transfer_tag = u32::from_be_bytes(b[20..24].try_into()?);
        let stat_sn_or_rsvd = u32::from_be_bytes(b[24..28].try_into()?);
        let exp_cmd_sn = u32::from_be_bytes(b[28..32].try_into()?);
        let max_cmd_sn = u32::from_be_bytes(b[32..36].try_into()?);
        let data_sn = u32::from_be_bytes(b[36..40].try_into()?);
        let buffer_offset = u32::from_be_bytes(b[40..44].try_into()?);
        let residual_count = u32::from_be_bytes(b[44..48].try_into()?);

        Ok(Self {
            opcode,
            flags,
            reserved2,
            status_or_rsvd,
            total_ahs_length,
            data_segment_length,
            lun,
            initiator_task_tag,
            target_transfer_tag,
            stat_sn_or_rsvd,
            exp_cmd_sn,
            max_cmd_sn,
            data_sn,
            buffer_offset,
            residual_count,
        })
    }
}

impl SendingData for ScsiDataIn {
    fn get_final_bit(&self) -> bool {
        self.flags.contains(DataInFlags::FINAL)
    }

    fn set_final_bit(&mut self) {
        // S => F, но F можно ставить и без S
        self.flags.insert(DataInFlags::FINAL);
    }

    fn get_continue_bit(&self) -> bool {
        !self.flags.contains(DataInFlags::FINAL)
    }

    fn set_continue_bit(&mut self) {
        // снимаем Final; если был Status-present, его тоже надо убрать,
        // потому что «S=1 ⇒ F=1» (RFC 7143 §11.8.1)
        self.flags.remove(DataInFlags::FINAL);
        self.flags.remove(DataInFlags::S);
    }
}

impl FromBytes for ScsiDataIn {
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bhs_bytes(bytes)
    }
}

impl BasicHeaderSegment for ScsiDataIn {
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
