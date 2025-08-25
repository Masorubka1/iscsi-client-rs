// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use anyhow::{Context, Result, anyhow};

use crate::models::data::Entry;

pub const FIXED_MIN_LEN: usize = 18;

#[repr(C)]
#[derive(Default, PartialEq)]
pub struct SenseData {
    pub valid: bool,
    pub response_code: u8,
    pub sense_key: u8,
    pub ili: bool,
    pub eom: bool,
    pub filemark: bool,
    pub information: u32,
    pub additional_len: u8,
    pub cmd_specific: u32,
    pub asc: u8,
    pub ascq: u8,
}

impl SenseData {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FIXED_MIN_LEN {
            return Err(anyhow!("sense buffer too small: {}", buf.len()));
        }

        let sense = if buf.len() >= 3 {
            let maybe_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let rc = buf[2] & 0x7F;
            if maybe_len + 2 == buf.len() && matches!(rc, 0x70..=0x73) {
                &buf[2..]
            } else {
                buf
            }
        } else {
            buf
        };

        if sense.len() < FIXED_MIN_LEN {
            return Err(anyhow!(
                "sense payload too small after prefix stripping: {}",
                sense.len()
            ));
        }

        let response_code = sense[0] & 0x7F;

        match response_code {
            0x70 | 0x71 => Self::parse_fixed(sense),
            0x72 | 0x73 => Err(anyhow!(
                "descriptor-format sense (0x{:02x}) is not supported yet",
                response_code
            )),
            other => Err(anyhow!("unknown sense response code 0x{:02x}", other)),
        }
    }

    fn parse_fixed(sense: &[u8]) -> Result<Self> {
        if sense.len() < FIXED_MIN_LEN {
            return Err(anyhow!("fixed sense too small: {}", sense.len()));
        }

        let valid = sense[0] & 0x80 != 0;
        let response_code = sense[0] & 0x7F;

        let filemark = sense[2] & 0x80 != 0;
        let eom = sense[2] & 0x40 != 0;
        let ili = sense[2] & 0x20 != 0;
        let sense_key = sense[2] & 0x0F;

        let information = u32::from_be_bytes(
            sense[3..7]
                .try_into()
                .context("failed to read Information (3..6)")?,
        );

        let additional_len = sense[7];

        let needed = 8usize + (additional_len as usize);
        if sense.len() < needed {
            return Err(anyhow!(
                "sense length mismatch: have {}, need at least {} (additional_len={})",
                sense.len(),
                needed,
                additional_len
            ));
        }

        let cmd_specific = u32::from_be_bytes(
            sense[8..12]
                .try_into()
                .context("failed to read Cmd-specific (8..11)")?,
        );

        let asc = sense[12];
        let ascq = sense[13];

        Ok(SenseData {
            valid,
            response_code,
            sense_key,
            ili,
            eom,
            filemark,
            information,
            additional_len,
            cmd_specific,
            asc,
            ascq,
        })
    }
}

impl fmt::Debug for SenseData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenseData")
            .field("valid", &self.valid)
            .field(
                "response_code",
                &format_args!("{:#04x}", self.response_code),
            )
            .field("sense_key", &format_args!("{:#x}", self.sense_key))
            .field("filemark", &self.filemark)
            .field("eom", &self.eom)
            .field("ili", &self.ili)
            .field("information", &self.information)
            .field("additional_len", &self.additional_len)
            .field("cmd_specific", &self.cmd_specific)
            .field("asc", &format_args!("{:#04x}", self.asc))
            .field("ascq", &format_args!("{:#04x}", self.ascq))
            .field("description", &asc_ascq_to_str(self.asc, self.ascq))
            .finish()
    }
}

/// Human-readable description for ASC/ASCQ from the generated SPC table.
/// Falls back to a generic message if the pair is not listed (vendor-specific).
#[inline]
pub fn asc_ascq_to_str(asc: u8, ascq: u8) -> &'static str {
    Entry::lookup(asc, ascq).unwrap_or("UNSPECIFIED / vendor specific")
}
