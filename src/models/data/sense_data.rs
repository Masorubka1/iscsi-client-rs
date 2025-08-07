use std::fmt;

use anyhow::{Context, Result, anyhow};

/// Sense data must be ≥ 18 bytes for fixed format.
pub const FIXED_MIN_LEN: usize = 18;

/// SPC-4 Table 43 — Fixed format sense-data byte layout
#[repr(C)]
#[derive(Default, PartialEq)]
pub struct SenseData {
    pub valid: bool,        // bit7 of byte0
    pub response_code: u8,  // low-7 bits of byte0
    pub sense_key: u8,      // high-4 bits of byte2
    pub ili: bool,          // bit1 of byte2
    pub eom: bool,          // bit2 of byte2
    pub filemark: bool,     // bit7 of byte2
    pub information: u32,   // bytes 3-6
    pub additional_len: u8, // byte7
    pub cmd_specific: u32,  // bytes 8-11
    pub asc: u8,            // Additional Sense Code
    pub ascq: u8,           /* Additional Sense Code Qualifier
                             * -- the remaining bytes (fru, sks…) are rarely used; add
                             * when needed */
}

impl SenseData {
    /// Parse *fixed-format* sense-data (SPC-4 § 4.5.3).
    ///
    /// The buffer must be at least 18 bytes long.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < FIXED_MIN_LEN {
            return Err(anyhow!(
                "sense buffer too small: {} < {FIXED_MIN_LEN}",
                buf.len()
            ));
        }

        let valid = buf[0] & 0x80 != 0;
        let response_code = buf[0] & 0x7F;
        let filemark = buf[2] & 0x80 != 0;
        let eom = buf[2] & 0x40 != 0;
        let ili = buf[2] & 0x20 != 0;
        let sense_key = buf[2] & 0x0F;

        let information = u32::from_be_bytes(
            buf[3..7]
                .try_into()
                .context("failed to read Information field (bytes 3‥6)")?,
        );

        let additional_len = buf[7];

        let cmd_specific = u32::from_be_bytes(
            buf[8..12]
                .try_into()
                .context("failed to read Cmd-specific field (bytes 8‥11)")?,
        );

        let asc = buf[12];
        let ascq = buf[13];

        Ok(Self {
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

/// Return the SPC-4 description for a given ASC/ASCQ pair.
///
/// * If the pair is not present in the official table, returns `"UNSPECIFIED /
///   vendor specific"`.
#[inline]
pub fn asc_ascq_to_str(asc: u8, ascq: u8) -> &'static str {
    hot_table(asc, ascq).unwrap_or("UNSPECIFIED / vendor specific")
}

fn hot_table(asc: u8, ascq: u8) -> Option<&'static str> {
    Some(match (asc, ascq) {
        (0x00, 0x00) => "No additional sense information",
        (0x02, 0x04) => "Not ready – LUN not ready, format in progress",
        (0x03, 0x11) => "Medium error – unrecovered read error",
        (0x04, 0x01) => "Logical unit is in process of becoming ready",
        (0x05, 0x20) => "Illegal request – invalid command information field",
        (0x24, 0x00) => "Illegal request – invalid field in CDB",
        (0x25, 0x00) => "Illegal request – logical unit not supported",
        (0x3A, 0x00) => "Medium not present",
        (0x40, 0x00) => "Data integrity error",
        _ => return None,
    })
}
