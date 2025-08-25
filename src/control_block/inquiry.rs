// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

//! INQUIRY (6) — CDB fillers that write into a provided 16-byte buffer.
//! Returns the CDB length actually used (always 6 bytes).
//!
//! CDB layout (SPC):
//!   [0] = 0x12 (INQUIRY)
//!   [1] = EVPD (bit 0); other bits reserved (CMDDT obsolete → 0)
//!   [2] = Page Code (only when EVPD=1; else 0)
//!   [3] = Subpage Code (only meaningful for some VPD pages; usually 0)
//!   [4] = Allocation Length (u8)
//!   [5] = Control

use anyhow::{Result, bail};

pub const INQUIRY_OPCODE: u8 = 0x12;

/// Common VPD page codes (subset).
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VpdPage {
    SupportedPages = 0x00,
    UnitSerial = 0x80,
    DeviceId = 0x83,
    ExtendedInquiry = 0x86,
    BlockLimits = 0xB0,                // SBC
    BlockDeviceCharacteristics = 0xB1, // SBC
    LbProvisioning = 0xB2,             // SBC
}

impl From<VpdPage> for u8 {
    #[inline]
    fn from(p: VpdPage) -> u8 {
        p as u8
    }
}

impl TryFrom<u8> for VpdPage {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(v: u8) -> Result<Self> {
        use VpdPage::*;
        Ok(match v {
            0x00 => SupportedPages,
            0x80 => UnitSerial,
            0x83 => DeviceId,
            0x86 => ExtendedInquiry,
            0xB0 => BlockLimits,
            0xB1 => BlockDeviceCharacteristics,
            0xB2 => LbProvisioning,
            _ => bail!("invalid vpd page: {v}"),
        })
    }
}

/// Fill a **Standard INQUIRY (EVPD=0)** CDB.
/// Sets Page Code/Subpage to 0.
#[inline]
pub fn fill_inquiry_standard(cdb: &mut [u8; 16], allocation_len: u8, control: u8) {
    cdb.fill(0);
    cdb[0] = INQUIRY_OPCODE;
    cdb[1] = 0x00; // EVPD=0
    cdb[2] = 0x00; // page code ignored when EVPD=0
    cdb[3] = 0x00;
    cdb[4] = allocation_len;
    cdb[5] = control;
}

/// Convenience: Standard INQUIRY with control=0.
#[inline]
pub fn fill_inquiry_standard_simple(cdb: &mut [u8; 16], allocation_len: u8) {
    fill_inquiry_standard(cdb, allocation_len, 0x00)
}

/// Fill a **VPD INQUIRY (EVPD=1, subpage=0)** CDB.
#[inline]
pub fn fill_inquiry_vpd(
    cdb: &mut [u8; 16],
    page: VpdPage,
    allocation_len: u8,
    control: u8,
) {
    fill_inquiry_vpd_with_subpage(cdb, page, 0x00, allocation_len, control)
}

/// Fill a **VPD INQUIRY (EVPD=1, explicit subpage)** CDB.
#[inline]
pub fn fill_inquiry_vpd_with_subpage(
    cdb: &mut [u8; 16],
    page: VpdPage,
    subpage_code: u8,
    allocation_len: u8,
    control: u8,
) {
    cdb.fill(0);
    cdb[0] = INQUIRY_OPCODE;
    cdb[1] = 0x01; // EVPD=1
    cdb[2] = page.into();
    cdb[3] = subpage_code;
    cdb[4] = allocation_len;
    cdb[5] = control;
}

/// Convenience: VPD INQUIRY (subpage=0) with control=0.
#[inline]
pub fn fill_inquiry_vpd_simple(
    cdb: &mut [u8; 16],
    page_code: VpdPage,
    allocation_len: u8,
) {
    fill_inquiry_vpd(cdb, page_code, allocation_len, 0x00)
}

/// Parsers for INQUIRY responses:
/// - Standard INQUIRY (EVPD=0)
/// - VPD 0x00 (Supported VPD Pages)
/// - VPD 0x80 (Unit Serial Number)
/// - VPD 0x83 (Device Identification — simplified descriptors)
#[derive(Debug, Clone)]
pub struct InquiryStandard {
    pub peripheral_qualifier: u8, // bits 7..5 of byte0
    pub device_type: u8,          // bits 4..0 of byte0
    pub rmb: bool,                // byte1 bit7
    pub version: u8,              // byte2
    pub response_data_format: u8, // byte3 low nibble
    pub additional_length: u8,    // byte4
    pub vendor_id: String,        // bytes 8..16
    pub product_id: String,       // bytes 16..32
    pub product_rev: String,      // bytes 32..36
}

impl InquiryStandard {
    pub fn device_type_str(&self) -> &'static str {
        match self.device_type {
            0x00 => "Direct-access block (disk)",
            0x01 => "Sequential-access (tape)",
            0x02 => "Printer (obsolete)",
            0x03 => "Processor",
            0x04 => "WORM",
            0x05 => "CD/DVD",
            0x06 => "Scanner (obsolete)",
            0x07 => "Optical memory",
            0x08 => "Medium changer",
            0x09 => "Communications",
            0x0C => "Storage array controller",
            0x0D => "Enclosure services",
            0x0E => "RBC",
            0x0F => "Optical card",
            0x11 => "Object-based storage",
            0x12 => "Automation/Drive Interface",
            _ => "Unknown/Reserved",
        }
    }
}

/// Parse a Standard INQUIRY (EVPD=0) response (minimum 36 bytes).
pub fn parse_inquiry_standard(buf: &[u8]) -> Result<InquiryStandard> {
    if buf.len() < 36 {
        bail!("INQUIRY buffer too short: {}", buf.len());
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let b3 = buf[3];

    let peripheral_qualifier = (b0 >> 5) & 0x07;
    let device_type = b0 & 0x1F;
    let rmb = (b1 & 0x80) != 0;
    let version = buf[2];
    let response_data_format = b3 & 0x0F;
    let additional_length = buf[4];

    Ok(InquiryStandard {
        peripheral_qualifier,
        device_type,
        rmb,
        version,
        response_data_format,
        additional_length,
        vendor_id: trim_ascii(&buf[8..16]),
        product_id: trim_ascii(&buf[16..32]),
        product_rev: trim_ascii(&buf[32..36]),
    })
}

/// Generic VPD header view: returns (page_code, payload)
fn vpd_payload(buf: &[u8]) -> Result<(u8, &[u8])> {
    if buf.len() < 4 {
        bail!("VPD buffer too short: {}", buf.len());
    }
    // byte0: PQ/DT (ignored here), byte1: page code, byte2..3: page length (BE)
    let page_code = buf[1];
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        bail!(
            "VPD truncated: header says {} bytes, have {}",
            len,
            buf.len().saturating_sub(4)
        );
    }
    Ok((page_code, &buf[4..4 + len]))
}

/// VPD 0x00 — Supported VPD Pages
pub fn parse_vpd_supported_pages(buf: &[u8]) -> Result<Vec<u8>> {
    let (pc, payload) = vpd_payload(buf)?;
    if pc != 0x00 {
        bail!("expected VPD page 0x00, got 0x{:02X}", pc);
    }
    Ok(payload.to_vec()) // each byte is a page code
}

/// VPD 0x80 — Unit Serial Number (ASCII, space-padded)
pub fn parse_vpd_unit_serial(buf: &[u8]) -> Result<String> {
    let (pc, payload) = vpd_payload(buf)?;
    if pc != 0x80 {
        bail!("expected VPD page 0x80, got 0x{:02X}", pc);
    }
    Ok(trim_ascii(payload))
}

/// VPD 0x83 — Device Identification (simplified)
///
/// We parse a list of Identification Descriptors with minimal fields:
/// - code_set (low 4 bits of byte0)
/// - piv (byte1 bit7)
/// - association (byte1 bits6..4)
/// - id_type (byte1 low 4 bits)
/// - identifier (as String: ASCII/UTF-8 decoded; otherwise hex)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdDescriptor {
    pub code_set: u8,
    pub piv: bool,
    pub association: u8,
    pub id_type: u8,
    pub identifier: String,
}

pub fn parse_vpd_device_id(buf: &[u8]) -> Result<Vec<DeviceIdDescriptor>> {
    let (pc, p) = vpd_payload(buf)?;
    if pc != 0x83 {
        bail!("expected VPD page 0x83, got 0x{:02X}", pc);
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= p.len() {
        let b0 = p[off];
        let b1 = p[off + 1];
        let len = u16::from_be_bytes([p[off + 2], p[off + 3]]) as usize;
        let start = off + 4;
        let end = start.saturating_add(len);
        if end > p.len() {
            // Stop on truncated descriptor (be permissive)
            break;
        }

        let code_set = b0 & 0x0F;
        let piv = (b1 & 0x80) != 0;
        let association = (b1 >> 4) & 0x03;
        let id_type = b1 & 0x0F;
        let id_bytes = &p[start..end];

        let identifier = match code_set {
            0x02 => trim_ascii(id_bytes), // ASCII
            0x03 => String::from_utf8_lossy(id_bytes).trim().to_string(), // UTF-8
            _ => hex_bytes(id_bytes),
        };

        out.push(DeviceIdDescriptor {
            code_set,
            piv,
            association,
            id_type,
            identifier,
        });

        off = end;
    }
    Ok(out)
}

fn trim_ascii(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .map(|&b| if b.is_ascii() { b as char } else { '?' })
        .collect();
    s.trim().to_string()
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut s, "{:02X}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_std_inquiry_min() {
        // Minimal 36-byte standard INQUIRY (EVPD=0)
        let mut b = [0u8; 36];
        b[0] = 0x00; // DT=0x00 disk
        b[1] = 0x00;
        b[2] = 0x06; // SPC-4-ish
        b[3] = 0x02; // RDF=2
        b[4] = 31; // n-4 bytes after byte4
        b[8..16].copy_from_slice(b"LIO-ORG ");
        b[16..32].copy_from_slice(b"TCMU device     ");
        b[32..36].copy_from_slice(b"0020");
        let s = parse_inquiry_standard(&b).expect("WTF");
        assert_eq!(s.device_type, 0x00);
        assert_eq!(s.vendor_id, "LIO-ORG");
        assert_eq!(s.product_id, "TCMU device");
        assert_eq!(s.product_rev, "0020");
    }

    #[test]
    fn parse_vpd_supported() {
        // PQ/DT = disk, page=0x00, len=3, payload: 0x00,0x80,0x83
        let b = [0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x83];
        let mut buf = Vec::new();
        buf.extend_from_slice(&b);
        let pages = parse_vpd_supported_pages(&buf).expect("WTF");
        assert_eq!(pages, vec![0x00, 0x80, 0x83]);
    }

    #[test]
    fn parse_vpd_device_id_basic() {
        // One ASCII T10 descriptor (code_set=ASCII=0x02, id_type=vendor-specific=0x00)
        // desc: b0=0x02, b1=assoc=0, id_type=0 -> 0x00, len=4, id="ABCD"
        let mut payload = vec![0x02, 0x00, 0x00, 0x04];
        payload.extend_from_slice(b"ABCD");
        // Wrap VPD header: PQ/DT, page=0x83, len=payload.len()
        let mut buf = vec![0x00, 0x83, 0x00, payload.len() as u8];
        buf.extend_from_slice(&payload);
        let v = parse_vpd_device_id(&buf).expect("WTF");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].identifier, "ABCD");
        assert_eq!(v[0].code_set, 0x02);
        assert_eq!(v[0].id_type, 0x00);
    }
}
