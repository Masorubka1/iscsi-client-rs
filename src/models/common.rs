use anyhow::Result;

use crate::{cfg::config::Config, models::opcode::BhsOpcode};

/// Common functionality for any iSCSI PDU “Basic Header Segment” (BHS).
///
/// A BHS is always 48-52 bytes long; higher‐level PDUs then may
/// carry additional AHS sections, a variable-length DataSegment,
/// and optional digests.  This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
pub trait BasicHeaderSegment: Sized {
    /// first u8 of BHS
    fn get_opcode(&self) -> BhsOpcode;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn ahs_length_bytes(&self) -> usize;

    /// Number of actual payload bytes in the DataSegment.
    fn data_length_bytes(&self) -> usize;

    /// Serialize the full PDU (header + data segment + padding) to raw bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Parse a PDU from raw bytes (header + data segment + padding).
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Encode the full PDU into a continuous hex string (no spaces).
    fn to_hex(&self) -> String {
        // takes the raw bytes and hex-encodes them
        hex::encode(self.to_bytes())
    }

    /// Decode a hex string (ignoring any whitespace) and parse into the PDU.
    fn from_hex(hex_str: &str) -> Result<Self> {
        // strip out whitespace
        let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
        // decode hex into bytes
        let bytes = hex::decode(&cleaned)
            .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
        // parse those bytes
        Self::from_bytes(&bytes)
    }
}

pub trait Builder: Sized {
    type Header: AsRef<[u8]>;
    /// Append raw bytes to the DataSegment (automatically updates
    /// the length fields in the BHS).
    /// A builder-like copy of `self` with `more` appended.
    fn append_data(self, more: Vec<u8>) -> Self;

    /// Consume this header-plus-data builder and produce a
    /// `(header_bytes, data_bytes)` pair ready for writing.
    fn build(self, cfg: &Config) -> Result<(Self::Header, Vec<u8>)>;
}
