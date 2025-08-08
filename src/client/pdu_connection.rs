use anyhow::Result;

use crate::{
    cfg::config::Config,
    models::{
        common::{BasicHeaderSegment, Builder},
        opcode::BhsOpcode,
    },
};

/// Trait for serializing a Protocol Data Unit (PDU) into bytes.
pub trait ToBytes: Sized {
    // The fixed length of the PDU header in bytes.
    // rust now don`t support compile time array length
    type Header: AsRef<[u8]>;

    /// Consume the PDU builder or object and produce:
    /// - A fixed-size array of `HEADER_LEN` bytes representing the PDU header.
    /// - A `Vec<u8>` containing the variable-length data segment.
    /// - A `Option<Vec<u8>>` containing the data-digest data segment.
    fn to_bytes(&mut self, cfg: &Config) -> Result<Vec<(Self::Header, Vec<u8>)>>;
}

/// Trait for deserializing a full PDU from raw bytes.
pub trait FromBytes: Sized + BasicHeaderSegment {
    /// Parse the full PDU from a contiguous byte buffer.
    ///
    /// The parsed `Response` (often a tuple of header struct, payload bytes,
    /// and digest), or an error if parsing fails.
    fn from_bhs_bytes(bytes: &[u8]) -> Result<Self> {
        let _ = BhsOpcode::try_from(bytes[0])
            .map_err(|e| anyhow::anyhow!("invalid opcode: {}", e))?;
        Self::from_bhs_bytes(bytes)
    }
}

impl<B> ToBytes for B
where B: Builder
{
    type Header = B::Header;

    fn to_bytes(&mut self, cfg: &Config) -> Result<Vec<(Self::Header, Vec<u8>)>> {
        self.build(cfg)
    }
}
