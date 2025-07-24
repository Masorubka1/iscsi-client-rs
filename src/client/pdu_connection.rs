use anyhow::Result;

use crate::models::common::Builder;

/// Trait for serializing a Protocol Data Unit (PDU) into bytes.
pub trait ToBytes: Sized {
    // The fixed length of the PDU header in bytes.
    // rust now don`t support compile time array length
    type Header: AsRef<[u8]>;

    /// Consume the PDU builder or object and produce:
    /// - A fixed-size array of `HEADER_LEN` bytes representing the PDU header.
    /// - A `Vec<u8>` containing the variable-length data segment.
    /// - A `Option<Vec<u8>>` containing the data-digest data segment.
    fn to_bytes(self) -> (Self::Header, Vec<u8>);
}

/// Trait for deserializing a full PDU from raw bytes.
pub trait FromBytes: Sized {
    /// The fixed length of the PDU header in bytes.
    ///
    /// rust now don`t support compile time array length
    const HEADER_LEN: usize;

    /// Given only the header bytes, inspect them to determine
    /// the total length of the entire PDU (header + payload + optional digest).
    ///
    /// The total PDU length in bytes, or an error if the header is malformed
    /// or too short.
    fn peek_total_len(header: &[u8]) -> Result<usize>;

    /// Parse the full PDU from a contiguous byte buffer.
    ///
    /// The parsed `Response` (often a tuple of header struct, payload bytes,
    /// and digest), or an error if parsing fails.
    fn from_bytes(buf: &[u8]) -> Result<(Self, Vec<u8>, Option<u32>)>;
}

impl<B> ToBytes for B
where B: Builder
{
    type Header = B::Header;

    fn to_bytes(self) -> (Self::Header, Vec<u8>) {
        self.build()
    }
}
