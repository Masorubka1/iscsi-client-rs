use crate::models::opcode::BhsOpcode;

/// Common functionality for any iSCSI PDU “Basic Header Segment” (BHS).
///
/// A BHS is always 48 bytes long; higher‐level PDUs then may
/// carry additional AHS sections, a variable-length DataSegment,
/// and optional digests.  This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
pub trait BasicHeaderSegment: Sized {
    /// Serialize BHS in 48 bytes
    fn get_opcode(&self) -> BhsOpcode;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn ahs_length_bytes(&self) -> usize;

    /// Number of actual payload bytes in the DataSegment.
    fn data_length_bytes(&self) -> usize;
}

pub trait Builder: Sized {
    /// Append raw bytes to the DataSegment (automatically updates
    /// the length fields in the BHS).
    /// A builder-like copy of `self` with `more` appended.
    fn append_data(self, more: Vec<u8>) -> Self;

    /// Consume this header-plus-data builder and produce a
    /// `(header_bytes, data_bytes)` pair ready for writing.
    fn build(self) -> ([u8; 48], Vec<u8>);
}
