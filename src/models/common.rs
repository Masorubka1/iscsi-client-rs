use anyhow::Result;
use enum_dispatch::enum_dispatch;

use crate::{cfg::config::Config, models::opcode::BhsOpcode};

pub const HEADER_LEN: usize = 48;

/// Common functionality for any iSCSI PDU “Basic Header Segment” (BHS).
///
/// A BHS is always 48 bytes long; higher‐level PDUs then may
/// carry additional AHS sections, a variable-length DataSegment,
/// and optional digests.  This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
#[enum_dispatch]
pub trait BasicHeaderSegment: Sized {
    fn to_bhs_bytes(&self) -> Result<[u8; HEADER_LEN]>;

    /// first u8 of BHS
    fn get_opcode(&self) -> &BhsOpcode;

    /// Expose Initiator Task Tag of this PDU
    fn get_initiator_task_tag(&self) -> u32;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn get_ahs_length_bytes(&self) -> usize;

    /// Number of extra AHS bytes (always a multiple of 4).
    fn set_ahs_length_bytes(&mut self, len: u8);

    /// Get number of actual payload bytes in the DataSegment.
    fn get_data_length_bytes(&self) -> usize;

    /// Set number of actual payload bytes in the DataSegment.
    fn set_data_length_bytes(&mut self, len: u32);

    /// Number of actual payload bytes in the DataSegment.
    fn total_length_bytes(&self) -> usize {
        let padding_ahs = (4 - (self.get_ahs_length_bytes() % 4)) % 4;
        let padding_data_segment = (4 - (self.get_data_length_bytes() % 4)) % 4;
        HEADER_LEN
            + self.get_ahs_length_bytes()
            + padding_ahs
            + self.get_data_length_bytes()
            + padding_data_segment
    }
}

pub trait Builder: Sized {
    type Header: AsRef<[u8]>;
    /// Append raw bytes to the DataSegment (automatically updates
    /// the length fields in the BHS).
    /// A builder-like copy of `self` with `more` appended.
    fn append_data(&mut self, more: Vec<u8>);

    /// Consume this header-plus-data builder and produce a
    /// `(header_bytes, data_bytes)` pair ready for writing.
    fn build(&mut self, cfg: &Config) -> Result<Vec<(Self::Header, Vec<u8>)>>;
}
