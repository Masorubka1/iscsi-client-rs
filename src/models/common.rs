//! This module defines common traits and constants for iSCSI Protocol Data
//! Units (PDUs). It includes traits for handling data transmission, managing
//! the Basic Header Segment (BHS), and building PDUs with data segments.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fmt;

use anyhow::Result;
use enum_dispatch::enum_dispatch;
use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U32, U64};

use crate::models::opcode::BhsOpcode;

/// The fixed length of the Basic Header Segment (BHS) in bytes.
pub const HEADER_LEN: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("initiator task tag 0xffffffff is reserved")]
pub struct InvalidInitiatorTaskTag;

/// Initiator Task Tag stored in iSCSI network byte order.
#[repr(transparent)]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
pub struct InitiatorTaskTag(U32<BigEndian>);

impl InitiatorTaskTag {
    pub(crate) const RESERVED: Self = Self(U32::new(u32::MAX));

    pub fn new(value: u32) -> Result<Self> {
        if value == u32::MAX {
            return Err(InvalidInitiatorTaskTag.into());
        }
        Ok(Self(U32::new(value)))
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for InitiatorTaskTag {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}

impl From<InitiatorTaskTag> for u32 {
    fn from(value: InitiatorTaskTag) -> Self {
        value.get()
    }
}

impl fmt::Display for InitiatorTaskTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// Target Task Tag stored in iSCSI network byte order.
#[repr(transparent)]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
pub struct TargetTaskTag(U32<BigEndian>);

impl TargetTaskTag {
    pub const RESERVED: Self = Self(U32::new(u32::MAX));

    pub fn new(value: u32) -> Self {
        Self(U32::new(value))
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<u32> for TargetTaskTag {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<TargetTaskTag> for u32 {
    fn from(value: TargetTaskTag) -> Self {
        value.get()
    }
}

impl fmt::Display for TargetTaskTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// Logical Unit Number stored in iSCSI network byte order.
#[repr(transparent)]
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
)]
pub struct LogicalUnitNumber(U64<BigEndian>);

impl LogicalUnitNumber {
    pub fn new(value: u64) -> Self {
        Self(U64::new(value))
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl From<u64> for LogicalUnitNumber {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<LogicalUnitNumber> for u64 {
    fn from(value: LogicalUnitNumber) -> Self {
        value.get()
    }
}

/// Common helper-trait for PDUs that may be fragmented into several
/// wire-frames (RFC 7143 ― “F”/“C” bits).
///
/// *Most* iSCSI PDUs are transferred in a single frame, but a few
/// (Text, Login, SCSI Command/Data, …) allow the sender to split the
/// **Data-Segment** into a sequence of chunks whose order is determined
/// by the transport; the target relies only on the *Continue* and *Final*
/// flags found in byte 1 of every Basic-Header-Segment.
///
/// Trait for PDU types that support data transmission control flags
///
/// Implementing `SendingData` lets generic helpers (e.g. the
/// `PDUWithData` builder or the `Connection` read-loop) toggle and query
/// those flags **without** knowing the concrete PDU type.
/// Provides methods to manage Final (F) and Continue (C) bits used in multi-PDU
/// sequences.
#[enum_dispatch]
pub trait SendingData: Sized {
    /// Return the current state of the **Final (F)** bit.
    fn get_final_bit(&self) -> bool;

    /// Force **F = 1** (and, if your PDU has it, clear **C**).
    fn set_final_bit(&mut self);

    /// Return the current state of the **Continue (C)** bit.
    fn get_continue_bit(&self) -> bool;

    /// Force **C = 1** (and clear **F**).
    fn set_continue_bit(&mut self);
}

/// Common functionality for any iSCSI PDU Basic Header Segment (BHS)
///
/// A BHS is always 48 bytes long according to RFC 7143; higher‐level PDUs then
/// may carry additional AHS sections, a variable-length DataSegment,
/// and optional digests. This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
///
/// All iSCSI PDU types must implement this trait to provide basic header
/// operations.
#[enum_dispatch]
pub trait BasicHeaderSegment: Sized + SendingData {
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> Result<()>;

    /// first u8 of BHS
    fn get_opcode(&self) -> Result<BhsOpcode>;

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
    #[inline]
    fn total_length_bytes(&self) -> usize {
        let padding_ahs = (4 - (self.get_ahs_length_bytes() % 4)) % 4;
        let padding_data_segment = (4 - (self.get_data_length_bytes() % 4)) % 4;

        HEADER_LEN
            + self.get_ahs_length_bytes()
            + padding_ahs
            + self.get_data_length_bytes()
            + padding_data_segment
    }

    #[inline]
    fn get_header_diggest(&self, enable_header_digest: bool) -> usize {
        4 * enable_header_digest as usize
    }

    #[inline]
    fn get_data_diggest(&self, enable_data_digest: bool) -> usize {
        4 * (self.get_data_length_bytes() > 0) as usize * enable_data_digest as usize
    }
}

// Forward SendingData to &mut T
impl<T: SendingData> SendingData for &mut T {
    #[inline]
    fn get_final_bit(&self) -> bool {
        (**self).get_final_bit()
    }

    #[inline]
    fn set_final_bit(&mut self) {
        (**self).set_final_bit()
    }

    #[inline]
    fn get_continue_bit(&self) -> bool {
        (**self).get_continue_bit()
    }

    #[inline]
    fn set_continue_bit(&mut self) {
        (**self).set_continue_bit()
    }
}

// Forward BasicHeaderSegment to &mut T
impl<T: BasicHeaderSegment> BasicHeaderSegment for &mut T {
    #[inline]
    fn to_bhs_bytes(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        (**self).to_bhs_bytes(buf)
    }

    #[inline]
    fn get_opcode(&self) -> anyhow::Result<BhsOpcode> {
        (**self).get_opcode()
    }

    #[inline]
    fn get_initiator_task_tag(&self) -> u32 {
        (**self).get_initiator_task_tag()
    }

    #[inline]
    fn get_ahs_length_bytes(&self) -> usize {
        (**self).get_ahs_length_bytes()
    }

    #[inline]
    fn set_ahs_length_bytes(&mut self, len: u8) {
        (**self).set_ahs_length_bytes(len)
    }

    #[inline]
    fn get_data_length_bytes(&self) -> usize {
        (**self).get_data_length_bytes()
    }

    #[inline]
    fn set_data_length_bytes(&mut self, len: u32) {
        (**self).set_data_length_bytes(len)
    }

    #[inline]
    fn total_length_bytes(&self) -> usize {
        (**self).total_length_bytes()
    }

    #[inline]
    fn get_header_diggest(&self, en: bool) -> usize {
        (**self).get_header_diggest(en)
    }

    #[inline]
    fn get_data_diggest(&self, en: bool) -> usize {
        (**self).get_data_diggest(en)
    }
}

/// A helper-trait for **builder objects** that construct a complete
/// iSCSI PDU: a 48-byte Basic-Header-Segment (BHS) plus the optional
/// **Data-Segment** and digests.
///
/// The concrete type that implements `Builder` usually owns a
/// *(header + payload)* pair and offers additional, PDU-specific setter
/// methods (e.g. `.lun( … )`, `.read()`, …).
///
/// When your application is ready to send the packet you call
/// [`Builder::build`]; the helper splits the payload into chunks that
/// respect *MaxRecvDataSegmentLength* and automatically toggles the
/// **F/C** bits on the header copies.
/// Trait for building iSCSI PDUs with progressive data assembly.
///
/// Provides functionality to construct PDU frames by appending data segments
/// and managing digest calculations. Implementations handle the wire format
/// serialization with proper padding and digest generation.
pub trait Builder: Sized {
    /// The concrete buffer type used to return the encoded header.
    type Header: AsRef<[u8]>;
    type Body: AsRef<[u8]>;

    /// Append raw bytes to the **Data-Segment** and update the
    /// `DataSegmentLength` field inside the owned header.
    fn append_data(&mut self, more: &[u8]);

    /// Finish the builder and produce one or more ready-to-send
    /// `(header_bytes, data_bytes)` frames.
    ///
    /// The `cfg` parameter is typically used to honour negotiated session
    /// limits such as *MaxRecvDataSegmentLength*.
    fn build(
        &mut self,
        max_recv_data_segment_length: usize,
    ) -> Result<(Self::Header, Self::Body)>;
}

#[cfg(test)]
mod wire_type_tests {
    use zerocopy::IntoBytes;

    use super::{InitiatorTaskTag, LogicalUnitNumber, TargetTaskTag};

    #[test]
    fn task_tag_is_big_endian_and_rejects_reserved_value() {
        let tag = InitiatorTaskTag::new(0x0102_0304).expect("valid ITT");

        assert_eq!(tag.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
        assert!(InitiatorTaskTag::new(u32::MAX).is_err());
    }

    #[test]
    fn lun_is_big_endian() {
        let lun = LogicalUnitNumber::new(0x0102_0304_0506_0708);

        assert_eq!(
            lun.as_bytes(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn target_task_tag_is_big_endian_and_allows_reserved_value() {
        let tag = TargetTaskTag::new(0x0102_0304);

        assert_eq!(tag.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(TargetTaskTag::RESERVED.get(), u32::MAX);
    }
}
