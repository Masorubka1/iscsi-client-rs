// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use enum_dispatch::enum_dispatch;

use crate::models::opcode::BhsOpcode;

pub const HEADER_LEN: usize = 48;

/// Common helper-trait for PDUs that may be fragmented into several
/// wire-frames (RFC 7143 ― “F”/“C” bits).
///
/// *Most* iSCSI PDUs are transferred in a single frame, but a few
/// (Text, Login, SCSI Command/Data, …) allow the sender to split the
/// **Data-Segment** into a sequence of chunks whose order is determined
/// by the transport; the target relies only on the *Continue* and *Final*
/// flags found in byte 1 of every Basic-Header-Segment.
///
/// Implementing `SendingData` lets generic helpers (e.g. the
/// `PDUWithData` builder or the `Connection` read-loop) toggle and query
/// those flags **without** knowing the concrete PDU type.
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

/// Common functionality for any iSCSI PDU “Basic Header Segment” (BHS).
///
/// A BHS is always 48 bytes long; higher‐level PDUs then may
/// carry additional AHS sections, a variable-length DataSegment,
/// and optional digests.  This trait encapsulates:
/// 1. extracting lengths out of the BHS,
/// 2. appending to the DataSegment,
/// 3. and finally building the full wire format.
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
    fn get_opcode(&self) -> anyhow::Result<crate::models::opcode::BhsOpcode> {
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
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<(Self::Header, Self::Body)>;
}
