// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;

use crate::models::{
    common::{BasicHeaderSegment, Builder},
    opcode::BhsOpcode,
};

/// A trait for serializing a Protocol Data Unit (PDU) into a byte
/// representation for transmission.
///
/// This trait provides functionality to convert PDU structures into their
/// binary format suitable for sending over the network according to iSCSI
/// protocol specifications.
pub trait ToBytes: Sized {
    // The fixed length of the PDU header in bytes.
    // rust now don`t support compile time array length
    type Header: AsRef<[u8]>;
    type Body: AsRef<[u8]>;

    /// Consume the PDU builder or object and produce:
    /// - A fixed-size array of `HEADER_LEN` bytes representing the PDU header.
    /// - A `Vec<u8>` containing the variable-length data segment.
    /// - A `Option<Vec<u8>>` containing the data-digest data segment.
    fn to_bytes(
        &mut self,
        max_recv_data_segment_length: usize,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<(Self::Header, Self::Body)>;
}

/// A trait for deserializing a Protocol Data Unit (PDU) from a raw byte stream.
///
/// This trait provides functionality to parse incoming binary data into
/// structured PDU objects. It requires the implementing type to also implement
/// BasicHeaderSegment for header access.
pub trait FromBytes: Sized + BasicHeaderSegment {
    /// Parse the full PDU from a contiguous byte buffer.
    ///
    /// The parsed `Response` (often a tuple of header struct, payload bytes,
    /// and digest), or an error if parsing fails.
    fn from_bhs_bytes(bytes: &mut [u8]) -> Result<&mut Self> {
        let _ = BhsOpcode::try_from(bytes[0])
            .map_err(|e| anyhow::anyhow!("invalid opcode: {}", e))?;
        Self::from_bhs_bytes(bytes)
    }
}

impl<B> ToBytes for B
where B: Builder
{
    type Body = B::Body;
    type Header = B::Header;

    fn to_bytes(
        &mut self,
        max_recv_data_segment_length: usize,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<(Self::Header, Self::Body)> {
        self.build(
            max_recv_data_segment_length,
            enable_header_digest,
            enable_data_digest,
        )
    }
}
