// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// iSCSI Reject Reason codes (RFC 7143 §11.17.1)
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq)]
pub enum RejectReason {
    /// 0x01 — Reserved (MUST NOT be used)
    #[default]
    Reserved = 0x01,
    /// 0x02 — Data (payload) digest error; original PDU may be resent
    DataDigestError = 0x02,
    /// 0x03 — SNACK Reject; original PDU may be resent
    SnackReject = 0x03,
    /// 0x04 — Protocol Error (e.g. SNACK Request for an already-acked status);
    /// cannot be resent
    ProtocolError = 0x04,
    /// 0x05 — Command not supported; cannot be resent
    CommandNotSupported = 0x05,
    /// 0x06 — Immediate command reject (too many immediate commands); original
    /// PDU may be resent
    ImmediateCmdReject = 0x06,
    /// 0x07 — Task in progress; cannot be resent
    TaskInProgress = 0x07,
    /// 0x08 — Invalid data ack; cannot be resent
    InvalidDataAck = 0x08,
    /// 0x09 — Invalid PDU field (e.g. bad ITT, invalid SNACK numbers); cannot
    /// be resent
    InvalidPduField = 0x09,
    /// 0x0A — Long op reject (out of resources generating TargetTransferTag);
    /// original PDU may be resent
    LongOpReject = 0x0A,
    /// 0x0B — Deprecated (“Negotiation Reset”); MUST NOT be used
    DeprecatedNegotiReset = 0x0B,
    /// 0x0C — Waiting for Logout; cannot be resent
    WaitingForLogout = 0x0C,
    /// Any other value — unassigned/reserved or vendor-specific
    Other(u8),
}

impl RejectReason {
    /// Decode from a raw byte (covers all values via `Other(..)`).
    #[inline]
    pub fn from_u8(b: u8) -> Self {
        match b {
            0x01 => RejectReason::Reserved,
            0x02 => RejectReason::DataDigestError,
            0x03 => RejectReason::SnackReject,
            0x04 => RejectReason::ProtocolError,
            0x05 => RejectReason::CommandNotSupported,
            0x06 => RejectReason::ImmediateCmdReject,
            0x07 => RejectReason::TaskInProgress,
            0x08 => RejectReason::InvalidDataAck,
            0x09 => RejectReason::InvalidPduField,
            0x0A => RejectReason::LongOpReject,
            0x0B => RejectReason::DeprecatedNegotiReset,
            0x0C => RejectReason::WaitingForLogout,
            other => RejectReason::Other(other),
        }
    }

    /// Encode to its wire byte.
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match *self {
            RejectReason::Reserved => 0x01,
            RejectReason::DataDigestError => 0x02,
            RejectReason::SnackReject => 0x03,
            RejectReason::ProtocolError => 0x04,
            RejectReason::CommandNotSupported => 0x05,
            RejectReason::ImmediateCmdReject => 0x06,
            RejectReason::TaskInProgress => 0x07,
            RejectReason::InvalidDataAck => 0x08,
            RejectReason::InvalidPduField => 0x09,
            RejectReason::LongOpReject => 0x0A,
            RejectReason::DeprecatedNegotiReset => 0x0B,
            RejectReason::WaitingForLogout => 0x0C,
            RejectReason::Other(code) => code,
        }
    }
}

impl From<&RejectReason> for u8 {
    #[inline]
    fn from(r: &RejectReason) -> u8 {
        r.as_u8()
    }
}
impl From<RejectReason> for u8 {
    #[inline]
    fn from(r: RejectReason) -> u8 {
        r.as_u8()
    }
}

#[repr(transparent)]
#[derive(Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawRejectReason(u8);

impl RawRejectReason {
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Infallible decode to the rich enum.
    #[inline]
    pub fn decode(self) -> RejectReason {
        RejectReason::from_u8(self.0)
    }

    /// Encode from the rich enum into the wire byte (in-place).
    #[inline]
    pub fn encode(&mut self, r: RejectReason) {
        self.0 = r.as_u8();
    }
}

// Correct conversion impls
impl From<RawRejectReason> for RejectReason {
    #[inline]
    fn from(w: RawRejectReason) -> Self {
        w.decode()
    }
}
impl From<RejectReason> for RawRejectReason {
    #[inline]
    fn from(r: RejectReason) -> Self {
        Self(r.as_u8())
    }
}
impl From<&RejectReason> for RawRejectReason {
    #[inline]
    fn from(r: &RejectReason) -> Self {
        Self(r.as_u8())
    }
}
