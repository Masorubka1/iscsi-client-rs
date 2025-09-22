//! This module defines the status codes for iSCSI Login Response PDUs.
//! It includes status classes and details for handling login outcomes.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use anyhow::{Result, anyhow, bail};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The status classes as per RFC 3720 §11.11.1
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// target accepted the request
    Success = 0,
    /// initiator must follow TargetAddress
    Redirection = 1,
    /// mistake on initiator side; do not retry
    InitiatorError = 2,
    /// target temporarily cannot fulfil; may retry
    TargetError = 3,
    Unknown(u8),
}

impl From<u8> for StatusClass {
    fn from(b: u8) -> Self {
        match b {
            0 => StatusClass::Success,
            1 => StatusClass::Redirection,
            2 => StatusClass::InitiatorError,
            3 => StatusClass::TargetError,
            other => StatusClass::Unknown(other),
        }
    }
}
impl From<StatusClass> for u8 {
    fn from(class: StatusClass) -> Self {
        match class {
            StatusClass::Success => 0x00,
            StatusClass::Redirection => 0x01,
            StatusClass::InitiatorError => 0x02,
            StatusClass::TargetError => 0x03,
            StatusClass::Unknown(v) => v,
        }
    }
}

/// Represents the detailed status of a login response.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatusDetail {
    /// The command completed successfully.
    Success(SuccessDetail),
    /// The initiator is being redirected to another target.
    Redirection(RedirectionDetail),
    /// An error occurred on the initiator side.
    InitiatorErr(InitiatorErrorDetail),
    /// An error occurred on the target side.
    TargetErr(TargetErrorDetail),
}

/// The detail for a successful login.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SuccessDetail {
    /// The command completed normally.
    CmdCompletedNormally = 0x00,
}

impl TryFrom<u8> for SuccessDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            0x00 => Ok(SuccessDetail::CmdCompletedNormally),
            other => Err(anyhow!("unknown Success detail code: {:#02x}", other)),
        }
    }
}

/// The detail for a login redirection.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RedirectionDetail {
    /// The target has been redirected.
    TargetRedirected = 0x01,
}

impl TryFrom<u8> for RedirectionDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            0x01 => Ok(RedirectionDetail::TargetRedirected),
            other => Err(anyhow!("unknown Redirection detail code: {:#02x}", other)),
        }
    }
}

/// Status-Detail for Status-Class = 0x02 (Initiator Error)
/// (см. IANA iSCSI Parameters: Login Response Status Codes → Status-Detail for
/// Status-Class=0x02)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorErrorDetail {
    /// 0x00 — Initiator error (общая ошибка инициализатора)
    InitiatorError = 0x00,
    /// 0x01 — Authentication failure
    AuthFailed = 0x01,
    /// 0x02 — Authorization failure
    AuthzFailed = 0x02,
    /// 0x03 — Not found (например, указанный параметр отсутствует)
    NotFound = 0x03,
    /// 0x04 — Target removed
    TargetRemoved = 0x04,
    /// 0x05 — Unsupported version
    UnsupportedVersion = 0x05,
    /// 0x06 — Too many connections
    TooManyConnections = 0x06,
    /// 0x07 — Missing parameter
    MissingParameter = 0x07,
    /// 0x08 — Can't include in session
    CantIncludeInSession = 0x08,
    /// 0x09 — Session type not supported
    SessionTypeNotSupported = 0x09,
    /// 0x0a — Session does not exist
    SessionDoesNotExist = 0x0a,
    /// 0x0b — Invalid during login
    InvalidDuringLogin = 0x0b,
    /// 0x0c–0xff — RESERVATED
    Reserved(u8),
}

impl TryFrom<u8> for InitiatorErrorDetail {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(InitiatorErrorDetail::InitiatorError),
            0x01 => Ok(InitiatorErrorDetail::AuthFailed),
            0x02 => Ok(InitiatorErrorDetail::AuthzFailed),
            0x03 => Ok(InitiatorErrorDetail::NotFound),
            0x04 => Ok(InitiatorErrorDetail::TargetRemoved),
            0x05 => Ok(InitiatorErrorDetail::UnsupportedVersion),
            0x06 => Ok(InitiatorErrorDetail::TooManyConnections),
            0x07 => Ok(InitiatorErrorDetail::MissingParameter),
            0x08 => Ok(InitiatorErrorDetail::CantIncludeInSession),
            0x09 => Ok(InitiatorErrorDetail::SessionTypeNotSupported),
            0x0a => Ok(InitiatorErrorDetail::SessionDoesNotExist),
            0x0b => Ok(InitiatorErrorDetail::InvalidDuringLogin),
            other => Err(anyhow!("unknown InitiatorErrorDetail: 0x{:02x}", other)),
        }
    }
}

/// iSCSI Login Status-Detail codes for Status-Class = TargetError (0x03)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TargetErrorDetail {
    /// (0x00) Target is busy, please retry later
    TargetBusy = 0x00,
    /// (0x01) Target’s protected area is busy
    TargetProtectedAreaBusy = 0x01,
    /// (0x02) Target cannot currently allocate requested resource
    TargetResourceUnavailable = 0x02,
    /// (0x03) Target encountered an internal error
    TargetInternalError = 0x03,
    /// (0x04–0xFE) Vendor-specific error
    VendorSpecific(u8),
    /// (0xFF) Reserved
    Reserved(u8),
}

impl TryFrom<u8> for TargetErrorDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self, Self::Error> {
        let detail = match raw {
            0x00 => TargetErrorDetail::TargetBusy,
            0x01 => TargetErrorDetail::TargetProtectedAreaBusy,
            0x02 => TargetErrorDetail::TargetResourceUnavailable,
            0x03 => TargetErrorDetail::TargetInternalError,
            0x04..=0xFE => TargetErrorDetail::VendorSpecific(raw),
            0xFF => TargetErrorDetail::Reserved(raw),
        };
        Ok(detail)
    }
}

impl TryFrom<(StatusClass, u8)> for StatusDetail {
    type Error = anyhow::Error;

    fn try_from((class, raw): (StatusClass, u8)) -> Result<Self> {
        Ok(match class {
            StatusClass::Success => StatusDetail::Success(SuccessDetail::try_from(raw)?),
            StatusClass::Redirection => {
                StatusDetail::Redirection(RedirectionDetail::try_from(raw)?)
            },
            StatusClass::InitiatorError => {
                StatusDetail::InitiatorErr(InitiatorErrorDetail::try_from(raw)?)
            },
            StatusClass::TargetError => {
                StatusDetail::TargetErr(TargetErrorDetail::try_from(raw)?)
            },
            _ => bail!("invalid class"),
        })
    }
}

impl From<InitiatorErrorDetail> for u8 {
    fn from(detail: InitiatorErrorDetail) -> Self {
        match detail {
            InitiatorErrorDetail::InitiatorError => 0x00,
            InitiatorErrorDetail::AuthFailed => 0x01,
            InitiatorErrorDetail::AuthzFailed => 0x02,
            InitiatorErrorDetail::NotFound => 0x03,
            InitiatorErrorDetail::TargetRemoved => 0x04,
            InitiatorErrorDetail::UnsupportedVersion => 0x05,
            InitiatorErrorDetail::TooManyConnections => 0x06,
            InitiatorErrorDetail::MissingParameter => 0x07,
            InitiatorErrorDetail::CantIncludeInSession => 0x08,
            InitiatorErrorDetail::SessionTypeNotSupported => 0x09,
            InitiatorErrorDetail::SessionDoesNotExist => 0x0A,
            InitiatorErrorDetail::InvalidDuringLogin => 0x0B,
            InitiatorErrorDetail::Reserved(v) => v,
        }
    }
}

impl From<TargetErrorDetail> for u8 {
    fn from(detail: TargetErrorDetail) -> Self {
        match detail {
            TargetErrorDetail::TargetBusy => 0x00,
            TargetErrorDetail::TargetProtectedAreaBusy => 0x01,
            TargetErrorDetail::TargetResourceUnavailable => 0x02,
            TargetErrorDetail::TargetInternalError => 0x03,
            TargetErrorDetail::VendorSpecific(v) => v,
            TargetErrorDetail::Reserved(v) => v,
        }
    }
}

impl From<StatusDetail> for u8 {
    fn from(detail: StatusDetail) -> Self {
        match detail {
            StatusDetail::Success(inner) => inner as u8,
            StatusDetail::Redirection(inner) => inner as u8,
            StatusDetail::InitiatorErr(inner) => inner.into(),
            StatusDetail::TargetErr(inner) => inner.into(),
        }
    }
}

/// Wire-safe, zero-copy wrapper for **Status-Class** (1 byte on the wire).
#[repr(transparent)]
#[derive(
    Copy, Clone, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct RawStatusClass(u8);

impl RawStatusClass {
    /// Returns the raw 8-bit value of the status class.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Creates a new `RawStatusClass` from a raw 8-bit value.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Decodes the raw value into a `StatusClass` enum.
    #[inline]
    pub fn decode(self) -> StatusClass {
        StatusClass::from(self.0)
    }

    /// Encodes a `StatusClass` enum into the raw value.
    #[inline]
    pub fn encode(&mut self, c: StatusClass) {
        self.0 = u8::from(c);
    }

    /// Checks if the status class is a known value.
    #[inline]
    pub const fn is_known(self) -> bool {
        matches!(self.0, 0..=3)
    }
}

impl From<RawStatusClass> for StatusClass {
    #[inline]
    fn from(r: RawStatusClass) -> Self {
        r.decode()
    }
}
impl From<StatusClass> for RawStatusClass {
    #[inline]
    fn from(c: StatusClass) -> Self {
        Self(u8::from(c))
    }
}

impl fmt::Debug for RawStatusClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawStatusClass({:?})", self.decode())
    }
}

/// Wire-safe, zero-copy wrapper for **Status-Detail** (1 byte on the wire).
///
/// Note: decoding requires the corresponding `StatusClass` to interpret the
/// byte.
#[repr(transparent)]
#[derive(
    Copy, Clone, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct RawStatusDetail(u8);

impl RawStatusDetail {
    /// Returns the raw 8-bit value of the status detail.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Creates a new `RawStatusDetail` from a raw 8-bit value.
    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Decodes the raw value into a `StatusDetail` enum, given the status
    /// class.
    #[inline]
    pub fn decode_with_class(self, class: StatusClass) -> Result<StatusDetail> {
        match class {
            StatusClass::Success => {
                Ok(StatusDetail::Success(SuccessDetail::try_from(self.0)?))
            },
            StatusClass::Redirection => Ok(StatusDetail::Redirection(
                RedirectionDetail::try_from(self.0)?,
            )),
            StatusClass::InitiatorError => Ok(StatusDetail::InitiatorErr(
                InitiatorErrorDetail::try_from(self.0)?,
            )),
            StatusClass::TargetError => Ok(StatusDetail::TargetErr(
                TargetErrorDetail::try_from(self.0)?,
            )),
            StatusClass::Unknown(v) => {
                bail!("cannot decode Status-Detail for unknown Status-Class {v:#04x}")
            },
        }
    }

    /// Encodes a `StatusDetail` enum into the raw value.
    #[inline]
    pub fn encode(&mut self, d: StatusDetail) {
        self.0 = u8::from(d);
    }
}

impl fmt::Debug for RawStatusDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawStatusDetail(0x{:02x})", self.0)
    }
}

/// A helper struct for handling the `StatusClass` and `StatusDetail` pair
/// together.
#[derive(Copy, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct RawStatusPair {
    /// The status class.
    pub class: RawStatusClass,
    /// The status detail.
    pub detail: RawStatusDetail,
}

impl Default for RawStatusPair {
    fn default() -> Self {
        Self::new()
    }
}

impl RawStatusPair {
    /// Creates a new `RawStatusPair` with default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            class: RawStatusClass::default(),
            detail: RawStatusDetail::default(),
        }
    }

    /// Decodes the raw pair into `StatusClass` and `StatusDetail` enums.
    #[inline]
    pub fn decode(self) -> Result<(StatusClass, StatusDetail)> {
        let class = self.class.decode();
        let detail = self.detail.decode_with_class(class)?;
        Ok((class, detail))
    }

    /// Encodes `StatusClass` and `StatusDetail` enums into the raw pair.
    #[inline]
    pub fn encode(&mut self, class: StatusClass, detail: StatusDetail) -> Result<()> {
        // sanity check: detail must match class (optional, but helps catch bugs)
        match (class, &detail) {
            (StatusClass::Success, StatusDetail::Success(_))
            | (StatusClass::Redirection, StatusDetail::Redirection(_))
            | (StatusClass::InitiatorError, StatusDetail::InitiatorErr(_))
            | (StatusClass::TargetError, StatusDetail::TargetErr(_)) => {},
            _ => bail!("StatusDetail does not match StatusClass"),
        }
        self.class.encode(class);
        self.detail.encode(detail);
        Ok(())
    }
}

impl fmt::Debug for RawStatusPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.decode() {
            Ok((c, d)) => write!(f, "RawStatusPair({:?}, {:?})", c, d),
            Err(_) => write!(
                f,
                "RawStatusPair(class={:?}, detail=0x{:02x})",
                self.class.decode(),
                self.detail.raw()
            ),
        }
    }
}
