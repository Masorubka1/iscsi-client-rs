// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fmt;

use anyhow::{Result, bail};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// iSCSI Logout Reason Code (Byte 1)
#[derive(Debug, Default, PartialEq, Clone)]
#[repr(u8)]
pub enum LogoutReason {
    /// Close the entire session (all connections)
    #[default]
    CloseSession = 0x01,
    /// Close a specific connection identified by CID
    CloseConnection = 0x02,
    /// Remove a connection for recovery purposes
    RemoveConnectionForRecovery = 0x03,
}

impl LogoutReason {
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            LogoutReason::CloseSession => 0x01,
            LogoutReason::CloseConnection => 0x02,
            LogoutReason::RemoveConnectionForRecovery => 0x03,
        }
    }
}

impl TryFrom<u8> for LogoutReason {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0x01 => LogoutReason::CloseSession,
            0x02 => LogoutReason::CloseConnection,
            0x03 => LogoutReason::RemoveConnectionForRecovery,
            other => bail!("unexpected logout code {other}"),
        })
    }
}

impl fmt::Display for LogoutReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogoutReason::*;
        let s = match self {
            CloseSession => "CloseSession",
            CloseConnection => "CloseConnection",
            RemoveConnectionForRecovery => "RemoveConnectionForRecovery",
        };
        f.write_str(s)
    }
}

/// Wire-safe, zero-copy wrapper for Logout Reason (1 byte on the wire).
///
/// Use this in BHS structs instead of `LogoutReason`:
/// `pub reason: RawLogoutReason`
#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct RawLogoutReason(u8);

impl Default for RawLogoutReason {
    #[inline]
    fn default() -> Self {
        Self(LogoutReason::CloseSession.as_u8())
    }
}

impl RawLogoutReason {
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Decode wire byte into the rich enum (`TryFrom<u8>` semantics).
    #[inline]
    pub fn decode(self) -> Result<LogoutReason> {
        LogoutReason::try_from(self.0)
    }

    /// Encode from the rich enum into the wire byte (in-place).
    #[inline]
    pub fn encode(&mut self, r: LogoutReason) {
        self.0 = r.as_u8();
    }
}

/* Convenience conversions */

impl TryFrom<RawLogoutReason> for LogoutReason {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(w: RawLogoutReason) -> Result<Self> {
        w.decode()
    }
}

impl From<LogoutReason> for RawLogoutReason {
    #[inline]
    fn from(r: LogoutReason) -> Self {
        Self(r.as_u8())
    }
}

impl From<&LogoutReason> for RawLogoutReason {
    #[inline]
    fn from(r: &LogoutReason) -> Self {
        Self(r.as_u8())
    }
}

/// iSCSI Logout Response Code (RFC 3720 §10.15.1)
#[derive(Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum LogoutResponseCode {
    /// 0 - connection or session closed successfully
    #[default]
    Success = 0x00,
    /// 1 - CID not found
    CidNotFound = 0x01,
    /// 2 - connection recovery is not supported
    RecoveryNotSupported = 0x02,
    /// 3 - cleanup failed for various reasons
    CleanupFailed = 0x03,
}

impl LogoutResponseCode {
    #[inline]
    pub fn as_u8(&self) -> u8 {
        match self {
            LogoutResponseCode::Success => 0x00,
            LogoutResponseCode::CidNotFound => 0x01,
            LogoutResponseCode::RecoveryNotSupported => 0x02,
            LogoutResponseCode::CleanupFailed => 0x03,
        }
    }
}

impl TryFrom<u8> for LogoutResponseCode {
    type Error = anyhow::Error;

    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0x00 => LogoutResponseCode::Success,
            0x01 => LogoutResponseCode::CidNotFound,
            0x02 => LogoutResponseCode::RecoveryNotSupported,
            0x03 => LogoutResponseCode::CleanupFailed,
            other => bail!("invalid LogoutResponseCode: {other:#04x}"),
        })
    }
}

impl fmt::Display for LogoutResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use LogoutResponseCode::*;
        let s = match self {
            Success => "Success",
            CidNotFound => "CidNotFound",
            RecoveryNotSupported => "RecoveryNotSupported",
            CleanupFailed => "CleanupFailed",
        };
        f.write_str(s)
    }
}

/// Wire-safe, zero-copy wrapper for Logout Response Code (1 byte on the wire).
///
/// Use this in your BHS structs:
/// `pub response_code: RawLogoutResponseCode`
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawLogoutResponseCode(u8);

impl Default for RawLogoutResponseCode {
    #[inline]
    fn default() -> Self {
        Self(LogoutResponseCode::Success.as_u8())
    }
}

impl RawLogoutResponseCode {
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Decode into the rich enum (`TryFrom<u8>` semantics).
    #[inline]
    pub fn decode(self) -> Result<LogoutResponseCode> {
        LogoutResponseCode::try_from(self.0)
    }

    /// Encode from the rich enum into the wire byte (in-place).
    #[inline]
    pub fn encode(&mut self, r: LogoutResponseCode) {
        self.0 = r.as_u8();
    }
}

impl TryFrom<RawLogoutResponseCode> for LogoutResponseCode {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(w: RawLogoutResponseCode) -> Result<Self> {
        w.decode()
    }
}

impl From<LogoutResponseCode> for RawLogoutResponseCode {
    #[inline]
    fn from(r: LogoutResponseCode) -> Self {
        Self(r.as_u8())
    }
}

impl From<&LogoutResponseCode> for RawLogoutResponseCode {
    #[inline]
    fn from(r: &LogoutResponseCode) -> Self {
        Self(r.as_u8())
    }
}

impl fmt::Debug for RawLogoutResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let decoded = match self.decode() {
            Ok(st) => format!("{st:?}"),
            Err(_e) => format!("invalid(0x{:02X})", self.raw()),
        };

        write!(f, "RawScsiStatus {{ {:?} }}", decoded)
    }
}
