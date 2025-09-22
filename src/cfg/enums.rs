// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use serde::{Deserialize, Serialize};

/// Boolean enumeration with string serialization support
///
/// Represents yes/no values with support for various string representations
/// including "Yes"/"No", "true"/"false", and "1"/"0".
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum YesNo {
    #[serde(
        rename = "Yes",
        alias = "yes",
        alias = "YES",
        alias = "true",
        alias = "True",
        alias = "1"
    )]
    Yes,
    #[serde(
        rename = "No",
        alias = "no",
        alias = "NO",
        alias = "false",
        alias = "False",
        alias = "0"
    )]
    No,
}
impl fmt::Display for YesNo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            YesNo::Yes => "Yes",
            YesNo::No => "No",
        })
    }
}
impl From<bool> for YesNo {
    fn from(b: bool) -> Self {
        if b { YesNo::Yes } else { YesNo::No }
    }
}
impl YesNo {
    pub fn as_bool(self) -> bool {
        matches!(self, YesNo::Yes)
    }
}

/// iSCSI session type enumeration
///
/// Defines the type of iSCSI session to establish.
/// Discovery sessions are used to discover available targets,
/// while Normal sessions are used for actual data access.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    #[serde(rename = "Discovery", alias = "discovery", alias = "DISCOVERY")]
    Discovery,
    #[serde(rename = "Normal", alias = "normal", alias = "NORMAL")]
    Normal,
}
impl fmt::Display for SessionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SessionType::Discovery => "Discovery",
            SessionType::Normal => "Normal",
        })
    }
}

/// Digest algorithm enumeration for iSCSI PDU integrity checking
///
/// Specifies which digest algorithm to use for header and data integrity.
/// None means no digest is used, CRC32C provides checksum-based integrity
/// checking.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    #[serde(rename = "None", alias = "none", alias = "NONE")]
    None,
    #[serde(rename = "CRC32C", alias = "crc32c")]
    CRC32C,
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Digest::None => "None",
            Digest::CRC32C => "CRC32C",
        })
    }
}
