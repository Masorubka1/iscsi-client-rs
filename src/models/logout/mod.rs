//! This module defines the structures for iSCSI Logout PDUs.
//! It includes submodules for common definitions, requests, and responses.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Defines common structures and enums for iSCSI Logout PDUs.
pub mod common;
/// Defines the structures for iSCSI Logout Request PDUs.
pub mod request;
/// Defines the structures for iSCSI Logout Response PDUs.
pub mod response;
