//! This module defines the structures for iSCSI Login PDUs.
//! It includes submodules for common definitions, requests, responses, and status codes.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Defines common structures and enums for iSCSI Login PDUs.
pub mod common;
/// Defines the structures for iSCSI Login Request PDUs.
pub mod request;
/// Defines the structures for iSCSI Login Response PDUs.
pub mod response;
/// Defines the status codes for iSCSI Login Response PDUs.
pub mod status;
