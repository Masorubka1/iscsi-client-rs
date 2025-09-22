//! This module defines the structures for iSCSI Command PDUs.
//! It includes submodules for common definitions, requests, responses, and
//! zero-copy structures.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Defines common structures and enums for iSCSI Command PDUs.
pub mod common;
/// Defines the structures for iSCSI SCSI Command Request PDUs.
pub mod request;
/// Defines the structures for iSCSI SCSI Command Response PDUs.
pub mod response;
/// Provides zero-copy structures for iSCSI Command PDUs.
pub mod zero_copy;
