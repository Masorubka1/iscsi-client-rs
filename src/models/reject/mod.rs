//! This module defines the structures for iSCSI Reject PDUs.
//! It includes submodules for the reject description and response.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::module_inception)]
/// Defines the description for iSCSI Reject PDUs.
pub mod reject_description;
/// Defines the structures for iSCSI Reject PDUs.
pub mod response;
