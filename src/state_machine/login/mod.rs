//! This module defines the state machine for the iSCSI Login phase.
//! It includes submodules for common definitions, CHAP authentication, and
//! plain login.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

pub mod common;
pub mod login_chap;
pub mod login_plain;
