//! This module contains state machines for handling iSCSI operations.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Common structures and traits for state machines.
pub mod common;
/// State machine for the Login phase.
pub mod login;
/// State machine for the Logout command.
pub mod logout_states;
/// State machine for NOP-Out and NOP-In exchanges.
pub mod nop_states;
/// State machine for the SCSI Read command.
pub mod read_states;
/// State machine for the SCSI Test Unit Ready command.
pub mod tur_states;
/// State machine for the SCSI Write command.
pub mod write_states;
