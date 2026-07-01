//! This crate provides a client-side implementation of the iSCSI protocol.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#[cfg(test)]
extern crate self as iscsi_client_rs;

/// Handles configuration, command-line parsing, and logging.
pub mod cfg;
/// Manages client connections, sessions, and the session pool.
pub mod client;
/// Implements various SCSI commands (control blocks).
pub mod control_block;
#[cfg(test)]
mod internal_tests;
/// Defines the data structures for iSCSI PDUs and SCSI commands.
pub mod models;
/// Contains state machines for handling iSCSI operations like Login, Logout,
/// Read, and Write.
pub mod state_machine;
