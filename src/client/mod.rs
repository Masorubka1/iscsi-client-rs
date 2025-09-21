//! This module manages client connections, sessions, and the session pool.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::module_inception)]
/// The main iSCSI client implementation.
pub mod client;
/// Common structures and functions for the client.
pub mod common;
/// Traits for handling PDU serialization and deserialization.
pub mod pdu_connection;
/// Manages a pool of iSCSI sessions.
pub mod pool_sessions;
