//! Isolated concurrency models using the production implementations.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![cfg(iscsi_loom)]

// Compile the private connection-state implementation with instrumented
// atomics. ITT tests use the instrumented implementation from the library
// itself.
mod sync {
    pub(crate) use loom::sync::atomic::{AtomicBool, Ordering};
}
#[path = "../src/client/connection_state.rs"]
mod connection_state;

#[path = "loom/test_connection_state.rs"]
mod test_connection_state;
#[path = "loom/test_itt.rs"]
mod test_itt;
