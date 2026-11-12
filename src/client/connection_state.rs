//! Atomic connection state shared by the I/O and command paths.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use crate::sync::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub(super) struct ConnectionState {
    poisoned: AtomicBool,
}

impl ConnectionState {
    pub(super) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    /// Marks the connection poisoned and returns true only to the first caller.
    /// Cancellation and pending-request cleanup are performed by the
    /// connection.
    pub(super) fn mark_poisoned(&self) -> bool {
        !self.poisoned.swap(true, Ordering::SeqCst)
    }
}
