//! Synchronization primitives instrumented during isolated Loom model tests.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

pub(crate) use std::sync::atomic::Ordering;
#[cfg(not(iscsi_loom))]
pub(crate) use std::sync::atomic::{AtomicBool, AtomicU32};

#[cfg(iscsi_loom)]
pub(crate) use loom::sync::atomic::{AtomicBool, AtomicU32};
