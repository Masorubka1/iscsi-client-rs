//! This module handles configuration, command-line parsing, and logging.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Command-line interface parsing.
pub mod cli;
/// Configuration file parsing and management.
pub mod config;
/// Enumerations used in configuration.
pub mod enums;
/// Logger initialization.
pub mod logger;
