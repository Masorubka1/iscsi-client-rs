//! This module defines the data structures for iSCSI PDUs and SCSI commands.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Defines the structures for SCSI Command PDUs.
pub mod command;
/// Defines common structures and traits for iSCSI models.
pub mod common;
/// Defines the structures for Data-In and Data-Out PDUs.
pub mod data;
/// Defines the generic PDU container and related traits.
pub mod data_fromat;
/// Defines the structures for Login PDUs.
pub mod login;
/// Defines the structures for Logout PDUs.
pub mod logout;
/// Defines the structures for NOP-In and NOP-Out PDUs.
pub mod nop;
/// Defines the iSCSI opcode enumeration.
pub mod opcode;
/// Defines parsing utilities for iSCSI PDUs.
pub mod parse;
/// Defines the structure for Ready To Transfer (R2T) PDUs.
pub mod ready_2_transfer;
/// Defines the structure for Reject PDUs.
pub mod reject;
/// Defines the structures for Text PDUs.
pub mod text;
