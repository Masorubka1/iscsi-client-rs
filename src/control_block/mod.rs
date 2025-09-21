//! This module implements various SCSI commands (control blocks).

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Implements the SCSI INQUIRY command.
pub mod inquiry;
/// Implements the SCSI MODE SENSE command.
pub mod mod_sense;
/// Implements the SCSI READ command.
pub mod read;
/// Implements the SCSI READ CAPACITY command.
pub mod read_capacity;
/// Implements the SCSI REPORT LUNS command.
pub mod report_luns;
/// Implements the SCSI REQUEST SENSE command.
pub mod request_sense;
/// Implements the SCSI TEST UNIT READY command.
pub mod test_unit_ready;
/// Implements the SCSI WRITE command.
pub mod write;
