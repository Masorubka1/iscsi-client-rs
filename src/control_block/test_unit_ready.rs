// SPDX-License-Identifier: AGPL-3.0-or-later GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

/// Build a standard TEST UNIT READY CDB with control = 0x00.
#[inline]
pub fn build_test_unit_ready(cdb: &mut [u8; 16], control: u8) {
    cdb.fill(0);
    cdb[0] = 0; // TEST UNIT READY(6) = 0x00
    cdb[5] = control;
}
