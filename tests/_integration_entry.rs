// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::all)]

mod integration_tests {

    pub mod common;

    pub mod check_tur;
    pub mod concurrent_io;
    pub mod io_boundaries;
    pub mod login_chap_ok;
    pub mod login_negative;
    pub mod login_plain_ok;
    pub mod logout_ok;
    pub mod mod_sense;
    pub mod read_sense;
    pub mod recovery;
    pub mod report_luns;
    pub mod send_targets_discovery;

    //inquiry
    pub mod inquiry;

    //rw
    pub mod get_capacity_read_write;
    pub mod read_write_read;
    pub mod write_1gb;
}
