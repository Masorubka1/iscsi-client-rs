// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::all)]

mod integration_tests {
    pub mod common;

    pub mod check_tur;
    pub mod get_capacity_read_write;
    pub mod login_chap_ok;
    pub mod login_plain_ok;
    pub mod logout_ok;
    pub mod read_write_read;
    pub mod write_1gb;
}
