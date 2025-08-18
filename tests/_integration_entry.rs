// tests/_integration_entry.rs
#![allow(clippy::all)]

mod integration_tests {
    pub mod common;

    pub mod get_capacity_read_write;
    pub mod login_chap_ok;
    pub mod login_plain_ok;
    pub mod logout_ok;
    pub mod read_write_read;
    pub mod write_1gb;
}
