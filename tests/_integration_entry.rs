// tests/_integration_entry.rs
#![allow(clippy::all)]

mod integration_tests {
    pub mod common;

    pub mod login_chap_ok;
    pub mod login_plain_ok;
    pub mod logout_ok;
    pub mod read10_write_read10;
}
