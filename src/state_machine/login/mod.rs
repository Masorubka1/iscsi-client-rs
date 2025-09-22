//! This module defines the state machine for the iSCSI Login phase.
//! It includes submodules for common definitions, CHAP authentication, and
//! plain login.

pub mod common;
pub mod login_chap;
pub mod login_plain;
