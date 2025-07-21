[![crates.io](https://img.shields.io/crates/v/iscsi-client-rs.svg)](https://crates.io/crates/iscsi-client-rs)
[![docs.rs](https://docs.rs/iscsi-client-rs/badge.svg)](https://docs.rs/iscsi-client-rs)
[![CI](https://github.com/your-org/iscsi-client-rs/workflows/CI/badge.svg)](https://github.com/your-org/iscsi-client-rs/actions)
[![license](https://img.shields.io/crates/l/iscsi-client-rs.svg)](LICENSE)

### iscsi-client-rs

A pure-Rust iSCSI initiator library and CLI for interacting with iSCSI targets.  It lets you build and send iSCSI PDUs, perform login (including CHAP), and exchange SCSI commands over TCP.

## WARNING ALL CODE TESTED ONLY WITH `targetcli`. ON OTHER TARGETS BEHAVIOUR UNEXPECTED

⸻

## Features

- Build and parse iSCSI Login PDUs across all phases (Security, Operational, Full-Feature)  
- Support for CHAP authentication (MD5 and HMAC-MD5)  
- High-level, pure-Rust API for login and SCSI command exchange  
- Async I/O powered by Tokio  
- Zero external C dependencies  
