# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

* Add NOP-Out / NOP-In support: `NopOutRequestBuilder`, `NopInResponse` parsing, ping flag, data/header-digest options
* Introduce `PduResponse` enum and first-class Reject–PDU handling in `Connection::call`
* Refactor `FromBytes` to return optional digest (u32) and unify digest handling
* Implement `Opcode` / `BhsOpcode` with top-bit flag masking (I/F bits)
* Expand `LoginFlags` & `ToLoginKeys` traits; improve YAML config support (Auth enum, ISID deserializer)
* Add `BasicHeaderSegment` / `Pdu` traits for common PDU logic, BHS-length & data-length plumbing
* Expose header-digest & data-digest support on both Login and NOP PDUs via CRC-32 iSCSI
* Refactor `Connection` to use `Mutex<TcpStream>` and dynamic header read for 48-byte PDUs
* Unit tests for NOP and Reject PDUs and for full end-to-end login + heartbeat loops
* **Split `TcpStream` into read/write halves** — refactor `Connection` to use `OwnedReadHalf`/`OwnedWriteHalf` with separate mutexes, removing head-of-line blocking and enabling true full-duplex I/O.
* **Introduce `io_with_timeout` helper** — a unified wrapper for read/write operations with `tokio::time::timeout`.
* **Add `BhsHeader` struct** implementing `BasicHeaderSegment::from_bhs_bytes` for direct 48-byte BHS parsing (lengths, opcode, ITT) without full PDU dispatch.
* **Provide test-only PDU helpers** — `to_hex` / `from_hex` under `#[cfg(test)]` for round-trip encoding/decoding in unit tests.

## \[0.1.0] - 2025-07-20

### Added

* Initial implementation of `LoginRequestBuilder` and `LoginResponse` parsing
* Enum types for `Stage`, `StatusClass`, `StatusDetail`, and related detail enums
* `ToBytes` and `FromBytes` traits for PDU serialization/parsing
* Unit tests comparing builder output against hex fixtures
* Async `Connection` API with `call` method for PDU exchange
* CHAP authentication flow example using HMAC-MD5
* Comprehensive README with usage examples

### Changed

* Moved flag and mask definitions into `login::common`
* Updated builder to return `(header, Vec<u8>)` for header-only and separate body
* Improved error messages and `anyhow` integration

### Fixed

* Correct calculation of `data_segment_length` and 4-byte alignment
* Custom `Debug` for `LoginFlags` to display CSG/NSG as enum variants
* Handling of optional header digest in response parsing

## \[0.0.1] - 2025-07-15

### Added

* Project scaffold and Cargo manifest
* Basic TCP connection setup in `client::client::Connection`
* Raw hex-to-binary fixture loader for testing
* Early versions of `LoginRequest` struct and `to_bhs_bytes`
* Prototype `login_minimal` unit test
