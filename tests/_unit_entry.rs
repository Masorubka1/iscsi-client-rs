// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::all)]

mod unit_tests {
    use std::fs;

    use anyhow::Result;
    use hex::FromHex;
    use iscsi_client_rs::{
        cfg::config::Config,
        client::pdu_connection::FromBytes,
        models::{
            common::{BasicHeaderSegment, HEADER_LEN},
            data_fromat::{PDUWithData, ZeroCopyType},
        },
    };

    // Helper to load a hex fixture and decode it to a byte vector.
    fn load_fixture(path: &str) -> Result<Vec<u8>> {
        let s = fs::read_to_string(path)?;
        let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
        Ok(Vec::from_hex(&cleaned)?)
    }

    fn parse<T: BasicHeaderSegment + FromBytes + ZeroCopyType>(
        bytes: &[u8],
        cfg: &Config,
    ) -> Result<PDUWithData<T>> {
        let mut header_buf = [0u8; HEADER_LEN];
        header_buf.copy_from_slice(&bytes[..HEADER_LEN]);
        let mut pdu = PDUWithData::<T>::from_header_slice(header_buf, &cfg);
        pdu.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;
        Ok(pdu)
    }

    pub mod test_login;
    pub mod test_nop;
    pub mod test_read;
    pub mod test_read_capacity;
    pub mod test_ready_to_transfer;
    pub mod test_reject;
    pub mod test_text;
    pub mod test_write;
}
