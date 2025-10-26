// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

#![allow(clippy::all)]

mod unit_tests {
    use std::fs;

    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use hex::FromHex;
    use iscsi_client_rs::{
        cfg::config::Config,
        client::pdu_connection::FromBytes,
        models::{
            common::{BasicHeaderSegment, HEADER_LEN},
            data_fromat::{PduRequest, PduResponse, ZeroCopyType},
        },
    };

    // Helper to load a hex fixture and decode it to a byte vector.
    fn load_fixture(path: &str) -> Result<Vec<u8>> {
        let s = fs::read_to_string(path)?;
        let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
        Ok(Vec::from_hex(&cleaned)?)
    }

    fn parse_imm<T>(bytes: &[u8], cfg: &Config) -> anyhow::Result<PduResponse<T>>
    where T: BasicHeaderSegment + FromBytes + ZeroCopyType {
        let mut header_buf = [0u8; HEADER_LEN];
        header_buf.copy_from_slice(&bytes[..HEADER_LEN]);

        let mut pdu = PduResponse::<T>::from_header_slice(header_buf, cfg);
        let payload = Bytes::copy_from_slice(&bytes[HEADER_LEN..]);
        pdu.parse_with_buff(&payload)?;
        Ok(pdu)
    }

    fn parse_mut<T>(bytes: &[u8], cfg: &Config) -> anyhow::Result<PduRequest<T>>
    where T: BasicHeaderSegment + FromBytes + ZeroCopyType {
        let mut header_buf = [0u8; HEADER_LEN];
        header_buf.copy_from_slice(&bytes[..HEADER_LEN]);

        let mut pdu = PduRequest::<T>::new_request(header_buf, cfg);
        let payload = BytesMut::from(&bytes[HEADER_LEN..]);
        pdu.parse_with_buff_mut(payload)?;
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
