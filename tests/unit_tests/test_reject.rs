// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::models::{
    common::HEADER_LEN,
    data_fromat::PDUWithData,
    opcode::{BhsOpcode, Opcode},
    reject::response::RejectPdu,
};

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_reject_parse() -> Result<()> {
    let bytes =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/reject_example.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(&bytes[..HEADER_LEN]);

    let mut pdu = PDUWithData::<RejectPdu>::from_header_slice(hdr_buf);
    pdu.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;

    assert!(!pdu.data.is_empty());
    assert!(pdu.header_digest.is_none());
    assert!(pdu.data_digest.is_none());

    let hdr = pdu.header_view().expect("valid Reject BHS");

    let op = BhsOpcode::try_from(hdr.opcode.raw())?;
    assert_eq!(op.opcode, Opcode::Reject, "expected Reject opcode 0x3f");

    assert_eq!(hdr.stat_sn.get(), 7_781_748);
    assert_eq!(hdr.exp_cmd_sn.get(), 0);

    Ok(())
}
