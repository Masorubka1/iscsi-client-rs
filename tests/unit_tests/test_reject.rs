use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::models::{
    common::HEADER_LEN,
    data_fromat::PDUWithData,
    opcode::{BhsOpcode, IfFlags, Opcode},
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

    let header = RejectPdu::from_bhs_bytes(&bytes[..HEADER_LEN])?;

    let parsed = PDUWithData::<RejectPdu>::parse(header, &bytes, false, false)?;

    assert!(!parsed.data.is_empty());
    assert!(parsed.header_digest.is_none());
    assert!(parsed.data_digest.is_none());

    assert_eq!(
        parsed.header.opcode,
        BhsOpcode {
            flags: IfFlags::empty(),
            opcode: Opcode::Reject
        },
        "expected Reject opcode 0x3f"
    );
    assert_eq!(parsed.header.stat_sn, 7_781_748);
    assert_eq!(parsed.header.exp_cmd_sn, 0);

    Ok(())
}
