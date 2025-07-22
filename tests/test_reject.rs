use std::fs;

use anyhow::Result;
use hex::FromHex;
use iscsi_client_rs::{
    client::pdu_connection::FromBytes,
    models::{
        opcode::{BhsOpcode, IfFlags, Opcode},
        reject::reject::RejectPdu,
    },
};

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_nop_in_parse() -> Result<()> {
    let bytes = load_fixture("tests/fixtures/reject_example.hex")?;
    assert!(bytes.len() >= 48);

    let (parsed, data, digest) = RejectPdu::from_bytes(&bytes)?;
    assert!(data.is_empty());
    assert!(digest.is_none());

    assert_eq!(
        parsed.opcode,
        BhsOpcode {
            flags: IfFlags::empty(),
            opcode: Opcode::Reject,
        },
        "expected NOP-IN opcode 0x3f"
    );
    assert_eq!(parsed.stat_sn, 7781748);
    assert_eq!(parsed.exp_cmd_sn, 0);

    Ok(())
}
