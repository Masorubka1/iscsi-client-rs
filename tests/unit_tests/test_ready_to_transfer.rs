// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev


use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    models::{
        common::HEADER_LEN,
        data_fromat::PDUWithData,
        opcode::{BhsOpcode, Opcode},
        ready_2_transfer::response::ReadyToTransfer,
    },
};

use crate::unit_tests::load_fixture;

#[test]
fn test_reject_parse() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let bytes =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/ready_to_transfer.hex")?;
    assert!(bytes.len() >= HEADER_LEN);

    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(&bytes[..HEADER_LEN]);

    let mut pdu = PDUWithData::<ReadyToTransfer>::from_header_slice(hdr_buf, &cfg);
    pdu.parse_with_buff(&bytes[HEADER_LEN..], false, false)?;

    assert!(pdu.data()?.is_empty());
    assert!(pdu.header_digest.is_none());
    assert!(pdu.data_digest.is_none());

    let hdr = pdu.header_view().expect("valid ReadyToTransfer BHS");

    let op = BhsOpcode::try_from(hdr.opcode.raw())?;
    assert_eq!(
        op.opcode,
        Opcode::ReadyToTransfer,
        "expected ReadyToTransfer opcode 0x31"
    );

    assert_eq!(hdr.stat_sn.get(), 6);
    assert_eq!(hdr.exp_cmd_sn.get(), 5);

    Ok(())
}
