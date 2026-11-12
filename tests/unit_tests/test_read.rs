// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use anyhow::{Context, Result};
use bytes::Bytes;
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::client::ClientConnection,
    control_block::read::build_read10,
    models::{
        command::{
            common::{ScsiStatus, TaskAttribute},
            request::{ScsiCommandRequest, ScsiCommandRequestBuilder},
        },
        common::{BasicHeaderSegment, Builder, HEADER_LEN},
        data::response::ScsiDataIn,
        data_fromat::{PduRequest, PduResponse},
        identifiers::{IttGen, Lun},
    },
    state_machine::read_states::ReadCtx,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

#[test]
fn test_read_pdu_build() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let expected =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read10_request.hex")?;

    let lun_bytes = [0, 1, 0, 0, 0, 0, 0, 0];
    let lun_be = u64::from_be_bytes(lun_bytes);

    let itt = 4;
    let cmd_sn = 1;
    let exp_stat_sn = 4;

    let mut cdb_read = [0u8; 16];
    build_read10(&mut cdb_read, 0x1234, 16, 0, 0);

    let header_builder = ScsiCommandRequestBuilder::new()
        .lun(lun_be)
        .initiator_task_tag(itt)
        .cmd_sn(cmd_sn)
        .exp_stat_sn(exp_stat_sn)
        .expected_data_transfer_length(512u32)
        .scsi_descriptor_block(&cdb_read)
        .read()
        .task_attribute(TaskAttribute::Simple);

    let mut header_buf = [0u8; HEADER_LEN];
    header_builder.header.to_bhs_bytes(&mut header_buf)?;

    let mut builder = PduRequest::<ScsiCommandRequest>::new_request(header_buf, &cfg);

    let (hdr_bytes, body_bytes) =
        &builder.build(cfg.login.flow.max_recv_data_segment_length as usize)?;

    assert_eq!(&hdr_bytes[..], &expected[..HEADER_LEN], "BHS mismatch");
    assert_eq!(
        body_bytes,
        &expected[HEADER_LEN..],
        "READ PDU payload mismatch"
    );
    Ok(())
}

#[test]
fn test_read_response_good() -> Result<()> {
    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let raw =
        load_fixture("tests/unit_tests/fixtures/scsi_commands/read10_response_good.hex")
            .context("failed to load read_response_good fixture")?;
    assert!(
        raw.len() >= HEADER_LEN,
        "fixture too small: {} < {}",
        raw.len(),
        HEADER_LEN
    );

    let (hdr_bytes, body_bytes) = raw.split_at(HEADER_LEN);

    let mut hdr_buf = [0u8; HEADER_LEN];
    hdr_buf.copy_from_slice(hdr_bytes);

    let mut pdu = PduResponse::<ScsiDataIn>::from_header_slice(hdr_buf, &cfg);
    pdu.parse_with_buff(&Bytes::copy_from_slice(body_bytes))
        .context("failed to parse ScsiDataIn PDU body")?;

    let header = pdu.header_view()?;

    assert!(header.flags.fin(), "FINAL bit must be set");
    assert!(header.flags.s(), "S bit (status present) must be set");

    assert_eq!(
        header.scsi_status(),
        Some(ScsiStatus::Good),
        "SCSI status must be GOOD(0)"
    );

    assert!(!pdu.header_view()?.flags.ack(), "A bit must be 0");
    // assert!(!pdu.header.flags.o(), "O bit must be 0");
    assert!(!header.flags.u(), "U bit must be 0");

    assert_eq!(
        pdu.data()?.len(),
        header.get_data_length_bytes(),
        "payload length mismatch: data.len() vs DataSegmentLength"
    );

    let payload = vec![0x00; header.get_data_length_bytes()];
    assert_eq!(&pdu.data()?, &payload);

    Ok(())
}

#[tokio::test]
async fn datain_acknowledges_statsn_only_when_status_is_present() -> Result<()> {
    let mut cfg = Config::load_from_file("tests/config.yaml")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    cfg.login.transport.target_address = listener.local_addr()?.to_string();
    let (conn, peer) = tokio::try_join!(
        ClientConnection::connect(cfg.clone(), CancellationToken::new()),
        async { listener.accept().await.context("accept test connection") }
    )?;

    for (status_present, stat_sn, expected) in [
        (true, 0u32, 1u32),
        (true, 41, 42),
        (true, u32::MAX, 0),
        (false, 0, 17),
        (false, 41, 17),
    ] {
        let exp_stat_sn = Arc::new(AtomicU32::new(17));
        let mut ctx = ReadCtx::new(
            conn.clone(),
            Lun::ZERO,
            &IttGen::default(),
            Arc::new(AtomicU32::new(0)),
            exp_stat_sn.clone(),
            0,
            [0; 16],
        );
        let mut header = [0; HEADER_LEN];
        header[0] = 0x25; // SCSI Data-In
        header[1] = if status_present { 0x81 } else { 0x80 }; // F and optional S
        header[24..28].copy_from_slice(&stat_sn.to_be_bytes());
        let mut pdu = PduResponse::<ScsiDataIn>::from_header_slice(header, &cfg);
        pdu.parse_with_buff(&Bytes::new())?;

        assert!(ctx.apply_datain_append(&pdu)?);
        assert_eq!(
            exp_stat_sn.load(Ordering::SeqCst),
            expected,
            "S={status_present}, StatSN={stat_sn}"
        );
        assert_eq!(
            ctx.rt.status_in_datain,
            status_present.then_some(ScsiStatus::Good)
        );
    }
    conn.kill_now();
    drop(peer);
    Ok(())
}
