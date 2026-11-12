// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
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
    state_machine::{common::StateMachineCtx, read_states::ReadCtx},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
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

        assert_eq!(ctx.apply_datain_append(&pdu)?, status_present);
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

async fn read_multiple_sequences(status_in_datain: bool) -> Result<()> {
    let mut cfg = Config::load_from_file("tests/config.yaml")?;
    cfg.login.flow.max_burst_length = 512;
    cfg.login.flow.first_burst_length = 512;
    cfg.login.flow.max_recv_data_segment_length = 512;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    cfg.login.transport.target_address = listener.local_addr()?.to_string();
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await?;
        let mut request = [0; HEADER_LEN];
        peer.read_exact(&mut request).await?;
        assert_eq!(request[32], 0x28, "expected READ(10)");
        for data_sn in 0..2u32 {
            let mut header = [0; HEADER_LEN];
            header[0] = 0x25; // Data-In
            header[1] = 0x80; // F ends each sequence, including the first one.
            if data_sn == 1 && status_in_datain {
                header[1] |= 1; // S: status accompanies the last data sequence.
                header[24..28].copy_from_slice(&11u32.to_be_bytes());
            }
            header[5..8].copy_from_slice(&512u32.to_be_bytes()[1..]);
            header[16..20].copy_from_slice(&request[16..20]);
            header[28..32].copy_from_slice(&2u32.to_be_bytes());
            header[32..36].copy_from_slice(&128u32.to_be_bytes());
            header[36..40].copy_from_slice(&data_sn.to_be_bytes());
            header[40..44].copy_from_slice(&(data_sn * 512).to_be_bytes());
            peer.write_all(&header).await?;
            peer.write_all(&[data_sn as u8 + 1; 512]).await?;
        }
        if !status_in_datain {
            let mut response = [0; HEADER_LEN];
            response[0] = 0x21; // Separate SCSI Response, GOOD status.
            response[1] = 0x80;
            response[16..20].copy_from_slice(&request[16..20]);
            response[24..28].copy_from_slice(&11u32.to_be_bytes());
            response[28..32].copy_from_slice(&2u32.to_be_bytes());
            response[32..36].copy_from_slice(&128u32.to_be_bytes());
            response[36..40].copy_from_slice(&2u32.to_be_bytes());
            peer.write_all(&response).await?;
        }
        server_stop.cancelled().await;
        Ok::<_, anyhow::Error>(())
    });
    let conn = ClientConnection::connect(cfg, stop.child_token()).await?;
    let mut cdb = [0; 16];
    build_read10(&mut cdb, 0, 2, 0, 0);
    let mut ctx = ReadCtx::new(
        conn,
        Lun::ZERO,
        &IttGen::default(),
        Arc::new(AtomicU32::new(1)),
        Arc::new(AtomicU32::new(11)),
        1024,
        cdb,
    );
    let cancel = CancellationToken::new();
    let result = timeout(Duration::from_secs(2), ctx.execute(&cancel)).await;
    stop.cancel();
    server.await??;
    let read = result.context("read did not finish")??;
    assert_eq!(read.data, [vec![1; 512], vec![2; 512]].concat());
    assert_eq!(read.last_response.is_some(), !status_in_datain);
    Ok(())
}

#[tokio::test]
async fn read_multiple_sequences_with_status_in_last_datain() -> Result<()> {
    read_multiple_sequences(true).await
}

#[tokio::test]
async fn read_multiple_sequences_with_separate_scsi_response() -> Result<()> {
    read_multiple_sequences(false).await
}
