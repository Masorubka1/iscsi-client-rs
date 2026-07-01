// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{fs, time::Duration};

use anyhow::{Context, Result};
use hex::FromHex;
use iscsi_client_rs::{
    cfg::{config::Config, enums::Digest},
    client::client::ClientConnection,
    models::{
        common::HEADER_LEN,
        data_fromat::PduRequest,
        nop::{
            request::{NopOutRequest, NopOutRequestBuilder},
            response::NopInResponse,
        },
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

fn load_fixture(path: &str) -> Result<Vec<u8>> {
    let s = fs::read_to_string(path)?;
    let cleaned = s.trim().replace(|c: char| c.is_whitespace(), "");
    Ok(Vec::from_hex(&cleaned)?)
}

fn test_config(
    target_address: String,
    timeout_connection: Duration,
    digest: Digest,
) -> Result<Config> {
    let mut cfg = Config::load_from_file("tests/configs/tgt/plain.yaml")?;
    cfg.login.transport.target_address = target_address;
    cfg.login.integrity.header_digest = digest;
    cfg.login.integrity.data_digest = digest;
    cfg.runtime.timeout_connection = timeout_connection;
    Ok(cfg)
}

async fn wait_until_poisoned(conn: &ClientConnection) -> Result<()> {
    timeout(Duration::from_secs(1), async {
        while !conn.is_poisoned() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("connection was not poisoned")?;
    Ok(())
}

#[tokio::test]
async fn eof_before_bhs_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        drop(stream);
    });

    let cfg = test_config(
        address.to_string(),
        Duration::from_millis(100),
        Digest::None,
    )?;
    let conn = ClientConnection::connect(cfg, CancellationToken::new()).await?;

    wait_until_poisoned(&conn).await?;
    server.await?;
    Ok(())
}

#[tokio::test]
async fn truncated_bhs_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        stream.write_all(&[0x20; 12]).await.expect("partial BHS");
    });

    let cfg = test_config(
        address.to_string(),
        Duration::from_millis(100),
        Digest::None,
    )?;
    let conn = ClientConnection::connect(cfg, CancellationToken::new()).await?;

    wait_until_poisoned(&conn).await?;
    server.await?;
    Ok(())
}

#[tokio::test]
async fn truncated_payload_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut header = [0u8; HEADER_LEN];
        header[0] = 0x20;
        header[5..8].copy_from_slice(&[0, 0, 8]);
        stream.write_all(&header).await.expect("BHS");
        stream.write_all(&[1, 2, 3]).await.expect("partial payload");
    });

    let cfg = test_config(
        address.to_string(),
        Duration::from_millis(100),
        Digest::None,
    )?;
    let conn = ClientConnection::connect(cfg, CancellationToken::new()).await?;

    wait_until_poisoned(&conn).await?;
    server.await?;
    Ok(())
}

#[tokio::test]
async fn read_timeout_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept");
        sleep(Duration::from_secs(1)).await;
    });

    let cfg = test_config(address.to_string(), Duration::from_millis(50), Digest::None)?;
    let conn = ClientConnection::connect(cfg, CancellationToken::new()).await?;

    wait_until_poisoned(&conn).await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn invalid_header_digest_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut response = load_fixture("tests/unit_tests/fixtures/nop/nop_in_response.hex")?;
    response.truncate(HEADER_LEN);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; HEADER_LEN + 4];
        stream.read_exact(&mut request).await.expect("NOP-Out");
        response[16..20].copy_from_slice(&request[16..20]);
        stream.write_all(&response).await.expect("NOP-In BHS");
        stream
            .write_all(&0xdead_beefu32.to_le_bytes())
            .await
            .expect("bad HeaderDigest");
        sleep(Duration::from_millis(100)).await;
    });

    let mut cfg = Config::load_from_file("tests/configs/tgt/crc.yaml")?;
    cfg.login.transport.target_address = address.to_string();
    cfg.runtime.timeout_connection = Duration::from_millis(200);
    let conn = ClientConnection::connect(cfg.clone(), CancellationToken::new()).await?;

    let itt = 42.into();
    let header = NopOutRequestBuilder::new()
        .initiator_task_tag(itt)
        .target_task_tag(NopOutRequest::DEFAULT_TAG)
        .immediate();
    let mut header_buf = [0u8; HEADER_LEN];
    header.header.to_bhs_bytes(&mut header_buf)?;
    let request = PduRequest::<NopOutRequest>::new_request(header_buf, &cfg);
    conn.send_request(itt, request).await?;

    let error = conn
        .read_response::<NopInResponse>(itt)
        .await
        .expect_err("invalid digest must fail");
    assert!(error.to_string().contains("HeaderDigest mismatch"));
    assert!(conn.is_poisoned());
    server.await?;
    Ok(())
}

#[tokio::test]
async fn invalid_data_digest_poisons_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut response = load_fixture("tests/unit_tests/fixtures/nop/nop_in_response.hex")?;
    response.truncate(HEADER_LEN);
    response[5..8].copy_from_slice(&[0, 0, 4]);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; HEADER_LEN + 4];
        stream.read_exact(&mut request).await.expect("NOP-Out");
        response[16..20].copy_from_slice(&request[16..20]);

        let header_digest = crc32c::crc32c(&response).to_le_bytes();
        stream.write_all(&response).await.expect("NOP-In BHS");
        stream
            .write_all(&header_digest)
            .await
            .expect("HeaderDigest");
        stream.write_all(b"ping").await.expect("NOP-In data");
        stream
            .write_all(&0xdead_beefu32.to_le_bytes())
            .await
            .expect("bad DataDigest");
        sleep(Duration::from_millis(100)).await;
    });

    let mut cfg = Config::load_from_file("tests/configs/tgt/crc.yaml")?;
    cfg.login.transport.target_address = address.to_string();
    cfg.runtime.timeout_connection = Duration::from_millis(200);
    let conn = ClientConnection::connect(cfg.clone(), CancellationToken::new()).await?;

    let itt: iscsi_client_rs::models::identifiers::Itt = 43_u32.into();
    let header = NopOutRequestBuilder::new()
        .initiator_task_tag(itt)
        .target_task_tag(NopOutRequest::DEFAULT_TAG)
        .immediate();
    let mut header_buf = [0u8; HEADER_LEN];
    header.header.to_bhs_bytes(&mut header_buf)?;
    let request = PduRequest::<NopOutRequest>::new_request(header_buf, &cfg);
    conn.send_request(itt, request).await?;

    let error = conn
        .read_response::<NopInResponse>(itt)
        .await
        .expect_err("invalid digest must fail");
    assert!(error.to_string().contains("DataDigest mismatch"));
    assert!(conn.is_poisoned());
    server.await?;
    Ok(())
}
