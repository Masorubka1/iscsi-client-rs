// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::config::{Config, login_keys_operational},
    client::{client::ClientConnection, pool_sessions::Pool},
    models::{
        common::HEADER_LEN,
        identifiers::{Cid, Isid, Tsih},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

async fn accept_login(
    listener: &TcpListener,
    negotiation: &[u8],
    tsih: Tsih,
) -> Result<TcpStream> {
    let (mut peer, _) = listener.accept().await?;
    let mut request = [0; HEADER_LEN];
    peer.read_exact(&mut request).await?;
    let data_len = u32::from_be_bytes([0, request[5], request[6], request[7]]) as usize;
    let mut payload = vec![0; (data_len + 3) & !3];
    peer.read_exact(&mut payload).await?;

    let mut response = [0; HEADER_LEN];
    response[0] = 0x23; // Login Response
    response[1] = 0x87; // Transit from Operational to Full Feature
    let length = (negotiation.len() as u32).to_be_bytes();
    response[5..8].copy_from_slice(&length[1..]);
    response[8..14].copy_from_slice(&request[8..14]);
    response[14..16].copy_from_slice(&tsih.get().to_be_bytes());
    response[16..20].copy_from_slice(&request[16..20]);
    response[24..28].copy_from_slice(&10u32.to_be_bytes());
    response[28..32].copy_from_slice(&1u32.to_be_bytes());
    response[32..36].copy_from_slice(&128u32.to_be_bytes());
    let mut data = negotiation.to_vec();
    data.resize((data.len() + 3) & !3, 0);
    peer.write_all(&response).await?;
    peer.write_all(&data).await?;
    Ok(peer)
}

#[tokio::test]
async fn duplicate_cid_preserves_existing_connection() -> Result<()> {
    let mut cfg = Config::load_from_file("tests/config.yaml")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    cfg.login.transport.target_address = listener.local_addr()?.to_string();
    let negotiation = login_keys_operational(&cfg);
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let tsih = Tsih::new(1);

    // Complete both logins so the second attempt reaches the CID insertion.
    let server = tokio::spawn(async move {
        let mut peers = Vec::new();
        for _ in 0..2 {
            let peer = accept_login(&listener, &negotiation, tsih).await?;
            peers.push(peer);
        }
        server_stop.cancelled().await;
        Ok::<_, anyhow::Error>(())
    });

    let pool = Pool::new(&cfg);
    let original = ClientConnection::connect(cfg.clone(), stop.child_token()).await?;
    let logged_in = pool
        .login_and_insert(
            Arc::from(cfg.login.identity.target_name.as_str()),
            Isid::new([0, 1, 2, 3, 4, 5]),
            Cid::ZERO,
            original.clone(),
        )
        .await?;
    assert_eq!(logged_in, tsih);
    let session = pool.sessions.get(&tsih).context("missing session")?.clone();
    let before = session
        .conns
        .get(&Cid::ZERO)
        .context("missing CID")?
        .clone();

    let duplicate = ClientConnection::connect(cfg, stop.child_token()).await?;
    let result = pool
        .add_connection_to_session(tsih, Cid::ZERO, duplicate)
        .await;
    let error = result.expect_err("duplicate CID must be rejected");
    assert!(
        error.to_string().contains("CID=0 already exists"),
        "{error:#}"
    );

    let after = session
        .conns
        .get(&Cid::ZERO)
        .context("original CID removed")?;
    assert!(Arc::ptr_eq(&before, after.value()));
    assert!(Arc::ptr_eq(&after.conn, &original));
    assert_eq!(session.conns.len(), 1);
    assert_eq!(pool.sessions.len(), 1);

    stop.cancel();
    server.await??;
    Ok(())
}

#[tokio::test]
async fn unsolicited_nop_is_answered_by_the_owning_session() -> Result<()> {
    let mut cfg = Config::load_from_file("tests/config.yaml")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    cfg.login.transport.target_address = listener.local_addr()?.to_string();
    let negotiation = login_keys_operational(&cfg);
    let (ready, bound) = tokio::sync::oneshot::channel::<()>();
    let tsih = Tsih::new(1);
    let server = tokio::spawn(async move {
        let mut peer = accept_login(&listener, &negotiation, tsih).await?;
        bound.await?;
        let mut nop = [0; HEADER_LEN];
        nop[0] = 0x20; // NOP-In
        nop[1] = 0x80;
        nop[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        nop[20..24].copy_from_slice(&7u32.to_be_bytes());
        nop[24..28].copy_from_slice(&11u32.to_be_bytes());
        nop[28..32].copy_from_slice(&1u32.to_be_bytes());
        nop[32..36].copy_from_slice(&128u32.to_be_bytes());
        peer.write_all(&nop).await?;

        let mut reply = [0; HEADER_LEN];
        timeout(Duration::from_secs(2), peer.read_exact(&mut reply)).await??;
        assert_eq!(reply[0], 0x40, "expected immediate NOP-Out");
        assert_eq!(&reply[16..20], &u32::MAX.to_be_bytes());
        assert_eq!(&reply[20..24], &7u32.to_be_bytes());
        Ok::<_, anyhow::Error>(())
    });
    let pool = Pool::new(&cfg);
    let conn =
        ClientConnection::connect(cfg.clone(), pool.cancel_token().child_token()).await?;
    pool.login_and_insert(
        Arc::from(cfg.login.identity.target_name.as_str()),
        Isid::new([0, 1, 2, 3, 4, 5]),
        Cid::ZERO,
        conn,
    )
    .await?;
    ready.send(()).expect("mock target exited before binding");
    server.await??;
    Ok(())
}
