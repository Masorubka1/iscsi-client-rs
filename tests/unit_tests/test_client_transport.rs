// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, atomic::AtomicU32};

use anyhow::Result;
use iscsi_client_rs::{
    cfg::config::Config,
    client::client::ClientConnection,
    control_block::read_capacity::build_read_capacity10,
    models::{
        common::HEADER_LEN,
        identifiers::{IttGen, Lun},
    },
    state_machine::{common::StateMachineCtx, read_states::ReadCtx},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn fragmented_responses_are_framed_and_routed_to_their_requests() -> Result<()> {
    let mut cfg = Config::load_from_file("tests/config.yaml")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    cfg.login.transport.target_address = listener.local_addr()?.to_string();
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        let (mut peer, _) = listener.accept().await?;
        let mut requests = [[0; HEADER_LEN]; 2];
        for request in &mut requests {
            peer.read_exact(request).await?;
        }

        // Reply in reverse order, splitting writes across both BHS and data.
        let mut frames = Vec::new();
        for index in [1, 0] {
            let mut header = [0; HEADER_LEN];
            header[0] = 0x25; // Data-In
            header[1] = 0x81; // F=1, S=1, GOOD
            header[7] = 8;
            header[16..20].copy_from_slice(&requests[index][16..20]);
            header[24..28].copy_from_slice(&(2 - index as u32).to_be_bytes());
            frames.extend_from_slice(&header);
            frames.extend_from_slice(&[index as u8 + 1; 8]);
        }
        for fragment in frames.chunks(7) {
            peer.write_all(fragment).await?;
            tokio::task::yield_now().await;
        }
        server_stop.cancelled().await;
        Ok::<_, anyhow::Error>(())
    });

    let conn = ClientConnection::connect(cfg, stop.child_token()).await?;
    let itt = IttGen::default();
    let cmd_sn = Arc::new(AtomicU32::new(0));
    let exp_stat_sn = Arc::new(AtomicU32::new(0));
    let mut cdb = [0; 16];
    build_read_capacity10(&mut cdb, 0, false, 0);
    let mut first = ReadCtx::new(
        conn.clone(),
        Lun::ZERO,
        &itt,
        cmd_sn.clone(),
        exp_stat_sn.clone(),
        8,
        cdb,
    );
    let mut second =
        ReadCtx::new(conn.clone(), Lun::ZERO, &itt, cmd_sn, exp_stat_sn, 8, cdb);
    let cancel = CancellationToken::new();
    let result = tokio::try_join!(first.execute(&cancel), second.execute(&cancel));
    stop.cancel();
    server.await??;
    let (first, second) = result?;
    assert_eq!(first.data, [1; 8]);
    assert_eq!(second.data, [2; 8]);
    Ok(())
}
