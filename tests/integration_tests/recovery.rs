// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{Config, login_keys_operational},
        logger::init_logger,
    },
    client::{client::ClientConnection, pool_sessions::Pool},
    models::{
        common::{BasicHeaderSegment, HEADER_LEN},
        identifiers::{Lun, Ttt},
        login::{
            common::Stage,
            request::LoginRequest,
            response::LoginResponse,
            status::{RawStatusPair, StatusClass, StatusDetail, SuccessDetail},
        },
        nop::{request::NopOutRequest, response::NopInResponse},
        opcode::{Opcode, RawBhsOpcode},
    },
    state_machine::nop_states::NopCtx,
};
use serial_test::serial;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};
use tokio_util::sync::CancellationToken;

use crate::integration_tests::common::{test_isid, test_path};

const TEST_TSIH: u16 = 0x0200;

fn load_plain_cfg(target_address: String) -> Result<Config> {
    let mut cfg = Config::load_from_file("tests/configs/tgt/plain.yaml")?;
    cfg.login.transport.target_address = target_address;
    cfg.runtime.timeout_connection = Duration::from_millis(300);
    Ok(cfg)
}

async fn read_frame(stream: &mut TcpStream) -> Result<([u8; HEADER_LEN], Vec<u8>)> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;

    let data_len = u32::from_be_bytes([0, header[5], header[6], header[7]]) as usize;
    let padded_len = data_len.next_multiple_of(4);
    let mut payload = vec![0u8; padded_len];
    if padded_len != 0 {
        stream.read_exact(&mut payload).await?;
        payload.truncate(data_len);
    }

    Ok((header, payload))
}

async fn write_frame(
    stream: &mut TcpStream,
    header: &[u8; HEADER_LEN],
    payload: &[u8],
) -> Result<()> {
    stream.write_all(header).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
        let padding = [0u8; 3];
        let pad_len = (4 - (payload.len() % 4)) % 4;
        if pad_len != 0 {
            stream.write_all(&padding[..pad_len]).await?;
        }
    }
    Ok(())
}

async fn write_login_response(
    stream: &mut TcpStream,
    cfg: &Config,
    request_header: [u8; HEADER_LEN],
    tsih: u16,
) -> Result<()> {
    let mut request_header = request_header;
    let request = LoginRequest::from_bhs_bytes(&mut request_header)?;

    let mut response = LoginResponse::default();
    response.opcode = {
        let mut opcode = RawBhsOpcode::default();
        opcode.set_opcode_known(Opcode::LoginResp);
        opcode
    };
    response.flags.set_transit(true);
    response.flags.set_csg(Stage::Operational);
    response.flags.set_nsg(Stage::FullFeature);
    response.version_max = request.version_max;
    response.version_active = request.version_max;
    response.isid = request.isid;
    response.tsih.set(tsih);
    response
        .initiator_task_tag
        .set(request.initiator_task_tag.get());
    response.stat_sn.set(0);
    response
        .exp_cmd_sn
        .set(request.cmd_sn.get().wrapping_add(1));
    response
        .max_cmd_sn
        .set(request.cmd_sn.get().wrapping_add(1));

    let mut status = RawStatusPair::new();
    status.encode(
        StatusClass::Success,
        StatusDetail::Success(SuccessDetail::CmdCompletedNormally),
    )?;
    response.status_class = status.class;
    response.status_detail = status.detail;

    let payload = login_keys_operational(cfg);
    response.set_data_length_bytes(payload.len() as u32);

    let mut header = [0u8; HEADER_LEN];
    response.to_bhs_bytes(&mut header)?;
    write_frame(stream, &header, &payload).await
}

async fn write_nop_in(
    stream: &mut TcpStream,
    request_header: [u8; HEADER_LEN],
) -> Result<()> {
    let mut request_header = request_header;
    let request = NopOutRequest::from_bhs_bytes(&mut request_header)?;

    let mut response = NopInResponse::default();
    response.opcode = {
        let mut opcode = RawBhsOpcode::default();
        opcode.set_opcode_known(Opcode::NopIn);
        opcode
    };
    response.lun.set(request.lun.get());
    response
        .initiator_task_tag
        .set(request.initiator_task_tag.get());
    response.target_task_tag.set(NopOutRequest::DEFAULT_TAG);
    response.stat_sn.set(1);
    response
        .exp_cmd_sn
        .set(request.cmd_sn.get().wrapping_add(1));
    response
        .max_cmd_sn
        .set(request.cmd_sn.get().wrapping_add(1));

    let mut header = [0u8; HEADER_LEN];
    response.to_bhs_bytes(&mut header)?;
    write_frame(stream, &header, &[]).await
}

async fn serve_recovery_target(listener: TcpListener, cfg: Config) -> Result<()> {
    let (mut first, _) = listener.accept().await?;
    let (login1, _) = read_frame(&mut first).await?;
    write_login_response(&mut first, &cfg, login1, TEST_TSIH).await?;
    let (_nop1, _) = read_frame(&mut first).await?;
    let stalled = tokio::spawn(async move {
        sleep(Duration::from_millis(700)).await;
        drop(first);
        Ok::<(), anyhow::Error>(())
    });

    let (mut second, _) = listener.accept().await?;
    let (login2, _) = read_frame(&mut second).await?;
    write_login_response(&mut second, &cfg, login2, TEST_TSIH).await?;
    let (nop2, _) = read_frame(&mut second).await?;
    write_nop_in(&mut second, nop2).await?;
    sleep(Duration::from_millis(100)).await;
    stalled.await??;
    Ok(())
}

#[tokio::test]
#[serial]
async fn poisoned_connection_is_recreated_after_timeout() -> Result<()> {
    let _ = init_logger(&test_path());

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let cfg = load_plain_cfg(address.to_string())?;

    let server = tokio::spawn(serve_recovery_target(listener, cfg.clone()));
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = ClientConnection::connect(cfg.clone(), CancellationToken::new()).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let tsih = pool
        .login_and_insert(target_name, test_isid(), 0, conn)
        .await
        .context("pool login failed")?;

    let before = pool
        .sessions
        .get(&tsih)
        .context("missing session after login")?
        .conns
        .get(&0)
        .context("missing CID=0 after login")?
        .conn
        .clone();

    pool.execute_with(tsih, 0, |c, itt, cmd_sn, exp_stat_sn| {
        NopCtx::new(
            c,
            Lun::from_raw(1u64 << 48),
            itt,
            cmd_sn,
            exp_stat_sn,
            Ttt::new_unchecked(NopOutRequest::DEFAULT_TAG),
        )
    })
    .await
    .context("NOP after recovery failed")?;

    let after = pool
        .sessions
        .get(&tsih)
        .context("missing session after recovery")?
        .conns
        .get(&0)
        .context("missing CID=0 after recovery")?
        .conn
        .clone();

    assert!(before.is_poisoned(), "original connection must be poisoned");
    assert!(
        !Arc::ptr_eq(&before, &after),
        "pool must replace poisoned connection"
    );
    assert!(
        !after.is_poisoned(),
        "replacement connection must remain healthy"
    );

    server.await??;
    Ok(())
}
