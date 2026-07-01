// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::logger::init_logger,
    client::pool_sessions::Pool,
    control_block::{
        read::build_read10,
        read_capacity::{build_read_capacity10, parse_read_capacity10_zerocopy},
        write::build_write10,
    },
    models::identifiers::Cid,
    state_machine::{read_states::ReadCtx, tur_states::TurCtx, write_states::WriteCtx},
};
use serial_test::serial;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

const REQUESTS: u32 = 32;
const START_LBA: u32 = 16_384;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[serial]
async fn concurrent_writes_and_reads_share_one_connection() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = Arc::new(load_config()?);
    let pool = Pool::new(&cfg);

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let tsih = pool
        .login_and_insert(target_name, test_isid(), Cid::ZERO, conn)
        .await
        .context("pool login failed")?;
    let lun = get_lun();
    let _ = pool
        .execute_with_ctx(tsih, Cid::ZERO, |env| TurCtx::from_execute_env(env, lun))
        .await;
    pool.execute_with_ctx(tsih, Cid::ZERO, |env| TurCtx::from_execute_env(env, lun))
        .await
        .context("TUR failed")?;

    let capacity = pool
        .execute_with_ctx(tsih, Cid::ZERO, |env| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::from_execute_env(env, lun, 8, cdb)
        })
        .await?;
    let block_size = parse_read_capacity10_zerocopy(&capacity.data)?
        .block_len
        .get() as usize;

    let mut writes = Vec::with_capacity(REQUESTS as usize);
    for index in 0..REQUESTS {
        let pool = Arc::clone(&pool);
        let payload = vec![(index as u8).wrapping_mul(17); block_size];
        writes.push(tokio::spawn(async move {
            pool.execute_with_ctx(tsih, Cid::ZERO, |env| {
                let mut cdb = [0u8; 16];
                build_write10(&mut cdb, START_LBA + index, 1, 0, 0);
                WriteCtx::from_execute_env(env, lun, cdb, payload.clone())
            })
            .await
        }));
    }
    for write in writes {
        write.await.context("write task panicked")??;
    }

    let mut reads = Vec::with_capacity(REQUESTS as usize);
    for index in 0..REQUESTS {
        let pool = Arc::clone(&pool);
        reads.push(tokio::spawn(async move {
            let result = pool
                .execute_with_ctx(tsih, Cid::ZERO, |env| {
                    let mut cdb = [0u8; 16];
                    build_read10(&mut cdb, START_LBA + index, 1, 0, 0);
                    ReadCtx::from_execute_env(env, lun, block_size as u32, cdb)
                })
                .await?;
            let expected = vec![(index as u8).wrapping_mul(17); block_size];
            anyhow::ensure!(
                result.data == expected,
                "payload mismatch for request {index}"
            );
            Ok::<(), anyhow::Error>(())
        }));
    }
    for read in reads {
        read.await.context("read task panicked")??;
    }

    pool.shutdown_gracefully(Duration::from_secs(10)).await
}
