// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::logger::init_logger,
    client::pool_sessions::Pool,
    control_block::{
        read::build_read10,
        read_capacity::{build_read_capacity10, parse_read_capacity10_zerocopy},
        write::build_write10,
    },
    state_machine::{read_states::ReadCtx, tur_states::TurCtx, write_states::WriteCtx},
};
use serial_test::serial;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn io_around_negotiated_segment_boundaries() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = Arc::new(load_config()?);
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let tsih = pool
        .login_and_insert(target_name, test_isid(), 0, conn)
        .await
        .context("pool login failed")?;
    let lun = get_lun();
    let _ = pool
        .execute_with_ctx(tsih, 0, |env| TurCtx::from_execute_env(env, lun))
        .await;
    pool.execute_with_ctx(tsih, 0, |env| TurCtx::from_execute_env(env, lun))
        .await
        .context("TUR failed")?;

    let capacity = pool
        .execute_with_ctx(tsih, 0, |env| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::from_execute_env(env, lun, 8, cdb)
        })
        .await?;
    let block_size = parse_read_capacity10_zerocopy(&capacity.data)?
        .block_len
        .get() as usize;

    let first_burst_blocks = cfg.login.flow.first_burst_length as usize / block_size;
    let segment_blocks =
        cfg.login.flow.max_recv_data_segment_length as usize / block_size;
    let mut block_counts = BTreeSet::from([1usize]);
    for boundary in [first_burst_blocks, segment_blocks] {
        if boundary > 1 {
            block_counts.insert(boundary - 1);
        }
        block_counts.insert(boundary);
    }
    if first_burst_blocks > 0 {
        block_counts.insert(first_burst_blocks + 1);
    }

    let mut lba = 20_000u32;
    for blocks in block_counts {
        anyhow::ensure!(blocks <= u16::MAX as usize);
        let byte_len = blocks * block_size;
        let payload = (0..byte_len)
            .map(|offset| (offset as u8).wrapping_add(blocks as u8))
            .collect::<Vec<_>>();

        pool.execute_with_ctx(tsih, 0, |env| {
            let mut cdb = [0u8; 16];
            build_write10(&mut cdb, lba, blocks as u16, 0, 0);
            WriteCtx::from_execute_env(env, lun, cdb, payload.clone())
        })
        .await
        .with_context(|| format!("WRITE boundary blocks={blocks}"))?;

        let read = pool
            .execute_with_ctx(tsih, 0, |env| {
                let mut cdb = [0u8; 16];
                build_read10(&mut cdb, lba, blocks as u16, 0, 0);
                ReadCtx::from_execute_env(env, lun, byte_len as u32, cdb)
            })
            .await
            .with_context(|| format!("READ boundary blocks={blocks}"))?;
        assert_eq!(read.data, payload, "boundary payload mismatch");
        lba += blocks as u32 + 8;
    }

    pool.shutdown_gracefully(Duration::from_secs(10)).await
}
