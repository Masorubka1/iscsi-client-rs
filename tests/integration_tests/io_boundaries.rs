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
    models::identifiers::Cid,
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

        pool.execute_with_ctx(tsih, Cid::ZERO, |env| {
            let mut cdb = [0u8; 16];
            build_write10(&mut cdb, lba, blocks as u16, 0, 0);
            WriteCtx::from_execute_env(env, lun, cdb, payload.clone())
        })
        .await
        .with_context(|| format!("WRITE boundary blocks={blocks}"))?;

        let read = pool
            .execute_with_ctx(tsih, Cid::ZERO, |env| {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn read_larger_than_negotiated_max_burst() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = load_config()?;
    let pool = Pool::new(&cfg);
    let conn = connect_cfg(&cfg).await?;
    let tsih = pool
        .login_and_insert(
            Arc::from(cfg.login.identity.target_name.as_str()),
            test_isid(),
            Cid::ZERO,
            conn,
        )
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
            let mut cdb = [0; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::from_execute_env(env, lun, 8, cdb)
        })
        .await
        .context("READ CAPACITY(10) failed")?;
    let capacity = parse_read_capacity10_zerocopy(&capacity.data)?;
    let block_size = capacity.block_len.get();
    anyhow::ensure!(block_size > 0, "target reported zero block size");
    let max_burst = cfg.login.flow.max_burst_length;
    let blocks = max_burst / block_size + 1;
    anyhow::ensure!(
        u64::from(blocks) <= u64::from(capacity.max_lba.get()) + 1,
        "target is too small for a read larger than MaxBurstLength"
    );
    let blocks = u16::try_from(blocks).context("read exceeds READ(10) block count")?;
    let byte_len = u32::from(blocks)
        .checked_mul(block_size)
        .context("read length overflow")?;
    assert!(byte_len > max_burst);

    // Exercise a single command larger than MaxBurstLength. Actual Data-In
    // sequence boundaries depend on the target; size alone does not assert F.
    let result = pool
        .execute_with_ctx(tsih, Cid::ZERO, |env| {
            let mut cdb = [0; 16];
            build_read10(&mut cdb, 0, blocks, 0, 0);
            ReadCtx::from_execute_env(env, lun, byte_len, cdb)
        })
        .await;
    let shutdown = pool.shutdown_gracefully(Duration::from_secs(10)).await;
    let read = result.with_context(|| {
        format!("single READ(10): bytes={byte_len}, MaxBurstLength={max_burst}")
    })?;
    assert_eq!(read.data.len(), byte_len as usize);
    shutdown
}
