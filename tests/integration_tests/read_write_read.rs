// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::{read::build_read10, write::build_write10},
    state_machine::{read_states::ReadCtx, write_states::WriteCtx},
};
use serial_test::serial;
use tokio::time::{sleep, timeout};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

fn pick_lba_from_isid(isid: [u8; 6]) -> u32 {
    let s: u32 = isid.iter().map(|&b| b as u32).sum();
    4096 + (s % 1024)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn read10_write10_read10_plain_pool() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Arc::new(load_config()?);

    if !matches!(cfg.login.auth, AuthConfig::None) {
        eprintln!("skip: auth.method != none in TEST_CONFIG");
        return Ok(());
    }

    // --- Pool + login ---
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.security.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();
    const BLK: usize = 512;
    let blocks: u16 = 1;
    let lba: u32 = pick_lba_from_isid(isid);

    // --- READ(10) #1 ---
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read10(&mut cdb, lba, blocks, 0, 0);
            ReadCtx::new(
                c,
                lun,
                itt,         // Arc<AtomicU32>
                cmd_sn,      // Arc<AtomicU32>
                exp_stat_sn, // Arc<AtomicU32>
                (BLK * blocks as usize) as u32,
                cdb,
            )
        })
        .await;
    let rd1 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read10(&mut cdb, lba, blocks, 0, 0);
            ReadCtx::new(
                c,
                lun,
                itt,         // Arc<AtomicU32>
                cmd_sn,      // Arc<AtomicU32>
                exp_stat_sn, // Arc<AtomicU32>
                (BLK * blocks as usize) as u32,
                cdb,
            )
        })
        .await
        .context("READ(10) #1.2 failed")?;
    assert_eq!(
        rd1.data.len(),
        BLK,
        "first READ must return exactly 1 block"
    );

    // --- WRITE(10) ---
    let payload = vec![0xA5u8; BLK];
    let write_once = || {
        pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_write10(&mut cdb, lba, blocks, 0, 0);
            WriteCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, cdb, payload.clone())
        })
    };

    if let Err(e) = write_once().await {
        eprintln!("WRITE(10) first attempt failed: {e}");
        sleep(Duration::from_millis(100)).await;
        write_once().await.context("WRITE(10) retry failed")?;
    }

    // --- READ(10) #2 ---
    let rd2 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read10(&mut cdb, lba, blocks, 0, 0);
            ReadCtx::new(
                c,
                lun,
                itt,
                cmd_sn,
                exp_stat_sn,
                (BLK * blocks as usize) as u32,
                cdb,
            )
        })
        .await
        .context("READ(10) #2 failed")?;

    assert_eq!(rd2.data, payload, "read data differs from what was written");

    timeout(
        cfg.extra_data.connections.timeout_connection,
        pool.logout_all(),
    )
    .await
    .context("logout timeout")??;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed from pool after CloseSession"
    );

    Ok(())
}
