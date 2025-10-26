// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    client::pool_sessions::Pool,
    control_block::{
        read::build_read10,
        read_capacity::{
            Rc10Raw, Rc16Raw, build_read_capacity10, build_read_capacity16,
            parse_read_capacity10_zerocopy, parse_read_capacity16_zerocopy,
        },
        write::build_write10,
    },
    state_machine::{read_states::ReadCtx, write_states::WriteCtx},
};
use serial_test::serial;
use tokio::time::sleep;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

fn pick_lba_from_isid(isid: [u8; 6]) -> u32 {
    let s: u32 = isid.iter().map(|&b| b as u32).sum();
    4096 + (s % 1024)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn read_capacity_then_write10_plain() -> Result<()> {
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
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let isid = test_isid();
    let cid: u16 = 0;

    let tsih = pool
        .login_and_insert(target_name, isid, cid, conn.clone())
        .await
        .context("pool login failed")?;

    let lun = get_lun();

    // ============ READ CAPACITY(10) ============
    let _ = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await;
    let rc10_bytes = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await
        .context("READ CAPACITY(10) failed")?
        .data;

    assert_eq!(rc10_bytes.len(), 8, "RC(10) must return 8 bytes");
    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&rc10_bytes)
        .context("failed to parse RC(10) payload")?;
    let blk_len_10 = rc10.block_len.get();
    assert!(
        blk_len_10.is_power_of_two(),
        "block_len(10) must be power-of-two"
    );
    let max_lba_10 = rc10.max_lba.get();

    // ============ READ CAPACITY(16) (optional) ============
    let (blk_len, max_lba_u64) = {
        let try_rc16 = pool
            .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                build_read_capacity16(&mut cdb, 0, false, 32, 0);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 32, cdb)
            })
            .await;

        match try_rc16 {
            Ok(rc16_res) => {
                let bytes = rc16_res.data;
                assert!(
                    bytes.len() >= 12,
                    "RC(16) payload must be at least 12 bytes, got {}",
                    bytes.len()
                );
                let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&bytes)
                    .context("parse RC(16) head")?;
                let blk16 = rc16.block_len.get();
                assert!(
                    blk16.is_power_of_two(),
                    "block_len(16) must be power-of-two"
                );

                if max_lba_10 != u32::MAX {
                    assert_eq!(
                        blk16, blk_len_10,
                        "block sizes differ between RC10 and RC16"
                    );
                }

                (blk16, rc16.max_lba.get())
            },
            Err(e) => {
                eprintln!("READ CAPACITY(16) skipped: {e}");
                (blk_len_10, max_lba_10 as u64)
            },
        }
    };

    let max_lba_usable = if max_lba_u64 == 0 {
        0
    } else {
        (max_lba_u64 - 1).min(u32::MAX as u64) as u32
    };
    let mut lba = pick_lba_from_isid(isid) % max_lba_usable.saturating_add(1);
    if lba == max_lba_usable {
        lba = max_lba_usable.saturating_sub(1);
    }

    // ============ READ(10) один блок ============
    let blk_sz = blk_len as usize;
    let blocks: u16 = 1;

    let rd1 = pool
        .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read10(&mut cdb, lba, blocks, 0, 0);
            ReadCtx::new(
                c,
                lun,
                itt,
                cmd_sn,
                exp_stat_sn,
                (blk_sz * blocks as usize) as u32,
                cdb,
            )
        })
        .await
        .context("READ(10) #1 failed")?;
    assert_eq!(
        rd1.data.len(),
        blk_sz,
        "first READ must return exactly 1 block"
    );

    // ============ WRITE(10) тот же LBA ============
    let payload = vec![0xA5u8; blk_sz];
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

    // ============ READ(10) назад и проверка ============
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
                (blk_sz * blocks as usize) as u32,
                cdb,
            )
        })
        .await
        .context("READ(10) #2 failed")?;

    assert_eq!(
        rd2.data, payload,
        "read-back data differs from what was written"
    );

    pool.shutdown_gracefully(Duration::from_secs(10)).await?;

    assert!(
        pool.sessions.get(&tsih).is_none(),
        "session must be removed after CloseSession"
    );

    Ok(())
}
