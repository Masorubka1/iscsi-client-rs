use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    client::{client::ClientConnection, pool_sessions::Pool},
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
use tokio::time::timeout;

use crate::integration_tests::common::{connect_cfg, get_lun, load_config, test_path};

fn fill_pattern(buf: &mut [u8], blk_sz: usize, lba_start: u64) {
    assert!(blk_sz > 0 && buf.len() % blk_sz == 0);
    for (i, chunk) in buf.chunks_exact(blk_sz).enumerate() {
        let v = (((lba_start as usize) + i) as u8) ^ 0xA5;
        unsafe { std::ptr::write_bytes(chunk.as_ptr() as *mut u8, v, blk_sz) }
    }
}

fn choose_lba_safely(max_lba: u64, need_blocks: u64) -> Result<u32> {
    // Берём «середину» устройства, чтобы сдвинуться от нуля и оставить запас.
    // Можно заменить на любую вашу стратегию выбора.
    if need_blocks == 0 {
        return Ok(1024);
    }
    if need_blocks - 1 > max_lba {
        bail!(
            "device too small: need {} blocks, have {}",
            need_blocks,
            max_lba + 1
        );
    }
    let mut lba = (max_lba + 1) / 3;
    let max_start = max_lba + 1 - need_blocks;
    if lba > max_start {
        lba = max_start;
    }
    Ok(lba as u32)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn write10_read10_1_gib_plain_pool_multi_tsih_mcs() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg: Arc<Config> = Arc::new(load_config()?);

    // --- Pool: логиним несколько сессий (tsih) из конфигурации ---
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();

    let tsihs = pool
        .login_sessions_from_cfg(&cfg)
        .await
        .context("login_sessions_from_cfg failed")?;
    assert!(!tsihs.is_empty(), "no sessions created by pool");

    // --- Для каждой сессии добавим дополнительные CIDs (MC/S) ---
    let max_conns = cfg.extra_data.connections.max_connections.max(1);
    for &tsih in &tsihs {
        for cid in 1..max_conns {
            // отдельный TCP для каждого CID
            let conn_i: Arc<ClientConnection> = connect_cfg(&cfg).await?;
            pool.add_connection_to_session(tsih, cid, conn_i)
                .await
                .with_context(|| {
                    format!("add_connection_to_session(tsih={tsih}, cid={cid})")
                })?;
        }
    }

    // --- Собираем список всех «воркеров»: (tsih, cid) ---
    let mut workers: Vec<(u16, u16)> = Vec::new();
    for &tsih in &tsihs {
        for cid in 0..max_conns {
            workers.push((tsih, cid));
        }
    }
    assert!(!workers.is_empty());

    let lun = get_lun();

    // --- Один раз снимаем READ CAPACITY (10/16) через первого воркера ---
    for (tsih, cid) in &workers {
        let _ = pool
            .execute_with(*tsih, *cid, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                build_read_capacity10(&mut cdb, 0, false, 0);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
            })
            .await;
    }
    let (tsih0, cid0) = workers[0];

    let rc10 = pool
        .execute_with(tsih0, cid0, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await
        .context("READ CAPACITY(10) failed")?;
    let rc10_raw: &Rc10Raw =
        parse_read_capacity10_zerocopy(&rc10.data).context("parse RC10")?;
    let blk_len_10 = rc10_raw.block_len.get();
    let max_lba_10 = rc10_raw.max_lba.get() as u64;

    let (blk_len, max_lba_u64) = {
        let try16 = pool
            .execute_with(tsih0, cid0, |c, itt, cmd_sn, exp_stat_sn| {
                let mut cdb = [0u8; 16];
                build_read_capacity16(&mut cdb, 0, false, 32, 0);
                ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 32, cdb)
            })
            .await;

        match try16 {
            Ok(rc16) => {
                let rc16_raw: &Rc16Raw =
                    parse_read_capacity16_zerocopy(&rc16.data).context("parse RC16")?;
                let bl = rc16_raw.block_len.get();
                let ml = rc16_raw.max_lba.get();
                if max_lba_10 != u32::MAX as u64 {
                    assert_eq!(bl, blk_len_10, "RC10/RC16 block size mismatch");
                }
                (bl, ml)
            },
            Err(_) => (blk_len_10, max_lba_10),
        }
    };

    let blk_sz = blk_len as usize;
    assert!(blk_sz.is_power_of_two() && blk_sz > 0);

    let want_bytes_total: usize = 1usize << 30;
    let need_blocks_total: usize = want_bytes_total / blk_sz;
    assert!(need_blocks_total > 0);

    let lba0: u32 = choose_lba_safely(max_lba_u64, need_blocks_total as u64)?;

    const FD_MAX_BYTES: usize = 8 * 1024 * 1024;
    let burst_bytes = cfg.login.negotiation.max_burst_length as usize;
    let mrdsl_bytes = cfg.login.negotiation.max_recv_data_segment_length as usize;

    let max_blocks_by_scsi10 = u16::MAX as usize;
    let max_blocks_by_fd = (FD_MAX_BYTES / blk_sz).max(1);
    let max_blocks_by_burst = (burst_bytes / blk_sz).max(1);
    let max_blocks_by_mrdsl = (mrdsl_bytes / blk_sz).max(1);

    let max_write_blocks_per_cmd = max_blocks_by_scsi10.min(max_blocks_by_fd);
    let max_read_blocks_per_cmd = max_blocks_by_scsi10
        .min(max_blocks_by_fd)
        .min(max_blocks_by_burst)
        .min(max_blocks_by_mrdsl);

    // --- Дробим суммарный объём равномерно по всем (tsih, cid) воркерам ---
    let n_workers = workers.len();
    let per_worker_blocks = (need_blocks_total + n_workers - 1) / n_workers;

    // ===================== Parallel Write =====================
    let mut write_handles = Vec::with_capacity(n_workers);
    for (widx, (tsih, cid)) in workers.iter().copied().enumerate() {
        let pool_cl = pool.clone();
        let this_start_blocks = widx * per_worker_blocks;
        if this_start_blocks >= need_blocks_total {
            continue;
        }
        let this_blocks = per_worker_blocks.min(need_blocks_total - this_start_blocks);
        let start_lba = lba0 as usize + this_start_blocks;

        write_handles.push(tokio::spawn(async move {
            let mut written = 0usize;
            while written < this_blocks {
                let blk_this = ((this_blocks - written) as u32)
                    .min(max_write_blocks_per_cmd as u32)
                    as usize;

                let start_lba_u32 = (start_lba + written) as u32;
                let len_bytes = blk_this * blk_sz;

                let mut payload = vec![0u8; len_bytes];
                fill_pattern(&mut payload, blk_sz, start_lba_u32 as u64);

                pool_cl
                    .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                        let mut cdb = [0u8; 16];
                        build_write10(&mut cdb, start_lba_u32, blk_this as u16, 0, 0);
                        WriteCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, cdb, payload)
                    })
                    .await
                    .with_context(|| {
                        format!(
                            "WRITE chunk tsih={} cid={} lba={} blks={}",
                            tsih, cid, start_lba_u32, blk_this
                        )
                    })?;

                written += blk_this;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in write_handles {
        h.await.expect("join write task")?;
    }

    // ===================== Parallel read + verify =====================
    let mut read_handles = Vec::with_capacity(n_workers);
    for (widx, (tsih, cid)) in workers.iter().copied().enumerate() {
        let pool_cl = pool.clone();
        let this_start_blocks = widx * per_worker_blocks;
        if this_start_blocks >= need_blocks_total {
            continue;
        }
        let this_blocks = per_worker_blocks.min(need_blocks_total - this_start_blocks);
        let start_lba = lba0 as usize + this_start_blocks;

        read_handles.push(tokio::spawn(async move {
            let mut done = 0usize;
            while done < this_blocks {
                let blk_this = ((this_blocks - done) as u32)
                    .min(max_read_blocks_per_cmd as u32)
                    as usize;

                let start_lba_u32 = (start_lba + done) as u32;
                let len_bytes = blk_this * blk_sz;

                let chunk = pool_cl
                    .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                        let mut cdb = [0u8; 16];
                        build_read10(&mut cdb, start_lba_u32, blk_this as u16, 0, 0);
                        ReadCtx::new(
                            c,
                            lun,
                            itt,
                            cmd_sn,
                            exp_stat_sn,
                            len_bytes as u32,
                            cdb,
                        )
                    })
                    .await
                    .with_context(|| {
                        format!(
                            "READ chunk tsih={} cid={} lba={} blks={}",
                            tsih, cid, start_lba_u32, blk_this
                        )
                    })?;

                // сверяем с эталоном
                let mut expected = vec![0u8; len_bytes];
                fill_pattern(&mut expected, blk_sz, start_lba_u32 as u64);
                if chunk.data != expected {
                    bail!(
                        "data mismatch tsih={} cid={} lba={} blocks={}",
                        tsih,
                        cid,
                        start_lba_u32,
                        blk_this
                    );
                }

                done += blk_this;
            }
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in read_handles {
        h.await.expect("join read task")?;
    }

    // --- Logout всех сессий и проверка очистки пула ---
    for tsih in tsihs {
        timeout(Duration::from_secs(30), pool.logout_session(tsih))
            .await
            .with_context(|| format!("logout timeout tsih={tsih}"))??;
        assert!(
            pool.sessions.get(&tsih).is_none(),
            "session {tsih} must be removed from pool after CloseSession"
        );
    }

    Ok(())
}
