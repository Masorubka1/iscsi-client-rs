// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright ...

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config, logger::init_logger},
    client::{client::ClientConnection, pool_sessions::Pool},
    control_block::{
        read::{build_read10, build_read16},
        read_capacity::{
            Rc10Raw, Rc16Raw, build_read_capacity10, build_read_capacity16,
            parse_read_capacity10_zerocopy, parse_read_capacity16_zerocopy,
        },
        write::{build_write10, build_write16},
    },
    models::nop::request::NopOutRequest,
    state_machine::{nop_states::NopCtx, read_states::ReadCtx, write_states::WriteCtx},
};
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

fn fill_pattern(buf: &mut [u8], blk_sz: usize, lba_start: u64) {
    assert!(blk_sz > 0 && buf.len() % blk_sz == 0);
    for (i, chunk) in buf.chunks_exact(blk_sz).enumerate() {
        let v = (((lba_start as usize) + i) as u8) ^ 0xA5;
        unsafe { std::ptr::write_bytes(chunk.as_ptr() as *mut u8, v, blk_sz) }
    }
}

fn choose_lba_safely(max_lba: u64, need_blocks: u64) -> Result<u32> {
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

#[tokio::main]
async fn main() -> Result<()> {
    let _init_logger = init_logger("tests/config_logger.yaml")?;

    // Load config
    let cfg: Arc<Config> = Arc::new(
        resolve_config_path("docker/lio/config.lio.yaml")
            .and_then(Config::load_from_file)
            .context("failed to resolve or load config")?,
    );

    // Create pool and attach weak self for unsolicited NOP auto-replies
    let pool = Arc::new(Pool::new(&cfg));
    pool.attach_self();
    // Probe TCP
    info!("Target is reachable");

    // ---- Login sessions from config ----
    let tsihs = pool
        .login_sessions_from_cfg(&cfg)
        .await
        .context("login_all failed")?;
    info!("Logged {} sessions", tsihs.len());
    assert!(!tsihs.is_empty());

    // ---- Add extra connections (MC/S) per session if requested in cfg ----
    let max_conns = cfg.extra_data.connections.max_connections.max(1);
    if max_conns > 1 {
        for &tsih in &tsihs {
            for cid in 1..max_conns {
                let conn = ClientConnection::connect((*cfg).clone()).await?;
                pool.add_connection_to_session(tsih, cid, conn)
                    .await
                    .with_context(|| {
                        format!("add_connection_to_session(tsih={tsih}, cid={cid})")
                    })?;
            }
        }
    }

    // ---- Build workers list (tsih, cid) ----
    let mut workers: Vec<(u16, u16)> = Vec::new();
    for &tsih in &tsihs {
        for cid in 0..max_conns {
            workers.push((tsih, cid));
        }
    }
    assert!(!workers.is_empty());
    info!("Workers: {}", workers.len());

    // ---- Read capacity on LUN 0 to discover geometry ----
    let lun: u64 = 1u64 << 48;

    // Do one small warm-up NOP on each session (optional)
    for &(tsih, cid) in &workers {
        timeout(
            Duration::from_secs(5),
            pool.execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                NopCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, NopOutRequest::DEFAULT_TAG)
            }),
        )
        .await
        .ok();
    }

    // Read capacity(10/16) using the first worker
    let (tsih0, cid0) = workers[0];

    let rc10 = pool
        .execute_with(tsih0, cid0, |c, itt, cmd_sn, exp_stat_sn| {
            let mut cdb = [0u8; 16];
            build_read_capacity10(&mut cdb, 0, false, 0);
            ReadCtx::new(c, lun, itt, cmd_sn, exp_stat_sn, 8, cdb)
        })
        .await
        .context("READ CAPACITY(10)")?;
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
    info!(
        "Device geometry: block={} bytes, max_lba={}",
        blk_sz, max_lba_u64
    );
    assert!(blk_sz.is_power_of_two() && blk_sz > 0);

    // ---- Plan a 1 GiB write+verify ----
    let want_bytes_total: usize = 1usize << 30;
    let need_blocks_total: usize = want_bytes_total / blk_sz;
    if need_blocks_total == 0 {
        bail!("Block size {} is larger than 1 GiB; adjust test", blk_sz);
    }
    let lba0: u32 = choose_lba_safely(max_lba_u64, need_blocks_total as u64)?;

    // Limits (like in the test)
    const FD_MAX_BYTES: usize = 8 * 1024 * 1024;
    let burst_bytes = cfg.login.negotiation.max_burst_length as usize;
    let mrdsl_bytes = cfg.login.negotiation.max_recv_data_segment_length as usize;
    let max_blocks_by_scsi10 = u16::MAX as usize;
    let max_blocks_by_fd = (FD_MAX_BYTES / blk_sz).max(1);
    let max_blocks_by_burst = (burst_bytes / blk_sz).max(1);
    let max_blocks_by_mrdsl = (mrdsl_bytes / blk_sz).max(1);

    // NB: для write тоже учитываем burst/mrdsl (безопасно даже при InitialR2T=Yes)
    let max_write_blocks_per_cmd = max_blocks_by_scsi10
        .min(max_blocks_by_fd)
        .min(max_blocks_by_burst)
        .min(max_blocks_by_mrdsl);
    let max_read_blocks_per_cmd = max_blocks_by_scsi10
        .min(max_blocks_by_fd)
        .min(max_blocks_by_burst)
        .min(max_blocks_by_mrdsl);

    // Разбрасываем по воркерам
    let n_workers = workers.len();
    let per_worker_blocks = (need_blocks_total + n_workers - 1) / n_workers;

    // ===================== Parallel WRITE =====================
    info!("Starting parallel WRITE(10) of 1 GiB …");
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

                let mut payload = vec![1u8; len_bytes];
                fill_pattern(&mut payload, blk_sz, start_lba_u32 as u64);

                // WRITE(10)
                pool_cl
                    .execute_with(tsih, cid, |c, itt, cmd_sn, exp_stat_sn| {
                        let mut cdb = [0u8; 16];
                        build_write16(
                            &mut cdb,
                            start_lba_u32 as u64,
                            blk_this as u32,
                            0,
                            0,
                        );
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
    info!("WRITE done.");

    // Маленькая пауза (даём таргету выровнять очередь/кэш)
    sleep(Duration::from_millis(200)).await;

    // ===================== Parallel READ + verify =====================
    info!("Starting parallel READ(10) + verify …");
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
                        build_read16(
                            &mut cdb,
                            start_lba_u32 as u64,
                            blk_this as u32,
                            0,
                            0,
                        );
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

                // Verify pattern
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
    info!("READ verify done.");

    // ---- Clean logout ----
    for &tsih in &tsihs {
        timeout(Duration::from_secs(30), pool.logout_session(tsih))
            .await
            .with_context(|| format!("logout timeout tsih={tsih}"))??;
        debug!("Logged out tsih={}", tsih);
    }
    info!("All sessions logged out.");

    Ok(())
}
