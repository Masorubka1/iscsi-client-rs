// SPDX-License-Identifier: AGPL-3.0-or-later=
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, atomic::Ordering};

use anyhow::{Context, Result, bail};
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    control_block::{
        read::build_read10,
        read_capacity::{
            Rc10Raw, Rc16Raw, build_read_capacity10, build_read_capacity16,
            parse_read_capacity10_zerocopy, parse_read_capacity16_zerocopy,
        },
        write::build_write10,
    },
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
        write_states::WriteCtx,
    },
};

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

fn fill_pattern(buf: &mut [u8], blk_sz: usize, lba_start: u64) {
    assert!(blk_sz > 0 && buf.len() % blk_sz == 0);
    for (i, chunk) in buf.chunks_exact(blk_sz).enumerate() {
        let v = (((lba_start as usize) + i) as u8) ^ 0xA5;
        unsafe { std::ptr::write_bytes(chunk.as_ptr() as *mut u8, v, blk_sz) }
    }
}

fn choose_lba_safely(isid: [u8; 6], max_lba: u64, need_blocks: u64) -> Result<u32> {
    let s: u64 = isid.iter().map(|&b| b as u64).sum();
    let mut lba = 4096 + (s % 1024);
    if need_blocks == 0 {
        return Ok(lba as u32);
    }
    if need_blocks - 1 > max_lba {
        bail!(
            "device too small: need {} blocks, have {}",
            need_blocks,
            max_lba + 1
        );
    }
    let max_start = max_lba + 1 - need_blocks;
    if lba > max_start {
        lba = max_start;
    }
    Ok(lba as u32)
}

#[tokio::test]
async fn write10_read10_1_gib_plain() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = Arc::new(load_config()?);

    let want_bytes_total: usize = 1usize << 30;

    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, 1, 0);
    match cfg.login.auth {
        AuthConfig::Chap(_) => lctx.set_chap_login(),
        AuthConfig::None => lctx.set_plain_login(),
    }
    lctx.execute().await.context("login failed")?;

    let login_pdu = lctx
        .last_response
        .as_ref()
        .context("no login last_response")?;
    let lh = login_pdu.header_view().context("login header")?;
    conn.counters
        .cmd_sn
        .store(lh.exp_cmd_sn.get(), Ordering::SeqCst);
    conn.counters
        .exp_stat_sn
        .store(lh.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
    conn.counters.itt.store(1, Ordering::SeqCst);

    let lun = get_lun();

    // READ CAPACITY(10)
    let mut cdb_rc10 = [0u8; 16];
    build_read_capacity10(&mut cdb_rc10, 0, false, 0);
    let mut rc10_ctx = ReadCtx::new(
        conn.clone(),
        lun,
        &conn.counters.itt,
        &conn.counters.cmd_sn,
        &conn.counters.exp_stat_sn,
        8,
        cdb_rc10,
    );
    let _ = rc10_ctx.execute().await;
    let mut rc10_ctx = ReadCtx::new(
        conn.clone(),
        lun,
        &conn.counters.itt,
        &conn.counters.cmd_sn,
        &conn.counters.exp_stat_sn,
        8,
        cdb_rc10,
    );
    rc10_ctx
        .execute()
        .await
        .context("READ CAPACITY(10) failed")?;
    let rc10_bytes = rc10_ctx.rt.acc;
    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&rc10_bytes)?;
    let blk_len_10 = rc10.block_len.get();
    let max_lba_10 = rc10.max_lba.get() as u64;

    // READ CAPACITY(16) (опционально)
    let (blk_len, max_lba_u64) = {
        let mut cdb = [0u8; 16];
        build_read_capacity16(&mut cdb, 0, false, 32, 0);
        let mut rc16_ctx = ReadCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            32,
            cdb,
        );
        match rc16_ctx.execute().await {
            Ok(()) => {
                let rc16_bytes = rc16_ctx.rt.acc;
                let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&rc16_bytes)?;
                let bl = rc16.block_len.get();
                let ml = rc16.max_lba.get();
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

    let need_blocks_total: usize = want_bytes_total / blk_sz;
    assert!(need_blocks_total > 0);

    let lba0: u32 = choose_lba_safely(isid, max_lba_u64, need_blocks_total as u64)?;

    // полезная нагрузка
    let total_bytes = need_blocks_total * blk_sz;
    let mut payload = vec![0u8; total_bytes];
    fill_pattern(&mut payload, blk_sz, lba0 as u64);

    // Ограничения на ОДНУ команду:
    //  - SCSI WRITE/READ(10): максимум 65535 блоков
    //  - FILEIO (страховка): 8 MiB
    //  - iSCSI MaxBurstLength (байты)
    //  - MRDSL ограничивает длину Data-In на одну READ-команду
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

    {
        let mut cdb = [0u8; 16];
        build_write10(&mut cdb, lba0, 1, 0, 0);
        let mut wctx = WriteCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            cdb,
            vec![0u8; blk_sz],
        );
        wctx.execute().await?;
    }

    // WRITE(10)
    let mut written_blocks: usize = 0;
    while written_blocks < need_blocks_total {
        let blk_this = ((need_blocks_total - written_blocks) as u32)
            .min(max_write_blocks_per_cmd as u32) as usize;

        let off = written_blocks * blk_sz;
        let len = blk_this * blk_sz;

        let mut cdb = [0u8; 16];
        build_write10(
            &mut cdb,
            (lba0 as usize + written_blocks) as u32,
            blk_this as u16,
            0,
            0,
        );

        let mut wctx = WriteCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            cdb,
            payload[off..off + len].to_vec(),
        );
        wctx.execute().await?;
        written_blocks += blk_this;
    }

    // READ(10)
    let mut read_back = Vec::with_capacity(total_bytes);
    let mut read_blocks: usize = 0;
    while read_blocks < need_blocks_total {
        let blk_this = ((need_blocks_total - read_blocks) as u32)
            .min(max_read_blocks_per_cmd as u32) as usize;

        let len = blk_this * blk_sz;

        let mut cdb = [0u8; 16];
        build_read10(
            &mut cdb,
            (lba0 as usize + read_blocks) as u32,
            blk_this as u16,
            0,
            0,
        );

        let mut rctx = ReadCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            len as u32,
            cdb,
        );
        rctx.execute().await?;
        let rd = rctx.rt.acc;
        assert_eq!(rd.len(), len);
        read_back.extend_from_slice(&rd);

        read_blocks += blk_this;
    }

    assert_eq!(read_back.len(), total_bytes);

    for (i, chunk) in read_back.chunks_exact(blk_sz).enumerate() {
        let expected = ((((lba0 as usize) + i) as u8) ^ 0xA5) as u8;
        if !(chunk[0] == expected && chunk[blk_sz - 1] == expected) {
            if chunk.iter().any(|&b| b != expected) {
                panic!(
                    "data mismatch at LBA {} (block #{})",
                    lba0 as u64 + i as u64,
                    i
                );
            }
        }
    }

    Ok(())
}
