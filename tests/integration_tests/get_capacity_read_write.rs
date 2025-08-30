// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::{Context, Result};
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
        // ВАЖНО: больше не импортируем run_* и enum-состояния
        common::StateMachineCtx,
        login::common::LoginCtx,
        read_states::ReadCtx,
        write_states::WriteCtx,
    },
};
use tokio::time::sleep;

use crate::integration_tests::common::{
    connect_cfg, get_lun, load_config, test_isid, test_path,
};

fn pick_lba_from_isid(isid: [u8; 6]) -> u32 {
    let s: u32 = isid.iter().map(|&b| b as u32).sum();
    4096 + (s % 1024)
}

#[tokio::test]
async fn read_capacity_then_write10_plain() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Arc::new(load_config()?);
    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    // -------- Login ----------
    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid */ 1,
        /* tsih */ 0,
    );

    match cfg.login.auth {
        AuthConfig::Chap(_) => lctx.set_chap_login(),
        AuthConfig::None => lctx.set_plain_login(),
    }

    lctx.execute().await.context("login failed")?;
    let login_pdu = lctx.last_response.expect("wee");
    let lh = login_pdu.header_view().context("login header")?;

    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);

    let lun = get_lun();

    // ============ READ CAPACITY(10) ============
    let mut cdb_rc10 = [0u8; 16];
    build_read_capacity10(
        &mut cdb_rc10,
        /* lba= */ 0,
        /* pmi= */ false,
        /* control= */ 0,
    );

    let mut rc10_ctx = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        8, // RC(10) returns 8 bytes
        cdb_rc10,
    );

    let _ = rc10_ctx.execute().await;
    let mut rc10_ctx = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        8, // RC(10) returns 8 bytes
        cdb_rc10,
    );
    rc10_ctx
        .execute()
        .await
        .context("READ CAPACITY(10) failed")?;
    let rc10_bytes = rc10_ctx.rt.acc;

    assert_eq!(rc10_bytes.len(), 8, "RC(10) must return 8 bytes");
    eprintln!("RC10 raw: {:02X?}", &rc10_bytes);

    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&rc10_bytes)
        .context("failed to parse RC(10) payload")?;
    let blk_len_10 = rc10.block_len.get();
    assert!(
        blk_len_10.is_power_of_two(),
        "block_len(10): {blk_len_10} must be power-of-two"
    );
    let max_lba_10 = rc10.max_lba.get();

    // ============ READ CAPACITY(16) (optional) ============
    let (blk_len, max_lba_u64) = {
        let mut cdb_rc16 = [0u8; 16];
        build_read_capacity16(
            &mut cdb_rc16,
            /* lba= */ 0,
            /* pmi= */ false,
            /* alloc_len= */ 32,
            /* control= */ 0,
        );

        let mut rc16_ctx =
            ReadCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, 32, cdb_rc16);

        match rc16_ctx.execute().await {
            Ok(()) => {
                let rc16_bytes = rc16_ctx.rt.acc;
                assert!(
                    rc16_bytes.len() >= 12,
                    "RC(16) payload must be at least 12 bytes, got {}",
                    rc16_bytes.len()
                );
                let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&rc16_bytes)
                    .context("failed to parse RC(16) head")?;
                let blk16 = rc16.block_len.get();
                assert!(
                    blk16.is_power_of_two(),
                    "block_len(16): {blk_len_10} must be power-of-two"
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

    // ============ READ(10) one block ============
    let blk_sz = blk_len as usize;
    let blocks: u16 = 1;

    let mut cdb_rd1 = [0u8; 16];
    build_read10(&mut cdb_rd1, lba, blocks, 0, 0);
    let mut rctx1 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (blk_sz * blocks as usize) as u32,
        cdb_rd1,
    );
    rctx1.execute().await.context("READ(10) #1 failed")?;
    let rd1 = rctx1.rt.acc;
    assert_eq!(rd1.len(), blk_sz, "first READ must return exactly 1 block");

    // ============ WRITE(10) same LBA, one block ============
    let mut cdb_wr = [0u8; 16];
    build_write10(&mut cdb_wr, lba, blocks, 0, 0);
    let payload = vec![0xA5u8; blk_sz];

    let mut wctx = WriteCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        cdb_wr,
        payload.clone(),
    );

    if let Err(e) = wctx.execute().await {
        eprintln!("WRITE(10) first attempt failed: {e}");
        sleep(Duration::from_millis(100)).await;
        let mut wctx2 = WriteCtx::new(
            conn.clone(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            cdb_wr,
            payload.clone(),
        );
        wctx2.execute().await.context("WRITE(10) retry failed")?;
    }

    // ============ READ(10) back & verify ============
    let mut cdb_rd2 = [0u8; 16];
    build_read10(&mut cdb_rd2, lba, blocks, 0, 0);
    let mut rctx2 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (blk_sz * blocks as usize) as u32,
        cdb_rd2,
    );
    rctx2.execute().await.context("READ(10) #2 failed")?;
    let rd2 = rctx2.rt.acc;

    assert_eq!(rd2, payload, "read-back data differs from what was written");

    Ok(())
}
