// SPDX-License-Identifier: GPL-3.0-or-later
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
        login_states::{LoginCtx, LoginStates, run_login, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
};
use tokio::time::sleep;

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

fn pick_lba_from_isid(isid: [u8; 6]) -> u32 {
    let s: u32 = isid.iter().map(|&b| b as u32).sum();
    4096 + (s % 1024)
}

#[tokio::test]
async fn read_capacity_then_write10_plain() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Arc::new(load_config()?);
    if !matches!(cfg.login.auth, AuthConfig::None) {
        eprintln!("⏭️  skip: auth.method != none in TEST_CONFIG (test for login_plain)");
        return Ok(());
    }

    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    // -------- Login ----------
    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid= */ 1,
        /* tsih= */ 1,
    );
    let login_state: LoginStates = start_plain();
    let login_status = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1 << 48;

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

    let _ = run_read(ReadStates::Start(ReadStart), &mut rc10_ctx).await;
    let rc10_pdu = run_read(ReadStates::Start(ReadStart), &mut rc10_ctx)
        .await
        .context("READ CAPACITY(10) failed")?;
    assert_eq!(rc10_pdu.data.len(), 8, "RC(10) must return 8 bytes");
    eprintln!("RC10 raw: {:02X?}", &rc10_pdu.data);

    let rc10: &Rc10Raw = parse_read_capacity10_zerocopy(&rc10_pdu.data)
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

        let mut rc16_ctx = ReadCtx::new(
            conn.clone(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            32, // обычно 32 байта
            cdb_rc16,
        );

        match run_read(ReadStates::Start(ReadStart), &mut rc16_ctx).await {
            Ok(rc16_pdu) => {
                assert!(
                    rc16_pdu.data.len() >= 12,
                    "RC(16) payload must be at least 12 bytes, got {}",
                    rc16_pdu.data.len()
                );
                let rc16: &Rc16Raw = parse_read_capacity16_zerocopy(&rc16_pdu.data)
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
                eprintln!("ℹ️  READ CAPACITY(16) skipped: {e}");
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
    let rd1 = run_read(ReadStates::Start(ReadStart), &mut rctx1).await?;
    assert_eq!(
        rd1.data.len(),
        blk_sz,
        "first READ must return exactly 1 block"
    );

    // ============ WRITE(10) same LBA, one block ============
    let mut cdb_wr = [0u8; 16];
    build_write10(&mut cdb_wr, lba, blocks, 0, 0);
    let payload = vec![0xA5u8; blk_sz];

    let mut wctx = WriteCtx::new(
        conn.clone(),
        cfg.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        cdb_wr,
        payload.clone(),
    );

    match run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await {
        Ok(_) => {},
        Err(_) => {
            sleep(Duration::from_millis(100)).await;
            let mut wctx2 = WriteCtx { ..wctx };
            run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx2).await?;
        },
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
    let rd2 = run_read(ReadStates::Start(ReadStart), &mut rctx2).await?;
    assert_eq!(
        rd2.data, payload,
        "read-back data differs from what was written"
    );

    Ok(())
}
