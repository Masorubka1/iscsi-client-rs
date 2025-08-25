// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, atomic::AtomicU32};

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    control_block::{read::build_read16, write::build_write16},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_plain},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

const BLK: usize = 512;

fn pick_lba_from_isid(isid: [u8; 6]) -> u64 {
    let s: u64 = isid.iter().map(|&b| b as u64).sum();
    4096 + (s % 1024)
}

// Deterministic per-block pattern (so we don't have to keep two 1 GiB buffers).
fn fill_pattern(buf: &mut [u8], lba_start: u64) {
    assert!(buf.len() % BLK == 0);
    for (i, chunk) in buf.chunks_exact(BLK).enumerate() {
        let v = (((lba_start as usize) + i) as u8) ^ 0xA5;
        // SAFETY: chunk is exactly BLK
        unsafe {
            std::ptr::write_bytes(chunk.as_ptr() as *mut u8, v, BLK);
        }
    }
}

#[tokio::test]
async fn write16_read16_1_gib_plain() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = Arc::new(load_config()?);
    if !matches!(cfg.login.auth, AuthConfig::None) {
        return Ok(());
    }

    let total_bytes: usize = 1usize << 30; // 1 GiB
    assert!(total_bytes % BLK == 0);
    let total_blocks = (total_bytes / BLK) as u32;

    let conn = connect_cfg(&cfg).await?;
    let isid = test_isid();

    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid= */ 1,
        /* tsih= */ 1,
    );
    let login_state: LoginStates = start_plain();
    let ls = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(ls.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(ls.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(ls.itt.wrapping_add(1));
    let lun = 1 << 48;
    let lba = pick_lba_from_isid(isid);

    let mut cdb_warm = [0u8; 16];
    build_write16(
        &mut cdb_warm,
        lba,
        /* blocks= */ 1,
        /* flags= */ 0,
        /* control= */ 0,
    );
    let payload_warm = vec![0x00u8; 512]; // один блок

    let mut wctx_warm = WriteCtx::new(
        conn.clone(),
        cfg.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        cdb_warm,
        payload_warm,
    );

    let _ = run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx_warm).await;

    let mut cdb_wr = [0u8; 16];
    build_write16(
        &mut cdb_wr,
        lba,
        total_blocks,
        /* flags= */ 0,
        /* control= */ 0,
    );

    let mut payload = vec![0u8; total_bytes];
    fill_pattern(&mut payload, lba);

    let mut wctx = WriteCtx::new(
        conn.clone(),
        cfg.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        cdb_wr,
        payload,
    );
    run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await?;

    drop(wctx);

    let mut cdb_rd = [0u8; 16];
    build_read16(
        &mut cdb_rd,
        lba,
        total_blocks,
        /* flags= */ 0,
        /* control= */ 0,
    );

    let mut rctx = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        total_bytes as u32, // expected length for reassembly
        cdb_rd,
    );
    let rd = run_read(ReadStates::Start(ReadStart), &mut rctx).await?;
    assert_eq!(rd.data.len(), total_bytes);

    for (i, chunk) in rd.data.chunks_exact(BLK).enumerate() {
        let expected = ((((lba as usize) + i) as u8) ^ 0xA5) as u8;
        if !(chunk[0] == expected && chunk[BLK - 1] == expected) {
            if chunk.iter().any(|&b| b != expected) {
                panic!("data mismatch at LBA {} (block #{})", lba + i as u64, i);
            }
        }
    }

    Ok(())
}
