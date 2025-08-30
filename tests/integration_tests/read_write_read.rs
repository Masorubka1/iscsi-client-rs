// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::AuthConfig, logger::init_logger},
    control_block::{read::build_read10, write::build_write10},
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, read_states::ReadCtx,
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
async fn read10_write10_read10_plain() -> Result<()> {
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
    let login_pdu = lctx.last_response.as_ref().expect("login last_response");
    let lh = login_pdu.header_view().context("login header")?;

    let cmd_sn = AtomicU32::new(lh.exp_cmd_sn.get());
    let exp_stat_sn = AtomicU32::new(lh.stat_sn.get().wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = get_lun();

    let cmd_sn_before = cmd_sn.load(Ordering::SeqCst);
    let exp_stat_sn_before = exp_stat_sn.load(Ordering::SeqCst);

    // -------- READ(10) #1 ----------
    const BLK: usize = 512;
    let blocks: u16 = 1;
    let lba: u32 = pick_lba_from_isid(isid);

    let mut cdb_rd1 = [0u8; 16];
    build_read10(&mut cdb_rd1, lba, blocks, 0, 0);
    let mut rctx1 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd1,
    );
    let _ = rctx1.execute().await;
    let mut rctx1 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd1,
    );
    rctx1.execute().await.context("READ(10) #1 failed")?;
    let rd1 = rctx1.rt.acc;
    assert_eq!(rd1.len(), BLK, "first READ must return exactly 1 block");

    // -------- WRITE(10) ----------
    let mut cdb_wr = [0u8; 16];
    build_write10(&mut cdb_wr, lba, blocks, 0, 0);
    let payload = vec![0xA5u8; BLK];

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

    // -------- READ(10) #2 ----------
    let mut cdb_rd2 = [0u8; 16];
    build_read10(&mut cdb_rd2, lba, blocks, 0, 0);
    let mut rctx2 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd2,
    );
    rctx2.execute().await.context("READ(10) #2 failed")?;
    let rd2 = rctx2.rt.acc;

    assert_eq!(rd2, payload, "read data differs from what was written");

    let cmd_sn_after = cmd_sn.load(Ordering::SeqCst);
    let exp_stat_sn_after = exp_stat_sn.load(Ordering::SeqCst);

    assert!(
        cmd_sn_after >= cmd_sn_before + 3,
        "CmdSN didn't advance enough: before={cmd_sn_before}, after={cmd_sn_after}"
    );
    assert!(
        exp_stat_sn_after >= exp_stat_sn_before,
        "ExpStatSN didn't advance: before={exp_stat_sn_before}, \
         after={exp_stat_sn_after}"
    );

    Ok(())
}
