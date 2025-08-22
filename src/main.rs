// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        cli::resolve_config_path,
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    client::client::ClientConnection,
    control_block::{
        read::build_read10,
        read_capacity::{
            Rc10Raw, Rc16Raw, build_read_capacity10, build_read_capacity16,
            parse_read_capacity10_zerocopy, parse_read_capacity16_zerocopy,
        },
        write::build_write10,
    },
    models::{logout::common::LogoutReason, nop::request::NopOutRequest},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        logout_states::{self, LogoutCtx, LogoutStates, run_logout},
        nop_states::{self, NopCtx, NopStates, run_nop},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        test_unit_ready::{Idle, TurCtx, TurStates, run_tur},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
    utils::generate_isid,
};
use tokio::{
    main,
    time::{self},
};
use tracing::info;

#[main]
async fn main() -> Result<()> {
    let _init_logger = init_logger("tests/config_logger.yaml")?;

    let cfg = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let conn = ClientConnection::connect(cfg.clone()).await?;
    info!("Connected to target");

    let (_isid, _isid_str) = generate_isid();
    info!("{_isid:?} {_isid_str}");
    let isid = [0, 2, 61, 0, 0, 14];

    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, 1, 0);

    let state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };

    let login_status = run_login(state, &mut lctx).await?;

    time::sleep(Duration::from_millis(2000)).await;

    // seed our three counters:
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1u64 << 48;

    let ttt = NopOutRequest::DEFAULT_TAG;
    {
        let mut ctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

        while itt.load(Ordering::SeqCst) != 2 {
            run_nop(NopStates::Idle(nop_states::Idle), &mut ctx).await?;
        }
    }

    {
        // ---- TEST UNIT READY ----
        let mut tctx = TurCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, lun);
        let _tur_status = run_tur(TurStates::Idle(Idle), &mut tctx).await?;
    }

    // —————— TEXT ——————
    /*match send_text(&conn, lun, &itt, ttt, &cmd_sn, &exp_stat_sn).await {
        Ok(resp) => {
            info!("[Text] resp={resp:?}");
        },
        Err(e) => {
            eprintln!("[Text] rejected or failed: {e}");
            return Err(e);
        },
    }*/

    let lba = {
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
        info!("max_lba_10: {max_lba_10}");

        // ============ READ CAPACITY(16) (optional) ============
        let (_blk_len, max_lba_u64) = {
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
        let mut lba = 0;
        if lba == max_lba_usable {
            lba = max_lba_usable.saturating_sub(1);
        }
        lba
    };

    let blk_sz = 512usize;
    let blocks: u16 = 1;

    {
        // ============ READ(10) one block ============
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
    }

    {
        // ============ WRITE(10) same LBA, one block ============
        let mut cdb_wr = [0u8; 16];
        build_write10(&mut cdb_wr, lba, blocks, 0, 0);
        let payload = vec![0xA5u8; blk_sz];

        let mut wctx = WriteCtx::new(
            conn.clone(),
            cfg.clone().into(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            cdb_wr,
            payload.clone(),
        );

        let _wd1 = run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await?;
    }

    // ============ READ(10) back & verify ============
    /*let mut cdb_rd2 = [0u8; 16];
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
    );*/

    // LOGOUT — close the whole session
    {
        let cid = 0u16;
        let reason = LogoutReason::CloseSession;

        let mut lctx =
            LogoutCtx::new(conn.clone(), &itt, &cmd_sn, &exp_stat_sn, cid, reason);

        let status =
            run_logout(LogoutStates::Idle(logout_states::Idle), &mut lctx).await?;
        info!(
            "LOGOUT done: itt={} cmd_sn={} exp_stat_sn={}",
            status.itt, status.cmd_sn, status.exp_stat_sn
        );
    }

    Ok(())
}
