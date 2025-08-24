// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{sync::atomic::Ordering, time::Duration};

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
        report_luns::{fill_report_luns, select_report},
        request_sense::fill_request_sense_simple,
        write::build_write10,
    },
    models::{logout::common::LogoutReason, nop::request::NopOutRequest},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        logout_states::{self, LogoutCtx, LogoutStates, run_logout},
        nop_states::{self, NopCtx, NopStates, run_nop},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        tur_states::{Idle, TurCtx, TurStates, run_tur},
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

    /*let cfg = resolve_config_path("tests/config.yaml")
    .and_then(Config::load_from_file)
    .context("failed to resolve or load config")?;*/

    let cfg = resolve_config_path("docker/lio/config.lio.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let conn = ClientConnection::connect(cfg.clone()).await?;
    info!("Connected to target");

    let (_isid, _isid_str) = generate_isid();
    info!("{_isid:?} {_isid_str}");
    let isid = [0, 2, 61, 0, 0, 14];
    let cid = 1;

    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, cid, 0);

    let state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };

    let login_status = run_login(state, &mut lctx).await?;

    time::sleep(Duration::from_millis(2000)).await;

    // seed our three counters:
    conn.counters
        .cmd_sn
        .store(login_status.exp_cmd_sn, Ordering::SeqCst);
    conn.counters
        .exp_stat_sn
        .store(login_status.stat_sn.wrapping_add(1), Ordering::SeqCst);
    conn.counters
        .itt
        .store(login_status.itt.wrapping_add(1), Ordering::SeqCst);

    let lun = 1u64 << 48;

    let ttt = NopOutRequest::DEFAULT_TAG;
    {
        let mut ctx = NopCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            ttt,
        );

        while conn.counters.itt.load(Ordering::SeqCst) != 2 {
            run_nop(NopStates::Idle(nop_states::Idle), &mut ctx).await?;
        }
    }

    {
        // ---- TEST UNIT READY ----
        let mut tctx = TurCtx::new(
            conn.clone(),
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            lun,
        );
        let _tur_status = run_tur(TurStates::Idle(Idle), &mut tctx).await;
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

    {
        let lun_report = 0;
        // --- REPORT LUNS (step 1): fetch only 8-byte header (LUN LIST LENGTH +
        // reserved) ---
        let mut cdb_hdr = [0u8; 16];
        fill_report_luns(
            &mut cdb_hdr,
            select_report::ALL_MAPPED,
            /* allocation_len */ 16,
            /* control */ 0x00,
        );

        let mut rctx_hdr = ReadCtx::new(
            conn.clone(),
            lun_report,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            16,
            cdb_hdr,
        );
        let hdr = run_read(ReadStates::Start(ReadStart), &mut rctx_hdr).await?;
        assert_eq!(hdr.data.len(), 16, "REPORT LUNS header must be 16 bytes");

        let lun_list_len =
            u32::from_be_bytes([hdr.data[0], hdr.data[1], hdr.data[2], hdr.data[3]])
                as usize;
        assert_eq!(lun_list_len % 8, 0, "LUN LIST LENGTH must be multiple of 8");

        // --- REPORT LUNS (шаг 2): читаем весь список
        let total_needed = 8 + lun_list_len; // header + список (кратен 8)
        let mut cdb_full = [0u8; 16];
        fill_report_luns(
            &mut cdb_full,
            select_report::ALL_MAPPED,
            total_needed as u32,
            0x00,
        );

        let mut rctx_full = ReadCtx::new(
            conn.clone(),
            lun_report,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            total_needed as u32,
            cdb_full,
        );
        let full = run_read(ReadStates::Start(ReadStart), &mut rctx_full).await?;
        assert_eq!(
            full.data.len(),
            total_needed,
            "unexpected REPORT LUNS length"
        );
        assert_eq!(
            &full.data[4..8],
            &[0, 0, 0, 0],
            "reserved bytes must be zero"
        );

        let lun_count = lun_list_len / 8;
        let mut luns = Vec::with_capacity(lun_count);
        for i in 0..lun_count {
            let off = 8 + i * 8;
            let be: [u8; 8] = full.data[off..off + 8].try_into().expect("WTF");
            luns.push(u64::from_be_bytes(be));
        }

        info!("REPORT LUNS: count={} -> {:?}", lun_count, luns);
    }

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
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            8, // RC(10) returns 8 bytes
            cdb_rc10,
        );
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
                &conn.counters.itt,
                &conn.counters.cmd_sn,
                &conn.counters.exp_stat_sn,
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
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
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
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            cdb_wr,
            payload.clone(),
        );

        let _wd1 = run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await?;
    }

    {
        let mut bad_rl_cdb = [0u8; 16];
        // invalid SELECT value 0x7F, allocation 16
        fill_report_luns(&mut bad_rl_cdb, 0x7F, 16, 0x00);

        let mut rctx_bad = ReadCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            16,
            bad_rl_cdb,
        );

        // We EXPECT an error here (CHECK CONDITION); do not fail the test.
        let _ = run_read(ReadStates::Start(ReadStart), &mut rctx_bad).await;

        // === Step 2: REQUEST SENSE (header pass: 8 bytes) using ReadCtx ===
        let mut rs_hdr_cdb = [0u8; 16];
        fill_request_sense_simple(&mut rs_hdr_cdb, /* alloc */ 8);

        let mut rctx_rs8 = ReadCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            8,
            rs_hdr_cdb,
        );
        let s8 = run_read(ReadStates::Start(ReadStart), &mut rctx_rs8).await?;
        assert_eq!(s8.data.len(), 8, "REQUEST SENSE header must be 8 bytes");

        let add_len = s8.data[7] as usize; // Additional Sense Length (byte 7)
        let total_needed = 8 + add_len;

        // === Step 3: REQUEST SENSE (full pass) ===
        let mut rs_full_cdb = [0u8; 16];
        fill_request_sense_simple(&mut rs_full_cdb, total_needed as u8);

        let mut rctx_rs_full = ReadCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            total_needed as u32,
            rs_full_cdb,
        );
        let sfull = run_read(ReadStates::Start(ReadStart), &mut rctx_rs_full).await?;
        assert_eq!(
            sfull.data.len(),
            total_needed,
            "unexpected REQUEST SENSE length"
        );

        // quick sanity on sense format
        let resp_code = sfull.data[0] & 0x7F;
        assert!(
            resp_code == 0x70 || resp_code == 0x71,
            "unexpected sense response code"
        );
    }

    // LOGOUT — close the whole session
    {
        let reason = LogoutReason::CloseSession;

        let mut lctx = LogoutCtx::new(
            conn.clone(),
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            cid,
            reason,
        );

        let status =
            run_logout(LogoutStates::Idle(logout_states::Idle), &mut lctx).await?;
        info!(
            "LOGOUT done: itt={} cmd_sn={} exp_stat_sn={}",
            status.itt, status.cmd_sn, status.exp_stat_sn
        );
    }

    Ok(())
}
