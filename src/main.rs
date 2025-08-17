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
    control_block::common::{build_read16, build_write16},
    models::{logout::request::LogoutReason, nop::request::NopOutRequest},
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        logout_states::{self, LogoutCtx, LogoutStates, run_logout},
        nop_states::{self, NopCtx, NopStates, run_nop},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
    utils::generate_isid,
};
use tokio::{
    main,
    time::{self, sleep},
};
use tracing::info;

const BLK: usize = 512;

fn pick_lba_from_isid(isid: [u8; 6]) -> u64 {
    let s: u64 = isid.iter().map(|&b| b as u64).sum();
    4096 + (s % 1024)
}

#[main]
async fn main() -> Result<()> {
    let _init_logger = init_logger("tests/config_logger.yaml")?;

    let cfg = resolve_config_path("tests/config_crc.yaml")
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
    let lun = [0, 1, 0, 0, 0, 0, 0, 0];
    let lba = pick_lba_from_isid(isid);
    let blocks: u32 = 1;

    let ttt = NopOutRequest::DEFAULT_TAG;

    let mut ctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    while itt.load(Ordering::SeqCst) != 2 {
        run_nop(NopStates::Idle(nop_states::Idle), &mut ctx).await?;
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

    let mut cdb_rd1 = [0u8; 16];
    build_read16(&mut cdb_rd1, lba, blocks, 0, 0);
    let mut rctx1 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd1,
    );
    let rd1 = run_read(ReadStates::Start(ReadStart), &mut rctx1).await?;
    assert_eq!(rd1.data.len(), BLK);

    let mut cdb_wr = [0u8; 16];
    build_write16(&mut cdb_wr, lba, blocks, 0, 0);
    let payload = vec![0xA5u8; BLK];

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

    match run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx).await {
        Ok(_) => {},
        Err(_) => {
            sleep(Duration::from_millis(100)).await;
            let mut wctx2 = WriteCtx { ..wctx };
            run_write(WriteStates::IssueCmd(IssueCmd), &mut wctx2).await?;
        },
    }

    let mut cdb_rd2 = [0u8; 16];
    build_read16(&mut cdb_rd2, lba, blocks, 0, 0);
    let mut rctx2 = ReadCtx::new(
        conn.clone(),
        lun,
        &itt,
        &cmd_sn,
        &exp_stat_sn,
        (BLK * blocks as usize) as u32,
        cdb_rd2,
    );
    let rd2 = run_read(ReadStates::Start(ReadStart), &mut rctx2).await?;
    assert_eq!(rd2.data, payload, "read data differs from what was written");

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
