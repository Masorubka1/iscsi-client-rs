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
    client::client::Connection,
    handlers::simple_scsi_command::{build_read10, build_write10, send_scsi_read},
    models::{
        logout::request::LogoutReason,
        nop::request::NopOutRequest,
    },
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        logout_states::{self, LogoutCtx, LogoutStates, run_logout},
        nop_states::{self, NopCtx, NopStates, run_nop},
        read_states::{ReadCtx, ReadStart, ReadStates, run_read},
        write_states::{IssueCmd, WriteCtx, WriteStates, run_write},
    },
    utils::generate_isid,
};
use tokio::{main, time};
use tracing::info;

#[main]
async fn main() -> Result<()> {
    let _init_logger = init_logger("tests/config_logger.yaml")?;

    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let conn = Connection::connect(config.clone()).await?;
    info!("Connected to target");

    let (_isid, _isid_str) = generate_isid();
    info!("{_isid:?} {_isid_str}");
    let isid = [0, 2, 61, 0, 0, 14];

    let mut lctx = LoginCtx::new(conn.clone(), &config, isid, 1, 0);

    let state: LoginStates = match config.login.auth {
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

    let ttt = NopOutRequest::DEFAULT_TAG;

    let mut ctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    while itt.load(Ordering::SeqCst) != 2 {
        run_nop(NopStates::Idle(nop_states::Idle), &mut ctx).await?;
    }

    // —————— TEXT ——————
    /*match send_text(&conn, [0u8; 8], &itt_counter, ttt, &cmd_sn, &exp_stat_sn).await {
        Ok(resp) => {
            info!("[Text] resp={resp:?}");
        },
        Err(e) => {
            eprintln!("[Text] rejected or failed: {e}");
            return Err(e);
        },
    }*/

    // —————— WRITE ——————
    {
        let mut cdb = [0u8; 16];
        let lba: u32 = 0x1234;
        let blocks: u16 = 1;
        build_write10(&mut cdb, lba, blocks, 0, 0);
        let sector_size = 512usize;
        let payload = vec![0x04; blocks as usize * sector_size];

        let mut ctx = WriteCtx {
            conn: conn.clone(),
            lun,
            itt: &itt,
            cmd_sn: &cmd_sn,
            exp_stat_sn: &exp_stat_sn,

            initial_r2t: false,
            immediate_data: false,

            cdb,
            payload: payload.clone(),
        };

        time::sleep(Duration::from_millis(100)).await;

        let status = run_write(WriteStates::IssueCmd(IssueCmd), &mut ctx).await;
        info!("First state machine write expected Failed: {status:?}");

        let mut ctx = WriteCtx {
            conn: conn.clone(),
            lun,
            itt: &itt,
            cmd_sn: &cmd_sn,
            exp_stat_sn: &exp_stat_sn,

            initial_r2t: false,
            immediate_data: false,

            cdb,
            payload: payload.clone(),
        };

        time::sleep(Duration::from_millis(100)).await;

        let status = run_write(WriteStates::IssueCmd(IssueCmd), &mut ctx).await?;
        println!(
            "Second WRITE done: itt={}, bytes_sent={}/{} next_data_sn={}",
            status.itt, status.sent_bytes, status.total_bytes, status.next_data_sn
        );

        time::sleep(Duration::from_millis(100)).await;
    }

    // READ
    {
        let mut cdb = [0u8; 16];
        let lba: u32 = 0x1234;
        let blocks: u16 = 1;
        let sector_size = 512u32;
        build_read10(&mut cdb, lba, blocks, 0, 0);

        let mut rctx = ReadCtx::new(
            conn.clone(),
            lun,
            &itt,
            &cmd_sn,
            &exp_stat_sn,
            blocks as u32 * sector_size,
            cdb,
        );

        let result = run_read(ReadStates::Start(ReadStart), &mut rctx).await?;
        assert_eq!(result.data.len(), (blocks as u32 * sector_size) as usize);
        time::sleep(Duration::from_millis(100)).await;
    }

    {
        let mut cdb = [0u8; 16];
        let lba: u32 = 0x1234;
        let blocks: u16 = 1;
        build_write10(&mut cdb, lba, blocks, 0, 0);

        let sector_size = 512usize;
        let payload = vec![0x05; blocks as usize * sector_size];

        let mut ctx = WriteCtx {
            conn: conn.clone(),
            lun,
            itt: &itt,
            cmd_sn: &cmd_sn,
            exp_stat_sn: &exp_stat_sn,

            initial_r2t: false,
            immediate_data: false,

            cdb,
            payload: payload.clone(),
        };

        time::sleep(Duration::from_millis(100)).await;

        let status = run_write(WriteStates::IssueCmd(IssueCmd), &mut ctx).await?;
        println!(
            "Third WRITE done: itt={}, bytes_sent={}/{} next_data_sn={}",
            status.itt, status.sent_bytes, status.total_bytes, status.next_data_sn
        );
    }

    // READ
    {
        let mut cdb_read = [0u8; 16];
        build_read10(&mut cdb_read, 0x1234, 1, 0, 0);
        match send_scsi_read(&conn, lun, &itt, &cmd_sn, &exp_stat_sn, 512, &cdb_read)
            .await
        {
            Ok(resp) => {
                println!("[IO] READ completed: resp={resp:?}");
            },
            Err(e) => {
                eprintln!("[IO] READ failed: {e}");
            },
        }
    }

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
