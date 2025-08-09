use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config, logger::init_logger},
    client::client::Connection,
    handlers::{
        login_simple::login_plain,
        simple_scsi_command::{
            build_read10, build_write10, send_scsi_read, send_scsi_write,
        },
    },
    models::nop::request::NopOutRequest,
    state_machine::nop_states::{Idle, NopCtx, NopStates, run_nop},
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

    let login_rsp = login_plain(&conn, &config, isid).await?;
    info!("Res1: {login_rsp:?}");

    time::sleep(Duration::from_millis(2000)).await;

    // seed our three counters:
    let cmd_sn = AtomicU32::new(login_rsp.header.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_rsp.header.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(1);
    let lun = [0, 1, 0, 0, 0, 0, 0, 0];

    let ttt = NopOutRequest::DEFAULT_TAG;

    let mut ctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    while itt.load(Ordering::SeqCst) != 10 {
        run_nop(NopStates::Idle(Idle), &mut ctx).await?;
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
        let sector_size = 512u32;

        let blocks = 1u16;
        let payload = vec![0x01; (blocks as u32 * sector_size) as usize];

        let mut cdb = [0u8; 16];
        build_write10(&mut cdb, 0x1234, blocks, 0, 0);

        match send_scsi_write(&conn, lun, &itt, &cmd_sn, &exp_stat_sn, &cdb, payload)
            .await
        {
            Ok(resp) => {
                info!("[WRITE] resp={resp:?}");
            },
            Err(e) => {
                eprintln!("[WRITE] rejected or failed: {e}");
            },
        };
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

    Ok(())
}
