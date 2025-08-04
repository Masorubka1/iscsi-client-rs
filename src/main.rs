use std::{
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config, logger::init_logger},
    client::client::Connection,
    handlers::{
        login_simple::login_plain,
        nop_handler::send_nop,
        simple_scsi_command::{
            build_read16, build_write16, send_scsi_read, send_scsi_write,
        },
    },
    models::nop::request::NopOutRequest,
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

    let conn = Arc::new(Connection::connect(config.clone()).await?);
    info!("Connected to target");

    let (_isid, _isid_str) = generate_isid();
    info!("{_isid:?} {_isid_str}");
    let isid = [0, 2, 61, 0, 0, 14];

    let login_rsp = login_plain(&conn, &config, isid).await?;
    info!("Res1: {login_rsp:?}");

    time::sleep(Duration::from_millis(2000)).await;

    // seed our three counters:
    let cmd_sn = AtomicU32::new(login_rsp.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_rsp.stat_sn.wrapping_add(1));
    let itt_counter = AtomicU32::new(1);
    let lun = [0, 1, 0, 0, 0, 0, 0, 0];

    let ttt = NopOutRequest::DEFAULT_TAG;
    // —————— NOP #1 ——————
    match send_nop(&conn, [0u8; 8], &itt_counter, ttt, &cmd_sn, &exp_stat_sn).await {
        Ok(resp) => {
            info!("[NOP1] resp={resp:?}");
        },
        Err(e) => {
            eprintln!("[NOP1] rejected or failed: {e}");
            return Err(e);
        },
    }

    time::sleep(Duration::from_millis(100)).await;

    // —————— NOP #2 ——————
    /*match send_nop(&conn, [0u8; 8], &itt_counter, ttt, &cmd_sn, &exp_stat_sn).await {
        Ok((hdr, data, _)) => {
            info!("[NOP2] hdr={hdr:?} data={data:?}");
        },
        Err(e) => {
            eprintln!("[NOP2] rejected or failed: {e}");
            return Err(e);
        },
    }*/

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
        build_write16(&mut cdb, 0x1234, 0, 0, 1);
        let write_buf = vec![0x01; 512];

        match send_scsi_write(
            &conn,
            lun,
            &itt_counter,
            &cmd_sn,
            &exp_stat_sn,
            &cdb,
            write_buf,
        )
        .await
        {
            Ok(resp) => {
                info!("[WRITE] resp={resp:?}");
            },
            Err(e) => {
                eprintln!("[WRITE] rejected or failed: {e}");
                //return Err(e);
            },
        };
    }

    // READ
    {
        let mut cdb_read = [0u8; 16];
        build_read16(&mut cdb_read, 0x1234, 16, 0, 0);
        match send_scsi_read(
            &conn,
            lun,
            &itt_counter,
            &cmd_sn,
            &exp_stat_sn,
            512,
            &cdb_read,
        )
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

// 4) Heartbeat-таск: NOP-Out / NOP-In каждую секунду
/*let hb_conn = conn.clone();
let hb_handle = tokio::spawn(async move {
    loop {
        let sn = cmd_sn_hb.fetch_add(1, Ordering::SeqCst);
        let esn = exp_stat_sn_hb.load(Ordering::SeqCst);
        let itag = itag_hb.fetch_add(1, Ordering::SeqCst);
        match send_nop(
            &hb_conn,
            [0u8; 8],
            itag,
            NopOutRequest::DEFAULT_TAG,
            sn,
            esn,
            true,
        )
        .await
        {
            Ok((hdr, data, _)) => {
                println!("[HEARTBEAT] NOP-In: hdr={hdr:?}, data={data:?}");
                exp_stat_sn_hb
                    .store(hdr.exp_cmd_sn.wrapping_add(1), Ordering::SeqCst);
            },
            Err(e) => {
                eprintln!("[HEARTBEAT] error: {e}");
            },
        }
        time::sleep(Duration::from_secs(1)).await;
    }
});*/

//time::sleep(Duration::from_secs(5)).await;
