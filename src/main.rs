use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::client::Connection,
    handlers::{login_simple::login_plain, nop_handler::send_nop},
    models::nop::request::NopOutRequest,
    utils::generate_isid,
};
use tokio::{main, time};

#[main]
async fn main() -> Result<()> {
    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let conn = Arc::new(Connection::connect(config.clone()).await?);
    println!("Connected to target");

    let (isid, isid_str) = generate_isid();
    println!("{isid:?} {isid_str}");

    let login_rsp = login_plain(&conn, &config, isid).await?;
    println!("Res1: {login_rsp:?}");

    let mut cmd_sn = login_rsp.exp_cmd_sn;
    let mut exp_stat_sn = login_rsp.stat_sn;
    let itag = Arc::new(AtomicU32::new(1));

    /*time::sleep(Duration::from_secs(1)).await;

    let text_rsp = text_request(
        &conn,
        &config,
        [0u8; 8],
        itag.load(Ordering::SeqCst),
        NopOutRequest::DEFAULT_TAG,
        exp_stat_sn,
    )
    .await?;
    println!("Res2: {text_rsp:?}");*/

    let hb_itag = itag.clone();
    let hb_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let result = {
                send_nop(
                    &hb_conn,
                    [0u8; 8],                       // LUN
                    hb_itag.load(Ordering::SeqCst), // InitiatorTaskTag
                    NopOutRequest::DEFAULT_TAG,
                    cmd_sn,      // our CmdSN
                    exp_stat_sn, // expected StatSN
                    true,        // set I bit
                )
                .await
            };
            match result {
                Ok((hdr, data, _dig)) => {
                    println!("[heartbeat] got NOP-In: {hdr:?}\n\n {data:?}");
                    cmd_sn = hdr.stat_sn;
                    exp_stat_sn = hdr.exp_cmd_sn.wrapping_add(1);
                },
                Err(e) => {
                    eprintln!("[heartbeat] NOP failed: {e}");
                },
            }

            hb_itag.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    time::sleep(Duration::from_secs(20)).await;

    Ok(())
}
