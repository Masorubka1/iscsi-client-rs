use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::client::Connection,
    handlers::{login_simple::login_plain, nop_handler::send_nop},
    models::nop::response::NopInResponse,
};
use tokio::{main, time};

#[main]
async fn main() -> Result<()> {
    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let conn = Arc::new(Connection::connect(&config.target.address).await?);
    println!("Connected to target");

    let login_rsp = login_plain(&conn, &config).await?;
    println!("Res1: {login_rsp:?}");

    let mut cmd_sn = login_rsp.exp_cmd_sn;
    let mut exp_stat_sn = login_rsp.max_cmd_sn;

    let hb_conn = conn.clone();
    tokio::spawn(async move {
        let mut itag = 1u32;
        loop {
            let result = {
                send_nop(
                    &hb_conn,
                    [0u8; 8], // LUN
                    itag,     // InitiatorTaskTag
                    NopInResponse::DEFAULT_TAG,
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

            itag = itag.wrapping_add(1);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    time::sleep(Duration::from_secs(40)).await;

    Ok(())
}
