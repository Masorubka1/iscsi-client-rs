use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{cli::resolve_config_path, config::Config},
    client::client::Connection,
    login::common::login_plain,
};
use tokio::main;

#[main]
async fn main() -> Result<()> {
    let config = resolve_config_path("tests/config.yaml")
        .and_then(Config::load_from_file)
        .context("failed to resolve or load config")?;

    let mut conn = Connection::connect(&config.target.address).await?;
    println!("Connected to target");

    let res = login_plain(&mut conn, &config).await?;
    println!("Res1: {res:?}");

    Ok(())
}
