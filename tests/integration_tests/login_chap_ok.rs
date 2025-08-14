use std::sync::{Arc, atomic::AtomicU32};

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    models::nop::request::NopOutRequest,
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap},
        nop_states::{self, NopCtx, NopStates, run_nop},
    },
};

use crate::integration_tests::common::{
    connect_cfg, load_config, lun8, test_isid, test_path,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_chap_ok() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;

    match cfg.login.auth {
        AuthConfig::Chap(_) => {},
        _ => {
            eprintln!("⏭️  skip: auth.method != chap in TEST_CONFIG");
            return Ok(());
        },
    }

    let conn: Arc<iscsi_client_rs::client::client::Connection> =
        connect_cfg(&cfg).await?;

    let isid = test_isid();
    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, 1, 0);

    let state: LoginStates = start_chap();
    let login_status = run_login(state, &mut lctx).await?;

    // После логина — 1 NOP на проверку канала
    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = lun8(1);

    let ttt = NopOutRequest::DEFAULT_TAG;
    let mut nctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    run_nop(NopStates::Idle(nop_states::Idle), &mut nctx).await?;

    Ok(())
}
