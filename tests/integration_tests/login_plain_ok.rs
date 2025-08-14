use std::sync::atomic::AtomicU32;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    models::nop::request::NopOutRequest,
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap, start_plain},
        nop_states::{self, NopCtx, NopStates, run_nop},
    },
};

use crate::integration_tests::common::{
    connect_cfg, load_config, lun8, test_isid, test_path,
};

#[tokio::test]
async fn login_and_nop() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;

    let conn = connect_cfg(&cfg).await?;

    let isid = test_isid();
    let mut lctx = LoginCtx::new(
        conn.clone(),
        &cfg,
        isid,
        /* cid= */ 1,
        /* tsih= */ 0,
    );

    let login_state: LoginStates = match cfg.login.auth {
        AuthConfig::Chap(_) => start_chap(),
        AuthConfig::None => start_plain(),
    };

    let login_status = run_login(login_state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = lun8(1);

    let ttt = NopOutRequest::DEFAULT_TAG;
    let mut nctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    run_nop(NopStates::Idle(nop_states::Idle), &mut nctx).await?;

    Ok(())
}
