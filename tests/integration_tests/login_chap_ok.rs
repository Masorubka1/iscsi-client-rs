// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::{Arc, atomic::AtomicU32};

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    client::client::ClientConnection,
    models::nop::request::NopOutRequest,
    state_machine::{
        login_states::{LoginCtx, LoginStates, run_login, start_chap},
        nop_states::{self, NopCtx, NopStates, run_nop},
    },
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

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

    let conn: Arc<ClientConnection> = connect_cfg(&cfg).await?;

    let isid = test_isid();
    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, 1, 0);

    let state: LoginStates = start_chap();
    let login_status = run_login(state, &mut lctx).await?;

    let cmd_sn = AtomicU32::new(login_status.exp_cmd_sn);
    let exp_stat_sn = AtomicU32::new(login_status.stat_sn.wrapping_add(1));
    let itt = AtomicU32::new(login_status.itt.wrapping_add(1));
    let lun = 1 << 48;

    let ttt = NopOutRequest::DEFAULT_TAG;
    let mut nctx = NopCtx::new(conn.clone(), lun, &itt, &cmd_sn, &exp_stat_sn, ttt);

    run_nop(NopStates::Idle(nop_states::Idle), &mut nctx).await?;

    Ok(())
}
