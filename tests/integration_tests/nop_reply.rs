// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        logger::init_logger,
    },
    models::{logout::common::LogoutReason, nop::request::NopOutRequest},
    state_machine::{
        common::StateMachineCtx, login::common::LoginCtx, logout_states::LogoutCtx,
        nop_states::NopCtx,
    },
    utils::generate_isid,
};
use tokio::time::{Duration, sleep, timeout};

use crate::integration_tests::common::{connect_cfg, get_lun, load_config, test_path};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_close_session() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg: Config = load_config()?;
    let conn = connect_cfg(&cfg).await?;

    let (isid, _s) = generate_isid();
    let cid = 1u16;
    let mut lctx = LoginCtx::new(conn.clone(), &cfg, isid, cid, 0);

    match cfg.login.auth {
        AuthConfig::Chap(_) => lctx.set_chap_login(),
        AuthConfig::None => lctx.set_plain_login(),
    }

    timeout(Duration::from_secs(10), lctx.execute())
        .await
        .context("login timeout")??;

    let login_pdu = lctx
        .last_response
        .as_ref()
        .context("no login last_response")?;
    let lh = login_pdu.header_view().context("login header")?;

    conn.counters
        .cmd_sn
        .store(lh.exp_cmd_sn.get(), Ordering::SeqCst);
    conn.counters
        .exp_stat_sn
        .store(lh.stat_sn.get().wrapping_add(1), Ordering::SeqCst);
    conn.counters
        .itt
        .store(lh.initiator_task_tag.wrapping_add(1), Ordering::SeqCst);

    let cmd_sn_before = conn.counters.cmd_sn.load(Ordering::SeqCst);
    let exp_stat_sn_before = conn.counters.exp_stat_sn.load(Ordering::SeqCst);

    let lun = get_lun();
    let mut times = 0;
    while times < 3 {
        let mut nctx = NopCtx::new(
            conn.clone(),
            lun,
            &conn.counters.itt,
            &conn.counters.cmd_sn,
            &conn.counters.exp_stat_sn,
            NopOutRequest::DEFAULT_TAG,
        );
        timeout(Duration::from_secs(10), nctx.execute())
            .await
            .context("nop timeout")??;
        times += 1;
    }

    sleep(Duration::from_secs(20)).await;

    let mut loctx = LogoutCtx::new(
        conn.clone(),
        &conn.counters.itt,
        &conn.counters.cmd_sn,
        &conn.counters.exp_stat_sn,
        cid,
        LogoutReason::CloseSession,
    );
    timeout(Duration::from_secs(10), loctx.execute())
        .await
        .context("logout timeout")??;

    let cmd_sn_after = conn.counters.cmd_sn.load(Ordering::SeqCst);
    let exp_stat_sn_after = conn.counters.exp_stat_sn.load(Ordering::SeqCst);

    assert!(cmd_sn_after >= cmd_sn_before);
    assert!(exp_stat_sn_after >= exp_stat_sn_before);

    Ok(())
}
