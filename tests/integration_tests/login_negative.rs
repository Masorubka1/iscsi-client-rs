// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::sync::Arc;

use anyhow::Result;
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, ChapConfig, Config},
        logger::init_logger,
    },
    client::pool_sessions::Pool,
    models::identifiers::Cid,
};

use crate::integration_tests::common::{connect_cfg, load_config, test_isid, test_path};

async fn assert_login_rejected(cfg: Config, isid_suffix: u8) -> Result<()> {
    let pool = Pool::new(&cfg);
    let conn = connect_cfg(&cfg).await?;
    let target_name: Arc<str> = Arc::from(cfg.login.identity.target_name.clone());
    let mut isid = test_isid().get();
    isid[5] = isid_suffix;

    let result = pool
        .login_and_insert(target_name, isid.into(), Cid::ZERO, conn)
        .await;
    assert!(
        result.is_err(),
        "invalid authentication unexpectedly succeeded"
    );
    assert!(pool.sessions.is_empty(), "failed login entered the pool");
    Ok(())
}

#[tokio::test]
async fn invalid_authentication_is_rejected() -> Result<()> {
    let _ = init_logger(&test_path());
    let cfg = load_config()?;

    match &cfg.login.auth {
        AuthConfig::Chap(chap) => {
            let mut wrong_secret = cfg.clone();
            wrong_secret.login.auth = AuthConfig::Chap(ChapConfig {
                username: chap.username.clone(),
                secret: "definitely-wrong-secret".into(),
            });
            assert_login_rejected(wrong_secret, 31).await?;

            let mut wrong_user = cfg.clone();
            wrong_user.login.auth = AuthConfig::Chap(ChapConfig {
                username: "unknown-user".into(),
                secret: chap.secret.clone(),
            });
            assert_login_rejected(wrong_user, 32).await?;

            let mut missing_chap = cfg;
            missing_chap.login.auth = AuthConfig::None;
            assert_login_rejected(missing_chap, 33).await?;
        },
        AuthConfig::None => {
            let mut unexpected_chap = cfg;
            unexpected_chap.login.auth = AuthConfig::Chap(ChapConfig {
                username: "testuser".into(),
                secret: "secretpass".into(),
            });
            assert_login_rejected(unexpected_chap, 34).await?;
        },
    }

    Ok(())
}
