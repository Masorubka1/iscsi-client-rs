// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{
        config::{AuthConfig, Config},
        enums::{Digest, SessionType},
        logger::init_logger,
    },
    state_machine::discovery::DiscoveredTarget,
};

use crate::integration_tests::common::test_path;

/// Verify that SendTargets discovery works against the current target.
///
/// Reuses `TEST_CONFIG` but switches to `SessionType: Discovery`, clears
/// `TargetName`, and forces plain discovery with no digests.
#[tokio::test]
async fn send_targets_discovery() -> Result<()> {
    let _ = init_logger(&test_path());

    let mut cfg =
        Config::load_from_file(&test_path()).context("failed to load test config")?;

    // Switch to discovery mode — no TargetName
    cfg.login.identity.session_type = SessionType::Discovery;
    cfg.login.identity.target_name.clear();
    cfg.login.auth = AuthConfig::None;
    cfg.login.integrity.header_digest = Digest::None;
    cfg.login.integrity.data_digest = Digest::None;

    let expected_iqn =
        if test_path().contains("/lio/") || test_path().contains("/truenas/") {
            "iqn.2025-08.com.example:disk0"
        } else {
            "iqn.2025-08.example:disk0"
        };

    let targets: Vec<DiscoveredTarget> =
        iscsi_client_rs::client::pool_sessions::Pool::discover_targets(&cfg)
            .await
            .context("discover_targets failed")?;

    assert!(
        !targets.is_empty(),
        "expected at least one target from SendTargets discovery"
    );

    let found = targets.iter().any(|t| t.target_name == expected_iqn);
    assert!(
        found,
        "expected target '{}' in discovery results, got: {:?}",
        expected_iqn,
        targets.iter().map(|t| &t.target_name).collect::<Vec<_>>()
    );

    if let Some(t) = targets.iter().find(|t| t.target_name == expected_iqn) {
        assert!(
            !t.target_addresses.is_empty(),
            "target '{}' should have at least one TargetAddress, got none",
            expected_iqn
        );
    }

    Ok(())
}
