// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, enums::SessionType, logger::init_logger},
    state_machine::discovery::DiscoveredTarget,
};

use crate::integration_tests::common::test_path;

/// Verify that SendTargets discovery works against the current target.
///
/// Reuses `TEST_CONFIG` but switches `SessionType` to `Discovery`,
/// clears `TargetName`, and overrides `AuthMethod` to `None` (the target
/// never requires CHAP for discovery).
#[tokio::test]
async fn send_targets_discovery_tgt() -> Result<()> {
    let _ = init_logger(&test_path());

    let mut cfg =
        Config::load_from_file(&test_path()).context("failed to load test config")?;

    // Switch to discovery mode
    cfg.login.identity.initiator_name.clear();
    cfg.login.identity.session_type = SessionType::Discovery;
    cfg.login.identity.target_name.clear();
    // Discovery never needs auth
    cfg.login.auth = iscsi_client_rs::cfg::config::AuthConfig::None;
    // Single connection is enough
    cfg.login.limits.max_connections = 1;

    let expected_iqn = if test_path().contains("/lio/") {
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
