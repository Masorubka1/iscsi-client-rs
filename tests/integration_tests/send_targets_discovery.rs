// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    state_machine::discovery::DiscoveredTarget,
};

use crate::integration_tests::common::test_path;

/// Verify that SendTargets discovery returns the expected target name and
/// portal address. Always discovers against a plain (no-auth) target;
/// the discovery port/IQN are derived from `TEST_CONFIG`.
#[tokio::test]
async fn send_targets_discovery_tgt() -> Result<()> {
    let _ = init_logger(&test_path());

    let test_cfg = test_path();

    // Pick the right discovery config and expected IQN based on which
    // target is running.
    let (discovery_cfg_path, expected_iqn) = if test_cfg.contains("/tgt/") {
        // All tgt profiles share the same plain discovery config and IQN.
        (
            "tests/configs/tgt/discovery.yaml",
            "iqn.2025-08.example:disk0",
        )
    } else if test_cfg.contains("/lio/") {
        (
            "tests/configs/lio/discovery.yaml",
            "iqn.2025-08.com.example:disk0",
        )
    } else {
        // Fallback: vanilla config at repo root
        ("tests/config.yaml", "iqn.2025-08.example:disk0")
    };

    let cfg = Config::load_from_file(discovery_cfg_path)
        .context("failed to load discovery config")?;

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

    // Verify that the discovered target has at least one portal address.
    if let Some(t) = targets.iter().find(|t| t.target_name == expected_iqn) {
        assert!(
            !t.target_addresses.is_empty(),
            "target '{}' should have at least one TargetAddress, got none",
            expected_iqn
        );
    }

    Ok(())
}
