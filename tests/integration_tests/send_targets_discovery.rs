// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::{Context, Result};
use iscsi_client_rs::{
    cfg::{config::Config, logger::init_logger},
    state_machine::discovery::DiscoveredTarget,
};

use crate::integration_tests::common::test_path;

/// Verify that SendTargets discovery against tgt returns the expected
/// target name and portal address.
///
/// Uses `tests/configs/tgt/discovery.yaml` — a dedicated config with
/// `SessionType: Discovery`, no `TargetName`, and `AuthMethod: None`.
#[tokio::test]
async fn send_targets_discovery_tgt() -> Result<()> {
    let _ = init_logger(&test_path());

    let cfg = Config::load_from_file("tests/configs/tgt/discovery.yaml")
        .context("failed to load discovery config")?;

    let targets: Vec<DiscoveredTarget> =
        iscsi_client_rs::client::pool_sessions::Pool::discover_targets(&cfg)
            .await
            .context("discover_targets failed")?;

    assert!(
        !targets.is_empty(),
        "expected at least one target from SendTargets discovery"
    );

    // The docker TGT container exports `iqn.2025-08.example:disk0`.
    let tgt_iqn = "iqn.2025-08.example:disk0";
    let found = targets.iter().any(|t| t.target_name == tgt_iqn);
    assert!(
        found,
        "expected target '{}' in discovery results, got: {:?}",
        tgt_iqn,
        targets.iter().map(|t| &t.target_name).collect::<Vec<_>>()
    );

    // Verify that the discovered target has at least one portal address.
    if let Some(t) = targets.iter().find(|t| t.target_name == tgt_iqn) {
        assert!(
            !t.target_addresses.is_empty(),
            "target '{}' should have at least one TargetAddress, got none",
            tgt_iqn
        );
    }

    Ok(())
}
