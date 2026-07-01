// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use iscsi_client_rs::cfg::config::{AuthConfig, Config};

#[test]
fn integration_configs_are_valid() -> Result<()> {
    for path in [
        "tests/configs/tgt/plain.yaml",
        "tests/configs/tgt/chap.yaml",
        "tests/configs/tgt/crc.yaml",
        "tests/configs/truenas/plain.yaml",
    ] {
        Config::load_from_file(path)?;
    }

    let plain = Config::load_from_file("tests/configs/lio/plain.yaml")?;
    assert!(matches!(plain.login.auth, AuthConfig::None));
    assert_eq!(plain.runtime.response_queue_capacity, 256);
    assert_eq!(plain.runtime.max_connection_recovery_attempts, 3);
    let mut invalid = plain;
    invalid.runtime.response_queue_capacity = 0;
    assert!(invalid.validate_and_normalize().is_err());

    let chap = Config::load_from_file("tests/configs/lio/chap.yaml")?;
    let AuthConfig::Chap(chap) = chap.login.auth else {
        panic!("LIO CHAP config must enable CHAP");
    };
    assert_eq!(chap.username, "testuser");
    assert_eq!(chap.secret, "secretpass");

    let crc = Config::load_from_file("tests/configs/lio/crc.yaml")?;
    assert!(matches!(crc.login.auth, AuthConfig::None));

    Ok(())
}
