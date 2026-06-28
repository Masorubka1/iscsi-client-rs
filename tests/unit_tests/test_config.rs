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
        "tests/configs/freebsd/plain.yaml",
        "tests/configs/truenas/plain.yaml",
    ] {
        Config::load_from_file(path)?;
    }

    let plain = Config::load_from_file("tests/configs/lio/plain.yaml")?;
    assert!(matches!(plain.login.auth, AuthConfig::None));

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
