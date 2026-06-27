// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use anyhow::Result;
use iscsi_client_rs::cfg::config::{AuthConfig, Config};

#[test]
fn lio_configs_are_valid() -> Result<()> {
    let plain = Config::load_from_file("ci/lio/config_plain.yaml")?;
    assert!(matches!(plain.login.auth, AuthConfig::None));

    let chap = Config::load_from_file("ci/lio/config_chap.yaml")?;
    let AuthConfig::Chap(chap) = chap.login.auth else {
        panic!("LIO CHAP config must enable CHAP");
    };
    assert_eq!(chap.username, "testuser");
    assert_eq!(chap.secret, "secretpass");

    let crc = Config::load_from_file("ci/lio/config_crc.yaml")?;
    assert!(matches!(crc.login.auth, AuthConfig::None));

    Ok(())
}
