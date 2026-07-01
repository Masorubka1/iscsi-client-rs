// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use iscsi_client_rs::state_machine::discovery::DiscoveryCtx;

#[test]
fn parse_single_target() {
    // Typical SendTargets response for one target.
    let payload =
        b"TargetName=iqn.2003-01.org.example:disk1\0TargetAddress=192.168.1.10:3260,1\0";
    let targets = DiscoveryCtx::parse_send_targets_response(payload);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].target_name, "iqn.2003-01.org.example:disk1");
    assert_eq!(targets[0].target_addresses.len(), 1);
    assert_eq!(targets[0].target_addresses[0], "192.168.1.10:3260,1");
}

#[test]
fn parse_multiple_targets() {
    // Response with two targets, each with one address.
    let payload = b"TargetName=iqn.2003-01.org.example:disk1\0TargetName=iqn.2003-01.org.example:disk2\0TargetAddress=10.0.0.1:3260,1\0TargetAddress=10.0.0.2:3260,1\0";
    let targets = DiscoveryCtx::parse_send_targets_response(payload);
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].target_name, "iqn.2003-01.org.example:disk1");
    assert_eq!(targets[0].target_addresses, vec!["10.0.0.1:3260,1"]);
    assert_eq!(targets[1].target_name, "iqn.2003-01.org.example:disk2");
    assert_eq!(targets[1].target_addresses, vec!["10.0.0.2:3260,1"]);
}

#[test]
fn parse_target_with_multiple_portals() {
    // One target with two portal addresses (separate TargetAddress keys).
    let payload = b"TargetName=iqn.2003-01.org.example:disk1\0TargetAddress=10.0.0.1:3260,1\0TargetAddress=10.0.0.2:3260,2\0";
    let targets = DiscoveryCtx::parse_send_targets_response(payload);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].target_name, "iqn.2003-01.org.example:disk1");
    assert_eq!(
        targets[0].target_addresses,
        vec!["10.0.0.1:3260,1", "10.0.0.2:3260,2"]
    );
}

#[test]
fn parse_empty_response() {
    let targets = DiscoveryCtx::parse_send_targets_response(b"");
    assert!(targets.is_empty());
}

#[test]
fn parse_response_without_target_name() {
    // Only TargetAddress without TargetName — should produce no targets.
    let payload = b"TargetAddress=10.0.0.1:3260,1\0";
    let targets = DiscoveryCtx::parse_send_targets_response(payload);
    assert!(targets.is_empty());
}
