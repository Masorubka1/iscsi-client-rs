// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{collections::HashMap, fs, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::cfg::enums::{Digest, SessionType, YesNo};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    /// Parameters that travel over the wire during Login(Security) and
    /// Operational negotiation.
    pub login: LoginConfig,
    /// Implementation/runtime parameters that live outside the iSCSI protocol.
    pub runtime: RuntimeConfig,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Combined Login(Security) + Operational negotiation settings grouped by
/// logical domains.
pub struct LoginConfig {
    /// Session identity (SessionType, Initiator, Target).
    pub identity: Identity,
    /// Authentication strategy (AuthMethod / CHAP).
    pub auth: AuthConfig,
    /// Header/Data digest preferences.
    pub integrity: Integrity,
    /// Read-side flow limits (MaxRecvDataSegmentLength / MaxBurst /
    /// FirstBurst).
    pub flow: Flow,
    /// Write-side flow control parameters (InitialR2T / ImmediateData /
    /// MaxOutstandingR2T).
    pub write_flow: WriteFlow,
    /// Ordering preferences (DataPDUInOrder / DataSequenceInOrder).
    pub ordering: Ordering,
    /// Error recovery configuration (ErrorRecoveryLevel).
    pub recovery: Recovery,
    /// DefaultTime2Wait / DefaultTime2Retain timers.
    pub timers: Timers,
    /// MaxConnections negotiation cap.
    pub limits: Limits,
    /// RFC7143 extensions plus custom vendor keys.
    pub extensions: Extensions,
    /// Transport hints (TargetAddress / TPGT) kept locally and never sent on
    /// the wire.
    pub transport: TransportHints,
}

/// Identity parameters reported during Login.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Identity {
    #[serde(rename = "SessionType")]
    /// Requested session type (Discovery or Normal).
    pub session_type: SessionType,

    #[serde(rename = "InitiatorName")]
    /// Initiator IQN (mandatory).
    pub initiator_name: String,

    #[serde(default, rename = "InitiatorAlias")]
    /// Optional human-readable alias for the initiator.
    pub initiator_alias: String,

    #[serde(default, rename = "TargetName")]
    /// Required for Normal sessions; ignored during Discovery.
    pub target_name: String,

    #[serde(rename = "IsX86")]
    /// Runtime hint describing whether the initiator runs on x86.
    pub is_x86: YesNo,
}

/// Transport hints that are stored locally but never sent over the wire.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct TransportHints {
    #[serde(default, rename = "TargetAddress")]
    /// Preferred target address.
    pub target_address: String,
    #[serde(default, rename = "TargetPortalGroupTag")]
    /// Target portal group tag to probe first.
    pub portal_group_tag: u16,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(tag = "AuthMethod")]
/// Authentication configuration exposed through the Login AuthMethod key.
pub enum AuthConfig {
    #[serde(rename = "None")]
    None,
    #[serde(rename = "CHAP")]
    Chap(ChapConfig),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// CHAP credentials used during challenge-response authentication.
pub struct ChapConfig {
    /// Username advertised via CHAP_N.
    pub username: String,
    /// Shared secret used to generate CHAP_R.
    pub secret: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Digest preferences advertised via HeaderDigest/DataDigest.
pub struct Integrity {
    #[serde(rename = "HeaderDigest")]
    /// Header digest algorithm.
    pub header_digest: Digest,
    #[serde(rename = "DataDigest")]
    /// Data digest algorithm.
    pub data_digest: Digest,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Flow-control limits for the read path.
pub struct Flow {
    #[serde(rename = "MaxRecvDataSegmentLength")]
    /// Maximum data segment length the initiator can receive.
    pub max_recv_data_segment_length: u32,
    #[serde(rename = "MaxBurstLength")]
    /// Maximum burst size accepted from the target.
    pub max_burst_length: u32,
    #[serde(rename = "FirstBurstLength")]
    /// Unsolicited burst size before an R2T is required.
    pub first_burst_length: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Flow-control settings for the write path.
pub struct WriteFlow {
    #[serde(rename = "InitialR2T")]
    /// Whether the target demands an R2T before unsolicited data (Yes/No).
    pub initial_r2t: YesNo,
    #[serde(rename = "ImmediateData")]
    /// Whether immediate unsolicited data is permitted.
    pub immediate_data: YesNo,
    #[serde(rename = "MaxOutstandingR2T")]
    /// Maximum number of concurrent outstanding R2T requests.
    pub max_outstanding_r2t: u8,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Ordering expectations negotiated with the target.
pub struct Ordering {
    #[serde(rename = "DataPDUInOrder")]
    /// Whether Data PDUs are expected to arrive in order.
    pub data_pdu_in_order: YesNo,
    #[serde(rename = "DataSequenceInOrder")]
    /// Whether data sequences must remain in order.
    pub data_sequence_in_order: YesNo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Error recovery configuration.
pub struct Recovery {
    #[serde(rename = "ErrorRecoveryLevel")]
    /// ErrorRecoveryLevel to negotiate.
    pub error_recovery_level: u8,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Login timeout knobs expressed as seconds.
pub struct Timers {
    #[serde(rename = "DefaultTime2Wait", with = "serde_secs")]
    /// DefaultTime2Wait (seconds before retry).
    pub default_time2wait: Duration,
    #[serde(rename = "DefaultTime2Retain", with = "serde_secs")]
    /// DefaultTime2Retain (seconds to retain resources).
    pub default_time2retain: Duration,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Upper bounds exposed through MaxConnections.
pub struct Limits {
    #[serde(rename = "MaxConnections")]
    /// Maximum number of connections allowed in the session.
    pub max_connections: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC7143 extensions + custom keys

#[derive(Deserialize, Serialize, Debug, Clone)]
/// RFC7143 extension keys along with vendor-specific overrides.
pub struct Extensions {
    #[serde(rename = "TaskReporting", skip_serializing_if = "Option::is_none")]
    /// Optional RFC7143 TaskReporting value.
    pub task_reporting: Option<TaskReporting>,

    #[serde(rename = "iSCSIProtocolLevel", skip_serializing_if = "Option::is_none")]
    /// Optional RFC7143 iSCSIProtocolLevel (defaults to 1 when omitted).
    pub iscsi_protocol_level: Option<u8>,

    #[serde(flatten)]
    /// Additional vendor or implementation-specific key-value pairs.
    pub custom: HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
/// RFC7143 TaskReporting values.
pub enum TaskReporting {
    RFC3720,
    ResponseFence,
    FastAbort,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Runtime-only settings that do not map to RFC keys.
pub struct RuntimeConfig {
    #[serde(rename = "MaxSessions")]
    /// External limit on the number of simultaneously tracked sessions.
    pub max_sessions: u32,

    #[serde(rename = "TimeoutConnection", with = "serde_secs")]
    /// Timeout for establishing the TCP connection.
    pub timeout_connection: Duration,
}

impl Config {
    /// Loads the configuration from YAML, validates it, and returns the
    /// ready-to-use value.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let mut cfg: Config =
            serde_yaml::from_str(&s).context("failed to parse config YAML")?;
        cfg.validate_and_normalize()?;
        Ok(cfg)
    }

    /// Validates invariants and normalizes derived fields.
    pub fn validate_and_normalize(&mut self) -> Result<()> {
        // Discovery sessions always use MaxConnections=1 and ERL=0.
        if self.login.identity.session_type.is_discovery() {
            if self.login.limits.max_connections != 1 {
                self.login.limits.max_connections = 1;
            }
            if self.login.recovery.error_recovery_level != 0 {
                self.login.recovery.error_recovery_level = 0;
            }
        }

        // Ensure the declared iSCSIProtocolLevel is valid if provided.
        if let Some(lv) = self.login.extensions.iscsi_protocol_level {
            ensure!(lv >= 1, "iSCSIProtocolLevel must be >= 1");
        }

        // Mandatory base fields.
        ensure!(
            !self.login.identity.initiator_name.is_empty(),
            "InitiatorName must not be empty"
        );
        if self.login.identity.session_type.is_normal() {
            ensure!(
                !self.login.identity.target_name.is_empty(),
                "TargetName is required for Normal session"
            );
        }

        ensure!(
            self.login.limits.max_connections >= 1,
            "MaxConnections must be >= 1"
        );
        ensure!(self.runtime.max_sessions >= 1, "MaxSessions must be >= 1");

        Ok(())
    }
}

// SessionType helpers
impl SessionType {
    pub fn is_discovery(&self) -> bool {
        matches!(self, SessionType::Discovery)
    }

    pub fn is_normal(&self) -> bool {
        matches!(self, SessionType::Normal)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Login key generation (Security / CHAP / Operational)

/// Builds a null-delimited `key=value` list, skipping `None` entries and
/// sorting by key name for a canonical order.
fn build_kv_sorted<'a, I>(items: I) -> Vec<u8>
where I: IntoIterator<Item = (&'a str, Option<String>)> {
    let mut vec: Vec<(String, String)> = items
        .into_iter()
        .filter_map(|(k, v)| v.map(|vv| (k.to_string(), vv)))
        .collect();

    // Canonical order is alphabetical by key name (stable).
    vec.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    // Convert to bytes with `\0` terminators per key/value pair.
    let mut out =
        Vec::with_capacity(vec.iter().map(|(k, v)| k.len() + 1 + v.len() + 1).sum());
    for (k, v) in vec {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(0);
    }
    out
}

/// Builds the Login(Security) payload with the minimal required keys
/// (SessionType, InitiatorName, optional alias, optional target, and optional
/// AuthMethod).
pub fn login_keys_security(cfg: &Config) -> Vec<u8> {
    let id = &cfg.login.identity;

    build_kv_sorted([
        ("SessionType", Some(id.session_type.to_string())),
        ("InitiatorName", Some(id.initiator_name.clone())),
        (
            "InitiatorAlias",
            (!id.initiator_alias.is_empty()).then(|| id.initiator_alias.clone()),
        ),
        (
            "TargetName",
            (id.session_type.is_normal() && !id.target_name.is_empty())
                .then(|| id.target_name.clone()),
        ),
        (
            "AuthMethod",
            Some(match cfg.login.auth {
                AuthConfig::None => "None".to_string(),
                AuthConfig::Chap(_) => "CHAP,None".to_string(),
            }),
        ),
    ])
}

/// Builds the initiator response for a CHAP challenge (CHAP_N / CHAP_R only).
pub fn login_keys_chap_response(user: &str, chap_r_upper_hex_with_0x: &str) -> Vec<u8> {
    build_kv_sorted([
        ("CHAP_N", Some(user.to_string())),
        ("CHAP_R", Some(chap_r_upper_hex_with_0x.to_string())),
    ])
}

/// Builds the Operational Negotiation payload (only operational keys). Ordering
/// is canonical and unset/empty values are skipped.
pub fn login_keys_operational(cfg: &Config) -> Vec<u8> {
    let n = &cfg.login;

    // (1) Base operational parameters.
    let mut items: Vec<(&str, Option<String>)> = vec![
        // Integrity.
        ("HeaderDigest", Some(n.integrity.header_digest.to_string())),
        ("DataDigest", Some(n.integrity.data_digest.to_string())),
        // Ordering and ERL.
        (
            "DataPDUInOrder",
            Some(n.ordering.data_pdu_in_order.to_string()),
        ),
        (
            "DataSequenceInOrder",
            Some(n.ordering.data_sequence_in_order.to_string()),
        ),
        (
            "ErrorRecoveryLevel",
            Some(n.recovery.error_recovery_level.to_string()),
        ),
        // Limits / sizes.
        (
            "FirstBurstLength",
            Some(n.flow.first_burst_length.to_string()),
        ),
        ("MaxBurstLength", Some(n.flow.max_burst_length.to_string())),
        (
            "MaxRecvDataSegmentLength",
            Some(n.flow.max_recv_data_segment_length.to_string()),
        ),
        // Write-side flow.
        (
            "ImmediateData",
            Some(n.write_flow.immediate_data.to_string()),
        ),
        ("InitialR2T", Some(n.write_flow.initial_r2t.to_string())),
        (
            "MaxOutstandingR2T",
            Some(n.write_flow.max_outstanding_r2t.to_string()),
        ),
        // Timers.
        (
            "DefaultTime2Retain",
            Some(n.timers.default_time2retain.as_secs().to_string()),
        ),
        (
            "DefaultTime2Wait",
            Some(n.timers.default_time2wait.as_secs().to_string()),
        ),
        // Connections.
        ("MaxConnections", Some(n.limits.max_connections.to_string())),
    ];

    // (2) RFC7143 extensions.
    if let Some(tr) = &n.extensions.task_reporting {
        let v = match tr {
            TaskReporting::RFC3720 => "RFC3720",
            TaskReporting::ResponseFence => "ResponseFence",
            TaskReporting::FastAbort => "FastAbort",
        }
        .to_string();
        items.push(("TaskReporting", Some(v)));
    }
    if let Some(pl) = n.extensions.iscsi_protocol_level {
        // Include the key only when explicitly configured (default value is implicit).
        items.push(("iSCSIProtocolLevel", Some(pl.to_string())));
    }

    // (3) Custom keys (X-*, Z-*, etc.).
    // Note: collisions with base keys are valid—values are concatenated by iSCSI.
    for (k, v) in &n.extensions.custom {
        items.push((k.as_str(), Some(v.clone())));
    }

    build_kv_sorted(items)
}

/// Serde helpers for representing `Duration` as a number of seconds.
mod serde_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}
