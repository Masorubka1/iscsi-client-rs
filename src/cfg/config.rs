// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{collections::HashMap, fs, path::Path, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cfg::enums::{Digest, SessionType, YesNo};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Config {
    pub login: LoginConfig,
    pub extra_data: ExtraDataConfig,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LoginConfig {
    pub security: SecurityConfig,
    pub negotiation: NegotiationConfig,
    pub auth: AuthConfig,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(tag = "AuthMethod")]
pub enum AuthConfig {
    #[serde(rename = "None")]
    None,
    #[serde(rename = "CHAP")]
    Chap(ChapConfig),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ChapConfig {
    pub username: String,
    pub secret: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SecurityConfig {
    #[serde(rename = "SessionType")]
    pub session_type: SessionType,
    #[serde(rename = "TargetPortalGroupTag")]
    pub portal_group_tag: u16,
    #[serde(rename = "InitiatorName")]
    pub initiator_name: String,
    #[serde(rename = "InitiatorAlias")]
    pub initiator_alias: String,
    #[serde(rename = "TargetName")]
    pub target_name: String,
    #[serde(rename = "TargetAddress")]
    pub target_address: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NegotiationConfig {
    #[serde(rename = "VersionMax")]
    pub version_max: u8,
    #[serde(rename = "VersionMin")]
    pub version_min: u8,

    #[serde(rename = "HeaderDigest")]
    pub header_digest: Digest,
    #[serde(rename = "DataDigest")]
    pub data_digest: Digest,

    #[serde(rename = "MaxRecvDataSegmentLength")]
    pub max_recv_data_segment_length: u32,
    #[serde(rename = "MaxBurstLength")]
    pub max_burst_length: u32,
    #[serde(rename = "FirstBurstLength")]
    pub first_burst_length: u32,

    #[serde(rename = "DataPDUInOrder")]
    pub data_pdu_in_order: YesNo,
    #[serde(rename = "DataSequenceInOrder")]
    pub data_sequence_in_order: YesNo,
    #[serde(rename = "ErrorRecoveryLevel")]
    pub error_recovery_level: u8,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ExtraDataConfig {
    pub markers: MarkerConfig,
    pub r2t: R2TConfig,
    pub connections: ConnectionConfig,
    #[serde(flatten)]
    pub custom: HashMap<String, String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MarkerConfig {
    #[serde(rename = "IFMarker")]
    pub if_marker: YesNo,
    #[serde(rename = "OFMarker")]
    pub of_marker: YesNo,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct R2TConfig {
    #[serde(rename = "InitialR2T")]
    pub initial_r2t: YesNo,
    #[serde(rename = "ImmediateData")]
    pub immediate_data: YesNo,
    #[serde(rename = "MaxOutstandingR2T")]
    pub max_outstanding_r2t: u8,

    #[serde(rename = "DefaultTime2Wait", with = "serde_secs")]
    pub default_time2wait: Duration,
    #[serde(rename = "DefaultTime2Retain", with = "serde_secs")]
    pub default_time2retain: Duration,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ConnectionConfig {
    #[serde(rename = "MaxConnections")]
    pub max_connections: u16,
    #[serde(rename = "MaxSessions")]
    pub max_sessions: u32, // внешний параметр, не RFC-ключ
    #[serde(rename = "TimeoutConnection", with = "serde_secs")]
    pub timeout_connection: Duration,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let cfg: Config =
            serde_yaml::from_str(&s).context("failed to parse config YAML")?;
        Ok(cfg)
    }
}

/// Trait to turn login and extra_data into key=value\x00 sequences
pub trait ToLoginKeys {
    fn to_login_keys(&self) -> Vec<String>;
}

impl ToLoginKeys for LoginConfig {
    fn to_login_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        // Security
        let sec = &self.security;
        keys.push(format!("SessionType={}\x00", sec.session_type));
        keys.push(format!("InitiatorName={}\x00", sec.initiator_name));
        keys.push(format!("InitiatorAlias={}\x00", sec.initiator_alias));
        keys.push(format!("TargetName={}\x00", sec.target_name));
        // Negotiation
        let neg = &self.negotiation;
        //keys.push(format!("VersionMax={}\x00", neg.version_max));
        //keys.push(format!("VersionMin={}\x00", neg.version_min));
        keys.push(format!("HeaderDigest={}\x00", neg.header_digest));
        keys.push(format!("DataDigest={}\x00", neg.data_digest));
        keys.push(format!(
            "MaxRecvDataSegmentLength={}\x00",
            neg.max_recv_data_segment_length
        ));
        keys.push(format!("MaxBurstLength={}\x00", neg.max_burst_length));
        keys.push(format!("FirstBurstLength={}\x00", neg.first_burst_length));
        keys.push(format!("DataPDUInOrder={}\x00", neg.data_pdu_in_order));
        keys.push(format!(
            "DataSequenceInOrder={}\x00",
            neg.data_sequence_in_order
        ));
        keys.push(format!(
            "ErrorRecoveryLevel={}\x00",
            neg.error_recovery_level
        ));

        keys.sort();
        keys
    }
}

impl ToLoginKeys for ExtraDataConfig {
    fn to_login_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        // markers
        keys.push(format!("IFMarker={}\x00", self.markers.if_marker));
        keys.push(format!("OFMarker={}\x00", self.markers.if_marker));
        // r2t
        keys.push(format!("InitialR2T={}\x00", self.r2t.initial_r2t));
        keys.push(format!("ImmediateData={}\x00", self.r2t.immediate_data));
        keys.push(format!(
            "MaxOutstandingR2T={}\x00",
            self.r2t.max_outstanding_r2t
        ));
        keys.push(format!(
            "DefaultTime2Wait={}\x00",
            self.r2t.default_time2wait.as_secs()
        ));
        keys.push(format!(
            "DefaultTime2Retain={}\x00",
            self.r2t.default_time2retain.as_secs()
        ));
        // connections
        keys.push(format!(
            "MaxConnections={}\x00",
            self.connections.max_connections
        ));
        keys.sort();
        keys
    }
}

impl ToLoginKeys for Config {
    fn to_login_keys(&self) -> Vec<String> {
        let mut keys = self.login.to_login_keys();
        keys.extend(self.extra_data.to_login_keys());
        keys.sort();
        keys
    }
}

#[inline]
fn kvz(k: &str, v: impl AsRef<str>) -> String {
    // key=value\0
    let mut s = String::with_capacity(k.len() + 1 + v.as_ref().len() + 1);
    s.push_str(k);
    s.push('=');
    s.push_str(v.as_ref());
    s.push('\0');
    s
}

fn join_bytes(keys: &[String]) -> Vec<u8> {
    keys.iter().flat_map(|s| s.as_bytes()).copied().collect()
}

pub fn login_keys_security(cfg: &Config) -> Vec<u8> {
    let sec = &cfg.login.security;

    let mut keys = vec![
        kvz("SessionType", sec.session_type.to_string()),
        kvz("InitiatorName", &sec.initiator_name),
        kvz("TargetName", &sec.target_name),
    ];

    match cfg.login.auth {
        AuthConfig::None => keys.push(kvz("AuthMethod", "None")),
        AuthConfig::Chap(_) => {
            keys.push(kvz("AuthMethod", "CHAP,None"));
        },
    }

    join_bytes(&keys)
}

/// response on CHAP: CHAP_N/CHAP_R
pub fn login_keys_chap_response(user: &str, chap_r_upper_hex_with_0x: &str) -> Vec<u8> {
    let keys = vec![kvz("CHAP_N", user), kvz("CHAP_R", chap_r_upper_hex_with_0x)];
    join_bytes(&keys)
}

/// OperationalNegotiation
pub fn login_keys_operational(cfg: &Config) -> Vec<u8> {
    let n = &cfg.login.negotiation;
    let e = &cfg.extra_data;

    let mut keys = vec![
        // Digest
        kvz("HeaderDigest", n.header_digest.to_string()),
        kvz("DataDigest", n.data_digest.to_string()),
        // Order/ERL
        kvz("DataPDUInOrder", n.data_pdu_in_order.to_string()),
        kvz("DataSequenceInOrder", n.data_sequence_in_order.to_string()),
        kvz("ErrorRecoveryLevel", n.error_recovery_level.to_string()),
        // Limits / sizes
        kvz(
            "MaxRecvDataSegmentLength",
            n.max_recv_data_segment_length.to_string(),
        ),
        kvz("MaxBurstLength", n.max_burst_length.to_string()),
        kvz("FirstBurstLength", n.first_burst_length.to_string()),
        // Markers
        kvz("IFMarker", e.markers.if_marker.to_string()),
        kvz("OFMarker", e.markers.of_marker.to_string()),
        // R2T / Immediate
        kvz("InitialR2T", e.r2t.initial_r2t.to_string()),
        kvz("ImmediateData", e.r2t.immediate_data.to_string()),
        kvz("MaxOutstandingR2T", e.r2t.max_outstanding_r2t.to_string()),
        kvz(
            "DefaultTime2Wait",
            e.r2t.default_time2wait.as_secs().to_string(),
        ),
        kvz(
            "DefaultTime2Retain",
            e.r2t.default_time2retain.as_secs().to_string(),
        ),
        // Connections
        kvz("MaxConnections", e.connections.max_connections.to_string()),
    ];

    for (k, v) in &e.custom {
        keys.push(kvz(k, v));
    }

    join_bytes(&keys)
}

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
