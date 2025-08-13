use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub login: LoginConfig,
    pub extra_data: ExtraDataConfig,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LoginConfig {
    pub security: SecurityConfig,
    pub negotiation: NegotiationConfig,
    pub auth: AuthConfig,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase", tag = "method")]
pub enum AuthConfig {
    /// no authentication
    None,
    /// CHAP: must provide a user and password
    Chap(ChapConfig),
}

#[derive(Deserialize, Debug, Clone)]
pub struct ChapConfig {
    pub username: String,
    pub secret: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SecurityConfig {
    #[serde(rename = "session_type")]
    pub session_type: String, // SessionType
    #[serde(rename = "portal_group_tag")]
    pub portal_group_tag: u16, // TargetPortalGroupTag

    #[serde(rename = "initiator_name")]
    pub initiator_name: String, // InitiatorName
    #[serde(rename = "initiator_alias")]
    pub initiator_alias: String, // InitiatorAlias

    #[serde(rename = "target_name")]
    pub target_name: String, // TargetName
    //#[serde(rename = "target_alias")]
    //pub target_alias: String, // TargetAlias
    #[serde(rename = "target_address")]
    pub target_address: String, // TargetAddress
}

#[derive(Deserialize, Debug, Clone)]
pub struct NegotiationConfig {
    #[serde(rename = "version_max")]
    pub version_max: u8, // VersionMax
    #[serde(rename = "version_min")]
    pub version_min: u8, // VersionMin
    #[serde(rename = "header_digest")]
    pub header_digest: String, // HeaderDigest
    #[serde(rename = "data_digest")]
    pub data_digest: String, // DataDigest

    #[serde(rename = "max_recv_data_segment_length")]
    pub max_recv_data_segment_length: u32,
    #[serde(rename = "max_burst_length")]
    pub max_burst_length: u32,
    #[serde(rename = "first_burst_length")]
    pub first_burst_length: u32,

    #[serde(rename = "data_pdu_in_order")]
    pub data_pdu_in_order: String,
    #[serde(rename = "data_sequence_in_order")]
    pub data_sequence_in_order: String,
    #[serde(rename = "error_recovery_level")]
    pub error_recovery_level: u8,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ExtraDataConfig {
    pub markers: MarkerConfig,
    pub r2t: R2TConfig,
    pub connections: ConnectionConfig,
    #[serde(flatten)]
    pub custom: HashMap<String, String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct MarkerConfig {
    #[serde(rename = "IFMarker")]
    pub if_marker: String,
    #[serde(rename = "OFMarker")]
    pub of_marker: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct R2TConfig {
    #[serde(rename = "initial_r2t")]
    pub initial_r2t: String,
    #[serde(rename = "immediate_data")]
    pub immediate_data: String,
    #[serde(rename = "max_outstanding_r2t")]
    pub max_outstanding_r2t: u8,
    #[serde(rename = "default_time2wait")]
    pub default_time2wait: u8,
    #[serde(rename = "default_time2retain")]
    pub default_time2retain: u8,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConnectionConfig {
    #[serde(rename = "max_connections")]
    pub max_connections: u8,
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
            self.r2t.default_time2wait
        ));
        keys.push(format!(
            "DefaultTime2Retain={}\x00",
            self.r2t.default_time2retain
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
        kvz("SessionType", &sec.session_type),
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
        kvz("HeaderDigest", &n.header_digest),
        kvz("DataDigest", &n.data_digest),
        // Order/ERL
        kvz("DataPDUInOrder", &n.data_pdu_in_order),
        kvz("DataSequenceInOrder", &n.data_sequence_in_order),
        kvz("ErrorRecoveryLevel", n.error_recovery_level.to_string()),
        // Limits / sizes
        kvz(
            "MaxRecvDataSegmentLength",
            n.max_recv_data_segment_length.to_string(),
        ),
        kvz("MaxBurstLength", n.max_burst_length.to_string()),
        kvz("FirstBurstLength", n.first_burst_length.to_string()),
        // Markers
        kvz("IFMarker", &e.markers.if_marker),
        kvz("OFMarker", &e.markers.of_marker),
        // R2T / Immediate
        kvz("InitialR2T", &e.r2t.initial_r2t),
        kvz("ImmediateData", &e.r2t.immediate_data),
        kvz("MaxOutstandingR2T", e.r2t.max_outstanding_r2t.to_string()),
        kvz("DefaultTime2Wait", e.r2t.default_time2wait.to_string()),
        kvz("DefaultTime2Retain", e.r2t.default_time2retain.to_string()),
        // Connections
        kvz("MaxConnections", e.connections.max_connections.to_string()),
    ];

    for (k, v) in &e.custom {
        keys.push(kvz(k, v));
    }

    join_bytes(&keys)
}
