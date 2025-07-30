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
        //keys.push(format!("TargetPortalGroupTag={}\x00", sec.portal_group_tag));
        keys.push(format!("InitiatorName={}\x00", sec.initiator_name));
        keys.push(format!("InitiatorAlias={}\x00", sec.initiator_alias));
        keys.push(format!("TargetName={}\x00", sec.target_name));
        //keys.push(format!("TargetAlias={}\x00", sec.target_alias));
        //keys.push(format!("TargetAddress={}\x00", sec.target_address));
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

        // Auth
        let auth = &self.auth;
        match auth {
            AuthConfig::None => {},
            AuthConfig::Chap(_) => keys.push("AuthMethod=CHAP, None\x00".to_string()),
        }

        keys.sort();
        keys
    }
}

impl ToLoginKeys for ExtraDataConfig {
    fn to_login_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        // markers
        keys.push(format!("IFMarker={}\x00", self.markers.if_marker));
        keys.push(format!("OFMarker={}\x00", self.markers.of_marker));
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
