use std::{fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Deserializer, de};

#[derive(Deserialize, Debug)]
pub struct Config {
    pub target: Target,
    pub initiator: Initiator,
    pub auth: Auth,
    pub negotiation: Negotiation,
    pub performance: Performance,
    pub extra_text: String,
}

#[derive(Deserialize, Debug)]
pub struct Target {
    pub iqn: String,
    pub address: String,
}

#[derive(Deserialize, Debug)]
pub struct Initiator {
    pub iqn: String,
    pub alias: String,
    /// six-byte ISID encoded as hex, e.g. "00023d000009"
    #[serde(deserialize_with = "deserialize_isid")]
    pub isid: [u8; 6],
}

fn deserialize_isid<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(&s)
        .map_err(|e| de::Error::custom(format!("invalid ISID hex `{s}`: {e}")))?;
    if bytes.len() != 6 {
        return Err(de::Error::invalid_length(bytes.len(), &"exactly 6 bytes"));
    }
    let mut arr = [0u8; 6];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "method")]
pub enum Auth {
    /// no authentication
    None,
    /// CHAP: must provide a user and password
    Chap { username: String, secret: String },
}

#[derive(Deserialize, Debug)]
pub struct Negotiation {
    pub version_max: u8,
    pub version_min: u8,
    pub header_digest: String,
    pub data_digest: String,
    pub session_type: String,
}

#[derive(Deserialize, Debug)]
pub struct Performance {
    pub max_recv_data_segment_length: u32,
    pub max_burst_length: u32,
    pub first_burst_length: u32,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&s)?;
        Ok(cfg)
    }
}

/// A small helper to serialize config structs into
/// iSCSI login key=value\x00 strings.
pub trait ToLoginKeys {
    /// Returns a sequence of null-terminated "Key=Value\x00" strings.
    fn to_login_keys(&self) -> Vec<String>;
}

impl ToLoginKeys for Initiator {
    fn to_login_keys(&self) -> Vec<String> {
        vec![
            format!("InitiatorName={}\x00", self.iqn),
            format!("InitiatorAlias={}\x00", self.alias),
        ]
    }
}

impl ToLoginKeys for Target {
    fn to_login_keys(&self) -> Vec<String> {
        vec![
            format!("TargetName={}\x00", self.iqn),
            format!("TargetAddress={}\x00", self.address),
        ]
    }
}

impl ToLoginKeys for Negotiation {
    fn to_login_keys(&self) -> Vec<String> {
        vec![
            format!("SessionType={}\x00", self.session_type),
            format!("VersionMax={}\x00", self.version_max),
            format!("VersionMin={}\x00", self.version_min),
            format!("HeaderDigest={}\x00", self.header_digest),
            format!("DataDigest={}\x00", self.data_digest),
        ]
    }
}

impl ToLoginKeys for Auth {
    fn to_login_keys(&self) -> Vec<String> {
        match self {
            Auth::None => vec!["AuthMethod=None\x00".into()],
            Auth::Chap {
                username,
                secret: _,
            } => vec![
                "AuthMethod=CHAP\x00".into(),
                format!("UserName={}\x00", username),
            ],
        }
    }
}

impl ToLoginKeys for Performance {
    fn to_login_keys(&self) -> Vec<String> {
        vec![
            format!(
                "MaxRecvDataSegmentLength={}\x00",
                self.max_recv_data_segment_length
            ),
            format!("MaxBurstLength={}\x00", self.max_burst_length),
            format!("FirstBurstLength={}\x00", self.first_burst_length),
        ]
    }
}
