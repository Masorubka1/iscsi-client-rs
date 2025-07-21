use anyhow::{Result, anyhow, bail};

/// The status classes as per RFC 3720 §11.11.1
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// target accepted the request
    Success = 0,
    /// initiator must follow TargetAddress
    Redirection = 1,
    /// mistake on initiator side; do not retry
    InitiatorError = 2,
    /// target temporarily cannot fulfil; may retry
    TargetError = 3,
    Unknown(u8),
}

impl From<u8> for StatusClass {
    fn from(b: u8) -> Self {
        match b {
            0 => StatusClass::Success,
            1 => StatusClass::Redirection,
            2 => StatusClass::InitiatorError,
            3 => StatusClass::TargetError,
            other => StatusClass::Unknown(other),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusDetail {
    Success(SuccessDetail),
    Redirection(RedirectionDetail),
    InitiatorErr(InitiatorErrorDetail),
    TargetErr(TargetErrorDetail),
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum SuccessDetail {
    CmdCompletedNormally = 0x00,
}

impl TryFrom<u8> for SuccessDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            0x00 => Ok(SuccessDetail::CmdCompletedNormally),
            other => Err(anyhow!("unknown Success detail code: {:#02x}", other)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum RedirectionDetail {
    TargetRedirected = 0x01,
}

impl TryFrom<u8> for RedirectionDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self> {
        match raw {
            0x01 => Ok(RedirectionDetail::TargetRedirected),
            other => Err(anyhow!("unknown Redirection detail code: {:#02x}", other)),
        }
    }
}

/// Status-Detail for Status-Class = 0x02 (Initiator Error)
/// (см. IANA iSCSI Parameters: Login Response Status Codes → Status-Detail for
/// Status-Class=0x02)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorErrorDetail {
    /// 0x00 — Initiator error (общая ошибка инициализатора)
    InitiatorError = 0x00,
    /// 0x01 — Authentication failure
    AuthFailed = 0x01,
    /// 0x02 — Authorization failure
    AuthzFailed = 0x02,
    /// 0x03 — Not found (например, указанный параметр отсутствует)
    NotFound = 0x03,
    /// 0x04 — Target removed
    TargetRemoved = 0x04,
    /// 0x05 — Unsupported version
    UnsupportedVersion = 0x05,
    /// 0x06 — Too many connections
    TooManyConnections = 0x06,
    /// 0x07 — Missing parameter
    MissingParameter = 0x07,
    /// 0x08 — Can't include in session
    CantIncludeInSession = 0x08,
    /// 0x09 — Session type not supported
    SessionTypeNotSupported = 0x09,
    /// 0x0a — Session does not exist
    SessionDoesNotExist = 0x0a,
    /// 0x0b — Invalid during login
    InvalidDuringLogin = 0x0b,
    /// 0x0c–0xff — RESERVATED
    Reserved(u8),
}

impl TryFrom<u8> for InitiatorErrorDetail {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(InitiatorErrorDetail::InitiatorError),
            0x01 => Ok(InitiatorErrorDetail::AuthFailed),
            0x02 => Ok(InitiatorErrorDetail::AuthzFailed),
            0x03 => Ok(InitiatorErrorDetail::NotFound),
            0x04 => Ok(InitiatorErrorDetail::TargetRemoved),
            0x05 => Ok(InitiatorErrorDetail::UnsupportedVersion),
            0x06 => Ok(InitiatorErrorDetail::TooManyConnections),
            0x07 => Ok(InitiatorErrorDetail::MissingParameter),
            0x08 => Ok(InitiatorErrorDetail::CantIncludeInSession),
            0x09 => Ok(InitiatorErrorDetail::SessionTypeNotSupported),
            0x0a => Ok(InitiatorErrorDetail::SessionDoesNotExist),
            0x0b => Ok(InitiatorErrorDetail::InvalidDuringLogin),
            other => Err(anyhow!("unknown InitiatorErrorDetail: 0x{:02x}", other)),
        }
    }
}

/// iSCSI Login Status-Detail codes for Status-Class = TargetError (0x03)
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TargetErrorDetail {
    /// (0x00) Target is busy, please retry later
    TargetBusy = 0x00,
    /// (0x01) Target’s protected area is busy
    TargetProtectedAreaBusy = 0x01,
    /// (0x02) Target cannot currently allocate requested resource
    TargetResourceUnavailable = 0x02,
    /// (0x03) Target encountered an internal error
    TargetInternalError = 0x03,
    /// (0x04–0xFE) Vendor-specific error
    VendorSpecific(u8),
    /// (0xFF) Reserved
    Reserved(u8),
}

impl TryFrom<u8> for TargetErrorDetail {
    type Error = anyhow::Error;

    fn try_from(raw: u8) -> Result<Self, Self::Error> {
        let detail = match raw {
            0x00 => TargetErrorDetail::TargetBusy,
            0x01 => TargetErrorDetail::TargetProtectedAreaBusy,
            0x02 => TargetErrorDetail::TargetResourceUnavailable,
            0x03 => TargetErrorDetail::TargetInternalError,
            0x04..=0xFE => TargetErrorDetail::VendorSpecific(raw),
            0xFF => TargetErrorDetail::Reserved(raw),
        };
        Ok(detail)
    }
}

impl TryFrom<(StatusClass, u8)> for StatusDetail {
    type Error = anyhow::Error;

    fn try_from((class, raw): (StatusClass, u8)) -> Result<Self> {
        Ok(match class {
            StatusClass::Success => StatusDetail::Success(SuccessDetail::try_from(raw)?),
            StatusClass::Redirection => {
                StatusDetail::Redirection(RedirectionDetail::try_from(raw)?)
            },
            StatusClass::InitiatorError => {
                StatusDetail::InitiatorErr(InitiatorErrorDetail::try_from(raw)?)
            },
            StatusClass::TargetError => {
                StatusDetail::TargetErr(TargetErrorDetail::try_from(raw)?)
            },
            _ => bail!("invalid class"),
        })
    }
}
