use std::fmt;

/// All iSCSI Reject Reason codes (RFC 3720 §10.4), plus catch-alls for reserved
/// and vendor-specific.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    CommandNotSupported = 0x00,
    InitiatorError = 0x01,
    TargetError = 0x02,
    LogicalUnitNotSupported = 0x03,
    TargetPortalGroupTagNotSupported = 0x04,
    InvalidConnectionID = 0x05,
    NoSession = 0x06,
    NoConnection = 0x07,
    DgstNotSupported = 0x08,
    DataPDUInOrderNotSupported = 0x09,
    DataSequenceInOrderNotSupported = 0x0A,
    Busy = 0x0B,
    TaskInProgress = 0x0C,
    CDBSegmentError = 0x0D,
    InvalidPDULength = 0x0E,
    UnsupportedVersion = 0x0F,
    /// Reserved (0x10–0x1F)
    Reserved1 = 0x10, // use .Other(0x10) … .Other(0x1F)
    AuthenticationFailed = 0x20,
    AuthorizationFailed = 0x21,
    InitiatorIDNotFound = 0x22,
    DuplicateSessionID = 0x23,
    /// Reserved (0x24–0x2F)
    Reserved2 = 0x24, // use .Other(0x24) … .Other(0x2F)
    /// Vendor-specific codes (0x30–0xFF)
    VendorSpecific(u8),
    /// Catch-all for any unhandled code
    Other(u8),
}

impl TryFrom<u8> for RejectReason {
    type Error = anyhow::Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Ok(match code {
            0x00 => RejectReason::CommandNotSupported,
            0x01 => RejectReason::InitiatorError,
            0x02 => RejectReason::TargetError,
            0x03 => RejectReason::LogicalUnitNotSupported,
            0x04 => RejectReason::TargetPortalGroupTagNotSupported,
            0x05 => RejectReason::InvalidConnectionID,
            0x06 => RejectReason::NoSession,
            0x07 => RejectReason::NoConnection,
            0x08 => RejectReason::DgstNotSupported,
            0x09 => RejectReason::DataPDUInOrderNotSupported,
            0x0A => RejectReason::DataSequenceInOrderNotSupported,
            0x0B => RejectReason::Busy,
            0x0C => RejectReason::TaskInProgress,
            0x0D => RejectReason::CDBSegmentError,
            0x0E => RejectReason::InvalidPDULength,
            0x0F => RejectReason::UnsupportedVersion,
            0x20 => RejectReason::AuthenticationFailed,
            0x21 => RejectReason::AuthorizationFailed,
            0x22 => RejectReason::InitiatorIDNotFound,
            0x23 => RejectReason::DuplicateSessionID,
            0x30..=0xFF => RejectReason::VendorSpecific(code),
            0x10..=0x1F | 0x24..=0x2F => RejectReason::Other(code),
        })
    }
}

impl From<RejectReason> for u8 {
    fn from(r: RejectReason) -> u8 {
        match r {
            RejectReason::CommandNotSupported => 0x00,
            RejectReason::InitiatorError => 0x01,
            RejectReason::TargetError => 0x02,
            RejectReason::LogicalUnitNotSupported => 0x03,
            RejectReason::TargetPortalGroupTagNotSupported => 0x04,
            RejectReason::InvalidConnectionID => 0x05,
            RejectReason::NoSession => 0x06,
            RejectReason::NoConnection => 0x07,
            RejectReason::DgstNotSupported => 0x08,
            RejectReason::DataPDUInOrderNotSupported => 0x09,
            RejectReason::DataSequenceInOrderNotSupported => 0x0A,
            RejectReason::Busy => 0x0B,
            RejectReason::TaskInProgress => 0x0C,
            RejectReason::CDBSegmentError => 0x0D,
            RejectReason::InvalidPDULength => 0x0E,
            RejectReason::UnsupportedVersion => 0x0F,

            RejectReason::Reserved1 => 0x10,
            RejectReason::Reserved2 => 0x24,

            RejectReason::AuthenticationFailed => 0x20,
            RejectReason::AuthorizationFailed => 0x21,
            RejectReason::InitiatorIDNotFound => 0x22,
            RejectReason::DuplicateSessionID => 0x23,

            RejectReason::VendorSpecific(code) => code,
            RejectReason::Other(code) => code,
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RejectReason::CommandNotSupported => {
                write!(f, "Command Not Supported (0x00)")
            },
            RejectReason::InitiatorError => write!(f, "Initiator Error (0x01)"),
            RejectReason::TargetError => write!(f, "Target Error (0x02)"),
            RejectReason::LogicalUnitNotSupported => {
                write!(f, "Logical Unit Not Supported (0x03)")
            },
            RejectReason::TargetPortalGroupTagNotSupported => {
                write!(f, "TPG Tag Not Supported (0x04)")
            },
            RejectReason::InvalidConnectionID => {
                write!(f, "Invalid Connection ID (0x05)")
            },
            RejectReason::NoSession => write!(f, "No Session (0x06)"),
            RejectReason::NoConnection => write!(f, "No Connection (0x07)"),
            RejectReason::DgstNotSupported => write!(f, "Digest Not Supported (0x08)"),
            RejectReason::DataPDUInOrderNotSupported => {
                write!(f, "Data PDU In-Order Not Supported (0x09)")
            },
            RejectReason::DataSequenceInOrderNotSupported => {
                write!(f, "Data Sequence In-Order Not Supported (0x0A)")
            },
            RejectReason::Busy => write!(f, "Busy (0x0B)"),
            RejectReason::TaskInProgress => write!(f, "Task In Progress (0x0C)"),
            RejectReason::CDBSegmentError => write!(f, "CDB Segment Error (0x0D)"),
            RejectReason::InvalidPDULength => write!(f, "Invalid PDU Length (0x0E)"),
            RejectReason::UnsupportedVersion => write!(f, "Unsupported Version (0x0F)"),
            RejectReason::Reserved1 => write!(f, "Reserved (0x10–0x1F)"),
            RejectReason::AuthenticationFailed => {
                write!(f, "Authentication Failed (0x20)")
            },
            RejectReason::AuthorizationFailed => write!(f, "Authorization Failed (0x21)"),
            RejectReason::InitiatorIDNotFound => {
                write!(f, "InitiatorID Not Found (0x22)")
            },
            RejectReason::DuplicateSessionID => write!(f, "Duplicate Session ID (0x23)"),
            RejectReason::Reserved2 => write!(f, "Reserved (0x24–0x2F)"),
            RejectReason::VendorSpecific(code) => {
                write!(f, "Vendor Specific (0x{code:02X})")
            },
            RejectReason::Other(code) => {
                write!(f, "Unknown Reject Reason (0x{code:02X})")
            },
        }
    }
}
