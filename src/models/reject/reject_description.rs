/// iSCSI Reject Reason codes (RFC 7143 §11.17.1)
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq)]
pub enum RejectReason {
    /// 0x01 — Reserved (MUST NOT be used)
    #[default]
    Reserved = 0x01,
    /// 0x02 — Data (payload) digest error; original PDU may be resent
    DataDigestError = 0x02,
    /// 0x03 — SNACK Reject; original PDU may be resent
    SnackReject = 0x03,
    /// 0x04 — Protocol Error (e.g. SNACK Request for an already-acked status);
    /// cannot be resent
    ProtocolError = 0x04,
    /// 0x05 — Command not supported; cannot be resent
    CommandNotSupported = 0x05,
    /// 0x06 — Immediate command reject (too many immediate commands); original
    /// PDU may be resent
    ImmediateCmdReject = 0x06,
    /// 0x07 — Task in progress; cannot be resent
    TaskInProgress = 0x07,
    /// 0x08 — Invalid data ack; cannot be resent
    InvalidDataAck = 0x08,
    /// 0x09 — Invalid PDU field (e.g. bad ITT, invalid SNACK numbers); cannot
    /// be resent
    InvalidPduField = 0x09,
    /// 0x0A — Long op reject (out of resources generating TargetTransferTag);
    /// original PDU may be resent
    LongOpReject = 0x0A,
    /// 0x0B — Deprecated (“Negotiation Reset”); MUST NOT be used
    DeprecatedNegotiReset = 0x0B,
    /// 0x0C — Waiting for Logout; cannot be resent
    WaitingForLogout = 0x0C,
    /// Any other value — unassigned/reserved or vendor-specific
    Other(u8),
}

impl TryFrom<u8> for RejectReason {
    type Error = anyhow::Error;

    fn try_from(b: u8) -> Result<Self, Self::Error> {
        Ok(match b {
            0x01 => RejectReason::Reserved,
            0x02 => RejectReason::DataDigestError,
            0x03 => RejectReason::SnackReject,
            0x04 => RejectReason::ProtocolError,
            0x05 => RejectReason::CommandNotSupported,
            0x06 => RejectReason::ImmediateCmdReject,
            0x07 => RejectReason::TaskInProgress,
            0x08 => RejectReason::InvalidDataAck,
            0x09 => RejectReason::InvalidPduField,
            0x0A => RejectReason::LongOpReject,
            0x0B => RejectReason::DeprecatedNegotiReset,
            0x0C => RejectReason::WaitingForLogout,
            other => RejectReason::Other(other),
        })
    }
}

impl From<&RejectReason> for u8 {
    fn from(r: &RejectReason) -> u8 {
        match *r {
            RejectReason::Reserved => 0x01,
            RejectReason::DataDigestError => 0x02,
            RejectReason::SnackReject => 0x03,
            RejectReason::ProtocolError => 0x04,
            RejectReason::CommandNotSupported => 0x05,
            RejectReason::ImmediateCmdReject => 0x06,
            RejectReason::TaskInProgress => 0x07,
            RejectReason::InvalidDataAck => 0x08,
            RejectReason::InvalidPduField => 0x09,
            RejectReason::LongOpReject => 0x0A,
            RejectReason::DeprecatedNegotiReset => 0x0B,
            RejectReason::WaitingForLogout => 0x0C,
            RejectReason::Other(code) => code,
        }
    }
}
