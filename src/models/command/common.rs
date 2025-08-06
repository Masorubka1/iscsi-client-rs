use std::{fmt, ptr};

use thiserror::Error;

bitflags::bitflags! {
    #[derive(Default, Clone, PartialEq)]
    /// iSCSI SCSI Command PDU flags
    pub struct ScsiCommandRequestFlags: u8 {
        const FINAL     = 0x80;
        const READ      = 0x40;
        const WRITE     = 0x20;
        /// lowest 3 bits represent the TaskAttribute
        const ATTR_MASK = 0b0000_0111;
    }
}

impl TryFrom<u8> for ScsiCommandRequestFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ScsiCommandRequestFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid ScsiCommandFlags: {:#08b}", value))
    }
}

impl fmt::Debug for ScsiCommandRequestFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ScsiCommandRequestFlags as F;

        write!(f, "ScsiCommandRequestFlags(")?;

        let mut sep = "";
        if self.contains(F::FINAL) {
            write!(f, "FINAL")?;
            sep = "|";
        }
        if self.contains(F::READ) {
            write!(f, "{sep}READ")?;
            sep = "|";
        }
        if self.contains(F::WRITE) {
            write!(f, "{sep}WRITE")?;
            sep = "|";
        }

        let attr_bits = self.bits() & F::ATTR_MASK.bits();
        let attr = TaskAttribute::from(attr_bits);
        write!(f, "{sep}ATTR={attr:?}({attr_bits:#04x})")?;

        write!(f, ")")
    }
}

/// SCSI Task Attributes, including reserved values
#[derive(Clone, Copy, PartialEq)]
pub enum TaskAttribute {
    Untagged,     // 0
    Simple,       // 1
    Ordered,      // 2
    HeadOfQueue,  // 3
    ACA,          // 4
    Reserved(u8), // 5..=7
}

impl From<u8> for TaskAttribute {
    fn from(value: u8) -> Self {
        match value {
            0 => TaskAttribute::Untagged,
            1 => TaskAttribute::Simple,
            2 => TaskAttribute::Ordered,
            3 => TaskAttribute::HeadOfQueue,
            4 => TaskAttribute::ACA,
            r @ 5..=7 => TaskAttribute::Reserved(r),
            other => TaskAttribute::Reserved(other),
        }
    }
}

impl From<TaskAttribute> for u8 {
    fn from(value: TaskAttribute) -> Self {
        match value {
            TaskAttribute::Untagged => 0,
            TaskAttribute::Simple => 1,
            TaskAttribute::Ordered => 2,
            TaskAttribute::HeadOfQueue => 3,
            TaskAttribute::ACA => 4,
            TaskAttribute::Reserved(v) => v & ScsiCommandRequestFlags::ATTR_MASK.bits(),
        }
    }
}

impl fmt::Debug for TaskAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaskAttribute::Untagged => write!(f, "Untagged"),
            TaskAttribute::Simple => write!(f, "Simple"),
            TaskAttribute::Ordered => write!(f, "Ordered"),
            TaskAttribute::HeadOfQueue => write!(f, "HeadOfQueue"),
            TaskAttribute::ACA => write!(f, "ACA"),
            TaskAttribute::Reserved(val) => write!(f, "Reserved({val})"),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, Clone, PartialEq)]
    /// iSCSI SCSI Command PDU flags
    pub struct ScsiCommandResponseFlags: u8 {
        const FINAL     = 0b1000_0000;
        /// Bidir Read Residual Overflow (o)
        const O_SMALL = 0b0001_0000;
        /// Bidir Read Residual Underflow (u)
        const U_SMALL = 0b0000_1000;
        /// Residual Overflow (O)
        const O_BIG = 0b0000_0100;
        /// Residual Underflow (U)
        const U_BIG = 0b0000_0010;
    }
}

impl TryFrom<u8> for ScsiCommandResponseFlags {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ScsiCommandResponseFlags::from_bits(value)
            .ok_or_else(|| anyhow::anyhow!("invalid ScsiCommandFlags: {:#08b}", value))
    }
}

/// The 1-byte “Response” field in a SCSI Response PDU (RFC 7143 § 11.4.3)
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCode {
    /// 0x00 – Command Completed at Target
    CommandCompleted = 0x00,
    /// 0x01 – Target Failure
    TargetFailure = 0x01,
    /// 0x80–0xFF – Vendor‐specific
    VendorSpecific(u8),
    /// 0x02–0x7F (excluding 0x01) and 0x02–0x7F – reserved by the spec
    Reserved(u8),
}

#[derive(Debug, Error)]
#[error("invalid response code: 0x{0:02x}")]
pub struct UnknownResponseCode(pub u8);

impl From<&ResponseCode> for u8 {
    fn from(value: &ResponseCode) -> Self {
        unsafe { ptr::read_unaligned(value as *const ResponseCode as *const u8) }
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = UnknownResponseCode;

    fn try_from(b: u8) -> Result<Self, Self::Error> {
        match b {
            0x00 => Ok(ResponseCode::CommandCompleted),
            0x01 => Ok(ResponseCode::TargetFailure),
            0x80..=0xFF => Ok(ResponseCode::VendorSpecific(b)),
            r @ 0x02..=0x7F => Ok(ResponseCode::Reserved(r)),
        }
    }
}

/// The 1-byte “Status” field in a SCSI Response PDU (RFC 7143 § 11.4.2)
///
/// Only valid when ResponseCode == CommandCompleted.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiStatus {
    Good = 0x00,
    CheckCondition = 0x02,
    Busy = 0x08,
    ReservationConflict = 0x18,
    TaskSetFull = 0x28,
    AcaActive = 0x30,
    TaskAborted = 0x40,
    /// Any other status codes defined in SAM-x or reserved
    Other(u8),
}

#[derive(Debug, Error)]
#[error("invalid SCSI status: 0x{0:02x}")]
pub struct UnknownScsiStatus(pub u8);

impl From<&ScsiStatus> for u8 {
    fn from(value: &ScsiStatus) -> Self {
        unsafe { ptr::read_unaligned(value as *const ScsiStatus as *const u8) }
    }
}

impl TryFrom<u8> for ScsiStatus {
    type Error = UnknownScsiStatus;

    fn try_from(b: u8) -> Result<Self, Self::Error> {
        let s = match b {
            0x00 => ScsiStatus::Good,
            0x02 => ScsiStatus::CheckCondition,
            0x08 => ScsiStatus::Busy,
            0x18 => ScsiStatus::ReservationConflict,
            0x28 => ScsiStatus::TaskSetFull,
            0x30 => ScsiStatus::AcaActive,
            0x40 => ScsiStatus::TaskAborted,
            other => ScsiStatus::Other(other),
        };
        Ok(s)
    }
}
