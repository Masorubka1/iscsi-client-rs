// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use core::fmt;

use anyhow::{Result, bail};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::models::command::common::{
    ResponseCode, ScsiCommandRequestFlags, ScsiCommandResponseFlags, ScsiStatus,
    TaskAttribute, UnknownResponseCode, UnknownScsiStatus,
};

/// 3-bit SCSI Task Attribute (lower bits of the request flags).
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawTaskAttribute(u8);

impl RawTaskAttribute {
    const MASK: u8 = 0b0000_0111;

    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0 & Self::MASK
    }

    #[inline]
    pub const fn new(bits3: u8) -> Self {
        Self(bits3 & Self::MASK)
    }

    /// Decode to high-level enum.
    #[inline]
    pub fn decode(&self) -> TaskAttribute {
        match self.raw() {
            0 => TaskAttribute::Untagged,
            1 => TaskAttribute::Simple,
            2 => TaskAttribute::Ordered,
            3 => TaskAttribute::HeadOfQueue,
            4 => TaskAttribute::ACA,
            r @ 5..=7 => TaskAttribute::Reserved(r),
            // unreachable due to mask
            _ => TaskAttribute::Reserved(self.raw()),
        }
    }

    /// Encode from high-level enum.
    #[inline]
    pub fn encode(&mut self, attr: TaskAttribute) {
        let v = match attr {
            TaskAttribute::Untagged => 0,
            TaskAttribute::Simple => 1,
            TaskAttribute::Ordered => 2,
            TaskAttribute::HeadOfQueue => 3,
            TaskAttribute::ACA => 4,
            TaskAttribute::Reserved(v) => v & Self::MASK,
        };
        self.0 = (self.0 & !Self::MASK) | v;
    }
}

impl From<TaskAttribute> for RawTaskAttribute {
    #[inline]
    fn from(a: TaskAttribute) -> Self {
        let mut r = RawTaskAttribute::default();
        r.encode(a);
        r
    }
}

impl From<RawTaskAttribute> for TaskAttribute {
    #[inline]
    fn from(r: RawTaskAttribute) -> Self {
        r.decode()
    }
}

/// Wire view for **SCSI Command Request** flags (byte 1 of the PDU).
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawScsiCmdReqFlags(u8);

impl RawScsiCmdReqFlags {
    pub const ATTR: u8 = 0x07;
    pub const FINAL: u8 = 0x80;
    pub const READ: u8 = 0x40;
    pub const WRITE: u8 = 0x20;

    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    #[inline]
    pub fn read(&self) -> bool {
        self.0 & Self::READ != 0
    }

    #[inline]
    pub fn write(&self) -> bool {
        self.0 & Self::WRITE != 0
    }

    #[inline]
    pub fn set_fin(&mut self, on: bool) {
        self.set(Self::FINAL, on)
    }

    #[inline]
    pub fn set_read(&mut self, on: bool) {
        self.set(Self::READ, on)
    }

    #[inline]
    pub fn set_write(&mut self, on: bool) {
        self.set(Self::WRITE, on)
    }

    #[inline]
    fn set(&mut self, bit: u8, on: bool) {
        if on {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    #[inline]
    pub fn task_attr(&self) -> TaskAttribute {
        RawTaskAttribute::new(self.0 & Self::ATTR).decode()
    }

    #[inline]
    pub fn set_task_attr(&mut self, attr: TaskAttribute) {
        let ra = RawTaskAttribute::from(attr);
        self.0 = (self.0 & !Self::ATTR) | ra.raw();
    }
}

impl From<ScsiCommandRequestFlags> for RawScsiCmdReqFlags {
    #[inline]
    fn from(f: ScsiCommandRequestFlags) -> Self {
        Self(f.bits())
    }
}
impl TryFrom<RawScsiCmdReqFlags> for ScsiCommandRequestFlags {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(r: RawScsiCmdReqFlags) -> Result<Self> {
        ScsiCommandRequestFlags::from_bits(r.raw()).ok_or_else(|| {
            anyhow::anyhow!("invalid ScsiCommandRequestFlags: {:#010b}", r.raw())
        })
    }
}

/// Wire view for **SCSI Command Response** flags (byte 1 of the PDU).
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawScsiCmdRespFlags(u8);

impl RawScsiCmdRespFlags {
    pub const FINAL: u8 = 0b1000_0000;
    // bidir read residual underflow
    pub const O_BIG: u8 = 0b0000_0100;
    pub const O_SMALL: u8 = 0b0001_0000;
    // residual overflow
    pub const U_BIG: u8 = 0b0000_0010;
    // bidir read residual overflow
    pub const U_SMALL: u8 = 0b0000_1000;

    // residual underflow

    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    #[inline]
    pub fn fin(&self) -> bool {
        self.0 & Self::FINAL != 0
    }

    #[inline]
    pub fn o_small(&self) -> bool {
        self.0 & Self::O_SMALL != 0
    }

    #[inline]
    pub fn u_small(&self) -> bool {
        self.0 & Self::U_SMALL != 0
    }

    #[inline]
    pub fn o_big(&self) -> bool {
        self.0 & Self::O_BIG != 0
    }

    #[inline]
    pub fn u_big(&self) -> bool {
        self.0 & Self::U_BIG != 0
    }

    #[inline]
    pub fn set_fin(&mut self, on: bool) {
        self.set(Self::FINAL, on)
    }

    #[inline]
    pub fn set_o_small(&mut self, on: bool) {
        self.set_pair(Self::O_SMALL, Self::U_SMALL, on)
    }

    #[inline]
    pub fn set_u_small(&mut self, on: bool) {
        self.set_pair(Self::U_SMALL, Self::O_SMALL, on)
    }

    #[inline]
    pub fn set_o_big(&mut self, on: bool) {
        self.set_pair(Self::O_BIG, Self::U_BIG, on)
    }

    #[inline]
    pub fn set_u_big(&mut self, on: bool) {
        self.set_pair(Self::U_BIG, Self::O_BIG, on)
    }

    #[inline]
    fn set(&mut self, bit: u8, on: bool) {
        if on {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    // keep mutual exclusion of U/O pairs
    #[inline]
    fn set_pair(&mut self, set_bit: u8, clear_bit: u8, on: bool) {
        if on {
            self.0 |= set_bit;
            self.0 &= !clear_bit;
        } else {
            self.0 &= !set_bit;
        }
    }

    /// RFC rule: not both U and O in the same pair.
    #[inline]
    pub fn validate(&self) -> Result<()> {
        if (self.o_big() && self.u_big()) || (self.o_small() && self.u_small()) {
            bail!("protocol error: both Underflow and Overflow bits set");
        }
        Ok(())
    }
}

/* Optional interop with bitflags type you already have. */
impl From<ScsiCommandResponseFlags> for RawScsiCmdRespFlags {
    #[inline]
    fn from(f: ScsiCommandResponseFlags) -> Self {
        Self(f.bits())
    }
}
impl TryFrom<RawScsiCmdRespFlags> for ScsiCommandResponseFlags {
    type Error = anyhow::Error;

    #[inline]
    fn try_from(r: RawScsiCmdRespFlags) -> Result<Self> {
        let f = ScsiCommandResponseFlags::from_bits(r.raw()).ok_or_else(|| {
            anyhow::anyhow!("invalid ScsiCommandResponseFlags: {:#010b}", r.raw())
        })?;
        // keep the same validation semantics as before
        if (f.contains(ScsiCommandResponseFlags::U_BIG)
            && f.contains(ScsiCommandResponseFlags::O_BIG))
            || (f.contains(ScsiCommandResponseFlags::U_SMALL)
                && f.contains(ScsiCommandResponseFlags::O_SMALL))
        {
            bail!("protocol error: both Underflow and Overflow bits set");
        }
        Ok(f)
    }
}

/// Wire view for the 1-byte **ResponseCode** field (SCSI Response PDU).
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawResponseCode(u8);

impl RawResponseCode {
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    #[inline]
    pub fn decode(&self) -> Result<ResponseCode, UnknownResponseCode> {
        match self.0 {
            0x00 => Ok(ResponseCode::CommandCompleted),
            0x01 => Ok(ResponseCode::TargetFailure),
            0x80..=0xFF => Ok(ResponseCode::VendorSpecific(self.0)),
            r @ 0x02..=0x7F => Ok(ResponseCode::Reserved(r)),
        }
    }

    #[inline]
    pub fn encode(&mut self, rc: ResponseCode) {
        self.0 = match rc {
            ResponseCode::CommandCompleted => 0x00,
            ResponseCode::TargetFailure => 0x01,
            ResponseCode::VendorSpecific(v) => v,
            ResponseCode::Reserved(v) => v,
        };
    }
}

impl TryFrom<RawResponseCode> for ResponseCode {
    type Error = UnknownResponseCode;

    #[inline]
    fn try_from(r: RawResponseCode) -> Result<Self, Self::Error> {
        r.decode()
    }
}
impl From<ResponseCode> for RawResponseCode {
    #[inline]
    fn from(rc: ResponseCode) -> Self {
        let mut w = RawResponseCode::default();
        w.encode(rc);
        w
    }
}

/// Wire view for the 1-byte **SCSI Status** field (SCSI Response PDU).
#[repr(transparent)]
#[derive(Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct RawScsiStatus(u8);

impl RawScsiStatus {
    #[inline]
    pub const fn raw(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn new_raw(v: u8) -> Self {
        Self(v)
    }

    #[inline]
    pub fn decode(&self) -> Result<ScsiStatus, UnknownScsiStatus> {
        Ok(match self.0 {
            0x00 => ScsiStatus::Good,
            0x02 => ScsiStatus::CheckCondition,
            0x08 => ScsiStatus::Busy,
            0x18 => ScsiStatus::ReservationConflict,
            0x28 => ScsiStatus::TaskSetFull,
            0x30 => ScsiStatus::AcaActive,
            0x40 => ScsiStatus::TaskAborted,
            other => ScsiStatus::Other(other),
        })
    }

    #[inline]
    pub fn encode(&mut self, st: ScsiStatus) {
        self.0 = match st {
            ScsiStatus::Good => 0x00,
            ScsiStatus::CheckCondition => 0x02,
            ScsiStatus::Busy => 0x08,
            ScsiStatus::ReservationConflict => 0x18,
            ScsiStatus::TaskSetFull => 0x28,
            ScsiStatus::AcaActive => 0x30,
            ScsiStatus::TaskAborted => 0x40,
            ScsiStatus::Other(v) => v,
        };
    }
}

impl TryFrom<RawScsiStatus> for ScsiStatus {
    type Error = UnknownScsiStatus;

    #[inline]
    fn try_from(r: RawScsiStatus) -> Result<Self, Self::Error> {
        r.decode()
    }
}
impl From<ScsiStatus> for RawScsiStatus {
    #[inline]
    fn from(s: ScsiStatus) -> Self {
        let mut w = RawScsiStatus::default();
        w.encode(s);
        w
    }
}

// ---------- RawTaskAttribute ----------
impl fmt::Debug for RawTaskAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawTaskAttribute {{ {:?} }}", self.decode())
    }
}

// ---------- RawScsiCmdReqFlags ----------
impl fmt::Debug for RawScsiCmdReqFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawScsiCmdReqFlags {{ ")?;
        if self.fin() {
            write!(f, "FIN|")?;
        }
        if self.read() {
            write!(f, "READ|")?;
        }
        if self.write() {
            write!(f, "WRITE|")?;
        }
        write!(f, "ATTR={:?} }}", self.task_attr())
    }
}

// ---------- RawScsiCmdRespFlags ----------
impl fmt::Debug for RawScsiCmdRespFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let valid = self.validate().is_ok();
        write!(f, "RawScsiCmdRespFlags {{ ")?;
        if self.fin() {
            write!(f, "FIN|")?;
        }
        if self.o_small() {
            write!(f, "O_SMALL|")?;
        }
        if self.u_small() {
            write!(f, "U_SMALL|")?;
        }
        if self.u_small() {
            write!(f, "O_BIG|")?;
        }
        if self.u_small() {
            write!(f, "U_BIG|")?;
        }
        write!(f, "valid{} }}", &valid)
    }
}

impl fmt::Debug for RawResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let decoded = match self.clone().decode() {
            Ok(rc) => format!("{rc:?}"),
            Err(_e) => format!("invalid(0x{:02X})", self.raw()),
        };

        f.debug_struct("RawResponseCode")
            .field("decoded", &decoded)
            .finish()
    }
}

// ---------- RawScsiStatus ----------
impl fmt::Debug for RawScsiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let decoded = match self.decode() {
            Ok(st) => format!("{st:?}"),
            Err(_e) => format!("invalid(0x{:02X})", self.raw()),
        };

        write!(f, "RawScsiStatus {{ {:?} }}", decoded)
    }
}
