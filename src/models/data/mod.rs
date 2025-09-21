//! This module defines the structures for iSCSI Data-In and Data-Out PDUs.
//! It includes submodules for common definitions, requests, responses, and sense data.

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::models::data::asc_ascq_gen::ASC_ASCQ;

mod asc_ascq_gen;
/// Defines common structures and flags for iSCSI Data-In and Data-Out PDUs.
pub mod common;
/// Defines the structures for iSCSI SCSI Data-Out PDUs.
pub mod request;
/// Defines the structures for iSCSI SCSI Data-In PDUs.
pub mod response;
/// Defines the structures for SCSI Sense Data.
pub mod sense_data;

/// Represents an entry in the ASC/ASCQ table.
pub struct Entry {
    code: usize,
    desc: &'static str,
}

impl Entry {
    /// Looks up the description for a given ASC/ASCQ code.
    #[inline]
    pub fn lookup(asc: u8, ascq: u8) -> Option<&'static str> {
        let k = ((asc as u16) << 8) | (ascq as u16);
        ASC_ASCQ_MAP.get(&k).copied()
    }
}

static ASC_ASCQ_MAP: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| {
    let mut m: HashMap<u16, &'static str> = HashMap::with_capacity(ASC_ASCQ.len());
    for e in ASC_ASCQ {
        let code = e.code as u16;
        match m.get(&code) {
            Some(cur) => {
                if e.desc.len() < cur.len() {
                    m.insert(code, e.desc);
                }
            },
            None => {
                m.insert(code, e.desc);
            },
        }
    }
    m
});
