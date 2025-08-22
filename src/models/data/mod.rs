use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::models::data::asc_ascq_gen::ASC_ASCQ;

mod asc_ascq_gen;
pub mod common;
pub mod request;
pub mod response;
pub mod sense_data;

pub struct Entry {
    code: usize,
    desc: &'static str,
}

impl Entry {
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
