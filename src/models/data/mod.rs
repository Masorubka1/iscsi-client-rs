use crate::models::data::asc_ascq_gen::ASC_ASCQ;

mod asc_ascq_gen;
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
        let code = ((asc as usize) << 8) | (ascq as usize);

        let mut best: Option<&'static str> = None;
        let mut best_len = usize::MAX;

        for e in ASC_ASCQ {
            if e.code == code {
                let len = e.desc.len();
                if len < best_len {
                    best_len = len;
                    best = Some(e.desc);
                }
            } else if e.code > code && best.is_some() {
                break;
            }
        }
        best
    }
}
