// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{any::type_name, fmt, marker::PhantomData};

use anyhow::{Context, Result, anyhow, bail};
use crc32c::crc32c_append;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32,
};

use crate::{
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN, SendingData},
        data::sense_data::SenseData,
        opcode::Opcode,
    },
};

pub trait ZeroCopyType: KnownLayout + Immutable + IntoBytes + ZFromBytes {}

#[inline]
fn pad_len(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

#[inline]
fn crc32c_of_parts(parts: &[&[u8]]) -> u32 {
    let mut acc = 0u32;
    for p in parts {
        if !p.is_empty() {
            acc = crc32c_append(acc, p);
        }
    }
    acc
}

#[inline]
fn crc32c_with_padding(parts: &[&[u8]], pad: usize) -> u32 {
    let mut acc = crc32c_of_parts(parts);
    if pad != 0 {
        let zeros = [0u8; 3];
        acc = crc32c_append(acc, &zeros[..pad]);
    }
    acc
}

#[inline]
fn compute_header_digest(bhs: &[u8], ahs: &[u8]) -> u32 {
    crc32c_with_padding(&[bhs, ahs], pad_len(ahs.len()))
}

#[inline]
fn compute_data_digest(data: &[u8]) -> u32 {
    crc32c_with_padding(&[data], pad_len(data.len()))
}

#[derive(PartialEq)]
pub struct PDUWithData<T> {
    pub header_buf: [u8; HEADER_LEN],
    pub aditional_heder: Vec<u8>,
    pub header_digest: Option<U32<BigEndian>>,
    pub data: Vec<u8>,
    pub data_digest: Option<U32<BigEndian>>,

    _marker: PhantomData<T>,
}

impl<T> Builder for PDUWithData<T>
where
    T: BasicHeaderSegment + SendingData + FromBytes + ZeroCopyType,
{
    type Header = [u8; HEADER_LEN];

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(&mut self, more: Vec<u8>) {
        self.data.extend_from_slice(&more);
        let len = self.data.len() as u32;
        self.header_view_mut()
            .expect("WFT unitialized pdu headers")
            .set_data_length_bytes(len);
    }

    /// Build finnal PDU (BHS + DataSegment)
    fn build(
        &mut self,
        max_recv_data_segment_length: usize,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<(Self::Header, Vec<u8>)> {
        if max_recv_data_segment_length < self.data.len() {
            bail!(
                "MaxRecvDataSegmentLength is less than data len: {}",
                self.data.len()
            );
        }

        let data_len = self.data.len() as u32;

        let opcode = {
            let header = self.header_view_mut().expect("building without header_buf");

            header.set_data_length_bytes(data_len);

            let opcode = header.get_opcode()?.opcode;

            if opcode != Opcode::ScsiDataOut && opcode != Opcode::LogoutReq {
                header.set_final_bit();
            }

            opcode
        };

        let padding_ahs = (4 - (self.aditional_heder.len() % 4)) % 4;
        let padding_chunk = (4 - (self.data.len() % 4)) % 4;
        let mut body = Vec::with_capacity(
            self.aditional_heder.len()
                + padding_ahs
                + (self.header_digest.is_some() as usize) * 4
                + self.data.len()
                + padding_chunk
                + (self.data_digest.is_some() as usize) * 4,
        );

        self.header_digest = if enable_header_digest && opcode != Opcode::LoginReq {
            Some(U32::<BigEndian>::new(compute_header_digest(
                &self.header_buf,
                &self.aditional_heder,
            )))
        } else {
            None
        };

        self.data_digest = if enable_data_digest
            && !self.data.is_empty()
            && opcode != Opcode::LoginReq
        {
            Some(U32::<BigEndian>::new(compute_data_digest(&self.data)))
        } else {
            None
        };

        if !self.aditional_heder.is_empty() {
            body.extend_from_slice(&self.aditional_heder);
            body.extend(std::iter::repeat_n(0u8, padding_ahs));
        }

        if let Some(hd) = self.header_digest {
            body.extend_from_slice(&hd.to_bytes());
        }

        body.extend_from_slice(&self.data[..]);
        body.extend(std::iter::repeat_n(0u8, padding_chunk));

        if let Some(dd) = self.data_digest {
            body.extend_from_slice(&dd.to_bytes());
        }

        Ok((self.header_buf, body))
    }
}

impl<T> PDUWithData<T> {
    pub fn from_header_slice(header_buf: [u8; HEADER_LEN]) -> Self {
        Self {
            header_buf,
            aditional_heder: Vec::new(),
            header_digest: None,
            data: Vec::new(),
            data_digest: None,
            _marker: PhantomData,
        }
    }

    pub fn rebind_pdu<U>(self) -> anyhow::Result<PDUWithData<U>>
    where
        U: BasicHeaderSegment,
    {
        Ok(PDUWithData::<U> {
            header_buf: self.header_buf,
            aditional_heder: self.aditional_heder,
            header_digest: self.header_digest,
            data: self.data,
            data_digest: self.data_digest,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T> PDUWithData<T>
where
    T: BasicHeaderSegment + FromBytes + ZeroCopyType,
{
    /// Header view (`&T`) backed by `self.header_buf`.
    #[inline]
    pub fn header_view(&self) -> Result<&T> {
        T::ref_from_bytes(self.header_buf.as_slice())
            .map_err(|e| anyhow!("{}", e.to_string()))
    }

    /// Mutable header view (`&mut T`) backed by `self.header_buf`.
    #[inline]
    pub fn header_view_mut(&mut self) -> Result<&mut T> {
        T::mut_from_bytes(self.header_buf.as_mut_slice())
            .map_err(|e| anyhow!("{}", e.to_string()))
    }

    /// Parse PDU: BHS(=48) + AHS + pad(AHS) + [HeaderDigest?] + Data +
    /// pad(Data) + [DataDigest?]
    pub fn parse_with_buff(
        &mut self,
        buf: &[u8],
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<()> {
        let tn = type_name::<T>();

        let header = self.header_view().context("parsing without header_buf")?;

        let ahs_len = header.get_ahs_length_bytes();
        let data_len = header.get_data_length_bytes();
        let ahs_pad = (4 - (ahs_len % 4)) % 4;
        let data_pad = (4 - (data_len % 4)) % 4;

        let mut off = 0;

        // --- AHS ---
        self.aditional_heder = if ahs_len > 0 {
            if buf.len() < off + ahs_len {
                bail!(
                    "{tn}: buffer {} too small for AHS end {}",
                    buf.len(),
                    off + ahs_len
                );
            }
            let v = buf[off..off + ahs_len].to_vec();
            off += ahs_len;

            if buf.len() < off + ahs_pad {
                bail!(
                    "{tn}: buffer {} too small for AHS padding end {}",
                    buf.len(),
                    off + ahs_pad
                );
            }
            off += ahs_pad;
            v
        } else {
            Vec::new()
        };

        // --- HeaderDigest? ---
        self.header_digest = if enable_header_digest {
            if buf.len() < off + 4 {
                bail!("{tn}: no room for HeaderDigest");
            }
            let hd = u32::from_be_bytes(
                buf[off..off + 4]
                    .try_into()
                    .context("expected header_digest, but failed to build")?,
            );
            off += 4;
            Some(U32::<BigEndian>::new(hd))
        } else {
            None
        };

        // --- Data ---
        if buf.len() < off + data_len {
            bail!(
                "{tn}: buffer {} too small for Data end {}",
                buf.len(),
                off + data_len
            );
        }
        self.data = buf[off..off + data_len].to_vec();
        off += data_len;

        if buf.len() < off + data_pad {
            bail!(
                "{tn}: buffer {} too small for Data padding end {}",
                buf.len(),
                off + data_pad
            );
        }
        off += data_pad;

        // --- DataDigest? ---
        self.data_digest = if enable_data_digest {
            if buf.len() < off + 4 {
                bail!("{tn}: no room for DataDigest");
            }
            let dd = u32::from_be_bytes(
                buf[off..off + 4]
                    .try_into()
                    .context("expected data_digest, but failed to build")?,
            );
            //off += 4;
            Some(U32::<BigEndian>::new(dd))
        } else {
            None
        };

        if enable_header_digest {
            let want = compute_header_digest(&self.header_buf, &self.aditional_heder);
            if self.header_digest.map(|hd| hd.get()) != Some(want) {
                bail!(
                    "{tn}: HeaderDigest mismatch: got={:?}, want={:#010x}",
                    self.header_digest,
                    want
                );
            }
        }
        if enable_data_digest && !self.data.is_empty() {
            let want = compute_data_digest(&self.data);
            if self.data_digest.map(|dd| dd.get()) != Some(want) {
                bail!(
                    "{tn}: DataDigest mismatch: got={:?}, want={:#010x}",
                    self.data_digest,
                    want
                );
            }
        }

        Ok(())
    }
}

struct HexPreview<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexPreview<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX: usize = 128;
        let slice = if self.0.len() > MAX {
            &self.0[..MAX]
        } else {
            self.0
        };
        let mut first = true;
        write!(f, "\"")?;
        for b in slice {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{b:02x}")?;
            first = false;
        }
        if self.0.len() > MAX {
            write!(f, " ... (+{} bytes)", self.0.len() - MAX)?;
        }
        write!(f, "\"")
    }
}

impl<T> fmt::Debug for PDUWithData<T>
where
    T: BasicHeaderSegment + SendingData + FromBytes + fmt::Debug + ZeroCopyType,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("PDUWithData");
        let header = &self.header_view().expect("failed to get header");

        ds.field("header", header);

        ds.field("data_len", &self.data.len());

        match self.header_digest {
            Some(hd) => ds.field("header_digest", &format_args!("{hd:#010x}")),
            None => ds.field("header_digest", &r"None"),
        };

        match self.data_digest {
            Some(dd) => ds.field("data_digest", &format_args!("{dd:#010x}")),
            None => ds.field("data_digest", &r"None"),
        };

        if header.get_opcode().expect("unable to get opcode").opcode
            == Opcode::ScsiCommandResp
            && !self.data.is_empty()
        {
            match SenseData::parse(&self.data) {
                Ok(sense) => {
                    ds.field("sense", &sense);
                },
                Err(_e) => {
                    ds.field("data_preview", &HexPreview(&self.data));
                },
            }
        } else if !self.data.is_empty() {
            ds.field("data_preview", &HexPreview(&self.data));
        } else {
            ds.field("data", &r"[]");
        }

        ds.finish()
    }
}
