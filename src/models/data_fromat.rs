// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::{any::type_name, fmt, marker::PhantomData, ops::Deref};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Bytes, BytesMut};
use crc32c::crc32c_append;
use zerocopy::{
    BigEndian, FromBytes as ZFromBytes, Immutable, IntoBytes, KnownLayout, U32,
};

use crate::{
    cfg::{config::Config, enums::Digest},
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

pub type PduRequest<T> = PDUWithData<T, BytesMut>;
pub type PduResponse<T> = PDUWithData<T, Bytes>;

#[derive(PartialEq)]
pub struct PDUWithData<T, Body = Bytes> {
    pub header_buf: [u8; HEADER_LEN],
    payload: Body,

    enable_header_digest: bool,
    enable_data_digest: bool,
    pub header_digest: Option<U32<BigEndian>>,
    pub data_digest: Option<U32<BigEndian>>,

    _marker: PhantomData<T>,
}

impl<T> Builder for PDUWithData<T, BytesMut>
where
    T: BasicHeaderSegment + SendingData + FromBytes + ZeroCopyType,
{
    type Header = [u8; HEADER_LEN];

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(&mut self, more: &[u8]) {
        self.payload.extend_from_slice(more);
        let len = self.payload.len() as u32;
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
        if max_recv_data_segment_length < self.payload.len() {
            bail!(
                "MaxRecvDataSegmentLength is less than data len: {}",
                self.payload.len()
            );
        }

        let (opcode, size_hd, size_dd, ahs_len, data_len) = {
            let hd_en = self.enable_header_digest;
            let dd_en = self.enable_data_digest;
            let header = self.header_view_mut().expect("building without header_buf");

            let opcode = header.get_opcode()?.opcode;

            if opcode != Opcode::ScsiDataOut && opcode != Opcode::LogoutReq {
                header.set_final_bit();
            }

            (
                opcode,
                header.get_header_diggest(hd_en),
                header.get_data_diggest(dd_en),
                header.get_ahs_length_bytes(),
                header.get_data_length_bytes(),
            )
        };

        let padding_ahs = (4 - (ahs_len % 4)) % 4;
        let padding_chunk = (4 - (data_len % 4)) % 4;
        let mut body = Vec::with_capacity(
            ahs_len + padding_ahs + size_hd + data_len + padding_chunk + size_dd,
        );

        self.header_digest = if enable_header_digest && opcode != Opcode::LoginReq {
            Some(U32::<BigEndian>::new(compute_header_digest(
                &self.header_buf,
                self.additional_header()?,
            )))
        } else {
            None
        };

        self.data_digest = if enable_data_digest
            && !self.payload.is_empty()
            && opcode != Opcode::LoginReq
        {
            Some(U32::<BigEndian>::new(compute_data_digest(self.data()?)))
        } else {
            None
        };

        body.extend_from_slice(self.additional_header()?);
        body.extend(std::iter::repeat_n(0u8, padding_ahs));

        if let Some(hd) = self.header_digest {
            body.extend_from_slice(&hd.to_bytes());
        }

        body.extend_from_slice(self.data()?);
        body.extend(std::iter::repeat_n(0u8, padding_chunk));

        if let Some(dd) = self.data_digest {
            body.extend_from_slice(&dd.to_bytes());
        }

        Ok((self.header_buf, body))
    }
}

impl<T> PDUWithData<T, Bytes> {
    pub fn from_header_slice(header_buf: [u8; HEADER_LEN], cfg: &Config) -> Self {
        Self {
            header_buf,
            payload: Bytes::new(),
            enable_header_digest: cfg.login.negotiation.header_digest == Digest::CRC32C,
            header_digest: None,
            enable_data_digest: cfg.login.negotiation.data_digest == Digest::CRC32C,
            data_digest: None,
            _marker: PhantomData,
        }
    }
}

impl<T> PDUWithData<T, BytesMut> {
    pub fn new_request(header_buf: [u8; HEADER_LEN], cfg: &Config) -> Self {
        Self {
            header_buf,
            payload: BytesMut::new(),
            enable_header_digest: cfg.login.negotiation.header_digest == Digest::CRC32C,
            header_digest: None,
            enable_data_digest: cfg.login.negotiation.data_digest == Digest::CRC32C,
            data_digest: None,
            _marker: PhantomData,
        }
    }

    pub fn parse_with_buff_mut(
        &mut self,
        mut buf: BytesMut,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<()>
    where
        T: BasicHeaderSegment + FromBytes + ZeroCopyType,
    {
        let tn = type_name::<T>();
        let h = self.header_view().context("parsing without header_buf")?;

        let ahs_len = h.get_ahs_length_bytes();
        let hd_len = h.get_header_diggest(enable_header_digest);
        let data_len = h.get_data_length_bytes();
        let dd_len = h.get_data_diggest(enable_data_digest);

        let ahs_pad = (4 - (ahs_len % 4)) % 4;
        let data_pad = (4 - (data_len % 4)) % 4;

        let need = ahs_len + ahs_pad + hd_len + data_len + data_pad + dd_len;
        if buf.len() < need {
            bail!("{tn}: buffer too small: have {}, need {}", buf.len(), need);
        }

        if buf.len() > need {
            buf.truncate(need);
        }

        self.payload = buf;

        let payload: &[u8] = &self.payload;

        let mut off = ahs_len + ahs_pad;

        self.header_digest = if enable_header_digest {
            let hd = u32::from_be_bytes(payload[off..off + hd_len].try_into()?);
            off += hd_len;
            Some(U32::<BigEndian>::new(hd))
        } else {
            None
        };

        off += data_len + data_pad;

        self.data_digest = if enable_data_digest {
            let dd = u32::from_be_bytes(payload[off..off + dd_len].try_into()?);
            Some(U32::<BigEndian>::new(dd))
        } else {
            None
        };

        if enable_header_digest {
            let want = compute_header_digest(&self.header_buf, self.additional_header()?);
            if self.header_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: HeaderDigest mismatch");
            }
        }
        if enable_data_digest {
            let data = self.data()?;
            let want = compute_data_digest(data);
            if !data.is_empty() && self.data_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: DataDigest mismatch");
            }
        }

        Ok(())
    }

    pub fn parse_with_buff_ref(
        &mut self,
        buf: &BytesMut,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<()>
    where
        T: BasicHeaderSegment + FromBytes + ZeroCopyType,
    {
        self.parse_with_buff_mut(buf.clone(), enable_header_digest, enable_data_digest)
    }
}

impl<T, B> PDUWithData<T, B>
where
    T: BasicHeaderSegment,
    B: Deref<Target = [u8]>,
{
    #[inline]
    pub fn header_view(&self) -> Result<&T>
    where
        T: FromBytes + ZeroCopyType,
    {
        T::ref_from_bytes(self.header_buf.as_slice())
            .map_err(|e| anyhow!("{}", e.to_string()))
    }

    #[inline]
    pub fn header_view_mut(&mut self) -> Result<&mut T>
    where
        T: FromBytes + ZeroCopyType,
    {
        T::mut_from_bytes(self.header_buf.as_mut_slice())
            .map_err(|e| anyhow!("{}", e.to_string()))
    }

    pub fn additional_header(&self) -> Result<&[u8]>
    where
        T: FromBytes + ZeroCopyType,
    {
        let ahs_size = self.header_view()?.get_ahs_length_bytes();
        Ok(&self.payload[0..ahs_size])
    }

    pub fn data(&self) -> Result<&[u8]>
    where
        T: FromBytes + ZeroCopyType,
    {
        let header = self.header_view()?;
        let ahs_size = header.get_ahs_length_bytes();
        let hd = header.get_header_diggest(self.enable_header_digest);
        let data_sz = header.get_data_length_bytes();
        let total = ahs_size + ((4 - (ahs_size % 4)) % 4) + hd;
        Ok(&self.payload[total..total + data_sz])
    }

    pub fn rebind_pdu<U>(self) -> anyhow::Result<PDUWithData<U, B>>
    where
        U: BasicHeaderSegment,
    {
        Ok(PDUWithData::<U, B> {
            header_buf: self.header_buf,
            payload: self.payload,
            enable_header_digest: self.enable_header_digest,
            header_digest: self.header_digest,
            enable_data_digest: self.enable_data_digest,
            data_digest: self.data_digest,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T> PDUWithData<T, Bytes>
where
    T: BasicHeaderSegment + FromBytes + ZeroCopyType,
{
    /// Parse PDU: BHS(=48) + AHS + pad(AHS) + [HeaderDigest?] + Data +
    /// pad(Data) + [DataDigest?]
    pub fn parse_with_buff(
        &mut self,
        buf: &Bytes,
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<()> {
        let tn = type_name::<T>();
        let h = self.header_view().context("parsing without header_buf")?;

        let ahs_len = h.get_ahs_length_bytes();
        let hd_len = h.get_header_diggest(enable_header_digest);
        let data_len = h.get_data_length_bytes();
        let dd_len = h.get_data_diggest(enable_data_digest);

        let ahs_pad = pad_len(ahs_len);
        let data_pad = pad_len(data_len);

        let need = ahs_len + ahs_pad + hd_len + data_len + data_pad + dd_len;
        if buf.len() < need {
            bail!("{tn}: buffer too small: have {}, need {}", buf.len(), need);
        }

        self.payload = buf.clone();

        let mut off = 0usize;
        off += ahs_len + ahs_pad;

        self.header_digest = if enable_header_digest {
            let hd = u32::from_be_bytes(buf[off..off + hd_len].try_into()?);
            off += hd_len;
            Some(U32::<BigEndian>::new(hd))
        } else {
            None
        };

        off += data_len + data_pad;

        self.data_digest = if enable_data_digest {
            let dd = u32::from_be_bytes(buf[off..off + dd_len].try_into()?);
            Some(U32::<BigEndian>::new(dd))
        } else {
            None
        };

        if enable_header_digest {
            let want = compute_header_digest(&self.header_buf, self.additional_header()?);
            if self.header_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: HeaderDigest mismatch");
            }
        }
        if enable_data_digest {
            let data = self.data()?;
            let want = compute_data_digest(data);
            if !data.is_empty() && self.data_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: DataDigest mismatch");
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

impl<T, B> fmt::Debug for PDUWithData<T, B>
where
    T: BasicHeaderSegment + SendingData + FromBytes + fmt::Debug + ZeroCopyType,
    B: Deref<Target = [u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("PDUWithData");
        let header = &self.header_view().expect("failed to get header");

        ds.field("header", header);

        let data = &self.data().expect("invlid pdu");

        ds.field("data_len", &data.len());

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
            && !data.is_empty()
        {
            match SenseData::parse(data) {
                Ok(sense) => {
                    ds.field("sense", &sense);
                },
                Err(_e) => {
                    ds.field("data_preview", &HexPreview(data));
                },
            }
        } else if !data.is_empty() {
            ds.field("data_preview", &HexPreview(data));
        } else {
            ds.field("data", &r"[]");
        }

        ds.finish()
    }
}
