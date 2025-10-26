//! This module defines the generic PDU container and related traits.
//! It provides a generic structure for iSCSI PDUs, handling data, headers, and
//! digests.

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
    cfg::{
        config::Config,
        enums::{Digest, YesNo},
    },
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, Builder, HEADER_LEN, SendingData},
        data::sense_data::SenseData,
        opcode::Opcode,
    },
};

/// A marker trait for types that can be used with zerocopy and are suitable for
/// iSCSI PDUs.
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

/// A type alias for a PDU request, which uses a mutable `BytesMut` body.
pub type PduRequest<T> = PDUWithData<T, BytesMut>;
/// A type alias for a PDU response, which uses an immutable `Bytes` body.
pub type PduResponse<T> = PDUWithData<T, Bytes>;

/// A generic container for an iSCSI Protocol Data Unit (PDU).
///
/// This struct holds the PDU's header, payload (data), and digest information.
/// It is generic over the body type, allowing it to be used for both requests
/// (with a mutable body) and responses (with an immutable body).
#[derive(PartialEq)]
pub struct PDUWithData<T, Body = Bytes> {
    /// The raw buffer for the Basic Header Segment (BHS).
    pub header_buf: [u8; HEADER_LEN],
    payload: Body,

    enable_header_digest: bool,
    enable_data_digest: bool,
    allocated_header_diggest: bool,
    /// The optional header digest value.
    pub header_digest: Option<U32<BigEndian>>,
    /// The optional data digest value.
    pub data_digest: Option<U32<BigEndian>>,

    pub is_x86: bool,

    _marker: PhantomData<T>,
}

impl<T> Builder for PDUWithData<T, BytesMut>
where T: BasicHeaderSegment + SendingData + FromBytes + ZeroCopyType
{
    type Body = Bytes;
    type Header = [u8; HEADER_LEN];

    /// On the first call, if HeaderDigest is enabled, reserve exactly one
    /// 4-byte slot for it right before DATA; then append DATA and update
    /// DataSegmentLength.
    fn append_data(&mut self, more: &[u8]) {
        let hd_len = self
            .header_view()
            .expect("uninitialized header")
            .get_header_diggest(self.enable_header_digest);
        if !self.allocated_header_diggest && hd_len != 0 {
            self.payload.extend_from_slice(&[0u8; 4][..hd_len]);
        }
        self.allocated_header_diggest = true;

        if !more.is_empty() {
            self.payload.extend_from_slice(more);
            // increment DataSegmentLength ONLY by DATA bytes
            let old = self
                .header_view()
                .expect("header_view failed")
                .get_data_length_bytes();
            let new_len = old.saturating_add(more.len()) as u32;
            self.header_view_mut()
                .expect("header_view_mut failed")
                .set_data_length_bytes(new_len);
        }
    }

    /// Finalize and return the already-laid-out body as Bytes.
    /// Ensures HeaderDigest slot exists (even for zero DATA), appends pad(DATA)
    /// and DataDigest.
    fn build(
        &mut self,
        max_recv_data_segment_length: usize,
    ) -> Result<(Self::Header, Self::Body)> {
        let (opcode, ahs_len, data_len, hd_len, dd_len) = {
            let enable_hd = self.enable_header_digest;
            let enable_dd = self.enable_data_digest;

            let h = self.header_view_mut().expect("building without header_buf");
            let opcode = h.get_opcode()?.opcode;
            h.set_final_bit();
            let ahs_len = h.get_ahs_length_bytes();
            let data_len = h.get_data_length_bytes();
            let hd_len = h.get_header_diggest(enable_hd); // 0 or 4
            let dd_len = h.get_data_diggest(enable_dd); // 0 or 4
            (opcode, ahs_len, data_len, hd_len, dd_len)
        };

        if data_len > max_recv_data_segment_length {
            bail!(
                "MaxRecvDataSegmentLength({max_recv_data_segment_length}) < \
                 data_len({data_len})"
            );
        }

        // compute pads
        let ahs_pad = pad_len(ahs_len);
        let data_pad = pad_len(data_len);
        self.append_data(&[]); // Allocate place for crc32 header
        self.payload.extend_from_slice(&[0u8; 4][..data_pad]);

        if hd_len != 0 && opcode != Opcode::LoginReq {
            let hd = compute_header_digest(&self.header_buf, self.additional_header()?);
            self.header_digest = Some(U32::<BigEndian>::new(hd));
            let expected_slice = [hd.to_le_bytes(), hd.to_be_bytes()];
            self.payload
                .get_mut(0..hd_len)
                .context("failed to get slice for crc in payload")?
                .clone_from_slice(&expected_slice[self.is_x86 as usize]);
        }

        // current payload should be: [AHS][padAHS][HD?][DATA]
        // we now append [padDATA][DD?] (exactly once)
        if dd_len != 0 && opcode != Opcode::LoginReq {
            let dd = compute_data_digest(self.data()?);
            self.data_digest = Some(U32::<BigEndian>::new(dd));
            let expected_slice = [dd.to_le_bytes(), dd.to_be_bytes()];
            self.payload
                .extend_from_slice(&expected_slice[self.is_x86 as usize]);
        }

        let expected = ahs_len + ahs_pad + hd_len + data_len + data_pad + dd_len;
        let actual = self.payload.len();
        if actual != expected {
            bail!(
                "payload size mismatch: actual={}, expected={} (ahs={} padAHS={} hd={} \
                 data={} padDATA={} dd={})",
                actual,
                expected,
                ahs_len,
                ahs_pad,
                hd_len,
                data_len,
                data_pad,
                dd_len
            );
        }

        let body = self.payload.clone();
        Ok((self.header_buf, body.freeze()))
    }
}

impl<T> PDUWithData<T, Bytes> {
    /// Creates a new `PDUWithData` instance from a header slice and
    /// configuration.
    pub fn from_header_slice(header_buf: [u8; HEADER_LEN], cfg: &Config) -> Self {
        Self {
            header_buf,
            payload: Bytes::new(),
            enable_header_digest: cfg.login.integrity.header_digest == Digest::CRC32C,
            header_digest: None,
            allocated_header_diggest: false,
            enable_data_digest: cfg.login.integrity.data_digest == Digest::CRC32C,
            data_digest: None,
            is_x86: cfg.login.identity.is_x86 == YesNo::Yes,
            _marker: PhantomData,
        }
    }
}

impl<T> PDUWithData<T, BytesMut> {
    /// Creates a new `PDUWithData` request instance with a mutable body.
    pub fn new_request(header_buf: [u8; HEADER_LEN], cfg: &Config) -> Self {
        Self {
            header_buf,
            payload: BytesMut::new(),
            enable_header_digest: cfg.login.integrity.header_digest == Digest::CRC32C,
            header_digest: None,
            allocated_header_diggest: false,
            enable_data_digest: cfg.login.integrity.data_digest == Digest::CRC32C,
            data_digest: None,
            is_x86: cfg.login.identity.is_x86 == YesNo::Yes,
            _marker: PhantomData,
        }
    }

    /// Parses the PDU payload from a mutable buffer, verifying digests.
    pub fn parse_with_buff_mut(&mut self, mut buf: BytesMut) -> Result<()>
    where T: BasicHeaderSegment + FromBytes + ZeroCopyType {
        let tn = type_name::<T>();
        let h = self.header_view().context("parsing without header_buf")?;

        let ahs_len = h.get_ahs_length_bytes();
        let hd_len = h.get_header_diggest(self.enable_header_digest);
        let data_len = h.get_data_length_bytes();
        let dd_len = h.get_data_diggest(self.enable_data_digest);

        let ahs_pad = pad_len(ahs_len);
        let data_pad = pad_len(data_len);

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

        self.header_digest = if self.enable_header_digest {
            let expected_slice = payload[off..off + hd_len].try_into()?;
            let hd = [
                u32::from_le_bytes(expected_slice),
                u32::from_be_bytes(expected_slice),
            ];
            off += hd_len;
            Some(U32::<BigEndian>::new(hd[self.is_x86 as usize]))
        } else {
            None
        };

        off += data_len + data_pad;

        self.data_digest = if self.enable_data_digest {
            let expected_slice = payload[off..off + dd_len].try_into()?;
            let dd = [
                u32::from_le_bytes(expected_slice),
                u32::from_be_bytes(expected_slice),
            ];
            Some(U32::<BigEndian>::new(dd[self.is_x86 as usize]))
        } else {
            None
        };

        if self.enable_header_digest {
            let want = compute_header_digest(&self.header_buf, self.additional_header()?);
            if self.header_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: HeaderDigest mismatch");
            }
        }
        if self.enable_data_digest {
            let data = self.data()?;
            let want = compute_data_digest(data);
            if !data.is_empty() && self.data_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: DataDigest mismatch");
            }
        }

        Ok(())
    }

    /// Parses the PDU payload from a reference to a mutable buffer.
    pub fn parse_with_buff_ref(&mut self, buf: &BytesMut) -> Result<()>
    where T: BasicHeaderSegment + FromBytes + ZeroCopyType {
        self.parse_with_buff_mut(buf.clone())
    }
}

impl<T, B> PDUWithData<T, B>
where
    T: BasicHeaderSegment,
    B: Deref<Target = [u8]>,
{
    /// Returns an immutable view of the PDU's header.
    #[inline]
    pub fn header_view(&self) -> Result<&T>
    where T: FromBytes + ZeroCopyType {
        T::ref_from_bytes(self.header_buf.as_slice()).map_err(|e| anyhow!("{}", e))
    }

    /// Returns a mutable view of the PDU's header.
    #[inline]
    pub fn header_view_mut(&mut self) -> Result<&mut T>
    where T: FromBytes + ZeroCopyType {
        T::mut_from_bytes(self.header_buf.as_mut_slice()).map_err(|e| anyhow!("{}", e))
    }

    /// Returns a slice of the Additional Header Segment (AHS).
    pub fn additional_header(&self) -> Result<&[u8]>
    where T: FromBytes + ZeroCopyType {
        let ahs_size = self.header_view()?.get_ahs_length_bytes();
        Ok(&self.payload[0..ahs_size])
    }

    /// Returns a slice of the PDU's data segment.
    pub fn data(&self) -> Result<&[u8]>
    where T: FromBytes + ZeroCopyType {
        let header = self.header_view()?;
        let ahs_len = header.get_ahs_length_bytes();
        let hd = header.get_header_diggest(self.enable_header_digest);
        let data_len = header.get_data_length_bytes();
        let total = ahs_len + pad_len(ahs_len) + hd;
        self.payload
            .get(total..total + data_len)
            .context("failed to get slice payload")
    }

    /// Rebinds the PDU to a different header type.
    pub fn rebind_pdu<U>(self) -> anyhow::Result<PDUWithData<U, B>>
    where U: BasicHeaderSegment {
        Ok(PDUWithData::<U, B> {
            header_buf: self.header_buf,
            payload: self.payload,
            enable_header_digest: self.enable_header_digest,
            header_digest: self.header_digest,
            allocated_header_diggest: self.allocated_header_diggest,
            enable_data_digest: self.enable_data_digest,
            data_digest: self.data_digest,
            is_x86: self.is_x86,
            _marker: PhantomData,
        })
    }
}

impl<T> PDUWithData<T, Bytes>
where T: BasicHeaderSegment + FromBytes + ZeroCopyType
{
    /// Parses the PDU payload from an immutable buffer, verifying digests.
    pub fn parse_with_buff(&mut self, buf: &Bytes) -> Result<()> {
        let tn = type_name::<T>();

        let h = self.header_view().context("parsing without header_buf")?;

        let ahs_len = h.get_ahs_length_bytes();
        let hd_len = h.get_header_diggest(self.enable_header_digest);
        let data_len = h.get_data_length_bytes();
        let dd_len = h.get_data_diggest(self.enable_data_digest);

        let ahs_pad = pad_len(ahs_len);
        let data_pad = pad_len(data_len);

        let need = ahs_len + ahs_pad + hd_len + data_len + data_pad + dd_len;
        if buf.len() < need {
            bail!("{tn}: buffer too small: have {}, need {}", buf.len(), need);
        }

        self.payload = buf.clone();

        let mut off = 0usize;
        off += ahs_len + ahs_pad;

        self.header_digest = if hd_len != 0 {
            let hd = u32::from_le_bytes(buf[off..off + hd_len].try_into()?);
            off += hd_len;
            Some(U32::<BigEndian>::new(hd))
        } else {
            None
        };

        off += data_len + data_pad;

        self.data_digest = if dd_len != 0 {
            let dd = u32::from_le_bytes(buf[off..off + dd_len].try_into()?);
            Some(U32::<BigEndian>::new(dd))
        } else {
            None
        };

        if hd_len != 0 {
            let want = compute_header_digest(&self.header_buf, self.additional_header()?);
            if self.header_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: HeaderDigest mismatch");
            }
        }
        if dd_len != 0 {
            let data = self.data()?;
            let want = compute_data_digest(data);
            if !data.is_empty() && self.data_digest.map(|x| x.get()) != Some(want) {
                bail!("{tn}: DataDigest mismatch");
            }
        }
        Ok(())
    }
}

/// A helper struct for providing a debug representation of a byte slice in
/// hexadecimal format. A helper struct for providing a debug representation of
/// a byte slice in hexadecimal format.
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
