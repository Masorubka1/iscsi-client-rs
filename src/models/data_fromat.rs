use std::{any::type_name, fmt};

use anyhow::{Context, Result, bail};

use crate::{
    cfg::config::Config,
    client::pdu_connection::FromBytes,
    models::{
        common::{BasicHeaderSegment, Builder, SendingData},
        data::sense_data::SenseData,
        opcode::Opcode,
    },
};

#[derive(PartialEq)]
pub struct PDUWithData<T> {
    pub header: T,
    pub aditional_heder: Vec<u8>,
    pub header_digest: Option<u32>,
    pub data: Vec<u8>,
    pub data_digest: Option<u32>,
}

impl<T> Builder for PDUWithData<T>
where T: BasicHeaderSegment + SendingData + FromBytes
{
    type Header = Vec<u8>;

    /// Appends raw bytes to the Data Segment and updates its length field.
    fn append_data(&mut self, more: Vec<u8>) {
        self.data.extend_from_slice(&more);
        let len = self.data.len() as u32;
        self.header.set_data_length_bytes(len);
    }

    /// Build finnal PDU (BHS + DataSegment)
    fn build(&mut self, cfg: &Config) -> Result<(Self::Header, Vec<u8>)> {
        let mrdsl = cfg.login.negotiation.max_recv_data_segment_length as usize;
        if mrdsl == 0 {
            bail!("MaxRecvDataSegmentLength is zero");
        }

        self.header.set_data_length_bytes(self.data.len() as u32);

        let opcode = &self.header.get_opcode().opcode;

        if opcode != &Opcode::ScsiDataOut && opcode != &Opcode::LogoutReq {
            self.header.set_final_bit();
        }

        let bhs = T::to_bhs_bytes(&self.header)?;

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

        if !self.aditional_heder.is_empty() {
            body.extend_from_slice(&self.aditional_heder);
            body.extend(std::iter::repeat_n(0u8, padding_ahs));
        }

        if let Some(hd) = self.header_digest {
            body.extend_from_slice(&hd.to_be_bytes());
        }

        body.extend_from_slice(&self.data[..]);
        body.extend(std::iter::repeat_n(0u8, padding_chunk));

        if let Some(dd) = self.data_digest {
            body.extend_from_slice(&dd.to_be_bytes());
        }

        Ok((bhs.to_vec(), body))
    }
}

impl<T> PDUWithData<T>
where T: BasicHeaderSegment + FromBytes
{
    pub fn from_header(header: T) -> Self {
        Self {
            header,
            aditional_heder: vec![],
            header_digest: None,
            data: vec![],
            data_digest: None,
        }
    }

    /// Parse PDU: BHS(=48) + AHS + pad(AHS) + [HeaderDigest?] + Data +
    /// pad(Data) + [DataDigest?]
    pub fn parse(
        header: T,
        buf: &[u8],
        enable_header_digest: bool,
        enable_data_digest: bool,
    ) -> Result<Self> {
        let tn = type_name::<T>();

        let ahs_len = header.get_ahs_length_bytes();
        let data_len = header.get_data_length_bytes();
        let ahs_pad = (4 - (ahs_len % 4)) % 4;
        let data_pad = (4 - (data_len % 4)) % 4;

        let mut off = 0;

        // --- AHS ---
        let aditional_heder = if ahs_len > 0 {
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
        let header_digest = if enable_header_digest {
            if buf.len() < off + 4 {
                bail!("{tn}: no room for HeaderDigest");
            }
            let hd = u32::from_be_bytes(
                buf[off..off + 4]
                    .try_into()
                    .context("expected header_digest, but failed to build")?,
            );
            off += 4;
            Some(hd)
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
        let data = buf[off..off + data_len].to_vec();
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
        let data_digest = if enable_data_digest {
            if buf.len() < off + 4 {
                bail!("{tn}: no room for DataDigest");
            }
            let dd = u32::from_be_bytes(
                buf[off..off + 4]
                    .try_into()
                    .context("expected data_digest, but failed to build")?,
            );
            //off += 4;
            Some(dd)
        } else {
            None
        };

        Ok(Self {
            header,
            aditional_heder,
            header_digest,
            data,
            data_digest,
        })
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
where T: BasicHeaderSegment + SendingData + FromBytes + fmt::Debug
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("PDUWithData");
        ds.field("header", &self.header);

        ds.field("data_len", &self.data.len());

        match self.header_digest {
            Some(hd) => ds.field("header_digest", &format_args!("{hd:#010x}")),
            None => ds.field("header_digest", &r"None"),
        };

        match self.data_digest {
            Some(dd) => ds.field("data_digest", &format_args!("{dd:#010x}")),
            None => ds.field("data_digest", &r"None"),
        };

        if self.header.get_opcode().opcode == Opcode::ScsiCommandResp
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
