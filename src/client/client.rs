use std::{
    fmt::{self, Debug},
    sync::Arc,
};

use anyhow::{Result, anyhow, bail};
use dashmap::{DashMap, Entry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, oneshot},
};
use tracing::{debug, warn};

use crate::{
    cfg::config::Config,
    client::{
        common::{RawPdu, io_with_timeout},
        pdu_connection::{FromBytes, ToBytes},
    },
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::PDUWithData,
        parse::Pdu,
    },
};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
#[derive(Debug)]
pub struct ClientConnection {
    pub reader: Mutex<OwnedReadHalf>,
    pub writer: Mutex<OwnedWriteHalf>,
    cfg: Config,
    sending: DashMap<u32, oneshot::Sender<RawPdu>>,
    reciver: DashMap<u32, oneshot::Receiver<RawPdu>>,
}

impl ClientConnection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config) -> Result<Arc<Self>> {
        let stream = TcpStream::connect(&cfg.login.security.target_address).await?;
        stream.set_linger(None)?;

        let (r, w) = stream.into_split();

        let conn = Self::from_split_no_reader(r, w, cfg);

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = reader.read_loop().await {
                warn!("read loop exited: {e}");
            }
        });

        Ok(conn)
    }

    pub fn from_split_no_reader(
        r: OwnedReadHalf,
        w: OwnedWriteHalf,
        cfg: Config,
    ) -> Arc<Self> {
        Arc::new(Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            cfg,
            sending: DashMap::new(),
            reciver: DashMap::new(),
        })
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write(
        &self,
        mut req: impl ToBytes<Header = Vec<u8>> + fmt::Debug,
    ) -> Result<()> {
        let mut w = self.writer.lock().await;
        for (mut out_header, out_data) in req.to_bytes(&self.cfg)? {
            debug!("SEND {req:?}");
            debug!(
                "Size_header: {} Size_data: {}",
                out_header.len(),
                out_data.len()
            );
            if out_data.is_empty() || self.cfg.extra_data.r2t.immediate_data == "Yes" {
                out_header.extend_from_slice(&out_data);
                io_with_timeout("write header and data", w.write_all(&out_header))
                    .await?;
            } else {
                io_with_timeout("write header", w.write_all(&out_header)).await?;
                io_with_timeout("write data", w.write_all(&out_data)).await?;
            }
        }
        Ok(())
    }

    pub async fn send_segment(
        &self,
        req: impl ToBytes<Header = Vec<u8>> + fmt::Debug,
    ) -> Result<()> {
        self.write(req).await
    }

    pub async fn send_request(
        &self,
        initiator_task_tag: u32,
        req: impl ToBytes<Header = Vec<u8>> + Debug,
    ) -> Result<()> {
        if self.sending.contains_key(&initiator_task_tag) {
            bail!(
                "Failed to send request, cause already sended other with same itt={}",
                initiator_task_tag
            )
        }

        let (tx, rx) = oneshot::channel();
        self.sending.insert(initiator_task_tag, tx);
        self.reciver.insert(initiator_task_tag, rx);
        if let Err(e) = self.write(req).await {
            let _ = self.sending.remove(&initiator_task_tag);
            let _ = self.reciver.remove(&initiator_task_tag);
            return Err(e);
        }

        Ok(())
    }

    pub async fn read_response<T: BasicHeaderSegment + FromBytes + Debug>(
        &self,
        initiator_task_tag: u32,
    ) -> Result<PDUWithData<T>> {
        let rx = match self.reciver.remove(&initiator_task_tag) {
            None => bail!("no pending request with itt={initiator_task_tag}"),
            Some((_, rx)) => rx,
        };

        let RawPdu {
            last_hdr_with_updated_data,
            data,
        } = rx.await.map_err(|_| {
            anyhow!("Failed to read response: connection closed before answer")
        })?;

        let pdu_header = T::from_bhs_bytes(&last_hdr_with_updated_data)?;
        let tmp = PDUWithData::<T>::parse(pdu_header, data.as_slice(), false, false);
        debug!("READ {tmp:?}");
        tmp
    }

    async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut hdr = [0u8; HEADER_LEN];
        let pending: DashMap<u32, RawPdu> = DashMap::new();

        loop {
            {
                let mut r = self.reader.lock().await;
                io_with_timeout("read header", r.read_exact(&mut hdr)).await?;
            }

            let pdu_hdr = Pdu::from_bhs_bytes(&hdr)?;
            let itt = pdu_hdr.get_initiator_task_tag();
            let cont_bit = pdu_hdr.get_continue_bit();
            let fin_bit = pdu_hdr.get_final_bit();
            let total = pdu_hdr.total_length_bytes();
            let ahs = pdu_hdr.get_ahs_length_bytes();

            let mut payload = Vec::with_capacity(total);
            payload.extend_from_slice(&hdr);

            if total > HEADER_LEN {
                payload.resize(total, 0);
                let mut r = self.reader.lock().await;
                io_with_timeout("read payload", r.read_exact(&mut payload[HEADER_LEN..]))
                    .await?;
            }

            // TODO: inplace support checking header_digest && data_digest
            match (cont_bit, fin_bit) {
                (true, false) => match pending.entry(itt) {
                    Entry::Occupied(mut e) => {
                        let e = e.get_mut();
                        e.data.extend_from_slice(&payload[HEADER_LEN..]);
                        e.last_hdr_with_updated_data = hdr;
                    },
                    Entry::Vacant(v) => {
                        v.insert(RawPdu {
                            last_hdr_with_updated_data: hdr,
                            data: payload[ahs + HEADER_LEN..].to_vec(),
                        });
                    },
                },

                (_, true) => {
                    let data_combined = if let Some((_, mut pend)) = pending.remove(&itt)
                    {
                        pend.data.extend_from_slice(&payload[ahs + HEADER_LEN..]);
                        pend.data
                    } else {
                        payload[HEADER_LEN..].to_vec()
                    };

                    let mut fixed_hdr = hdr;
                    let len_be = (data_combined.len() as u32).to_be_bytes();
                    fixed_hdr[5..8].copy_from_slice(&len_be[1..4]);

                    if let Some((_, tx)) = self.sending.remove(&itt) {
                        let _ = tx.send(RawPdu {
                            last_hdr_with_updated_data: fixed_hdr,
                            data: data_combined,
                        });
                    }
                },

                (false, false) => {
                    if let Some((_, tx)) = self.sending.remove(&itt) {
                        let _ = tx.send(RawPdu {
                            last_hdr_with_updated_data: hdr,
                            data: payload,
                        });
                    }
                },
            }
        }
    }
}
