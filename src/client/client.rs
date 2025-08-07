use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use dashmap::{DashMap, Entry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, oneshot},
    time::timeout,
};
use tracing::{info, warn};

use crate::{
    cfg::config::Config,
    client::pdu_connection::{FromBytes, ToBytes},
    models::{
        common::{BasicHeaderSegment, HEADER_LEN, SendingData},
        data_fromat::PDUWithData,
        parse::Pdu,
    },
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

async fn io_with_timeout<F, T>(label: &'static str, fut: F) -> Result<T>
where F: Future<Output = std::io::Result<T>> {
    match timeout(IO_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(anyhow!("{label} timeout")),
    }
}

struct Pending {
    first_hdr: [u8; HEADER_LEN],
    data: Vec<u8>,
}

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
pub struct Connection {
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
    cfg: Config,
    sending: DashMap<u32, oneshot::Sender<Pending>>,
    reciver: DashMap<u32, oneshot::Receiver<Pending>>,
}

impl Connection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config) -> Result<Arc<Connection>> {
        let stream = TcpStream::connect(&cfg.login.security.target_address).await?;
        stream.set_linger(None)?;

        // IDK why i need splited r/w socket
        let (r, w) = stream.into_split();

        let conn = Arc::new(Connection {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
            cfg,
            sending: DashMap::new(),
            reciver: DashMap::new(),
        });

        let reader = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = reader.read_loop().await {
                warn!("read loop exited: {e}");
            }
        });

        Ok(conn)
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write(&self, mut req: impl ToBytes<Header = Vec<u8>>) -> Result<()> {
        let mut w = self.writer.lock().await;
        for (out_header, out_data) in req.to_bytes(&self.cfg)? {
            info!(
                "Size_header: {} Size_data: {}",
                out_header.len(),
                out_data.len()
            );
            io_with_timeout("write header", w.write_all(&out_header)).await?;
            if !out_data.is_empty() {
                io_with_timeout("write data", w.write_all(&out_data)).await?;
            }
        }
        Ok(())
    }

    pub async fn send_request(
        &self,
        initiator_task_tag: u32,
        req: impl ToBytes<Header = Vec<u8>>,
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

    pub async fn read_response<T: BasicHeaderSegment + FromBytes>(
        &self,
        initiator_task_tag: u32,
    ) -> Result<PDUWithData<T>> {
        let rx = match self.reciver.remove(&initiator_task_tag) {
            None => bail!("no pending request with itt={initiator_task_tag}"),
            Some((_, rx)) => rx,
        };

        let Pending { first_hdr, data } = rx.await.map_err(|_| {
            anyhow!("Failed to read response: connection closed before answer")
        })?;

        let pdu_header = T::from_bhs_bytes(&first_hdr)?;
        PDUWithData::<T>::parse(pdu_header, data.as_slice(), false, false)
    }

    async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut hdr = [0u8; HEADER_LEN];
        let pending: DashMap<u32, Pending> = DashMap::new();

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

            let mut payload = Vec::with_capacity(total);
            payload.extend_from_slice(&hdr);

            if total > HEADER_LEN {
                payload.resize(total, 0);
                let mut r = self.reader.lock().await;
                io_with_timeout("read payload", r.read_exact(&mut payload[HEADER_LEN..]))
                    .await?;
            }

            match (cont_bit, fin_bit) {
                (true, false) => match pending.entry(itt) {
                    Entry::Occupied(mut e) => {
                        e.get_mut().data.extend_from_slice(&payload[HEADER_LEN..]);
                    },
                    Entry::Vacant(v) => {
                        v.insert(Pending {
                            first_hdr: hdr,
                            data: payload[HEADER_LEN..].to_vec(),
                        });
                    },
                },

                (_, true) => {
                    let data_combined = if let Some((_, mut pend)) = pending.remove(&itt)
                    {
                        pend.data.extend_from_slice(&payload[HEADER_LEN..]);
                        pend.data
                    } else {
                        payload[HEADER_LEN..].to_vec()
                    };

                    let mut fixed_hdr = hdr;
                    let len_be = (data_combined.len() as u32).to_be_bytes();
                    fixed_hdr[5..8].copy_from_slice(&len_be[1..4]);

                    if let Some((_, tx)) = self.sending.remove(&itt) {
                        let _ = tx.send(Pending {
                            first_hdr: fixed_hdr,
                            data: data_combined,
                        });
                    }
                },

                (false, false) => {
                    if let Some((_, tx)) = self.sending.remove(&itt) {
                        let _ = tx.send(Pending {
                            first_hdr: hdr,
                            data: payload,
                        });
                    }
                },
            }
        }
    }
}
