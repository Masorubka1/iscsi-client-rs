use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail};
use dashmap::DashMap;
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
        common::{BasicHeaderSegment, HEADER_LEN},
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

pub type Data = ([u8; 48], Vec<u8>);
/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
pub struct Connection {
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
    cfg: Config,
    sending: DashMap<u32, oneshot::Sender<Data>>,
    reciver: DashMap<u32, oneshot::Receiver<Data>>,
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

        let (header, body) = rx.await.map_err(|_| {
            anyhow!("Failed to read response: connection closed before answer")
        })?;

        let pdu_header = T::from_bhs_bytes(&header)?;
        PDUWithData::<T>::parse(pdu_header, body.as_slice(), false, false)
    }

    async fn read_loop(self: Arc<Self>) -> Result<()> {
        let mut hdr = [0u8; HEADER_LEN];
        loop {
            {
                let mut r = self.reader.lock().await;
                if let Err(e) =
                    io_with_timeout("read header", r.read_exact(&mut hdr)).await
                {
                    warn!("read header failed: {e}");
                    break Ok(());
                }
            }

            let pdu_hdr = Pdu::from_bhs_bytes(&hdr)?;
            let total = pdu_hdr.total_length_bytes(); // 48 + AHS + pad + Data + pad + digests

            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&hdr);

            if total > HEADER_LEN {
                buf.resize(total, 0);
                let mut r = self.reader.lock().await;
                if let Err(e) =
                    io_with_timeout("read payload", r.read_exact(&mut buf[HEADER_LEN..]))
                        .await
                {
                    warn!("read payload failed: {e}");
                    break Ok(());
                }
            }

            let itt = pdu_hdr.get_initiator_task_tag();

            match self.sending.remove(&itt) {
                Some((_, tx)) => {
                    let _ = tx.send((hdr, buf));
                },
                None => {
                    warn!(%itt, "unsolicited PDU");
                },
            }
        }
    }
}
