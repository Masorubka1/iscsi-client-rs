use anyhow::{Result, anyhow, bail};
use dashmap::DashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, oneshot},
};
use tracing::{info, warn};

use crate::{
    cfg::config::Config,
    client::pdu_connection::{FromBytes, ToBytes},
    models::{common::BasicHeaderSegment, parse::Pdu},
};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
pub struct Connection {
    socket: Mutex<TcpStream>,
    cfg: Config,
    sending: DashMap<u32, oneshot::Sender<Pdu>>,
    reciver: DashMap<u32, oneshot::Receiver<Pdu>>,
}

impl Connection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(cfg: Config) -> Result<Self> {
        let stream =
            TcpStream::connect(cfg.login.security.target_address.clone()).await?;
        stream.set_linger(None)?;
        Ok(Self {
            socket: Mutex::new(stream),
            cfg,
            sending: DashMap::new(),
            reciver: DashMap::new(),
        })
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write(&self, req: impl ToBytes<Header = Vec<u8>>) -> Result<()> {
        let mut socket = self.socket.lock().await;
        let (out_header, out_data) = req.to_bytes(&self.cfg)?;
        info!(
            "Size_header: {} Size_data: {}",
            out_header.len(),
            out_data.len()
        );
        socket.write_all(&out_header).await?;
        if !out_data.is_empty() {
            socket.write_all(&out_data).await?;
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

        self.write(req).await?;

        Ok(())
    }

    pub async fn read_response(&self, initiator_task_tag: u32) -> Result<Pdu> {
        let rx = match self.reciver.remove(&initiator_task_tag) {
            None => bail!("no pending request with itt={initiator_task_tag}"),
            Some((_, rx)) => rx,
        };
        let _ = self.sending.remove(&initiator_task_tag);

        rx.await
            .map_err(|_| anyhow!("connection closed before answer"))
    }

    pub async fn start_reading_loop(&self) -> Result<()> {
        loop {
            let mut hdr = [0u8; 48];
            {
                let mut sock = self.socket.lock().await;
                sock.read_exact(&mut hdr[..48]).await?;
            }

            let pdu_hdr = Pdu::from_bhs_bytes(&hdr)?;
            let total = pdu_hdr.total_length_bytes(); // 48 + AHS + Data + pad(+digest)

            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&hdr);
            if total > 48 {
                buf.resize(total, 0);
                let mut sock = self.socket.lock().await;
                sock.read_exact(&mut buf[48..]).await?;
            }

            let pdu = Pdu::from_bytes(&buf)?;
            let itt = pdu.get_initiator_task_tag();
            match self.sending.remove(&itt) {
                Some((_, tx)) => {
                    let _ = tx.send(pdu);
                },
                None => {
                    warn!(%itt, "unsolicited PDU – нет получателя");
                },
            }
        }
    }
}
