use anyhow::{Result, anyhow, bail};
use dashmap::{DashMap, DashSet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, oneshot},
};
use tracing::{error, info, warn};

use crate::{
    cfg::config::Config,
    client::pdu_connection::{FromBytes, ToBytes},
    models::{
        common::BasicHeaderSegment,
        opcode::{BhsOpcode, Opcode},
        parse::{self, Pdu},
        reject::response::RejectPdu,
    },
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
        socket.write_all(&out_header).await?;
        if !out_data.is_empty() {
            socket.write_all(&out_data).await?;
        }
        Ok(())
    }

    pub async fn send_request(
        &self,
        req: impl ToBytes<Header = Vec<u8>> + BasicHeaderSegment,
    ) -> Result<()> {
        if self.sending.contains_key(&req.get_initiator_task_tag()) {
            bail!(
                "Failed to send request, cause already sended other with same itt={}",
                req.get_initiator_task_tag()
            )
        }

        let (tx, rx) = oneshot::channel();
        self.sending.insert(req.get_initiator_task_tag(), tx);
        self.reciver.insert(req.get_initiator_task_tag(), rx);

        let _ = self.write(req).await?;

        Ok(())
    }

    pub async fn read_response(
        &self,
        initiator_task_tag: u32,
    ) -> Result<impl BasicHeaderSegment> {
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
            // TODO: make buff dynamic size
            let mut header_buf = vec![0u8; 48];
            {
                let mut sock = self.socket.lock().await;
                sock.read_exact(&mut header_buf[..48]).await?;
            }

            let pdu = Pdu::from_bytes(header_buf.as_ref());
            let pdu = if let Err(e) = pdu {
                error!("invalid opcode in response: {}", e);
                continue;
            } else {
                pdu.unwrap()
            };
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
