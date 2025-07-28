use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{
    cfg::config::Config,
    client::pdu_connection::{FromBytes, ToBytes},
    models::{
        opcode::{BhsOpcode, Opcode},
        reject::response::RejectPdu,
    },
};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
#[derive(Debug)]
pub struct Connection {
    socket: Mutex<TcpStream>,
    cfg: Config,
}

pub enum PduResponse<R> {
    /// A “normal” response of type `R::Response`
    Normal(R),
    /// A Reject PDU, with its parsed header and any data (always empty)
    Reject((RejectPdu, Vec<u8>, Option<u32>)),
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
        })
    }

    /// Send a request PDU and await a parsed response.
    /// Returns the parsed response (often a tuple of header struct, data bytes,
    /// and optional digest), or an error on I/O or parsing failure.
    pub async fn call<const REQUEST_HEADER_LEN: usize, Res>(
        &self,
        req: impl ToBytes<Header = [u8; REQUEST_HEADER_LEN]>,
    ) -> Result<PduResponse<(Res, Vec<u8>, Option<u32>)>>
    where
        Res: FromBytes,
    {
        let _ = self
            .write::<REQUEST_HEADER_LEN>(req)
            .await
            .map_err(|e| anyhow!(e.to_string()));

        let (mut data, is_reject) = self.is_reject(Res::HEADER_LEN).await?;

        let response_len = match is_reject {
            false => Res::peek_total_len(&data[..REQUEST_HEADER_LEN])?,
            true => RejectPdu::peek_total_len(&data[..REQUEST_HEADER_LEN])?,
        };
        let mut rest = vec![0u8; response_len - REQUEST_HEADER_LEN];
        {
            let mut sock = self.socket.lock().await;
            sock.read_exact(&mut rest).await?;
        }
        data.extend_from_slice(&rest);

        Ok(if is_reject {
            PduResponse::Reject(RejectPdu::from_bytes(&data)?)
        } else {
            PduResponse::Normal(Res::from_bytes(&data)?)
        })
    }

    /// Helper to serialize and write a PDU to the socket.
    async fn write<const REQUEST_HEADER_LEN: usize>(
        &self,
        req: impl ToBytes<Header = [u8; REQUEST_HEADER_LEN]>,
    ) -> Result<()> {
        let mut socket = self.socket.lock().await;
        let (out_header, out_data): ([u8; REQUEST_HEADER_LEN], _) =
            req.to_bytes(&self.cfg)?;
        socket.write_all(&out_header).await?;
        if !out_data.is_empty() {
            socket.write_all(&out_data).await?;
        }
        Ok(())
    }

    /// Reads only the header‐length needed to distinguish a Reject PDU
    /// (52 bytes) from a normal response (Res::HEADER_LEN), returning:
    ///  - the length we actually read,
    ///  - the buffer containing those header bytes,
    ///  - a bool flag indicating “is a Reject?”
    async fn is_reject(&self, expected_header_len: usize) -> Result<(Vec<u8>, bool)> {
        let mut header_buf = vec![0u8; expected_header_len];
        {
            let mut sock = self.socket.lock().await;
            sock.read_exact(&mut header_buf[..expected_header_len])
                .await?;
        }

        let bhs = BhsOpcode::try_from(header_buf[0])
            .map_err(|e| anyhow!("invalid opcode in response: {}", e))?;

        Ok((header_buf, bhs.opcode == Opcode::Reject))
    }
}
