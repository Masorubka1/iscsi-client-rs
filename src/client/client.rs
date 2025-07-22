use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::{
    client::pdu_connection::{FromBytes, ToBytes},
    models::{
        opcode::{BhsOpcode, Opcode},
        reject::reject::RejectPdu,
    },
};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
#[derive(Debug)]
pub struct Connection {
    socket: Mutex<TcpStream>,
}

pub enum PduResponse<R> {
    /// A “normal” response of type `R::Response`
    Normal(R),
    /// A Reject PDU, with its parsed header and any data (always empty)
    Reject((RejectPdu, Vec<u8>, Option<u32>)),
}

impl Connection {
    /// Establishes a new TCP connection to the given address.
    pub async fn connect(addr: &str) -> Result<Self> {
        Ok(Self {
            socket: Mutex::new(TcpStream::connect(addr).await?),
        })
    }

    /// Send a request PDU and await a parsed response.
    /// Returns the parsed response (often a tuple of header struct, data bytes,
    /// and optional digest), or an error on I/O or parsing failure.
    pub async fn call<Req, Res>(
        &self,
        req: Req,
    ) -> Result<PduResponse<(Res, Vec<u8>, Option<u32>)>>
    where
        Req: ToBytes<48>,
        Res: FromBytes,
    {
        {
            let mut socket = self.socket.lock().await;
            let (out_header, out_data) = req.to_bytes();
            socket.write_all(&out_header).await?;
            if !out_data.is_empty() {
                socket.write_all(&out_data).await?;
            }
        }

        let mut header_buf = vec![0u8; RejectPdu::HEADER_LEN];
        {
            let mut sock = self.socket.lock().await;
            sock.read_exact(&mut header_buf[..Res::HEADER_LEN]).await?;
        }

        let bhs = BhsOpcode::try_from(header_buf[0])
            .map_err(|e| anyhow!("invalid opcode in response: {}", e))?;

        let header_len = if bhs.opcode == Opcode::Reject {
            let mut sock = self.socket.lock().await;
            sock.read_exact(&mut header_buf[Res::HEADER_LEN..RejectPdu::HEADER_LEN])
                .await?;
            RejectPdu::HEADER_LEN
        } else {
            Res::HEADER_LEN
        };

        let total = Res::peek_total_len(&header_buf[..header_len])?;
        let mut rest = vec![0u8; total - header_len];
        {
            let mut sock = self.socket.lock().await;
            sock.read_exact(&mut rest).await?;
        }
        header_buf.extend_from_slice(&rest);

        Ok(if bhs.opcode == Opcode::Reject {
            PduResponse::Reject(RejectPdu::from_bytes(&header_buf)?)
        } else {
            PduResponse::Normal(Res::from_bytes(&header_buf)?)
        })
    }
}
