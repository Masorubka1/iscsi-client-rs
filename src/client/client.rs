use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::client::pdu_connection::{FromBytes, ToBytes};

/// A simple iSCSI connection wrapper over a TCP stream.
///
/// Manages sending requests (PDUs) and receiving responses by
/// framing based on header information.
#[derive(Debug)]
pub struct Connection {
    socket: Mutex<TcpStream>,
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
    pub async fn call<Req, Res>(&self, req: Req) -> Result<Res::Response>
    where
        Req: ToBytes<48> + Sized,
        Res: FromBytes,
    {
        // send
        {
            let mut socket = self.socket.lock().await;
            let (out_header, out_data) = req.to_bytes();
            socket.write_all(&out_header).await?;
            if !out_data.is_empty() {
                socket.write_all(&out_data).await?;
            }
            //println!("send {} {}", out_header.len(), out_data.len());
        }

        // get
        let (mut header_buf, rest) = {
            let mut socket = self.socket.lock().await;
            let mut header_buf = vec![0u8; Res::HEADER_LEN];
            socket.read_exact(&mut header_buf).await?;

            let total_len = Res::peek_total_len(&header_buf)?;

            let mut rest = vec![0u8; total_len - Res::HEADER_LEN + 1];
            socket.read_exact(&mut rest).await?;
            (header_buf, rest)
        };
        header_buf.extend_from_slice(&rest);
        Res::from_bytes(&header_buf)
    }
}
