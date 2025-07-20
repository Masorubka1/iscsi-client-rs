use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::client::pdu_connection::{FromBytes, ToBytes};

pub struct Connection {
    socket: TcpStream,
}

impl Connection {
    pub async fn connect(addr: &str) -> Result<Self> {
        Ok(Self {
            socket: TcpStream::connect(addr).await?,
        })
    }

    pub async fn call<Req, Res>(&mut self, req: Req) -> Result<Res::Response>
    where
        Req: ToBytes<48> + Sized,
        Res: FromBytes,
    {
        let (out_header, out_data) = req.to_bytes();
        self.socket.write_all(&out_header).await?;
        self.socket.write_all(&out_data).await?;

        let mut header_buf = vec![0u8; Res::HEADER_LEN];
        self.socket.read_exact(&mut header_buf).await?;

        let total_len = Res::peek_total_len(&header_buf)?;

        let mut rest = vec![0u8; total_len - Res::HEADER_LEN];
        println!(
            "total_len: {}, rest: {}",
            total_len,
            total_len - Res::HEADER_LEN
        );
        self.socket.read_exact(&mut rest).await?;

        header_buf.extend_from_slice(&rest);
        Res::from_bytes(&header_buf)
    }
}
