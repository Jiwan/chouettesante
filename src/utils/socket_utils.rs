use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::{error::Elapsed, timeout}};

pub trait SocketUtils {
    async fn rcv_from_slice<'a>(&self, buf: &'a mut [u8]) -> io::Result<(&'a [u8], SocketAddr)>;
    async fn rcv_from_timeout<'a>(&self, buf: &'a mut [u8], timeout_ms: Duration) -> Result<io::Result<(&'a [u8], SocketAddr)>, Elapsed>;
}
    
impl SocketUtils for UdpSocket {
    async fn rcv_from_slice<'a>(&self, buf: &'a mut [u8]) -> io::Result<(&'a [u8], SocketAddr)> {
        let (n, addr) = self.recv_from(buf).await?;
        Ok((&buf[..n], addr))
    }

    async fn rcv_from_timeout<'a>(&self, buf: &'a mut [u8], timeout_ms: Duration) -> Result<io::Result<(&'a [u8], SocketAddr)>, Elapsed> {
        match timeout(timeout_ms, self.recv_from(buf)).await {
            Ok(Ok((n, addr))) => Ok(Ok((&buf[..n], addr))),
            Ok(Err(e)) => Ok(Err(e)),
            Err(elapsed) => Err(elapsed),
        }
    }
}
