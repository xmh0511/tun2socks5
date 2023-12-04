use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    session_info::{IpProtocol, SessionInfo},
};
pub use args::Args;
pub use error::{Error, Result};
use ipstack::stream::{IpStackStream, IpStackTcpStream};
use proxy_handler::{ConnectionManager, ProxyHandler};
use socks::SocksProxyManager;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use udp_stream::UdpStream;

mod args;
mod directions;
mod error;
mod proxy_handler;
mod session_info;
mod socks;

pub async fn main_entry<D>(device: D, mtu: u16, packet_info: bool, args: Args) -> crate::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_addr = args.server_addr;

    use socks5_impl::protocol::Version::V5;
    let mgr = Arc::new(SocksProxyManager::new(server_addr, V5, None)) as Arc<dyn ConnectionManager>;

    let mut ip_stack = ipstack::IpStack::new(device, mtu, packet_info);

    loop {
        match ip_stack.accept().await? {
            IpStackStream::Tcp(tcp) => {
                let info = SessionInfo::new(tcp.local_addr(), tcp.peer_addr(), IpProtocol::Tcp);
                let proxy_handler = mgr.new_proxy_handler(info, false)?;
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_connection(tcp, server_addr, proxy_handler).await {
                        log::error!("handle tcp connection failed \"{}\"", err);
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                let _proxy_handler = mgr.new_proxy_handler(info, true);

                let s = UdpStream::connect(server_addr).await;
                if let Err(ref err) = s {
                    log::error!("connect UDP server failed \"{}\"", err);
                    continue;
                }
                log::info!("==== New UDP connection ====");
                let (mut t_rx, mut t_tx) = tokio::io::split(udp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s?);
                tokio::spawn(async move {
                    let _r = tokio::join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    };
                    log::info!("==== end UDP connection ====");
                });
            }
        };
    }
}

async fn handle_tcp_connection(
    tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler + Send + Sync>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    log::info!("==== New TCP connection {} ====", proxy_handler.lock().await.get_connection_info());

    let _ = handle_proxy_connection(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let _r = tokio::join! {
         tokio::io::copy(&mut t_rx, &mut s_tx) ,
         tokio::io::copy(&mut s_rx, &mut t_tx),
    };

    log::info!("====== end tcp connection ======");

    Ok(())
}

async fn handle_proxy_connection(
    server: &mut TcpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler + Send + Sync>>,
) -> crate::Result<Option<SocketAddr>> {
    let mut launched = false;
    let mut proxy_handler = proxy_handler.lock().await;
    let dir = OutgoingDirection::ToServer;

    loop {
        if proxy_handler.connection_established() {
            break;
        }

        if !launched {
            let data = proxy_handler.peek_data(dir).buffer;
            let len = data.len();
            if len == 0 {
                return Err("proxy_handler went wrong".into());
            }
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);

            launched = true;
        }

        let mut buf = [0_u8; 4096];
        let len = server.read(&mut buf).await?;
        if len == 0 {
            return Err("server closed accidentially".into());
        }
        let event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &buf[..len],
        };
        proxy_handler.push_data(event)?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len == 0 {
            return Err("proxy_handler went wrong".into());
        }
        server.write_all(data).await?;
        proxy_handler.consume_data(dir, len);
    }
    Ok(proxy_handler.get_udp_associate())
}
