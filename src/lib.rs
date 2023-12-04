use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    session_info::{IpProtocol, SessionInfo},
};
pub use args::Args;
pub use error::{Error, Result};
use ipstack::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
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

const DNS_PORT: u16 = 53;

pub async fn main_entry<D>(device: D, mtu: u16, packet_info: bool, args: Args) -> crate::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_addr = args.server_addr;
    let dns_addr = args.dns_addr;

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
                let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                if info.dst.port() == DNS_PORT && addr_is_private(&info.dst) {
                    info.dst.set_ip(dns_addr);
                }
                let proxy_handler = mgr.new_proxy_handler(info, true)?;
                tokio::spawn(async move {
                    if let Err(err) = handle_udp_associate_connection(udp, server_addr, proxy_handler).await {
                        log::error!("handle udp connection failed \"{}\"", err);
                    }
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

async fn handle_udp_associate_connection(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler + Send + Sync>>,
) -> crate::Result<()> {
    use socks5_impl::protocol::{StreamOperation, UdpHeader};
    let mut server = TcpStream::connect(server_addr).await?;
    let info = proxy_handler.lock().await.get_connection_info();
    log::info!("==== New UDP connection {} ====", info);

    let udp_addr = handle_proxy_connection(&mut server, proxy_handler).await?;
    let udp_addr = udp_addr.ok_or("udp associate failed")?;

    let mut udp_server = UdpStream::connect(udp_addr).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                // Add SOCKS5 UDP header to the incoming data
                let mut s5_udp_data = Vec::<u8>::new();
                UdpHeader::new(0, info.dst.into()).write_to_stream(&mut s5_udp_data)?;
                s5_udp_data.extend_from_slice(buf1);

                udp_server.write_all(&s5_udp_data).await?;
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                // Remove SOCKS5 UDP header from the incoming data
                let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;

                udp_stack.write_all(&buf2[header.len()..]).await?;
            }
        }
    }

    log::info!("==== end UDP connection ====");

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

// FIXME: use IpAddr::is_global() instead when it's stable
pub fn addr_is_private(addr: &SocketAddr) -> bool {
    fn is_benchmarking(addr: &std::net::Ipv4Addr) -> bool {
        addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
    }
    fn addr_v4_is_private(addr: &std::net::Ipv4Addr) -> bool {
        is_benchmarking(addr) || addr.is_private() || addr.is_loopback() || addr.is_link_local()
    }
    match addr {
        SocketAddr::V4(addr) => addr_v4_is_private(addr.ip()),
        SocketAddr::V6(_) => false,
    }
}
