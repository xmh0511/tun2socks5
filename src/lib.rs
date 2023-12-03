use crate::{
    directions::OutgoingDirection,
    session_info::{IpProtocol, SessionInfo},
};
pub use args::Args;
pub use error::{Error, Result};
use ipstack::stream::IpStackStream;
use proxy_handler::ConnectionManager;
use socks::SocksProxyManager;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
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

                let s = TcpStream::connect(server_addr).await;
                if let Err(ref err) = s {
                    log::error!("connect TCP server {} failed \"{}\"", info, err);
                    continue;
                }
                log::info!("==== New TCP connection {} ====", info);
                let (mut t_rx, mut t_tx) = tokio::io::split(tcp);
                let (mut s_rx, mut s_tx) = tokio::io::split(s?);
                tokio::spawn(async move {
                    proxy_handler.lock().unwrap().peek_data(OutgoingDirection::ToServer);
                    let _r = tokio::join! {
                         tokio::io::copy(&mut t_rx, &mut s_tx) ,
                         tokio::io::copy(&mut s_rx, &mut t_tx),
                    };

                    log::info!("====== end tcp connection ======");
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
