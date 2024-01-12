use crate::{
    args::ProxyType,
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    http::HttpManager,
    session_info::{IpProtocol, SessionInfo},
    virtual_dns::VirtualDns,
};
pub use clap;
use ipstack::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
use proxy_handler::{ProxyHandler, ProxyHandlerManager};
use socks::SocksProxyManager;
use std::{collections::VecDeque, future::Future, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{
        mpsc::{error::SendError, Receiver, Sender},
        Mutex,
    },
};
use tproxy_config::is_private_ip;
use udp_stream::UdpStream;
pub use {
    args::Args,
    error::{Error, Result},
};

mod android;
mod args;
mod directions;
mod dns;
mod error;
mod http;
mod proxy_handler;
mod session_info;
mod socks;
mod virtual_dns;

const DNS_PORT: u16 = 53;

static TASK_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering::Relaxed;

pub struct Builder<D> {
    device: D,
    mtu: Option<u16>,
    packet_info: Option<bool>,
    args: Args,
}

impl<D: AsyncRead + AsyncWrite + Unpin + Send + 'static> Builder<D> {
    pub fn new(device: D, args: Args) -> Self {
        Builder {
            device,
            args,
            mtu: None,
            packet_info: None,
        }
    }
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
    pub fn packet_info(mut self, packet_info: bool) -> Self {
        self.packet_info = Some(packet_info);
        self
    }
    pub fn build(self) -> Tun2Socks5<impl Future<Output = crate::Result<()>> + Send + 'static> {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        Tun2Socks5(
            run(
                self.device,
                self.mtu.unwrap_or(1500),
                self.packet_info.unwrap_or(cfg!(target_family = "unix")),
                self.args,
                rx,
            ),
            tx,
        )
    }
}

pub struct Tun2Socks5<F: Future>(F, Sender<()>);

impl<F: Future + Send + 'static> Tun2Socks5<F>
where
    F::Output: Send,
{
    pub fn start(self) -> (JoinHandle<F::Output>, Quit) {
        let r = tokio::spawn(self.0);
        (JoinHandle(r), Quit(self.1))
    }
}

pub struct Quit(Sender<()>);

impl Quit {
    pub async fn trigger(&self) -> Result<(), SendError<()>> {
        self.0.send(()).await
    }
}

#[repr(transparent)]
struct TokioJoinError(tokio::task::JoinError);

impl From<TokioJoinError> for crate::Result<()> {
    fn from(value: TokioJoinError) -> Self {
        Err(crate::Error::Io(value.0.into()))
    }
}

pub struct JoinHandle<R>(tokio::task::JoinHandle<R>);

impl<R: From<TokioJoinError>> Future for JoinHandle<R> {
    type Output = R;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(r) => std::task::Poll::Ready(r),
            Err(e) => std::task::Poll::Ready(TokioJoinError(e).into()),
        }
    }
}

pub async fn run<D>(device: D, mtu: u16, packet_info: bool, args: Args, mut quit: Receiver<()>) -> crate::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let virtual_dns = if args.dns == args::ArgDns::Virtual {
        Some(Arc::new(Mutex::new(VirtualDns::new())))
    } else {
        None
    };

    use socks5_impl::protocol::Version::{V4, V5};
    let mgr = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)) as Arc<dyn ProxyHandlerManager>,
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)) as Arc<dyn ProxyHandlerManager>,
        ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)) as Arc<dyn ProxyHandlerManager>,
    };

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(mtu);
    ipstack_config.packet_info(packet_info);
    ipstack_config.tcp_timeout(std::time::Duration::from_secs(600)); // 10 minutes
    ipstack_config.udp_timeout(std::time::Duration::from_secs(10)); // 10 seconds

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, device);

    loop {
        let virtual_dns = virtual_dns.clone();
        let ip_stack_stream = tokio::select! {
            _ = quit.recv() => {
                log::info!("");
                log::info!("Ctrl-C recieved, exiting...");
                break;
            }
            ip_stack_stream = ip_stack.accept() => {
                ip_stack_stream?
            }
        };
        match ip_stack_stream {
            IpStackStream::Tcp(tcp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let info = SessionInfo::new(tcp.local_addr(), tcp.peer_addr(), IpProtocol::Tcp);
                let domain_name = if let Some(virtual_dns) = &virtual_dns {
                    let mut virtual_dns = virtual_dns.lock().await;
                    virtual_dns.touch_ip(&tcp.peer_addr().ip());
                    virtual_dns.resolve_ip(&tcp.peer_addr().ip()).cloned()
                } else {
                    None
                };
                let proxy_handler = mgr.new_proxy_handler(info, domain_name, false).await?;
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_session(tcp, server_addr, proxy_handler).await {
                        log::error!("{} error \"{}\"", info, err);
                    }
                    log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                });
            }
            IpStackStream::Udp(udp) => {
                log::trace!("Session count {}", TASK_COUNT.fetch_add(1, Relaxed) + 1);
                let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                if info.dst.port() == DNS_PORT {
                    if is_private_ip(info.dst.ip()) {
                        info.dst.set_ip(dns_addr);
                    }
                    if args.dns == args::ArgDns::OverTcp {
                        let proxy_handler = mgr.new_proxy_handler(info, None, false).await?;
                        tokio::spawn(async move {
                            if let Err(err) = handle_dns_over_tcp_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                                log::error!("{} error \"{}\"", info, err);
                            }
                            log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                        });
                        continue;
                    }
                    if args.dns == args::ArgDns::Virtual {
                        tokio::spawn(async move {
                            if let Some(virtual_dns) = virtual_dns {
                                if let Err(err) = handle_virtual_dns_session(udp, virtual_dns).await {
                                    log::error!("{} error \"{}\"", info, err);
                                }
                            }
                            log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                        });
                        continue;
                    }
                    assert_eq!(args.dns, args::ArgDns::Direct);
                }
                let domain_name = if let Some(virtual_dns) = &virtual_dns {
                    let mut virtual_dns = virtual_dns.lock().await;
                    virtual_dns.touch_ip(&udp.peer_addr().ip());
                    virtual_dns.resolve_ip(&udp.peer_addr().ip()).cloned()
                } else {
                    None
                };
                let proxy_handler = mgr.new_proxy_handler(info, domain_name, true).await?;
                tokio::spawn(async move {
                    if let Err(err) = handle_udp_associate_session(udp, server_addr, proxy_handler, ipv6_enabled).await {
                        log::error!("{} error \"{}\"", info, err);
                    }
                    log::trace!("Session count {}", TASK_COUNT.fetch_sub(1, Relaxed) - 1);
                });
            }
        }
    }
    Ok(())
}

async fn handle_virtual_dns_session(mut udp: IpStackUdpStream, dns: Arc<Mutex<VirtualDns>>) -> crate::Result<()> {
    let mut buf = [0_u8; 4096];
    loop {
        let len = udp.read(&mut buf).await?;
        if len == 0 {
            break;
        }
        let (msg, qname, ip) = dns.lock().await.generate_query(&buf[..len])?;
        udp.write_all(&msg).await?;
        log::debug!("Virtual DNS query: {} -> {}", qname, ip);
    }
    Ok(())
}

async fn handle_tcp_session(
    tcp_stack: IpStackTcpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let result = tokio::join! {
         tokio::io::copy(&mut t_rx, &mut s_tx),
         tokio::io::copy(&mut s_rx, &mut t_tx),
    };
    let result = match result {
        (Ok(t), Ok(s)) => Ok((t, s)),
        (Err(e), _) | (_, Err(e)) => Err(e),
    };

    log::info!("Ending {} with {:?}", session_info, result);

    Ok(())
}

async fn handle_udp_associate_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    use socks5_impl::protocol::{Address, StreamOperation, UdpHeader};
    let mut server = TcpStream::connect(server_addr).await?;
    let session_info = proxy_handler.lock().await.get_session_info();
    let domain_name = proxy_handler.lock().await.get_domain_name();
    log::info!("Beginning {}", session_info);

    let udp_addr = handle_proxy_session(&mut server, proxy_handler).await?;
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

                let s5addr = if let Some(domain_name) = &domain_name {
                    Address::DomainAddress(domain_name.clone(), session_info.dst.port())
                } else {
                    session_info.dst.into()
                };

                // Add SOCKS5 UDP header to the incoming data
                let mut s5_udp_data = Vec::<u8>::new();
                UdpHeader::new(0, s5addr).write_to_stream(&mut s5_udp_data)?;
                s5_udp_data.extend_from_slice(buf1);

                udp_server.write_all(&s5_udp_data).await?;
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                // Remove SOCKS5 UDP header from the server data
                let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                let data = &buf2[header.len()..];

                let buf = if session_info.dst.port() == DNS_PORT {
                    let mut message = dns::parse_data_to_dns_message(data, false)?;
                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }
                    message.to_vec()?
                } else {
                    data.to_vec()
                };

                udp_stack.write_all(&buf).await?;
            }
        }
    }

    log::info!("Ending {}", session_info);

    Ok(())
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    server_addr: SocketAddr,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let mut server = TcpStream::connect(server_addr).await?;

    let session_info = proxy_handler.lock().await.get_session_info();
    log::info!("Beginning {}", session_info);

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

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

                _ = dns::parse_data_to_dns_message(buf1, false)?;

                // Insert the DNS message length in front of the payload
                let len = u16::try_from(buf1.len())?;
                let mut buf = Vec::with_capacity(std::mem::size_of::<u16>() + usize::from(len));
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(buf1);

                server.write_all(&buf).await?;
            }
            len = server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let mut buf = buf2[..len].to_vec();

                let mut to_send: VecDeque<Vec<u8>> = VecDeque::new();
                loop {
                    if buf.len() < 2 {
                        break;
                    }
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() < len + 2 {
                        break;
                    }

                    // remove the length field
                    let data = buf[2..len + 2].to_vec();

                    let mut message = dns::parse_data_to_dns_message(&data, false)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    log::trace!("DNS over TCP query result: {} -> {:?}", name, ip);

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    to_send.push_back(message.to_vec()?);
                    if len + 2 == buf.len() {
                        break;
                    }
                    buf = buf[len + 2..].to_vec();
                }

                while let Some(packet) = to_send.pop_front() {
                    udp_stack.write_all(&packet).await?;
                }
            }
        }
    }

    log::info!("Ending {}", session_info);

    Ok(())
}

async fn handle_proxy_session(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<Option<SocketAddr>> {
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
                return Err("proxy_handler launched went wrong".into());
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
        proxy_handler.push_data(event).await?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
        }
    }
    Ok(proxy_handler.get_udp_associate())
}
