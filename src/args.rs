use clap::Parser;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Parser)]
#[command(author, version, about = "tun2socks5 application.", long_about = None)]
pub struct Args {
    /// Proxy server address, likes `127.0.0.1:8080`
    #[arg(short, long, value_name = "IP:port")]
    pub server_addr: SocketAddr,

    /// IPv6 enabled
    #[arg(short = '6', long)]
    pub ipv6_enabled: bool,

    /// DNS handling strategy
    #[arg(short, long, value_name = "strategy", value_enum, default_value = "direct")]
    pub dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    pub dns_addr: IpAddr,

    /// IPs used in routing setup which should bypass the tunnel
    #[arg(short, long, value_name = "IP")]
    pub bypass: Vec<IpAddr>,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    pub verbosity: ArgVerbosity,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgVerbosity {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// DNS query handling strategy
/// - OverTcp: Use TCP to send DNS queries to the DNS server
/// - Direct: Do not handle DNS by relying on DNS server bypassing
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum ArgDns {
    OverTcp,
    #[default]
    Direct,
}
