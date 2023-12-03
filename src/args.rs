use clap::Parser;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Copy, Clone, Parser)]
#[command(author, version, about = "tun2socks5 application.", long_about = None)]
pub struct Args {
    /// echo server address, likes `127.0.0.1:8080`
    #[arg(short, long, value_name = "IP:port")]
    pub server_addr: SocketAddr,

    /// DNS handling strategy
    #[arg(short, long, value_name = "strategy", value_enum, default_value = "Direct")]
    pub dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    pub dns_addr: IpAddr,

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
