//!
//! Build: `cargo build --examples`
//! Usage: `target/debug/examples/tun --server-addr 127.0.0.1:8080`
//!
//! This example must be run as root or administrator privileges.
//! Then please run the `echo` example server, which listens on TCP & UDP ports 127.0.0.1:8080.
//! To route traffic to the tun interface, run the following command with root or administrator privileges:
//! ```
//! sudo ip route add 1.2.3.4/32 dev utun3    # Linux
//! route add 1.2.3.4 mask 255.255.255.255 10.0.0.1 metric 100  # Windows
//! sudo route add 1.2.3.4/32 10.0.0.1  # Apple macOS
//! ```
//! Now you can test it with `nc 1.2.3.4 2323` or `nc -u 1.2.3.4 2323`.
//! You can watch the echo information in the `nc` console.
//!

use clap::Parser;
use std::net::Ipv4Addr;
use tun2socks5::{main_entry, Args};

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let default = format!("{}={:?}", module_path!(), args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let ipv4 = Ipv4Addr::new(10, 0, 0, 33);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let gateway = Ipv4Addr::new(10, 0, 0, 1);

    let mut config = tun::Configuration::default();
    config.address(ipv4).netmask(netmask).mtu(MTU as i32).up();
    config.destination(gateway).name("utun3");

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(target_os = "windows")]
    config.platform(|config| {
        config.initialize(Some(12324323423423434234_u128));
    });

    let device = tun::create_as_async(&config)?;

    main_entry(device, MTU, true, args).await?;

    Ok(())
}
