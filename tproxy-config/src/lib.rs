mod linux;
mod macos;
mod private_ip;
mod tproxy_args;
mod windows;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
pub use {private_ip::is_private_ip, tproxy_args::TproxyArgs};

#[cfg(target_os = "linux")]
pub use {linux::tproxy_remove, linux::tproxy_setup};

#[cfg(target_os = "windows")]
pub use {windows::tproxy_remove, windows::tproxy_setup};

#[cfg(target_os = "macos")]
pub use {macos::tproxy_remove, macos::tproxy_setup};

pub const TUN_NAME: &str = if cfg!(target_os = "linux") {
    "tun0"
} else if cfg!(target_os = "windows") {
    "wintun"
} else if cfg!(target_os = "macos") {
    "utun3"
} else {
    // panic!("Unsupported OS")
    "unknown-tun"
};
pub const TUN_MTU: u16 = 1500;
pub const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

#[allow(dead_code)]
#[cfg(unix)]
pub(crate) const DNS_SYS_CFG_FILE: &str = "/etc/resolv.conf";

#[allow(dead_code)]
pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

#[allow(dead_code)]
pub(crate) fn get_record_file_path() -> PathBuf {
    let temp_dir = std::env::temp_dir();
    temp_dir.join("tproxy_config_routing_backup.json")
}
