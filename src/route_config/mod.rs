mod linux;
mod macos;
mod windows;

use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "linux")]
pub use {linux::config_restore, linux::config_settings};

#[cfg(target_os = "windows")]
pub use {windows::config_restore, windows::config_settings};

#[cfg(target_os = "macos")]
pub use {macos::config_restore, macos::config_settings};

pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
#[cfg(unix)]
pub(crate) const DNS_SYS_CFG_FILE: &str = "/etc/resolv.conf";

pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}
