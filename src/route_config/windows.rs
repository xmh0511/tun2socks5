#![cfg(target_os = "windows")]

use crate::route_config::{run_command, TUN_DNS, TUN_GATEWAY};
use std::net::{IpAddr, Ipv4Addr};

pub(crate) static mut ORIGINAL_GATEWAY: Option<IpAddr> = None;

pub fn config_settings(bypass_ips: &[IpAddr], tun_name: &str, dns_addr: Option<IpAddr>) -> std::io::Result<()> {
    // 1. Setup the adapter's DNS
    // command: `netsh interface ip set dns "utun3" static 8.8.8.8`
    let dns_addr = dns_addr.unwrap_or(TUN_DNS);
    let tun_name = format!("\"{}\"", tun_name);
    let args = &["interface", "ip", "set", "dns", &tun_name, "static", &dns_addr.to_string()];
    run_command("netsh", args)?;
    log::info!("netsh {:?}", args);

    // 2. Route all traffic to the adapter, here the destination is adapter's gateway
    // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();
    let gateway = TUN_GATEWAY.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
    run_command("route", args)?;
    log::info!("route {:?}", args);

    let original_gateway = get_default_gateway()?;
    unsafe {
        ORIGINAL_GATEWAY = Some(original_gateway);
    }

    // 3. route the bypass ip to the original gateway
    // command: `route add bypass_ip original_gateway metric 1`
    for bypass_ip in bypass_ips {
        let args = &["add", &bypass_ip.to_string(), &original_gateway.to_string(), "metric", "1"];
        run_command("route", args)?;
        log::info!("route {:?}", args);
    }

    Ok(())
}

pub fn config_restore(_bypass_ips: &[IpAddr], _tun_name: &str) -> std::io::Result<()> {
    if unsafe { ORIGINAL_GATEWAY.is_none() } {
        return Ok(());
    }
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let original_gateway = unsafe { ORIGINAL_GATEWAY.take() }.ok_or(err)?;
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Remove current adapter's route
    // command: `route delete 0.0.0.0 mask 0.0.0.0`
    let args = &["delete", &unspecified, "mask", &unspecified];
    run_command("route", args)?;

    // 2. Add back the original gateway route
    // command: `route add 0.0.0.0 mask 0.0.0.0 original_gateway metric 200`
    let original_gateway = original_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &original_gateway, "metric", "200"];
    run_command("route", args)?;

    Ok(())
}

pub(crate) fn get_default_gateway() -> std::io::Result<IpAddr> {
    let args = &[
        "-Command",
        "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | ForEach-Object { $_.DefaultIPGateway }",
    ];
    let gateways = run_command("powershell", args)?;

    let stdout = String::from_utf8_lossy(&gateways).into_owned();
    let lines: Vec<&str> = stdout.lines().collect();

    let mut ipv4_gateway = None;
    let mut ipv6_gateway = None;

    for line in lines {
        if let Ok(ip) = <IpAddr as std::str::FromStr>::from_str(line) {
            match ip {
                IpAddr::V4(_) => {
                    ipv4_gateway = Some(ip);
                    break;
                }
                IpAddr::V6(_) => {
                    ipv6_gateway = Some(ip);
                }
            }
        }
    }

    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    ipv4_gateway.or(ipv6_gateway).ok_or(err)
}
