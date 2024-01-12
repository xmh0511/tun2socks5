#![cfg(target_os = "windows")]

use crate::{run_command, TproxyArgs};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

pub(crate) static mut ORIGINAL_GATEWAY: Option<IpAddr> = None;

#[derive(Serialize, Deserialize, Debug)]
struct DefaultConfigFile {
    gateway: Option<IpAddr>,
}

fn check_and_restore(tproxy_args: &TproxyArgs) {
    let path = crate::get_record_file_path();
    if !path.exists() {
        return;
    }
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Ok(content) = serde_json::from_str(&s) {
            let content: DefaultConfigFile = content;
            unsafe {
                ORIGINAL_GATEWAY = content.gateway;
            };
            tproxy_remove(tproxy_args).unwrap();
        }
    }
}

pub fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    // check whether a recent exception exit
    check_and_restore(tproxy_args);

    // 1. Setup the adapter's DNS
    // command: `netsh interface ip set dns "utun3" static 8.8.8.8`
    let dns_addr = tproxy_args.tun_dns;
    let tun_name = format!("\"{}\"", tproxy_args.tun_name);
    let args = &["interface", "ip", "set", "dns", &tun_name, "static", &dns_addr.to_string()];
    run_command("netsh", args)?;
    #[cfg(feature = "log")]
    log::info!("netsh {:?}", args);

    // 2. Route all traffic to the adapter, here the destination is adapter's gateway
    // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();
    let gateway = tproxy_args.tun_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
    run_command("route", args)?;
    #[cfg(feature = "log")]
    log::info!("route {:?}", args);

    let (original_gateway, _) = get_default_gateway()?;
    unsafe {
        ORIGINAL_GATEWAY = Some(original_gateway);
    }

    // 3. route the bypass ip to the original gateway
    // command: `route add bypass_ip original_gateway metric 1`
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["add", &bypass_ip.to_string(), &original_gateway.to_string(), "metric", "1"];
        run_command("route", args)?;
        #[cfg(feature = "log")]
        log::info!("route {:?}", args);
    }

    {
        let disk_record = unsafe { DefaultConfigFile { gateway: ORIGINAL_GATEWAY } };
        let record_file_content = serde_json::to_string(&disk_record)?;
        std::fs::write(crate::get_record_file_path(), record_file_content)?;
    }

    Ok(())
}

pub fn tproxy_remove(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    if unsafe { ORIGINAL_GATEWAY.is_none() } {
        return Ok(());
    }
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let original_gateway = unsafe { ORIGINAL_GATEWAY.take() }.ok_or(err)?;
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 0. delete persistent route
    // command: `route -p delete 0.0.0.0 mask 0.0.0.0 10.0.0.1`
    let gateway = tproxy_args.tun_gateway.to_string();
    let args = &["-p", "delete", &unspecified, "mask", &unspecified, &gateway];
    if let Err(_err) = run_command("route", args) {
        #[cfg(feature = "log")]
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // 1. Remove current adapter's route
    // command: `route delete 0.0.0.0 mask 0.0.0.0`
    let args = &["delete", &unspecified, "mask", &unspecified];
    if let Err(_err) = run_command("route", args) {
        #[cfg(feature = "log")]
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // 2. Add back the original gateway route
    // command: `route add 0.0.0.0 mask 0.0.0.0 original_gateway metric 200`
    let original_gateway = original_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &original_gateway, "metric", "200"];
    if let Err(_err) = run_command("route", args) {
        #[cfg(feature = "log")]
        log::debug!("command \"route {:?}\" error: {}", args, _err);
    }

    // remove the record file anyway
    let _ = std::fs::remove_file(crate::get_record_file_path());

    Ok(())
}

pub(crate) fn get_default_gateway() -> std::io::Result<(IpAddr, String)> {
    let cmd = "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | ForEach-Object { $_.DefaultIPGateway }";
    let gateways = run_command("powershell", &["-Command", cmd])?;

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
    let addr = ipv4_gateway.or(ipv6_gateway).ok_or(err)?;
    let iface = get_default_gateway_interface()?;
    Ok((addr, iface))
}

pub(crate) fn get_default_gateway_interface() -> std::io::Result<String> {
    let cmd = "Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1 -ExpandProperty NetConnectionID";
    let iface = run_command("powershell", &["-Command", cmd])?;

    let stdout = String::from_utf8_lossy(&iface).into_owned();
    let iface = stdout.trim().to_string();

    Ok(iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_gateway() {
        let (addr, iface) = get_default_gateway().unwrap();
        println!("addr: {:?}, iface: {}", addr, iface);
    }
}
