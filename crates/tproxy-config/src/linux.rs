#![cfg(target_os = "linux")]

use crate::{run_command, TproxyArgs, DNS_SYS_CFG_FILE};
use std::net::IpAddr;

pub fn tproxy_settings(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    let tun_name = &tproxy_args.tun_name;
    // sudo ip tuntap add name tun0 mode tun
    let args = &["tuntap", "add", "name", tun_name, "mode", "tun"];
    run_command("ip", args)?;

    // sudo ip link set tun0 up
    let args = &["link", "set", tun_name, "up"];
    run_command("ip", args)?;

    // sudo ip route add "${bypass_ip}" $(ip route | grep '^default' | cut -d ' ' -f 2-)
    let args = &["-c", "ip route | grep '^default' | cut -d ' ' -f 2-"];
    let out = run_command("sh", args)?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let cmd = format!("ip route add {} {}", bypass_ip, stdout.trim());
        let args = &["-c", &cmd];
        if let Err(err) = run_command("sh", args) {
            log::trace!("run_command {}", err);
        }
    }

    // sudo ip route add 128.0.0.0/1 dev tun0
    let args = &["route", "add", "128.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 0.0.0.0/1 dev tun0
    let args = &["route", "add", "0.0.0.0/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add ::/1 dev tun0
    let args = &["route", "add", "::/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo ip route add 8000::/1 dev tun0
    let args = &["route", "add", "8000::/1", "dev", tun_name];
    run_command("ip", args)?;

    // sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"
    let file = std::fs::OpenOptions::new().write(true).truncate(true).open(DNS_SYS_CFG_FILE)?;
    let mut writer = std::io::BufWriter::new(file);
    use std::io::Write;
    writeln!(writer, "nameserver 198.18.0.1")?;

    Ok(())
}

pub fn tproxy_restore(tproxy_args: &TproxyArgs) -> std::io::Result<()> {
    // sudo route del bypass_ip
    for bypass_ip in tproxy_args.bypass_ips.iter() {
        let args = &["del", &bypass_ip.to_string()];
        run_command("route", args)?;
    }

    // sudo ip link del tun0
    let args = &["link", "del", &tproxy_args.tun_name];
    run_command("ip", args)?;

    // sudo systemctl restart systemd-resolved.service
    let args = &["restart", "systemd-resolved.service"];
    run_command("systemctl", args)?;

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn get_default_gateway() -> std::io::Result<(IpAddr, String)> {
    // Command: sh -c "ip route | grep default | awk '{print $3}'"
    let cmd = "ip route | grep default | awk '{print $3}'";
    let out = run_command("sh", &["-c", cmd])?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    use std::str::FromStr;
    let addr = IpAddr::from_str(stdout.trim()).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    let cmd = "ip route | grep default | awk '{print $5}'";
    let out = run_command("sh", &["-c", cmd])?;
    let stdout = String::from_utf8_lossy(&out).into_owned();
    let iface = stdout.trim().to_string();

    Ok((addr, iface))
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
