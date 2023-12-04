use std::net::{IpAddr, Ipv4Addr};

pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

pub static mut DEFAULT_GATEWAY: Option<IpAddr> = None;

#[cfg(windows)]
pub fn config_settings<'a>(bypass_ips: &[IpAddr], _dns_addr: Option<IpAddr>) -> std::io::Result<()> {
    // let adapter = self.wintun_session.get_adapter();

    // // Setup the adapter's address/mask/gateway
    // let address = TUN_IPV4;
    // let mask = TUN_NETMASK;
    // let gateway = TUN_GATEWAY;
    // adapter
    //     .set_network_addresses_tuple(address, mask, Some(gateway))
    //     .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // // 1. Setup the adapter's DNS
    // let interface = GUID::from(adapter.get_guid());
    // let dns = dns_addr.unwrap_or("8.8.8.8".parse::<IpAddr>().unwrap());
    // let dns2 = "8.8.4.4".parse::<IpAddr>().unwrap();
    // set_interface_dns_settings(interface, &[dns, dns2])?;

    // 2. Route all traffic to the adapter, here the destination is adapter's gateway
    // command: `route add 0.0.0.0 mask 0.0.0.0 10.1.0.1 metric 6`
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();
    let gateway = TUN_GATEWAY.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &gateway, "metric", "6"];
    run_command("route", args)?;
    log::info!("route {:?}", args);

    let old_gateway = get_default_gateway()?;
    unsafe {
        DEFAULT_GATEWAY = Some(old_gateway);
    }

    // 3. route the bypass ip to the old gateway
    // command: `route add bypass_ip old_gateway metric 1`
    for bypass_ip in bypass_ips {
        let args = &["add", &bypass_ip.to_string(), &old_gateway.to_string(), "metric", "1"];
        run_command("route", args)?;
        log::info!("route {:?}", args);
    }

    Ok(())
}

#[cfg(unix)]
pub fn config_settings<'a>(bypass_ips: &[IpAddr], dns_addr: Option<IpAddr>) -> std::io::Result<()> {
    unimplemented!()
}

#[cfg(windows)]
pub fn config_restore() -> std::io::Result<()> {
    if unsafe { DEFAULT_GATEWAY.is_none() } {
        return Ok(());
    }
    let err = std::io::Error::new(std::io::ErrorKind::Other, "No default gateway found");
    let old_gateway = unsafe { DEFAULT_GATEWAY.take() }.ok_or(err)?;
    let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

    // 1. Remove current adapter's route
    // command: `route delete 0.0.0.0 mask 0.0.0.0`
    let args = &["delete", &unspecified, "mask", &unspecified];
    run_command("route", args)?;

    // 2. Add back the old gateway route
    // command: `route add 0.0.0.0 mask 0.0.0.0 old_gateway metric 200`
    let old_gateway = old_gateway.to_string();
    let args = &["add", &unspecified, "mask", &unspecified, &old_gateway, "metric", "200"];
    run_command("route", args)?;

    Ok(())
}

#[cfg(unix)]
pub fn config_restore() -> std::io::Result<()> {
    unimplemented!()
}

pub fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

#[cfg(windows)]
pub(crate) fn get_default_gateway() -> std::io::Result<IpAddr> {
    let gateways = run_command(
        "powershell",
        &[
            "-Command",
            "Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | ForEach-Object { $_.DefaultIPGateway }",
        ],
    )?;

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
    ipv4_gateway.or(ipv6_gateway).ok_or_else(|| err)
}

#[cfg(unix)]
pub(crate) fn get_default_gateway() -> std::io::Result<IpAddr> {
    unimplemented!()
}
