use clap::Parser;
use tun2socks5::{config_restore, config_settings, main_entry, Args, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let default = format!("{}={:?}", module_path!(), args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let mut config = tun::Configuration::default();
    config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(MTU as i32).up();
    config.destination(TUN_GATEWAY).name("utun3");

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    #[cfg(target_os = "windows")]
    config.platform(|config| {
        config.initialize(Some(12324323423423434234_u128));
    });

    let device = tun::create_as_async(&config)?;

    config_settings(&args.bypass, "utun3", Some(args.dns_addr))?;

    main_entry(device, MTU, true, args).await?;

    config_restore()?;

    Ok(())
}
