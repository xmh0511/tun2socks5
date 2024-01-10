use tproxy_config::{TproxyArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use tun2socks5::{Args, Builder};

// const MTU: u16 = 1500;
const MTU: u16 = u16::MAX;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::default();

    let bypass_ips = args.bypass.clone();

    // let default = format!("{}={:?}", module_path!(), args.verbosity);
    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let mut config = tun::Configuration::default();
    config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(MTU as i32).up();
    config.destination(TUN_GATEWAY);
    if let Some(tun_fd) = args.tun_fd {
        config.raw_fd(tun_fd);
    } else {
        config.name(&args.tun);
    }

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
        config.apply_settings(false);
    });

    #[cfg(target_os = "windows")]
    config.platform(|config| {
        config.initialize(Some(12324323423423434234_u128));
    });

    #[allow(unused_variables)]
    let mut tproxy_args = TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&bypass_ips);
    #[allow(unused_assignments)]
    if args.tun_fd.is_none() {
        tproxy_args = tproxy_args.tun_name(&args.tun);
    }

    #[allow(unused_mut, unused_assignments, unused_variables)]
    let mut setup = true;

    #[cfg(target_os = "linux")]
    {
        setup = args.setup;
        if setup {
            tproxy_config::tproxy_setup(&tproxy_args)?;
        }
    }

    let device = tun::create_as_async(&config)?;

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    if setup {
        tproxy_config::tproxy_setup(&tproxy_args)?;
    }

    let tun2socks5 = Builder::new(device, args).build();
    let (join_handle, quit) = tun2socks5.start();

    ctrlc2::set_async_handler(async move {
        quit.trigger().await.expect("quit error");
    })
    .await;

    if let Err(err) = join_handle.await {
        log::trace!("main_entry error {}", err);
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        tproxy_config::tproxy_remove(&tproxy_args)?;
    }

    Ok(())
}
