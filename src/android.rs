#![cfg(target_os = "android")]

use crate::{
    args::{ArgDns, ArgProxy},
    error::{Error, Result},
    Args, Builder, Quit,
};
use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jint},
    JNIEnv,
};
use std::sync::Arc;

static mut TUN_QUIT: Option<Arc<Quit>> = None;

/// # Safety
///
/// Running tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_run(
    mut env: JNIEnv,
    _clazz: JClass,
    proxy_url: JString,
    tun_fd: jint,
    tun_mtu: jint,
    verbose: jboolean,
    dns_over_tcp: jboolean,
) -> jint {
    let log_level = if verbose != 0 { "trace" } else { "info" };
    let filter_str = &format!("off,tun2proxy={log_level}");
    let filter = android_logger::FilterBuilder::new().parse(filter_str).build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("tun2proxy")
            .with_max_level(log::LevelFilter::Trace)
            .with_filter(filter),
    );

    if TUN_QUIT.is_some() {
        log::error!("tun2proxy already started");
        return -1;
    }

    let block = async move {
        let proxy_url = get_java_string(&mut env, &proxy_url)?;
        let proxy = ArgProxy::from_url(proxy_url)?;
        log::info!("Proxy {} server: {}", proxy.proxy_type, proxy.addr);

        let args = Args {
            dns: if dns_over_tcp != 0 { ArgDns::OverTcp } else { ArgDns::Direct },
            proxy,
            ..Args::default()
        };

        let mut config = tun::Configuration::default();
        config.raw_fd(tun_fd);

        let device = tun::create_as_async(&config).map_err(std::io::Error::from)?;

        let tun2proxy = Builder::new(device, args).packet_info(false).mtu(tun_mtu as _).build();
        let (join_handle, quit) = tun2proxy.start();

        TUN_QUIT = Some(Arc::new(quit));

        join_handle.await
    };

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_err) => {
            log::error!("failed to create tokio runtime with error: {:?}", _err);
            -1
        }
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(_err) => {
                log::error!("failed to run tun2proxy with error: {:?}", _err);
                -2
            }
        },
    }
}

/// # Safety
///
/// Shutdown tun2proxy
#[no_mangle]
pub unsafe extern "C" fn Java_com_github_shadowsocks_bg_Tun2proxy_stop(_env: JNIEnv, _: JClass) -> jint {
    let res = match &TUN_QUIT {
        None => {
            log::error!("tun2proxy not started");
            -1
        }
        Some(tun_quit) => match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Err(_err) => {
                log::error!("failed to create tokio runtime with error: {:?}", _err);
                -2
            }
            Ok(rt) => match rt.block_on(async move { tun_quit.trigger().await }) {
                Ok(_) => 0,
                Err(_err) => {
                    log::error!("failed to stop tun2proxy with error: {:?}", _err);
                    -3
                }
            },
        },
    };
    TUN_QUIT = None;
    res
}

unsafe fn get_java_string<'a>(env: &'a mut JNIEnv, string: &'a JString) -> Result<&'a str, Error> {
    let str_ptr = env.get_string(string)?.as_ptr();
    let s: &str = std::ffi::CStr::from_ptr(str_ptr).to_str()?;
    Ok(s)
}
