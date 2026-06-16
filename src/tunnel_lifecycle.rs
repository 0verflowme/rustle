use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tun_rs::DeviceBuilder;

use crate::data_plane::DataPlane;
use crate::packet_engine::MAX_IN_FLIGHT_DNS_QUERIES;
use crate::routing::{
    add_ssh_control_route, add_target_routes, prefix_to_mask, target_route_parts,
    ControlRouteGuard, RouteGuard,
};
use crate::transport_model::Destination;
use crate::{dns, platform, tcp_core, DEFAULT_TUN_IP};

pub(crate) type ShutdownSignalFuture = Pin<Box<dyn Future<Output = Result<&'static str>> + Send>>;

pub(crate) struct TunConfig {
    pub(crate) tun_ip: Ipv4Addr,
    pub(crate) tun_prefix: u8,
    pub(crate) mtu: u16,
    pub(crate) name: Option<String>,
}

impl TunConfig {
    pub(crate) fn new(tun_ip: Ipv4Addr, tun_prefix: u8, mtu: u16, name: Option<String>) -> Self {
        Self {
            tun_ip,
            tun_prefix,
            mtu,
            name,
        }
    }
}

pub(crate) struct OpenTun {
    pub(crate) dev: tun_rs::AsyncDevice,
    pub(crate) if_name: String,
    pub(crate) if_index: u32,
}

pub(crate) fn configured_tun_builder(config: &TunConfig) -> Result<DeviceBuilder> {
    let mut builder = DeviceBuilder::new()
        .ipv4(config.tun_ip, config.tun_prefix, None)
        .mtu(config.mtu);
    if let Some(name) = config.name.as_deref() {
        builder = builder.name(name);
    }
    platform::prepare_tun_builder(builder)
}

pub(crate) fn open_tun(config: &TunConfig) -> Result<OpenTun> {
    let builder = configured_tun_builder(config)?;
    let dev = builder
        .build_async()
        .context("failed to create TUN device; root/administrator privileges are required")?;
    let if_name = dev.name().context("failed to read TUN interface name")?;
    let if_index = dev
        .if_index()
        .context("failed to read TUN interface index")?;

    eprintln!(
        "tun: created {if_name} index={if_index} mtu={} addr={}/{}",
        config.mtu, config.tun_ip, config.tun_prefix
    );

    Ok(OpenTun {
        dev,
        if_name,
        if_index,
    })
}

pub(crate) struct TunnelHostConfig {
    pub(crate) tun_config: TunConfig,
    pub(crate) tun: OpenTun,
    pub(crate) target_routes: Vec<Ipv4Net>,
    pub(crate) ssh_control_ip: Option<Ipv4Addr>,
    pub(crate) configure_dns: bool,
    pub(crate) dns_remote: Destination,
    pub(crate) data_plane: Arc<dyn DataPlane>,
}

pub(crate) struct TunnelHost {
    pub(crate) tun: OpenTun,
    pub(crate) route_parts: Vec<tcp_core::Ipv4NetParts>,
    pub(crate) cleanup: TunnelCleanup,
}

pub(crate) async fn open_tunnel_host(config: TunnelHostConfig) -> Result<TunnelHost> {
    let control_route = match config.ssh_control_ip {
        Some(ip) => add_ssh_control_route(ip)?,
        None => None,
    };
    let routes = add_target_routes(
        &config.target_routes,
        &config.tun.if_name,
        config.tun.if_index,
        config.tun_config.tun_ip,
    )?;
    let (dns_guard, local_dns_proxy) = if config.configure_dns {
        let virtual_dns_ip =
            virtual_dns_ip(config.tun_config.tun_ip, config.tun_config.tun_prefix)?;
        let system_dns_ip = platform::system_dns_server_ip(virtual_dns_ip);
        let local_dns_proxy = if system_dns_ip.is_loopback() {
            Some(
                start_local_dns_proxy(
                    system_dns_ip,
                    Arc::clone(&config.data_plane),
                    config.dns_remote.clone(),
                )
                .await
                .with_context(|| {
                    format!("failed to start local DNS proxy on {system_dns_ip}:53")
                })?,
            )
        } else {
            None
        };
        let guard = platform::configure_system_dns(&config.tun.if_name, system_dns_ip)
            .with_context(|| {
                format!("failed to configure system DNS for {}", config.tun.if_name)
            })?;
        eprintln!("dns: configured host resolver to use DNS {system_dns_ip}");
        (Some(guard), local_dns_proxy)
    } else {
        (None, None)
    };
    let route_parts = target_route_parts(&config.target_routes);

    Ok(TunnelHost {
        tun: config.tun,
        route_parts,
        cleanup: TunnelCleanup::new(dns_guard, local_dns_proxy, routes, control_route),
    })
}

pub(crate) struct TunnelCleanup {
    dns_guard: Option<platform::DnsConfigGuard>,
    local_dns_proxy: Option<LocalDnsProxy>,
    routes: Vec<RouteGuard>,
    control_route: Option<ControlRouteGuard>,
}

impl TunnelCleanup {
    fn new(
        dns_guard: Option<platform::DnsConfigGuard>,
        local_dns_proxy: Option<LocalDnsProxy>,
        routes: Vec<RouteGuard>,
        control_route: Option<ControlRouteGuard>,
    ) -> Self {
        Self {
            dns_guard,
            local_dns_proxy,
            routes,
            control_route,
        }
    }
}

impl Drop for TunnelCleanup {
    fn drop(&mut self) {
        self.dns_guard.take();
        self.local_dns_proxy.take();
        self.routes.clear();
        self.control_route.take();
    }
}

pub(crate) struct LocalDnsProxy {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalDnsProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn start_local_dns_proxy(
    bind_ip: Ipv4Addr,
    data_plane: Arc<dyn DataPlane>,
    remote: Destination,
) -> Result<LocalDnsProxy> {
    let socket = Arc::new(
        UdpSocket::bind((bind_ip, dns::DNS_PORT))
            .await
            .with_context(|| format!("failed to bind local DNS proxy on {bind_ip}:53"))?,
    );
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_DNS_QUERIES));
    eprintln!("dns: local resolver proxy listening on {bind_ip}:53");

    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 4096];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(err) => {
                    eprintln!("dns: local resolver proxy receive failed: {err:#}");
                    break;
                }
            };
            let query = Bytes::copy_from_slice(&buf[..len]);
            let permit = match Arc::clone(&permits).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    eprintln!(
                        "dns: local resolver proxy dropping query from {peer} because the in-flight cap is reached"
                    );
                    if let Some(response) = dns::build_dns_servfail_response(query.as_ref()) {
                        let _ = socket.send_to(&response, peer).await;
                    }
                    continue;
                }
            };

            let socket = Arc::clone(&socket);
            let data_plane = Arc::clone(&data_plane);
            let remote = remote.clone();
            tokio::spawn(async move {
                let _permit = permit;
                eprintln!(
                    "dns: forwarding local resolver query from {peer} over {} to {}:{}",
                    data_plane.label(),
                    remote.host,
                    remote.port
                );
                let response = match data_plane
                    .query_dns(remote, query.clone(), DEFAULT_TUN_IP)
                    .await
                {
                    Ok(response) => response,
                    Err(err) => {
                        eprintln!("dns: local resolver proxy query failed for {peer}: {err:#}");
                        match dns::build_dns_servfail_response(query.as_ref()) {
                            Some(response) => Bytes::from(response),
                            None => return,
                        }
                    }
                };
                if let Err(err) = socket.send_to(response.as_ref(), peer).await {
                    eprintln!("dns: local resolver proxy response to {peer} failed: {err:#}");
                }
            });
        }
    });

    Ok(LocalDnsProxy { task })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnixShutdownSignal {
    Terminate,
    Hangup,
}

#[cfg(unix)]
impl UnixShutdownSignal {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::Hangup => "hangup",
        }
    }

    pub(crate) fn os_name(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Hangup => "SIGHUP",
        }
    }

    pub(crate) fn kind(self) -> tokio::signal::unix::SignalKind {
        match self {
            Self::Terminate => tokio::signal::unix::SignalKind::terminate(),
            Self::Hangup => tokio::signal::unix::SignalKind::hangup(),
        }
    }
}

#[cfg(unix)]
pub(crate) fn unix_shutdown_signals() -> [UnixShutdownSignal; 2] {
    [UnixShutdownSignal::Terminate, UnixShutdownSignal::Hangup]
}

pub(crate) fn shutdown_signal() -> ShutdownSignalFuture {
    Box::pin(wait_for_shutdown_signal())
}

async fn wait_for_shutdown_signal() -> Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::signal;

        let [terminate, hangup] = unix_shutdown_signals();
        let mut sigterm = signal(terminate.kind())
            .with_context(|| format!("failed to listen for {}", terminate.os_name()))?;
        let mut sighup = signal(hangup.kind())
            .with_context(|| format!("failed to listen for {}", hangup.os_name()))?;
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl+C")?;
                Ok("interrupt")
            }
            received = sigterm.recv() => {
                received.with_context(|| format!("{} stream closed", terminate.os_name()))?;
                Ok(terminate.label())
            }
            received = sighup.recv() => {
                received.with_context(|| format!("{} stream closed", hangup.os_name()))?;
                Ok(hangup.label())
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for Ctrl+C")?;
        Ok("interrupt")
    }
}

pub(crate) fn virtual_dns_ip(tun_ip: Ipv4Addr, tun_prefix: u8) -> Result<Ipv4Addr> {
    if tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if tun_prefix > 30 {
        bail!("--dns requires a TUN prefix of /30 or wider so Rustle can reserve a virtual DNS IP");
    }

    let mask = u32::from(prefix_to_mask(tun_prefix));
    let network = u32::from(tun_ip) & mask;
    let broadcast = network | !mask;
    let first = network + 1;
    let last = broadcast - 1;
    let tun = u32::from(tun_ip);
    let preferred = (network + 53).clamp(first, last);

    for candidate in [preferred, first, first.saturating_add(1), last] {
        if candidate >= first && candidate <= last && candidate != tun {
            return Ok(Ipv4Addr::from(candidate));
        }
    }

    bail!("no usable virtual DNS IP in TUN subnet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_dns_ip_uses_stable_host_inside_tun_subnet() {
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 255, 255, 1), 24).unwrap(),
            Ipv4Addr::new(10, 255, 255, 53)
        );
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 30).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 31).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_shutdown_signals_include_hangup_and_terminate() {
        let signals: Vec<_> = unix_shutdown_signals()
            .into_iter()
            .map(|signal| (signal.label(), signal.os_name()))
            .collect();

        assert_eq!(
            signals,
            vec![("terminate", "SIGTERM"), ("hangup", "SIGHUP")]
        );
    }
}
