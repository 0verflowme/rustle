use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tun_rs::DeviceBuilder;

use crate::data_plane::{
    query_dns_over_transport, BridgeRuntimeOptions, BridgeTransportKind, Destination, DnsTransport,
};
use crate::packet_engine::{
    run_tunnel_loop, smol_now, tun_ipv4_packet, write_packets_to_tun, MAX_IN_FLIGHT_DNS_QUERIES,
    PACKET_BUF_SIZE,
};
use crate::remote_helper::effective_bridge_agent_command;
use crate::{
    connect_bridge_runtime, parse_destination, resolve_ssh_target,
    validate_agent_session_request_count, validate_ssh_session_count,
};
use crate::{dns, platform, tcp_core, SshArgs, TunCaptureArgs, TunnelArgs, DEFAULT_TUN_IP};

pub(crate) async fn run_tun_capture(args: TunCaptureArgs) -> Result<()> {
    validate_tun_args(&args)?;
    let target_routes = expand_target_routes(&args.targets)?;

    let builder =
        configured_tun_builder(args.tun_ip, args.tun_prefix, args.mtu, args.name.as_deref())?;

    let dev = builder
        .build_async()
        .context("failed to create TUN device; root/administrator privileges are required")?;
    let if_name = dev.name().context("failed to read TUN interface name")?;
    let if_index = dev
        .if_index()
        .context("failed to read TUN interface index")?;

    eprintln!(
        "tun: created {if_name} index={if_index} mtu={} addr={}/{}",
        args.mtu, args.tun_ip, args.tun_prefix
    );

    let routes = add_target_routes(&target_routes, &if_name, if_index, args.tun_ip)?;
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = capture_packets(dev, flow_manager, args.exit_after_packets).await;
    drop(routes);
    result
}

pub(crate) async fn run_tunnel(args: TunnelArgs) -> Result<()> {
    validate_tunnel_args(&args)?;
    let agent_command = effective_bridge_agent_command(
        args.bridge_transport,
        args.agent_command.as_deref(),
        args.agent_path.as_deref(),
    )?;
    let target_routes = expand_target_routes(&args.targets)?;
    let dns_remote = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    let ssh_control_ip = args
        .ssh
        .ssh_server
        .as_deref()
        .map(|_| ssh_control_ip_to_protect(&args.ssh, &target_routes))
        .transpose()?
        .flatten();

    let builder =
        configured_tun_builder(args.tun_ip, args.tun_prefix, args.mtu, args.name.as_deref())?;
    let dev = builder
        .build_async()
        .context("failed to create TUN device; root/administrator privileges are required")?;
    let if_name = dev.name().context("failed to read TUN interface name")?;
    let if_index = dev
        .if_index()
        .context("failed to read TUN interface index")?;

    eprintln!(
        "tun: created {if_name} index={if_index} mtu={} addr={}/{}",
        args.mtu, args.tun_ip, args.tun_prefix
    );

    let (bridge_runtime, dns_transport) = connect_bridge_runtime(
        &args.ssh,
        args.bridge_transport,
        &agent_command,
        args.mtu,
        Some(&dns_remote),
        BridgeRuntimeOptions {
            ssh_sessions: args.ssh_sessions,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: true,
        },
    )
    .await?;
    let control_route = match ssh_control_ip {
        Some(ip) => add_ssh_control_route(ip)?,
        None => None,
    };
    let routes = add_target_routes(&target_routes, &if_name, if_index, args.tun_ip)?;
    let (dns_guard, local_dns_proxy) = if args.configure_dns {
        let virtual_dns_ip = virtual_dns_ip(args.tun_ip, args.tun_prefix)?;
        let system_dns_ip = platform::system_dns_server_ip(virtual_dns_ip);
        let local_dns_proxy = if system_dns_ip.is_loopback() {
            Some(
                start_local_dns_proxy(system_dns_ip, dns_transport.clone(), dns_remote.clone())
                    .await
                    .with_context(|| {
                        format!("failed to start local DNS proxy on {system_dns_ip}:53")
                    })?,
            )
        } else {
            None
        };
        let guard = platform::configure_system_dns(&if_name, system_dns_ip)
            .with_context(|| format!("failed to configure system DNS for {if_name}"))?;
        eprintln!("dns: configured host resolver to use DNS {system_dns_ip}");
        (Some(guard), local_dns_proxy)
    } else {
        (None, None)
    };
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = run_tunnel_loop(
        dev,
        flow_manager,
        bridge_runtime,
        dns_transport,
        dns_remote,
        Duration::from_millis(args.udp_idle_timeout_ms),
        Box::pin(shutdown_signal()),
    )
    .await;
    drop(dns_guard);
    drop(local_dns_proxy);
    drop(routes);
    drop(control_route);
    result
}

pub(crate) fn configured_tun_builder(
    tun_ip: Ipv4Addr,
    tun_prefix: u8,
    mtu: u16,
    name: Option<&str>,
) -> Result<DeviceBuilder> {
    let mut builder = DeviceBuilder::new().ipv4(tun_ip, tun_prefix, None).mtu(mtu);
    if let Some(name) = name {
        builder = builder.name(name);
    }
    platform::prepare_tun_builder(builder)
}

pub(crate) async fn capture_packets(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    exit_after_packets: Option<u64>,
) -> Result<()> {
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let started_at = StdInstant::now();
    let mut captured_packets = 0_u64;
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                eprintln!("signal: {} received", signal?);
                return Ok(());
            }
            result = dev.recv(&mut buf) => {
                let len = result.context("failed to read packet from TUN device")?;
                captured_packets = captured_packets.saturating_add(1);
                let Some(packet) = tun_ipv4_packet(&buf[..len]) else {
                    eprintln!("packet: len={len} non_ipv4");
                    continue;
                };
                match parse_ipv4_metadata(packet) {
                    Ok(packet) => {
                        eprintln!(
                            "packet: len={} total_len={} proto={} src={} dst={}",
                            len,
                            packet.total_len,
                            packet.protocol,
                            packet.src,
                            packet.dst
                        );
                        match tcp_core::parse_ipv4_tcp_segment(&buf[..len]) {
                            Ok(Some(segment)) => {
                                eprintln!(
                                    "tcp: {}:{} -> {}:{} syn={} ack={} fin={} rst={} opening_syn={} payload_len={}",
                                    segment.flow.src_ip,
                                    segment.flow.src_port,
                                    segment.flow.dst_ip,
                                    segment.flow.dst_port,
                                    segment.flags.syn,
                                    segment.flags.ack,
                                    segment.flags.fin,
                                    segment.flags.rst,
                                    segment.flags.is_opening_syn(),
                                    segment.payload_len
                                );
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!("tcp: parse_error={err}");
                            }
                        }

                        flow_manager
                            .ingest_packet_into(
                                smol_now(started_at),
                                &buf[..len],
                                &mut outbound_packets,
                            )
                            .context("failed to feed packet into userspace TCP engine")?;
                        let _ = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                        for snapshot in flow_manager.snapshots() {
                            eprintln!(
                                "flow: {:?} state={:?} buffered_rx={}",
                                snapshot.key,
                                snapshot.state,
                                snapshot.buffered_rx
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("packet: len={len} parse_error={err}");
                    }
                }
                if exit_after_packets
                    .is_some_and(|limit| captured_packets >= limit)
                {
                    eprintln!("capture: exit-after-packets reached ({captured_packets})");
                    return Ok(());
                }
            }
        }
    }
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

pub(crate) async fn shutdown_signal() -> Result<&'static str> {
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

pub(crate) fn validate_tun_args(args: &TunCaptureArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
    platform::preflight_route_management().context("route preflight failed")?;
    if args.tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if args.mtu < 576 {
        bail!("mtu must be at least the IPv4 minimum of 576 bytes");
    }
    if args.mtu as usize > PACKET_BUF_SIZE {
        bail!("mtu must not exceed packet buffer size {PACKET_BUF_SIZE}");
    }
    Ok(())
}

pub(crate) fn validate_tunnel_args(args: &TunnelArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
    let Some(remote) = args.ssh.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    let _ = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto
            | BridgeTransportKind::DirectTcpip
            | BridgeTransportKind::QuicNative
    ) {
        validate_ssh_session_count(args.ssh_sessions)?;
    }
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto | BridgeTransportKind::Agent | BridgeTransportKind::QuicAgent
    ) {
        validate_agent_session_request_count(args.agent_sessions)?;
    }
    if args.udp_idle_timeout_ms == 0 {
        bail!("udp-idle-timeout-ms must be at least 1");
    }
    platform::preflight_route_management().context("route preflight failed")?;
    if args.tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if args.mtu < 576 {
        bail!("mtu must be at least the IPv4 minimum of 576 bytes");
    }
    if args.mtu as usize > PACKET_BUF_SIZE {
        bail!("mtu must not exceed packet buffer size {PACKET_BUF_SIZE}");
    }
    if args.configure_dns {
        virtual_dns_ip(args.tun_ip, args.tun_prefix)?;
        platform::preflight_system_dns().context("DNS preflight failed")?;
    }
    let _ = remote;
    Ok(())
}

pub(crate) fn parse_target_cidr(input: &str) -> std::result::Result<Ipv4Net, String> {
    if let Ok(cidr) = input.parse::<Ipv4Net>() {
        return Ok(cidr);
    }

    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| format!("target CIDR must be IPv4/prefix, got {input}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("target CIDR prefix must be 0..=32, got {input}"))?;
    if prefix > 32 {
        return Err(format!("target CIDR prefix must be <= 32, got {input}"));
    }

    let parts = parse_abbreviated_ipv4_octets(addr, input)?;
    let ip = Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]);
    Ipv4Net::new(ip, prefix).map_err(|err| format!("invalid target CIDR {input}: {err}"))
}

pub(crate) fn parse_abbreviated_ipv4_octets(
    addr: &str,
    original: &str,
) -> std::result::Result<[u8; 4], String> {
    let raw_parts = addr.split('.').collect::<Vec<_>>();
    if raw_parts.is_empty() || raw_parts.len() > 4 {
        return Err(format!(
            "invalid abbreviated IPv4 address in target CIDR {original}"
        ));
    }

    let mut octets = [0_u8; 4];
    for (index, part) in raw_parts.iter().enumerate() {
        if part.is_empty() {
            return Err(format!(
                "invalid abbreviated IPv4 address in target CIDR {original}"
            ));
        }
        octets[index] = part
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 octet {part:?} in target CIDR {original}"))?;
    }
    Ok(octets)
}

pub(crate) fn expand_target_routes(targets: &[Ipv4Net]) -> Result<Vec<Ipv4Net>> {
    if targets.is_empty() {
        bail!("at least one target CIDR is required");
    }
    let mut expanded = Vec::with_capacity(targets.len().saturating_add(1));
    for target in targets {
        if target.prefix_len() == 0 {
            expanded.push("0.0.0.0/1".parse().expect("valid split default route"));
            expanded.push("128.0.0.0/1".parse().expect("valid split default route"));
        } else if !expanded.contains(target) {
            expanded.push(*target);
        }
    }

    if expanded.len() > smoltcp::config::IFACE_MAX_ROUTE_COUNT {
        bail!(
            "too many target CIDRs: {} requested, maximum is {}",
            expanded.len(),
            smoltcp::config::IFACE_MAX_ROUTE_COUNT
        );
    }
    Ok(expanded)
}

pub(crate) fn ssh_control_ip_to_protect(
    ssh: &SshArgs,
    targets: &[Ipv4Net],
) -> Result<Option<Ipv4Addr>> {
    let ssh_addr = resolve_ssh_target(ssh)?.addr;
    let addrs = ssh_addr
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH server address {ssh_addr}"))?;

    for addr in addrs {
        if let IpAddr::V4(ip) = addr.ip() {
            for target in targets {
                if target.contains(&ip) {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}

pub(crate) fn target_route_parts(targets: &[Ipv4Net]) -> Vec<tcp_core::Ipv4NetParts> {
    targets
        .iter()
        .map(|target| tcp_core::Ipv4NetParts::new(target.network(), target.prefix_len()))
        .collect()
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
    transport: DnsTransport,
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
            let transport = transport.clone();
            let remote = remote.clone();
            tokio::spawn(async move {
                let _permit = permit;
                eprintln!(
                    "dns: forwarding local resolver query from {peer} over {} to {}:{}",
                    transport.label(),
                    remote.host,
                    remote.port
                );
                let response = match query_dns_over_transport(
                    transport,
                    &remote,
                    query.as_ref(),
                    DEFAULT_TUN_IP,
                )
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

#[derive(Debug)]
pub(crate) struct Ipv4PacketMetadata {
    pub(crate) total_len: u16,
    pub(crate) protocol: u8,
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
}

pub(crate) fn parse_ipv4_metadata(packet: &[u8]) -> Result<Ipv4PacketMetadata> {
    if packet.len() < 20 {
        bail!("short IPv4 packet");
    }

    let version = packet[0] >> 4;
    if version != 4 {
        bail!("not IPv4 version {version}");
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 {
        bail!("invalid IPv4 header length {header_len}");
    }
    if packet.len() < header_len {
        bail!("truncated IPv4 header");
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if usize::from(total_len) > packet.len() {
        bail!("truncated IPv4 payload");
    }

    Ok(Ipv4PacketMetadata {
        total_len,
        protocol: packet[9],
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExistingRoute {
    pub(crate) gateway: Option<Ipv4Addr>,
    pub(crate) if_name: Option<String>,
    pub(crate) if_index: Option<u32>,
}

pub(crate) trait ControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute>;
    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
pub(crate) struct SystemControlRouteCommandExecutor;

impl ControlRouteCommandExecutor for SystemControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute> {
        lookup_existing_route_to(target)
    }

    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()> {
        run_control_route_command(action, target, route)
    }
}

pub(crate) struct ControlRouteGuard<
    E: ControlRouteCommandExecutor = SystemControlRouteCommandExecutor,
> {
    target: Ipv4Addr,
    route: ExistingRoute,
    executor: E,
}

impl<E: ControlRouteCommandExecutor> ControlRouteGuard<E> {
    fn add(target: Ipv4Addr, route: ExistingRoute, executor: E) -> Result<Self> {
        executor.run_control_route_command(RouteAction::Add, target, &route)?;
        Ok(Self {
            target,
            route,
            executor,
        })
    }
}

impl<E: ControlRouteCommandExecutor> Drop for ControlRouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) =
            self.executor
                .run_control_route_command(RouteAction::Delete, self.target, &self.route)
        {
            eprintln!(
                "route: failed to delete SSH control host route {}: {err:#}",
                self.target
            );
        } else {
            eprintln!("route: deleted SSH control host route {}", self.target);
        }
    }
}

pub(crate) fn add_ssh_control_route(target: Ipv4Addr) -> Result<Option<ControlRouteGuard>> {
    add_ssh_control_route_with(target, SystemControlRouteCommandExecutor)
}

pub(crate) fn add_ssh_control_route_with<E: ControlRouteCommandExecutor + Clone>(
    target: Ipv4Addr,
    executor: E,
) -> Result<Option<ControlRouteGuard<E>>> {
    let route = executor
        .lookup_route_to(target)
        .with_context(|| format!("failed to inspect existing route to SSH server {target}"))?;
    if !route_requires_control_host_route(&route) {
        eprintln!(
            "route: existing route to SSH control connection {target} is already direct via {route:?}"
        );
        return Ok(None);
    }
    let guard = ControlRouteGuard::add(target, route.clone(), executor)
        .with_context(|| format!("failed to add SSH control host route for {target}"))?;
    eprintln!("route: protected SSH control connection to {target} via {route:?}");
    Ok(Some(guard))
}

pub(crate) fn route_requires_control_host_route(route: &ExistingRoute) -> bool {
    route
        .gateway
        .is_some_and(|gateway| !gateway.is_unspecified())
}

pub(crate) trait RouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
pub(crate) struct SystemRouteCommandExecutor;

impl RouteCommandExecutor for SystemRouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()> {
        run_route_command(action, target, if_name, if_index, gateway)
    }
}

pub(crate) struct RouteGuard<E: RouteCommandExecutor = SystemRouteCommandExecutor> {
    target: Ipv4Net,
    if_name: String,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
}

impl<E: RouteCommandExecutor> RouteGuard<E> {
    fn add(
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
        executor: E,
    ) -> Result<Self> {
        executor.run_route_command(RouteAction::Add, target, if_name, if_index, gateway)?;
        Ok(Self {
            target,
            if_name: if_name.to_owned(),
            if_index,
            gateway,
            executor,
        })
    }
}

pub(crate) fn add_target_routes(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<Vec<RouteGuard>> {
    add_target_routes_with(
        targets,
        if_name,
        if_index,
        gateway,
        SystemRouteCommandExecutor,
    )
}

pub(crate) fn add_target_routes_with<E: RouteCommandExecutor + Clone>(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
) -> Result<Vec<RouteGuard<E>>> {
    let mut routes = Vec::with_capacity(targets.len());
    for target in targets {
        let route = RouteGuard::add(*target, if_name, if_index, gateway, executor.clone())
            .with_context(|| format!("failed to add target route {target}"))?;
        eprintln!("route: added {target} via {if_name}");
        routes.push(route);
    }
    Ok(routes)
}

impl<E: RouteCommandExecutor> Drop for RouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) = self.executor.run_route_command(
            RouteAction::Delete,
            self.target,
            &self.if_name,
            self.if_index,
            self.gateway,
        ) {
            eprintln!("route: failed to delete {}: {err:#}", self.target);
        } else {
            eprintln!("route: deleted {}", self.target);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAction {
    Add,
    Delete,
}

pub(crate) fn run_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<()> {
    let (program, args) = route_command(action, target, if_name, if_index, gateway)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

pub(crate) fn run_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<()> {
    let (program, args) = control_route_command(action, target, route)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute control route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "control route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("route")
        .args(["-n", "get", &target.to_string()])
        .output()
        .context("failed to execute route -n get")?;
    if !output.status.success() {
        bail!(
            "route -n get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_macos_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "linux")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("ip")
        .args(["-4", "route", "get", &target.to_string()])
        .output()
        .context("failed to execute ip route get")?;
    if !output.status.success() {
        bail!(
            "ip route get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_linux_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "windows")]
pub(crate) fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let script = format!(
        "$r = Find-NetRoute -RemoteIPAddress '{}' | Select-Object -First 1; if ($null -eq $r) {{ exit 1 }}; '{{0}} {{1}}' -f $r.InterfaceIndex, $r.NextHop",
        target
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("failed to execute Find-NetRoute")?;
    if !output.status.success() {
        bail!(
            "Find-NetRoute {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_windows_find_net_route(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn lookup_existing_route_to(_target: Ipv4Addr) -> Result<ExistingRoute> {
    bail!(
        "SSH control route protection is not implemented for {}",
        env::consts::OS
    );
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse_macos_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => {
                gateway = value.trim().parse::<Ipv4Addr>().ok();
            }
            "interface" => {
                let value = value.trim();
                if !value.is_empty() {
                    if_name = Some(value.to_owned());
                }
            }
            _ => {}
        }
    }

    if gateway.is_none() && if_name.is_none() {
        bail!("route output did not include a gateway or interface");
    }
    Ok(ExistingRoute {
        gateway,
        if_name,
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_linux_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;
    let tokens: Vec<_> = output.split_whitespace().collect();
    for pair in tokens.windows(2) {
        match pair[0] {
            "via" => gateway = pair[1].parse::<Ipv4Addr>().ok(),
            "dev" => if_name = Some(pair[1].to_owned()),
            _ => {}
        }
    }

    let Some(if_name) = if_name else {
        bail!("ip route output did not include a dev field");
    };
    Ok(ExistingRoute {
        gateway,
        if_name: Some(if_name),
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn parse_windows_find_net_route(output: &str) -> Result<ExistingRoute> {
    let mut fields = output.split_whitespace();
    let if_index = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include InterfaceIndex"))?
        .parse::<u32>()
        .context("failed to parse Find-NetRoute InterfaceIndex")?;
    let gateway = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include NextHop"))?
        .parse::<Ipv4Addr>()
        .context("failed to parse Find-NetRoute NextHop")?;

    Ok(ExistingRoute {
        gateway: Some(gateway),
        if_name: None,
        if_index: Some(if_index),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(linux_route_command(action, target, if_name))
}

#[cfg(target_os = "linux")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    linux_control_route_command(action, target, route)
}

#[cfg(target_os = "macos")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(macos_route_command(action, target, if_name))
}

#[cfg(target_os = "macos")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    macos_control_route_command(action, target, route)
}

#[cfg(target_os = "windows")]
pub(crate) fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    _if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(windows_route_command(action, target, if_index, gateway))
}

#[cfg(target_os = "windows")]
pub(crate) fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    windows_control_route_command(action, target, route)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    (
        "ip".to_owned(),
        vec![
            "route".to_owned(),
            verb.to_owned(),
            target.to_string(),
            "dev".to_owned(),
            if_name.to_owned(),
        ],
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn linux_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    let mut args = vec!["route".to_owned(), verb.to_owned(), format!("{target}/32")];
    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway.filter(|gateway| !gateway.is_unspecified()) {
            args.extend(["via".to_owned(), gateway.to_string()]);
        }
        let if_name = route
            .if_name
            .as_deref()
            .ok_or_else(|| anyhow!("Linux control route requires an interface name"))?;
        args.extend(["dev".to_owned(), if_name.to_owned()]);
    }

    Ok(("ip".to_owned(), args))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };

    let mut args = if target.prefix_len() == 32 {
        vec![
            verb.to_owned(),
            "-host".to_owned(),
            target.addr().to_string(),
        ]
    } else {
        vec![
            verb.to_owned(),
            "-net".to_owned(),
            target.network().to_string(),
            "-netmask".to_owned(),
            prefix_to_mask(target.prefix_len()).to_string(),
        ]
    };

    if matches!(action, RouteAction::Add) {
        args.extend(["-interface".to_owned(), if_name.to_owned()]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };
    let mut args = vec![verb.to_owned(), "-host".to_owned(), target.to_string()];

    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway {
            args.push(gateway.to_string());
        } else {
            let if_name = route
                .if_name
                .as_deref()
                .ok_or_else(|| anyhow!("macOS control route requires a gateway or interface"))?;
            args.extend(["-interface".to_owned(), if_name.to_owned()]);
        }
    }

    Ok(("route".to_owned(), args))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_index: u32,
    gateway: Ipv4Addr,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "ADD",
        RouteAction::Delete => "DELETE",
    };
    let mut args = vec![
        verb.to_owned(),
        target.network().to_string(),
        "MASK".to_owned(),
        prefix_to_mask(target.prefix_len()).to_string(),
        gateway.to_string(),
    ];
    if matches!(action, RouteAction::Add) {
        args.extend([
            "METRIC".to_owned(),
            "1".to_owned(),
            "IF".to_owned(),
            if_index.to_string(),
        ]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn windows_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let if_index = route
        .if_index
        .ok_or_else(|| anyhow!("Windows control route requires an interface index"))?;
    let gateway = route
        .gateway
        .ok_or_else(|| anyhow!("Windows control route requires a next hop"))?;
    Ok(windows_route_command(
        action,
        Ipv4Net::new(target, 32).expect("host route prefix is valid"),
        if_index,
        gateway,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn route_command(
    _action: RouteAction,
    _target: Ipv4Net,
    _if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    bail!("route management is not implemented for this operating system")
}

pub(crate) fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(bits)
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

    bail!("could not reserve a virtual DNS IP inside {tun_ip}/{tun_prefix}")
}
