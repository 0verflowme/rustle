use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};

use crate::control_plane::connect_bridge_runtime;
use crate::data_plane::{spawn_dns_query_on_data_plane, DataPlane, RuntimeDataPlane};
use crate::defaults::DEFAULT_TUN_IP;
use crate::packet_engine::{
    parse_dns_request_for_tunnel, parse_udp_request_for_agent_tunnel, smol_now, tun_ipv4_packet,
    TunnelEngine, UdpAssociationTransportPlan, MAX_ACTIVE_UDP_ASSOCIATIONS,
    MAX_IN_FLIGHT_DNS_QUERIES, PACKET_BUF_SIZE,
};
use crate::remote_helper::bridge_agent_command_plan;
use crate::routing::{
    add_target_routes, expand_target_routes, ssh_control_ip_to_protect, target_route_parts,
};
use crate::ssh_control::{validate_agent_session_request_count, validate_ssh_session_count};
use crate::transport_model::{
    parse_destination, BridgeRuntimeOptions, BridgeTransportKind, Destination, DnsResponseEvent,
    UdpAssociationEvents,
};
use crate::tun_io::TunWriter;
pub(crate) use crate::tunnel_lifecycle::virtual_dns_ip;
use crate::tunnel_lifecycle::{
    open_tun, open_tunnel_host, shutdown_signal, ShutdownSignalFuture, TunConfig, TunnelCleanup,
    TunnelHostConfig,
};
use crate::{platform, tcp_core, TunCaptureArgs, TunnelArgs};

const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) async fn run_tun_capture(args: TunCaptureArgs) -> Result<()> {
    validate_tun_args(&args)?;
    let target_routes = expand_target_routes(&args.targets)?;
    let tun = open_tun(&TunConfig::new(
        args.tun_ip,
        args.tun_prefix,
        args.mtu,
        args.name,
    ))?;

    let routes = add_target_routes(&target_routes, &tun.if_name, tun.if_index, args.tun_ip)?;
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = capture_packets(tun.dev, flow_manager, args.exit_after_packets).await;
    drop(routes);
    result
}

pub(crate) async fn run_tunnel(args: TunnelArgs) -> Result<()> {
    validate_tunnel_args(&args)?;
    let tunnel = PreparedTunnel::prepare(args).await?;
    tunnel.run().await
}

struct PreparedTunnel {
    supervisor: TunnelSupervisor,
    cleanup: TunnelCleanup,
}

impl PreparedTunnel {
    async fn prepare(args: TunnelArgs) -> Result<Self> {
        let helper_plan = bridge_agent_command_plan(
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
        let tun_config = TunConfig::new(args.tun_ip, args.tun_prefix, args.mtu, args.name);
        let tun = open_tun(&tun_config)?;

        let (bridge_runtime, _dns_transport) = connect_bridge_runtime(
            &args.ssh,
            args.bridge_transport,
            helper_plan,
            args.mtu,
            Some(&dns_remote),
            BridgeRuntimeOptions {
                ssh_sessions: args.ssh_sessions,
                agent_sessions: args.agent_sessions,
                fast_start_auto_agent_lanes: true,
            },
        )
        .await?;
        let data_plane: Arc<dyn DataPlane> =
            Arc::new(RuntimeDataPlane::from_bridge_runtime(bridge_runtime));
        let host = open_tunnel_host(TunnelHostConfig {
            tun_config,
            tun,
            target_routes,
            ssh_control_ip,
            configure_dns: args.configure_dns,
            dns_remote: dns_remote.clone(),
            data_plane: Arc::clone(&data_plane),
        })
        .await?;

        let flow_manager = tcp_core::FlowManager::new(
            args.tun_ip,
            args.tun_prefix,
            &host.route_parts,
            usize::from(args.mtu),
        )
        .context("failed to initialize userspace TCP flow manager")?;

        Ok(Self {
            supervisor: TunnelSupervisor::new(
                host.tun.dev,
                flow_manager,
                data_plane,
                dns_remote,
                Duration::from_millis(args.udp_idle_timeout_ms),
                shutdown_signal(),
            ),
            cleanup: host.cleanup,
        })
    }

    async fn run(self) -> Result<()> {
        let Self {
            supervisor,
            cleanup,
        } = self;
        let result = supervisor.run().await;
        drop(cleanup);
        result
    }
}

pub(crate) struct TunnelSupervisor {
    dev: tun_rs::AsyncDevice,
    flow_manager: tcp_core::FlowManager,
    data_plane: Arc<dyn DataPlane>,
    dns_remote: Destination,
    udp_association_idle_timeout: Duration,
    shutdown: ShutdownSignalFuture,
}

impl TunnelSupervisor {
    pub(crate) fn new(
        dev: tun_rs::AsyncDevice,
        flow_manager: tcp_core::FlowManager,
        data_plane: Arc<dyn DataPlane>,
        dns_remote: Destination,
        udp_association_idle_timeout: Duration,
        shutdown: ShutdownSignalFuture,
    ) -> Self {
        Self {
            dev,
            flow_manager,
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            shutdown,
        }
    }
}

impl TunnelSupervisor {
    pub(crate) async fn run(self) -> Result<()> {
        let Self {
            dev,
            flow_manager,
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            mut shutdown,
        } = self;

        let tun = TunWriter::new(dev);
        let mut buf = vec![0_u8; PACKET_BUF_SIZE];
        let mut udp_actions = Vec::new();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1024);
        let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel(DNS_EVENT_CHANNEL_DEPTH);
        let (udp_response_tx, mut udp_response_rx) =
            tokio::sync::mpsc::channel(UDP_RESPONSE_EVENT_CHANNEL_DEPTH);
        let (udp_close_tx, mut udp_close_rx) =
            tokio::sync::mpsc::channel(UDP_CLOSE_EVENT_CHANNEL_DEPTH);
        let udp_events = UdpAssociationEvents {
            response_tx: udp_response_tx,
            close_tx: udp_close_tx,
        };
        let mut engine = TunnelEngine::new(flow_manager);
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let mut stats_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + STATS_LOG_INTERVAL,
            STATS_LOG_INTERVAL,
        );
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                signal = &mut shutdown => {
                    eprintln!("signal: {} received", signal?);
                    eprintln!(
                        "stats: final {}",
                        engine.status_line(data_plane.snapshot().await)
                    );
                    return Ok(());
                }
                result = tun.recv(&mut buf) => {
                    let len = result?;
                    engine.record_tun_rx(len);
                    let Some(packet) = tun_ipv4_packet(&buf[..len]) else {
                        continue;
                    };
                    if let Some(request) = parse_dns_request_for_tunnel(packet) {
                        engine.record_dns_forwarded();
                        eprintln!(
                            "dns: forwarding UDP query {}:{} -> {}:{} over {} to {}:{}",
                            request.src_ip,
                            request.src_port,
                            request.dst_ip,
                            request.dst_port,
                            data_plane.label(),
                            dns_remote.host,
                            dns_remote.port
                        );
                        if engine.try_admit_dns() {
                            spawn_dns_query_on_data_plane(
                                Arc::clone(&data_plane),
                                dns_remote.clone(),
                                request,
                                dns_tx.clone(),
                                DEFAULT_TUN_IP,
                            );
                        } else {
                            eprintln!(
                                "dns: dropping query because {} DNS queries are already in flight",
                                engine.dns_inflight_limit()
                            );
                            engine.record_dns_drop();
                            let tun_write = tun
                                .write_dns_event(DnsResponseEvent {
                                    request,
                                    result: Err("DNS in-flight limit reached".to_owned()),
                                })
                                .await?;
                            engine.record_tun_write(tun_write);
                        }
                        continue;
                    }
                    if let Some(request) = parse_udp_request_for_agent_tunnel(packet) {
                        let udp_transport = data_plane.caps().udp_associations.then(|| {
                            let label = data_plane
                                .udp_label()
                                .expect("UDP-capable data plane must provide a UDP label");
                            UdpAssociationTransportPlan::new(label, Arc::clone(&data_plane))
                        });
                        engine.handle_udp_datagram(
                            udp_transport,
                            request,
                            udp_events.clone(),
                            udp_association_idle_timeout,
                            &mut udp_actions,
                            &mut |transport, key, from_local, events, idle_timeout| {
                                transport.spawn_udp_association(key, from_local, events, idle_timeout);
                            },
                        );
                        continue;
                    }

                    engine
                        .ingest_tcp_packet(packet)
                        .context("failed to feed packet into userspace TCP engine")?;
                    tun.write_engine_packets(&mut engine).await?;
                    engine.ensure_bridges(
                        data_plane.admission_limits(),
                        |id, event_tx| data_plane.spawn_tcp_bridge(id, event_tx),
                        event_tx.clone(),
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(&mut engine).await?;
                    engine.expire_and_prune()?;
                }
                event = dns_rx.recv() => {
                    if let Some(event) = event {
                        engine.complete_dns();
                        let remote_ok = event.result.is_ok();
                        let tun_write = tun.write_dns_event(event).await?;
                        engine.record_dns_delivery(remote_ok, tun_write);
                    }
                }
                event = udp_response_rx.recv() => {
                    if let Some(event) = event {
                        let tun_write = tun.write_udp_response(event.key, event.payload).await?;
                        engine.record_udp_delivery(tun_write);
                    }
                }
                event = udp_close_rx.recv() => {
                    if let Some(event) = event {
                        engine.close_udp_association(event.key);
                        if let Some(error) = event.error {
                            eprintln!(
                                "udp: association {}:{} -> {}:{} closed with error: {error}",
                                event.key.src_ip,
                                event.key.src_port,
                                event.key.dst_ip,
                                event.key.dst_port,
                            );
                            engine.record_udp_close_error();
                        }
                    }
                }
                event = event_rx.recv(), if !engine.should_pause_bridge_events() => {
                    let Some(event) = event else {
                        bail!("SSH bridge event channel closed");
                    };
                    engine.handle_bridge_event(event)?;
                    engine.poll_tcp();
                    tun.write_engine_packets(&mut engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(&mut engine).await?;
                    engine.expire_and_prune()?;
                }
                _ = stats_tick.tick() => {
                    eprintln!(
                        "stats: {}",
                        engine.status_line(data_plane.snapshot().await)
                    );
                }
                _ = tick.tick() => {
                    engine.poll_tcp();
                    tun.write_engine_packets(&mut engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(&mut engine).await?;
                    engine.ensure_bridges(
                        data_plane.admission_limits(),
                        |id, event_tx| data_plane.spawn_tcp_bridge(id, event_tx),
                        event_tx.clone(),
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.expire_and_prune()?;
                }
            }
        }
    }
}

pub(crate) async fn capture_packets(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    exit_after_packets: Option<u64>,
) -> Result<()> {
    let tun = TunWriter::new(dev);
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let started_at = StdInstant::now();
    let mut captured_packets = 0_u64;
    let mut shutdown = shutdown_signal();

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                eprintln!("signal: {} received", signal?);
                return Ok(());
            }
            result = tun.recv(&mut buf) => {
                let len = result?;
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
                        let _ = tun.write_packets(&mut outbound_packets).await?;
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, CommandKind};
    use crate::defaults::{DEFAULT_MTU, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};
    use crate::transport_model::BridgeTransportKind;

    #[test]
    fn parse_ipv4_metadata_accepts_minimal_header() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 10, 10,
            0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let metadata = parse_ipv4_metadata(&packet).expect("valid packet");
        assert_eq!(metadata.total_len, 40);
        assert_eq!(metadata.protocol, 6);
        assert_eq!(metadata.src, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(metadata.dst, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn parse_ipv4_metadata_rejects_non_ipv4() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x60;
        let err = parse_ipv4_metadata(&packet).expect_err("IPv6 must not parse as IPv4");
        assert!(err.to_string().contains("not IPv4"));
    }

    #[test]
    fn validate_tun_args_accepts_full_tunnel_route() {
        let args = TunCaptureArgs {
            targets: vec!["0.0.0.0/0".parse().unwrap()],
            tun_ip: DEFAULT_TUN_IP,
            tun_prefix: DEFAULT_TUN_PREFIX,
            mtu: DEFAULT_MTU,
            name: None,
            exit_after_packets: None,
        };

        validate_tun_args(&args).expect("full tunnel should expand to split routes");
    }

    #[test]
    fn tunnel_subcommand_rejects_zero_udp_idle_timeout() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--udp-idle-timeout-ms",
            "0",
        ])
        .expect("tunnel CLI with zero UDP idle timeout");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        let err = validate_tunnel_args(&args).expect_err("zero UDP timeout must be rejected");
        assert!(err.to_string().contains("udp-idle-timeout-ms"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote_by_default() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        validate_tunnel_args(&args).expect("agent can use hostname DNS");
    }

    #[test]
    fn explicit_auto_tunnel_validates_direct_fallback_session_count() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "auto",
            "--ssh-sessions",
            "0",
        ])
        .expect("tunnel CLI with zero SSH sessions");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Auto);
        let err = validate_tunnel_args(&args)
            .expect_err("explicit auto fallback needs valid ssh sessions");
        assert!(err.to_string().contains("--ssh-sessions"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("agent supports hostname DNS remote through OpenTcpHost");
    }

    #[test]
    fn quic_native_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "quic-native",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with native QUIC hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("native QUIC supports hostname DNS remote through TCP host open");
    }
}
