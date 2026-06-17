use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::control_plane::{connect_tunnel_runtime, validate_agent_session_request_count};
use crate::data_plane::{spawn_dns_query_on_data_plane, spawn_udp_association, DataPlane};
use crate::defaults::DEFAULT_TUN_IP;
use crate::packet_engine::{
    parse_dns_request_for_tunnel, parse_udp_request_for_agent_tunnel, tun_ipv4_packet,
    TcpBridgeStart, TunnelEngine, UdpAssociationStart, UdpAssociationTransportPlan,
    UdpIngressAction, MAX_ACTIVE_UDP_ASSOCIATIONS, MAX_IN_FLIGHT_DNS_QUERIES, PACKET_BUF_SIZE,
};
use crate::remote_helper::bridge_agent_command_plan;
use crate::routing::{expand_target_routes, ssh_control_ip_to_protect};
use crate::ssh_control::validate_ssh_session_count;
use crate::transport_model::{
    parse_destination, BridgeTransportKind, Destination, DnsResponseEvent, TunnelRuntimeOptions,
    UdpAssociationEvents,
};
use crate::tun_io::TunWriter;
pub(crate) use crate::tunnel_lifecycle::virtual_dns_ip;
use crate::tunnel_lifecycle::{
    open_tun, open_tunnel_host, shutdown_signal, ShutdownSignal, TunConfig, TunnelCleanup,
    TunnelHostConfig,
};
use crate::{platform, ssh_bridge, tcp_core, TunnelArgs};

const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) async fn run_tunnel(args: TunnelArgs) -> Result<()> {
    validate_tunnel_args(&args)?;
    let shutdown = shutdown_signal().await?;
    let mut startup_shutdown = shutdown.clone();
    let Some(tunnel) = await_startup_or_shutdown(
        &mut startup_shutdown,
        PreparedTunnel::prepare(args, shutdown),
    )
    .await?
    else {
        return Ok(());
    };
    tunnel.run().await
}

struct PreparedTunnel {
    supervisor: TunnelSupervisor,
    cleanup: TunnelCleanup,
}

impl PreparedTunnel {
    async fn prepare(args: TunnelArgs, shutdown: ShutdownSignal) -> Result<Self> {
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

        let runtime = connect_tunnel_runtime(
            &args.ssh,
            args.bridge_transport,
            helper_plan,
            args.mtu,
            Some(&dns_remote),
            TunnelRuntimeOptions {
                ssh_sessions: args.ssh_sessions,
                agent_sessions: args.agent_sessions,
                fast_start_auto_agent_lanes: true,
            },
        )
        .await?;
        let data_plane = runtime.data_plane();
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
                shutdown,
            ),
            cleanup: host.cleanup,
        })
    }

    async fn run(mut self) -> Result<()> {
        let result = self.supervisor.run().await;
        let Self { cleanup, .. } = self;
        drop(cleanup);
        result
    }
}

pub(crate) struct TunnelSupervisor {
    dev: tun_rs::AsyncDevice,
    engine: TunnelEngine,
    data_plane: Arc<dyn DataPlane>,
    dns_remote: Destination,
    udp_association_idle_timeout: Duration,
    shutdown: ShutdownSignal,
}

impl TunnelSupervisor {
    pub(crate) fn new(
        dev: tun_rs::AsyncDevice,
        flow_manager: tcp_core::FlowManager,
        data_plane: Arc<dyn DataPlane>,
        dns_remote: Destination,
        udp_association_idle_timeout: Duration,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            dev,
            engine: TunnelEngine::new(flow_manager),
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            shutdown,
        }
    }
}

impl TunnelSupervisor {
    pub(crate) async fn run(&mut self) -> Result<()> {
        let Self {
            dev,
            engine,
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            shutdown,
        } = self;

        let tun = TunWriter::new(dev);
        let data_plane = Arc::clone(data_plane);
        let dns_remote = dns_remote.clone();
        let udp_association_idle_timeout = *udp_association_idle_timeout;
        let mut buf = vec![0_u8; PACKET_BUF_SIZE];
        let mut tcp_bridge_starts = Vec::new();
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
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let mut stats_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + STATS_LOG_INTERVAL,
            STATS_LOG_INTERVAL,
        );
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                signal = shutdown.recv() => {
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
                                engine.dns_admission_limit()
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
                            UdpAssociationTransportPlan::new(label)
                        });
                        engine.plan_udp_datagram(
                            udp_transport,
                            request,
                            udp_events.clone(),
                            udp_association_idle_timeout,
                            &mut udp_actions,
                        );
                        execute_udp_ingress_actions(engine, &data_plane, &mut udp_actions);
                        continue;
                    }

                    engine
                        .ingest_tcp_packet(packet)
                        .context("failed to feed packet into userspace TCP engine")?;
                    tun.write_engine_packets(engine).await?;
                    engine.plan_bridge_starts(
                        data_plane.admission_limits(),
                        &mut tcp_bridge_starts,
                    )?;
                    execute_tcp_bridge_starts(
                        engine,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        &event_tx,
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(engine).await?;
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
                    engine.handle_bridge_event_batch(event, &mut event_rx)?;
                    engine.poll_tcp();
                    tun.write_engine_packets(engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(engine).await?;
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
                    tun.write_engine_packets(engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun.write_engine_packets(engine).await?;
                    engine.plan_bridge_starts(
                        data_plane.admission_limits(),
                        &mut tcp_bridge_starts,
                    )?;
                    execute_tcp_bridge_starts(
                        engine,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        &event_tx,
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.expire_and_prune()?;
                }
            }
        }
    }
}

fn execute_tcp_bridge_starts(
    engine: &mut TunnelEngine,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<ssh_bridge::BridgeEvent>,
) -> Result<()> {
    for start in starts.drain(..) {
        let bridge = data_plane.spawn_tcp_bridge(start.id, start.ready_wait_ms, event_tx.clone());
        engine.register_tcp_bridge(start, bridge)?;
    }
    Ok(())
}

fn execute_udp_ingress_actions(
    engine: &mut TunnelEngine,
    data_plane: &Arc<dyn DataPlane>,
    actions: &mut Vec<UdpIngressAction>,
) {
    for action in actions.drain(..) {
        if let Some(start) = engine.apply_udp_ingress_action(action) {
            execute_udp_association_start(data_plane, start);
        }
    }
}

fn execute_udp_association_start(data_plane: &Arc<dyn DataPlane>, start: UdpAssociationStart) {
    eprintln!(
        "udp: opening association {}:{} -> {}:{} over {}",
        start.key.src_ip,
        start.key.src_port,
        start.key.dst_ip,
        start.key.dst_port,
        start.transport_label,
    );
    spawn_udp_association(
        data_plane.open_udp_ipv4(start.key.into_open_request()),
        start.key,
        start.from_local,
        start.events,
        start.idle_timeout,
    );
}

async fn await_startup_or_shutdown<T, Fut>(
    shutdown: &mut ShutdownSignal,
    startup: Fut,
) -> Result<Option<T>>
where
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::select! {
        result = startup => result.map(Some),
        signal = shutdown.recv() => {
            eprintln!("signal: {} received during startup", signal?);
            Ok(None)
        }
    }
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, CommandKind};
    use crate::transport_model::BridgeTransportKind;

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

    #[tokio::test]
    async fn startup_shutdown_wins_over_pending_startup() {
        let mut shutdown = ShutdownSignal::triggered_for_test("interrupt");
        let startup = std::future::pending::<Result<&'static str>>();

        let result = await_startup_or_shutdown(&mut shutdown, startup)
            .await
            .expect("shutdown should be clean");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn ready_startup_wins_when_shutdown_is_pending() {
        let mut shutdown = ShutdownSignal::pending_for_test();

        let result =
            await_startup_or_shutdown(&mut shutdown, async { Ok::<_, anyhow::Error>("prepared") })
                .await
                .expect("startup should complete");

        assert_eq!(result, Some("prepared"));
    }
}
