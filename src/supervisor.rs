use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tun_rs::DeviceBuilder;

use crate::control_plane::connect_bridge_runtime;
use crate::data_plane::{spawn_dns_query_on_data_plane, DataPlane, RuntimeDataPlane};
use crate::packet_engine::{
    drain_local_bytes_to_bridges, ensure_bridges, execute_udp_ingress_actions, expire_stale_flows,
    handle_bridge_event_into, parse_dns_request_for_tunnel, parse_udp_request_for_agent_tunnel,
    plan_udp_datagram_actions, prune_closed_flows, smol_now, tun_ipv4_packet, DnsInflight,
    RemoteBacklogs, TunWriteStats, TunnelStats, UdpAssociationTransportPlan,
    MAX_ACTIVE_UDP_ASSOCIATIONS, MAX_IN_FLIGHT_DNS_QUERIES, PACKET_BUF_SIZE,
    REMOTE_BACKLOG_BYTES_PER_FLOW,
};
use crate::remote_helper::bridge_agent_command_plan;
use crate::routing::{
    add_ssh_control_route, add_target_routes, expand_target_routes, prefix_to_mask,
    ssh_control_ip_to_protect, target_route_parts,
};
use crate::ssh_control::{validate_agent_session_request_count, validate_ssh_session_count};
use crate::transport_model::{
    parse_destination, BridgeRuntimeOptions, BridgeTransportKind, Destination, DnsResponseEvent,
    UdpAssociation, UdpAssociationEvents, UdpFlowKey,
};
use crate::{dns, platform, ssh_bridge, tcp_core, TunCaptureArgs, TunnelArgs, DEFAULT_TUN_IP};

const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

type ShutdownSignalFuture = Pin<Box<dyn Future<Output = Result<&'static str>> + Send>>;

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
                start_local_dns_proxy(system_dns_ip, Arc::clone(&data_plane), dns_remote.clone())
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
        data_plane,
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

pub(crate) async fn run_tunnel_loop(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    data_plane: Arc<dyn DataPlane>,
    dns_remote: Destination,
    udp_association_idle_timeout: Duration,
    mut shutdown: ShutdownSignalFuture,
) -> Result<()> {
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let mut ready_flow_ids = Vec::new();
    let mut flow_keys = Vec::new();
    let mut backlog_flow_ids = Vec::new();
    let mut backlog_closed_flows = Vec::new();
    let mut bridge_event_closed_flows = Vec::new();
    let mut expired_flows = Vec::new();
    let mut removable_flows = Vec::new();
    let mut udp_actions = Vec::new();
    let started_at = StdInstant::now();
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
    let mut bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
    let mut udp_associations = HashMap::<UdpFlowKey, UdpAssociation>::new();
    let mut remote_backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
    let mut dns_inflight = DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES);
    let mut udp_inflight = DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS);
    let mut stats = TunnelStats::new();
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
                    stats.status_line(
                        flow_manager.active_flow_count(),
                        bridges.len(),
                        &remote_backlogs,
                        &dns_inflight,
                        &udp_inflight,
                        data_plane.snapshot().await,
                    )
                );
                return Ok(());
            }
            result = dev.recv(&mut buf) => {
                let len = result.context("failed to read packet from TUN device")?;
                stats.record_tun_rx(len);
                let Some(packet) = tun_ipv4_packet(&buf[..len]) else {
                    continue;
                };
                if let Some(request) = parse_dns_request_for_tunnel(packet) {
                    stats.dns_forwarded = stats.dns_forwarded.saturating_add(1);
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
                    if dns_inflight.try_admit() {
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
                            dns_inflight.max()
                        );
                        stats.dns_dropped = stats.dns_dropped.saturating_add(1);
                        stats.record_dns_response(false);
                        let tun_write = write_dns_event_to_tun(
                            &dev,
                            DnsResponseEvent {
                                request,
                                result: Err("DNS in-flight limit reached".to_owned()),
                            },
                        )
                        .await?;
                        stats.record_tun_write(tun_write);
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
                    plan_udp_datagram_actions(
                        udp_transport,
                        request,
                        &mut udp_associations,
                        &mut udp_inflight,
                        udp_events.clone(),
                        udp_association_idle_timeout,
                        &mut udp_actions,
                    );
                    execute_udp_ingress_actions(
                        &mut udp_actions,
                        &mut udp_associations,
                        &mut udp_inflight,
                        &mut stats,
                        &mut |transport, key, from_local, events, idle_timeout| {
                            transport.spawn_udp_association(key, from_local, events, idle_timeout);
                        },
                    );
                    continue;
                }

                let now = smol_now(started_at);
                flow_manager
                    .ingest_packet_into(now, packet, &mut outbound_packets)
                    .context("failed to feed packet into userspace TCP engine")?;
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                let admission_stats = ensure_bridges(
                    &mut flow_manager,
                    &mut bridges,
                    data_plane.admission_limits(),
                    |id, event_tx| data_plane.spawn_tcp_bridge(id, event_tx),
                    event_tx.clone(),
                    &mut ready_flow_ids,
                    now,
                )?;
                stats.record_bridge_admission(admission_stats);
                let drain_stats =
                    drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
                stats.record_local_drain(drain_stats);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    smol_now(started_at),
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                stats.expired_flows = stats.expired_flows.saturating_add(expire_stale_flows(
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    smol_now(started_at),
                    &mut expired_flows,
                ) as u64);
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
            event = dns_rx.recv() => {
                if let Some(event) = event {
                    dns_inflight.complete();
                    let remote_ok = event.result.is_ok();
                    let tun_write = write_dns_event_to_tun(&dev, event).await?;
                    stats.record_dns_delivery(remote_ok, tun_write);
                }
            }
            event = udp_response_rx.recv() => {
                if let Some(event) = event {
                    let tun_write = write_udp_response_to_tun(&dev, event.key, event.payload).await?;
                    stats.record_udp_delivery(tun_write);
                }
            }
            event = udp_close_rx.recv() => {
                if let Some(event) = event {
                    udp_associations.remove(&event.key);
                    udp_inflight.complete();
                    if let Some(error) = event.error {
                        eprintln!(
                            "udp: association {}:{} -> {}:{} closed with error: {error}",
                            event.key.src_ip,
                            event.key.src_port,
                            event.key.dst_ip,
                            event.key.dst_port,
                        );
                        stats.record_udp_response(false);
                    }
                }
            }
            event = event_rx.recv(), if !remote_backlogs.should_pause_bridge_events() => {
                let Some(event) = event else {
                    bail!("SSH bridge event channel closed");
                };
                stats.record_bridge_event(&event);
                let now = smol_now(started_at);
                let outcome = handle_bridge_event_into(
                    event,
                    &mut flow_manager,
                    &mut remote_backlogs,
                    now,
                    &mut bridge_event_closed_flows,
                )?;
                stats.remote_backlog_overflows = stats
                    .remote_backlog_overflows
                    .saturating_add(outcome.remote_backlog_overflows);
                stats.stale_bridge_events = stats
                    .stale_bridge_events
                    .saturating_add(outcome.stale_bridge_events);
                for flow in bridge_event_closed_flows.drain(..) {
                    bridges.remove(&flow);
                }
                flow_manager.poll_into(now, &mut outbound_packets);
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    now,
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                stats.expired_flows = stats.expired_flows.saturating_add(
                    expire_stale_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        now,
                        &mut expired_flows,
                    ) as u64
                );
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
            _ = stats_tick.tick() => {
                eprintln!(
                    "stats: {}",
                    stats.status_line(
                        flow_manager.active_flow_count(),
                        bridges.len(),
                        &remote_backlogs,
                        &dns_inflight,
                        &udp_inflight,
                        data_plane.snapshot().await,
                    )
                );
            }
            _ = tick.tick() => {
                let now = smol_now(started_at);
                flow_manager.poll_into(now, &mut outbound_packets);
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    now,
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                let admission_stats = ensure_bridges(
                    &mut flow_manager,
                    &mut bridges,
                    data_plane.admission_limits(),
                    |id, event_tx| data_plane.spawn_tcp_bridge(id, event_tx),
                    event_tx.clone(),
                    &mut ready_flow_ids,
                    now,
                )?;
                stats.record_bridge_admission(admission_stats);
                let drain_stats =
                    drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
                stats.record_local_drain(drain_stats);
                stats.expired_flows = stats.expired_flows.saturating_add(
                    expire_stale_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        now,
                        &mut expired_flows,
                    ) as u64
                );
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
        }
    }
}

struct RemoteFlushScratch<'a> {
    backlog_flow_ids: &'a mut Vec<tcp_core::FlowId>,
    closed_flows: &'a mut Vec<tcp_core::FlowKey>,
    packets: &'a mut Vec<tcp_core::PacketBuf>,
}

async fn flush_remote_backlogs_to_tun(
    dev: &tun_rs::AsyncDevice,
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    now: smoltcp::time::Instant,
    scratch: RemoteFlushScratch<'_>,
    stats: &mut TunnelStats,
) -> Result<()> {
    remote_backlogs.flush_all_into(
        flow_manager,
        now,
        scratch.backlog_flow_ids,
        scratch.closed_flows,
    )?;
    for closed_flow in scratch.closed_flows.drain(..) {
        bridges.remove(&closed_flow);
    }
    flow_manager.poll_into(now, scratch.packets);
    let tun_write = write_packets_to_tun(dev, scratch.packets).await?;
    stats.record_tun_write(tun_write);
    Ok(())
}

pub(crate) async fn write_dns_event_to_tun(
    dev: &tun_rs::AsyncDevice,
    event: DnsResponseEvent,
) -> Result<TunWriteStats> {
    let payload = match event.result {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("dns: remote query failed: {err}");
            let Some(payload) = dns::build_dns_servfail_response(event.request.payload.as_ref())
            else {
                return Ok(TunWriteStats::default());
            };
            Bytes::from(payload)
        }
    };

    let packet = dns::build_udp_dns_response(&event.request, &payload)
        .context("failed to synthesize DNS UDP response packet")?;
    write_packet_to_tun(dev, &packet, "DNS response").await
}

pub(crate) async fn write_udp_response_to_tun(
    dev: &tun_rs::AsyncDevice,
    key: UdpFlowKey,
    payload: Bytes,
) -> Result<TunWriteStats> {
    let request = key.response_template();
    let packet = dns::build_udp_response(&request, &payload)
        .context("failed to synthesize UDP response packet")?;
    write_packet_to_tun(dev, &packet, "UDP response").await
}

pub(crate) async fn write_packets_to_tun(
    dev: &tun_rs::AsyncDevice,
    packets: &mut Vec<tcp_core::PacketBuf>,
) -> Result<TunWriteStats> {
    let mut stats = TunWriteStats::default();
    for packet in packets.drain(..) {
        stats.combine(write_packet_to_tun(dev, packet.as_ref(), "userspace TCP packet").await?);
    }
    Ok(stats)
}

pub(crate) async fn write_packet_to_tun(
    dev: &tun_rs::AsyncDevice,
    packet: &[u8],
    description: &'static str,
) -> Result<TunWriteStats> {
    let len = packet.len();
    let mut stats = TunWriteStats::default();
    match tokio::time::timeout(TUN_WRITE_TIMEOUT, dev.send(packet)).await {
        Ok(Ok(_)) => {
            stats.record_written(len);
        }
        Ok(Err(err)) => {
            return Err(err)
                .with_context(|| format!("failed to write {description} to TUN device"));
        }
        Err(_) => {
            eprintln!(
                "tun: dropping {len}-byte {description} after {}ms waiting for TUN write",
                TUN_WRITE_TIMEOUT.as_millis()
            );
            stats.record_dropped(len);
        }
    }
    Ok(stats)
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
