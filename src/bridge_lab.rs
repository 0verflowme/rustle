use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use smoltcp::iface::{Config as SmolConfig, Interface, Route, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Cidr};
use tokio::io::{self, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::cli::BridgeLabArgs;
use crate::control_plane::connect_bridge_runtime;
use crate::lab_support::{default_http_request, parse_ipv4_destination, percentile_nearest_rank};
use crate::packet_engine::{
    drain_local_bytes_to_bridges, ensure_bridges, expire_stale_flows, handle_bridge_event_into,
    prune_closed_flows, smol_now, RemoteBacklogs, REMOTE_BACKLOG_BYTES_PER_FLOW,
};
use crate::remote_helper::bridge_agent_command_plan;
use crate::transport_model::BridgeRuntimeOptions;
use crate::{ssh_bridge, tcp_core, DEFAULT_MTU, DEFAULT_TUN_PREFIX};

const BRIDGE_LAB_EVENT_BATCH: usize = 32;

pub(crate) struct BridgeLabClient {
    pub(crate) flow: tcp_core::FlowKey,
    pub(crate) client_ip: Ipv4Addr,
    pub(crate) client_port: u16,
    pub(crate) iface: Interface,
    pub(crate) device: tcp_core::PacketQueueDevice,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) handle: smoltcp::iface::SocketHandle,
    pub(crate) sent_request: bool,
    pub(crate) request_sent_at: Option<StdInstant>,
    pub(crate) response_complete_at: Option<StdInstant>,
    pub(crate) saw_bridge_close: bool,
    pub(crate) response: Vec<u8>,
}

pub(crate) fn receive_lab_client_response(client: &mut BridgeLabClient) -> Result<usize> {
    let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
    let mut received = 0_usize;
    while socket.can_recv() {
        let mut buf = [0_u8; 16 * 1024];
        let len = socket
            .recv_slice(&mut buf)
            .context("failed to receive synthetic lab response")?;
        if len == 0 {
            break;
        }
        client.response.extend_from_slice(&buf[..len]);
        received = received.saturating_add(len);
    }
    Ok(received)
}

pub(crate) fn bridge_lab_client_complete(client: &BridgeLabClient) -> bool {
    client.sent_request && client.saw_bridge_close && bridge_lab_response_complete(&client.response)
}

pub(crate) fn abort_bridge_lab_client_socket(client: &mut BridgeLabClient) -> bool {
    let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
    if !socket.is_active() {
        return false;
    }
    socket.abort();
    true
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BridgeLabLatencySummary {
    pub(crate) p50_us: u128,
    pub(crate) p95_us: u128,
    pub(crate) max_us: u128,
}

pub(crate) fn record_bridge_lab_response_completion(
    client: &mut BridgeLabClient,
    now: StdInstant,
) -> bool {
    if client.response_complete_at.is_none()
        && client.sent_request
        && bridge_lab_response_complete(&client.response)
    {
        client.response_complete_at = Some(now);
        true
    } else {
        false
    }
}

fn bridge_lab_client_latency_us(client: &BridgeLabClient) -> Option<u128> {
    let sent_at = client.request_sent_at?;
    let completed_at = client.response_complete_at?;
    Some(completed_at.saturating_duration_since(sent_at).as_micros())
}

pub(crate) fn bridge_lab_latency_summary(
    clients: &[BridgeLabClient],
    latencies_us: &mut Vec<u128>,
) -> BridgeLabLatencySummary {
    latencies_us.clear();
    latencies_us.extend(clients.iter().filter_map(bridge_lab_client_latency_us));
    bridge_lab_latency_percentiles(latencies_us.as_mut_slice())
}

pub(crate) fn bridge_lab_latency_percentiles(latencies_us: &mut [u128]) -> BridgeLabLatencySummary {
    if latencies_us.is_empty() {
        return BridgeLabLatencySummary::default();
    }
    latencies_us.sort_unstable();
    BridgeLabLatencySummary {
        p50_us: percentile_nearest_rank(latencies_us, 50),
        p95_us: percentile_nearest_rank(latencies_us, 95),
        max_us: *latencies_us
            .last()
            .expect("non-empty bridge latency sample must have max"),
    }
}

pub(crate) fn bridge_lab_response_complete(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = &response[..header_end];
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let Some(content_length) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    }) else {
        return false;
    };

    response.len() >= header_end + 4 + content_length
}

pub(crate) async fn run_bridge_lab(args: BridgeLabArgs) -> Result<()> {
    if args.connections == 0 {
        bail!("bridge-lab --connections must be greater than zero");
    }
    let min_completed = args.min_completed.unwrap_or(args.connections);
    if min_completed == 0 || min_completed > args.connections {
        bail!("bridge-lab --min-completed must be between 1 and --connections");
    }
    if args.deadline_ms.is_some_and(|deadline| deadline == 0) {
        bail!("bridge-lab --deadline-ms must be greater than zero");
    }
    let base_client_port = 49152_u16;
    if args.connections > usize::from(u16::MAX - base_client_port) + 1 {
        bail!("bridge-lab --connections is too large for the synthetic client port range");
    }

    let destination = parse_ipv4_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));
    let helper_plan = bridge_agent_command_plan(
        args.bridge_transport,
        args.agent_command.as_deref(),
        args.agent_path.as_deref(),
    )?;
    let (bridge_runtime, _) = connect_bridge_runtime(
        &args.ssh,
        args.bridge_transport,
        helper_plan,
        DEFAULT_MTU,
        None,
        BridgeRuntimeOptions {
            ssh_sessions: args.ssh_sessions,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: false,
        },
    )
    .await?;

    let mut flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        DEFAULT_TUN_PREFIX,
        &[tcp_core::Ipv4NetParts::new(destination.ip, 32)],
        usize::from(DEFAULT_MTU),
    )
    .context("failed to initialize bridge lab FlowManager")?;

    let mut clients = Vec::with_capacity(args.connections);
    for offset in 0..args.connections {
        let client_port = base_client_port + offset as u16;
        let flow = tcp_core::FlowKey::tcp(
            args.client_ip,
            client_port,
            destination.ip,
            destination.port,
        );
        let (iface, device, sockets, handle) = synthetic_lab_client(
            args.client_ip,
            args.tun_ip,
            destination.ip,
            destination.port,
            client_port,
        )?;
        clients.push(BridgeLabClient {
            flow,
            client_ip: args.client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        });
    }

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let mut bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
    let mut pending_bridge_events = VecDeque::<ssh_bridge::BridgeEvent>::new();
    let mut remote_backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
    let mut ready_flow_ids = Vec::new();
    let mut flow_keys = Vec::new();
    let mut backlog_flow_ids = Vec::new();
    let mut closed_flows = Vec::new();
    let mut bridge_event_closed_flows = Vec::new();
    let mut expired_flows = Vec::new();
    let mut removable_flows = Vec::new();
    let started_at = StdInstant::now();
    let deadline_secs = 30_u64.max(args.connections as u64);
    let deadline = tokio::time::Instant::now()
        + args
            .deadline_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(deadline_secs));

    loop {
        let now = smol_now(started_at);
        let mut made_progress = false;
        for index in 0..clients.len() {
            let packets = {
                let client = &mut clients[index];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut flow_manager)?
            };
            made_progress |=
                route_lab_packets_to_clients(now, packets, &mut clients, &mut flow_manager)? > 0;
        }
        made_progress |= pump_lab_manager_to_clients(now, &mut flow_manager, &mut clients)? > 0;

        ensure_bridges(
            &mut flow_manager,
            &mut bridges,
            bridge_runtime.admission_limits(),
            |id, event_tx| bridge_runtime.spawn_tcp_bridge(id, event_tx),
            event_tx.clone(),
            &mut ready_flow_ids,
            now,
        )?;

        for lab_client in &mut clients {
            let socket = lab_client.sockets.get_mut::<tcp::Socket>(lab_client.handle);
            if !lab_client.sent_request && socket.can_send() {
                socket
                    .send_slice(request.as_bytes())
                    .context("failed to send synthetic lab request")?;
                lab_client.sent_request = true;
                lab_client.request_sent_at = Some(StdInstant::now());
                made_progress = true;
            }
            made_progress |= receive_lab_client_response(lab_client)? > 0;
            made_progress |= record_bridge_lab_response_completion(lab_client, StdInstant::now());
        }

        for index in 0..clients.len() {
            let packets = {
                let client = &mut clients[index];
                drain_lab_client_to_manager(now, client, &mut flow_manager)?
            };
            made_progress |=
                route_lab_packets_to_clients(now, packets, &mut clients, &mut flow_manager)? > 0;
        }
        let drain_stats =
            drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
        made_progress |= drain_stats.bytes_to_bridge > 0;

        let mut processed_bridge_events = 0_usize;
        while processed_bridge_events < BRIDGE_LAB_EVENT_BATCH
            && !remote_backlogs.should_pause_bridge_events()
        {
            let event = if let Some(event) = pending_bridge_events.pop_front() {
                event
            } else {
                let Ok(event) = event_rx.try_recv() else {
                    break;
                };
                event
            };
            processed_bridge_events += 1;
            match &event {
                ssh_bridge::BridgeEvent::Closed { id }
                | ssh_bridge::BridgeEvent::RemoteEof { id }
                    if clients.iter().any(|client| client.flow == id.key) =>
                {
                    if let Some(client) = clients.iter_mut().find(|client| client.flow == id.key) {
                        client.saw_bridge_close = true;
                    }
                }
                _ => {}
            }
            let _ = handle_bridge_event_into(
                event,
                &mut flow_manager,
                &mut remote_backlogs,
                now,
                &mut bridge_event_closed_flows,
            )?;
            for closed_flow in bridge_event_closed_flows.drain(..) {
                bridges.remove(&closed_flow);
            }
        }
        made_progress |= processed_bridge_events > 0;
        let backlog_bytes_before_flush = remote_backlogs.total_bytes();
        remote_backlogs.flush_all_into(
            &mut flow_manager,
            now,
            &mut backlog_flow_ids,
            &mut closed_flows,
        )?;
        made_progress |= remote_backlogs.total_bytes() != backlog_bytes_before_flush;
        for closed_flow in closed_flows.drain(..) {
            bridges.remove(&closed_flow);
            made_progress = true;
        }
        made_progress |= expire_stale_flows(
            &mut flow_manager,
            &mut bridges,
            &mut remote_backlogs,
            now,
            &mut expired_flows,
        ) > 0;

        made_progress |= pump_lab_manager_to_clients(now, &mut flow_manager, &mut clients)? > 0;
        for lab_client in &mut clients {
            made_progress |= receive_lab_client_response(lab_client)? > 0;
            made_progress |= record_bridge_lab_response_completion(lab_client, StdInstant::now());
        }
        made_progress |= prune_closed_flows(
            &mut flow_manager,
            &mut bridges,
            &mut remote_backlogs,
            &mut removable_flows,
        )? > 0;

        let completed = clients
            .iter()
            .filter(|client| bridge_lab_client_complete(client))
            .count();
        if completed >= min_completed {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let sent = clients.iter().filter(|client| client.sent_request).count();
            let closed = clients
                .iter()
                .filter(|client| client.saw_bridge_close)
                .count();
            let response_bytes: usize = clients.iter().map(|client| client.response.len()).sum();
            bail!(
                "bridge lab timed out; completed={completed}/{min_completed}, sent_requests={sent}/{}, closed={closed}/{}, response_bytes={response_bytes}",
                clients.len(),
                clients.len()
            );
        }

        if !made_progress {
            tokio::select! {
                event = event_rx.recv() => {
                    if let Some(event) = event {
                        pending_bridge_events.push_back(event);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        } else {
            tokio::task::yield_now().await;
        }
    }

    let cleanup_iterations = settle_bridge_lab_cleanup(
        started_at,
        &mut flow_manager,
        &mut bridges,
        &mut remote_backlogs,
        &mut clients,
        &mut event_rx,
        BridgeLabCleanupScratch {
            backlog_flow_ids: &mut backlog_flow_ids,
            closed_flows: &mut closed_flows,
            bridge_event_closed_flows: &mut bridge_event_closed_flows,
            removable_flows: &mut removable_flows,
        },
    )
    .await?;

    let elapsed = started_at.elapsed();
    let response_bytes: usize = clients.iter().map(|client| client.response.len()).sum();
    if args.summary {
        let mut latencies_us = Vec::with_capacity(clients.len());
        let latency = bridge_lab_latency_summary(&clients, &mut latencies_us);
        let completed = clients
            .iter()
            .filter(|client| bridge_lab_client_complete(client))
            .count();
        println!(
            "bridge_lab_summary connections={} completed={} response_bytes={} elapsed_ms={} p50_us={} p95_us={} max_us={} active_flows={} active_bridges={} backlog_flows={} backlog_bytes={} cleanup_iterations={}",
            clients.len(),
            completed,
            response_bytes,
            elapsed.as_millis(),
            latency.p50_us,
            latency.p95_us,
            latency.max_us,
            flow_manager.active_flow_count(),
            bridges.len(),
            remote_backlogs.active_flow_count(),
            remote_backlogs.total_bytes(),
            cleanup_iterations,
        );
    } else {
        let mut response = Vec::with_capacity(response_bytes);
        for client in &clients {
            response.extend_from_slice(&client.response);
        }
        io::stdout()
            .write_all(&response)
            .await
            .context("failed to write bridge lab response to stdout")?;
    }
    Ok(())
}

struct BridgeLabCleanupScratch<'a> {
    backlog_flow_ids: &'a mut Vec<tcp_core::FlowId>,
    closed_flows: &'a mut Vec<tcp_core::FlowKey>,
    bridge_event_closed_flows: &'a mut Vec<tcp_core::FlowKey>,
    removable_flows: &'a mut Vec<tcp_core::FlowKey>,
}

async fn settle_bridge_lab_cleanup(
    started_at: StdInstant,
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    clients: &mut [BridgeLabClient],
    event_rx: &mut mpsc::Receiver<ssh_bridge::BridgeEvent>,
    scratch: BridgeLabCleanupScratch<'_>,
) -> Result<usize> {
    for iteration in 0..64_usize {
        let now = smol_now(started_at);
        for index in 0..clients.len() {
            let _ = abort_bridge_lab_client_socket(&mut clients[index]);

            let packets = {
                let client = &mut clients[index];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, flow_manager)?
            };
            let _ = route_lab_packets_to_clients(now, packets, clients, flow_manager)?;
        }

        let _ = pump_lab_manager_to_clients(now, flow_manager, clients)?;
        let mut processed_bridge_events = 0_usize;
        while processed_bridge_events < BRIDGE_LAB_EVENT_BATCH
            && !remote_backlogs.should_pause_bridge_events()
        {
            let Ok(event) = event_rx.try_recv() else {
                break;
            };
            processed_bridge_events += 1;
            let _ = handle_bridge_event_into(
                event,
                flow_manager,
                remote_backlogs,
                now,
                scratch.bridge_event_closed_flows,
            )?;
            for closed_flow in scratch.bridge_event_closed_flows.drain(..) {
                bridges.remove(&closed_flow);
            }
        }
        remote_backlogs.flush_all_into(
            flow_manager,
            now,
            scratch.backlog_flow_ids,
            scratch.closed_flows,
        )?;
        for closed_flow in scratch.closed_flows.drain(..) {
            bridges.remove(&closed_flow);
        }
        let _ = prune_closed_flows(
            flow_manager,
            bridges,
            remote_backlogs,
            scratch.removable_flows,
        )?;

        if flow_manager.active_flow_count() == 0
            && bridges.is_empty()
            && remote_backlogs.active_flow_count() == 0
            && remote_backlogs.total_bytes() == 0
        {
            return Ok(iteration + 1);
        }

        tokio::task::yield_now().await;
    }

    Ok(64)
}

pub(crate) fn synthetic_lab_client(
    client_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    client_port: u16,
) -> Result<(
    Interface,
    tcp_core::PacketQueueDevice,
    SocketSet<'static>,
    smoltcp::iface::SocketHandle,
)> {
    let mut device = tcp_core::PacketQueueDevice::new(usize::from(DEFAULT_MTU));
    let mut config = SmolConfig::new(HardwareAddress::Ip);
    config.random_seed = 0x4252_4c41_4221;

    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::from(client_ip), DEFAULT_TUN_PREFIX))
            .expect("smoltcp default IP address storage must fit lab client address");
    });
    iface.routes_mut().update(|routes| {
        routes
            .push(Route {
                cidr: IpCidr::Ipv4(Ipv4Cidr::new(destination_ip, 32)),
                via_router: IpAddress::from(gateway),
                preferred_until: None,
                expires_at: None,
            })
            .expect("smoltcp default route storage must fit lab destination route");
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut client_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; tcp_core::TCP_SEND_BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; tcp_core::TCP_RECV_BUFFER_BYTES]),
    );
    client_socket.set_ack_delay(None);
    client_socket.set_nagle_enabled(false);
    let client_handle = sockets.add(client_socket);
    sockets
        .get_mut::<tcp::Socket>(client_handle)
        .connect(
            iface.context(),
            (IpAddress::from(destination_ip), destination_port),
            client_port,
        )
        .context("failed to connect synthetic lab client socket")?;

    Ok((iface, device, sockets, client_handle))
}

pub(crate) fn drain_lab_client_to_manager(
    now: SmolInstant,
    client: &mut BridgeLabClient,
    flow_manager: &mut tcp_core::FlowManager,
) -> Result<Vec<tcp_core::PacketBuf>> {
    let mut outbound = Vec::new();
    for packet in client.device.drain_tx() {
        let response_packets = flow_manager
            .ingest_packet(now, packet.as_ref())
            .context("failed to feed lab client packet into FlowManager")?;
        outbound.extend(response_packets);
    }
    Ok(outbound)
}

pub(crate) fn pump_lab_manager_to_clients(
    now: SmolInstant,
    flow_manager: &mut tcp_core::FlowManager,
    clients: &mut [BridgeLabClient],
) -> Result<usize> {
    let packets = flow_manager.poll(now);
    route_lab_packets_to_clients(now, packets, clients, flow_manager)
}

pub(crate) fn route_lab_packets_to_clients(
    now: SmolInstant,
    mut packets: Vec<tcp_core::PacketBuf>,
    clients: &mut [BridgeLabClient],
    flow_manager: &mut tcp_core::FlowManager,
) -> Result<usize> {
    let mut routed = 0_usize;
    let mut pending = VecDeque::with_capacity(packets.len());
    pending.extend(packets.drain(..));
    let mut client_ack_packets = VecDeque::new();
    let mut generated = Vec::new();

    while !pending.is_empty() || !client_ack_packets.is_empty() {
        while let Some(packet) = pending.pop_front() {
            let Some(segment) = tcp_core::parse_ipv4_tcp_segment(packet.as_ref())
                .context("failed to inspect lab TCP packet")?
            else {
                continue;
            };

            let Some(client_index) = clients.iter().position(|client| {
                client.client_ip == segment.flow.dst_ip
                    && client.client_port == segment.flow.dst_port
            }) else {
                bail!(
                    "lab packet has no synthetic client: {}:{} -> {}:{}",
                    segment.flow.src_ip,
                    segment.flow.src_port,
                    segment.flow.dst_ip,
                    segment.flow.dst_port
                );
            };

            {
                let client = &mut clients[client_index];
                client.device.inject(packet.as_ref())?;
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                let _ = receive_lab_client_response(client)?;

                for client_packet in client.device.drain_tx() {
                    client_ack_packets.push_back(Bytes::copy_from_slice(client_packet.as_ref()));
                }
            }
            routed = routed.saturating_add(1);
        }

        if let Some(client_packet) = client_ack_packets.pop_front() {
            flow_manager
                .ingest_packet_into(now, client_packet.as_ref(), &mut generated)
                .context("failed to feed synthetic client response packet into FlowManager")?;
            pending.extend(generated.drain(..));
        }
    }
    Ok(routed)
}
