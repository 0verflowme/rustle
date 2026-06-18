use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
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
use crate::control_plane::connect_tunnel_runtime;
use crate::data_plane::{spawn_tcp_bridge_on_data_plane, DataPlane};
use crate::defaults::{DEFAULT_MTU, DEFAULT_TUN_PREFIX};
use crate::lab_support::{
    default_http_request, parse_ipv4_destination, percentile_nearest_rank, Ipv4Destination,
};
use crate::packet_engine::{
    drain_local_bytes_to_bridges, expire_stale_flows, handle_bridge_event_into, plan_bridge_starts,
    prune_closed_flows, register_tcp_bridge, smol_now, RemoteBacklogs, TcpBridgeHandles,
    TcpBridgeStart, REMOTE_BACKLOG_BYTES_PER_FLOW,
};
use crate::transport_model::TunnelRuntimeOptions;
use crate::{flow_bridge, tcp_core};

const BRIDGE_LAB_EVENT_BATCH: usize = 32;
const BRIDGE_LAB_BASE_CLIENT_PORT: u16 = 49152;

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BridgeLabCompletionFlags {
    sent_request: bool,
    saw_bridge_close: bool,
    response_complete: bool,
}

fn bridge_lab_completion_satisfied(flags: BridgeLabCompletionFlags) -> bool {
    flags.sent_request && flags.saw_bridge_close && flags.response_complete
}

fn bridge_lab_client_completion_flags(client: &BridgeLabClient) -> BridgeLabCompletionFlags {
    BridgeLabCompletionFlags {
        sent_request: client.sent_request,
        saw_bridge_close: client.saw_bridge_close,
        response_complete: bridge_lab_response_complete(&client.response),
    }
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
    if bridge_lab_should_record_response_completion(
        client.sent_request,
        bridge_lab_response_complete(&client.response),
        client.response_complete_at.is_some(),
    ) {
        client.response_complete_at = Some(now);
        true
    } else {
        false
    }
}

fn bridge_lab_should_record_response_completion(
    sent_request: bool,
    response_complete: bool,
    already_recorded: bool,
) -> bool {
    sent_request && response_complete && !already_recorded
}

fn bridge_lab_latency_us(
    sent_at: Option<StdInstant>,
    completed_at: Option<StdInstant>,
) -> Option<u128> {
    let sent_at = sent_at?;
    let completed_at = completed_at?;
    Some(completed_at.saturating_duration_since(sent_at).as_micros())
}

fn bridge_lab_client_latency_us(client: &BridgeLabClient) -> Option<u128> {
    bridge_lab_latency_us(client.request_sent_at, client.response_complete_at)
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
        max_us: latencies_us.last().copied().unwrap_or_default(),
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

fn validate_bridge_lab_request(
    connections: usize,
    min_completed: Option<usize>,
    deadline_ms: Option<u64>,
    base_client_port: u16,
) -> Result<usize> {
    if connections == 0 {
        bail!("bridge-lab --connections must be greater than zero");
    }
    let min_completed = min_completed.unwrap_or(connections);
    if min_completed == 0 || min_completed > connections {
        bail!("bridge-lab --min-completed must be between 1 and --connections");
    }
    if deadline_ms == Some(0) {
        bail!("bridge-lab --deadline-ms must be greater than zero");
    }
    if connections > bridge_lab_client_port_capacity(base_client_port) {
        bail!("bridge-lab --connections is too large for the synthetic client port range");
    }
    Ok(min_completed)
}

fn validate_bridge_lab_args(args: &BridgeLabArgs) -> Result<usize> {
    validate_bridge_lab_request(
        args.connections,
        args.min_completed,
        args.deadline_ms,
        BRIDGE_LAB_BASE_CLIENT_PORT,
    )
}

fn bridge_lab_client_port_capacity(base_client_port: u16) -> usize {
    usize::from(u16::MAX - base_client_port) + 1
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BridgeLabAccountingSample {
    sent_request: bool,
    saw_bridge_close: bool,
    response_complete: bool,
    response_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BridgeLabAccounting {
    completed: usize,
    sent_requests: usize,
    closed: usize,
    response_bytes: usize,
}

fn bridge_lab_accounting_from_samples(
    samples: impl IntoIterator<Item = BridgeLabAccountingSample>,
) -> BridgeLabAccounting {
    let mut accounting = BridgeLabAccounting::default();
    for sample in samples {
        accounting.sent_requests += usize::from(sample.sent_request);
        accounting.closed += usize::from(sample.saw_bridge_close);
        accounting.response_bytes = accounting
            .response_bytes
            .saturating_add(sample.response_bytes);
        accounting.completed +=
            usize::from(bridge_lab_completion_satisfied(BridgeLabCompletionFlags {
                sent_request: sample.sent_request,
                saw_bridge_close: sample.saw_bridge_close,
                response_complete: sample.response_complete,
            }));
    }
    accounting
}

fn bridge_lab_client_accounting(clients: &[BridgeLabClient]) -> BridgeLabAccounting {
    bridge_lab_accounting_from_samples(clients.iter().map(|client| {
        let flags = bridge_lab_client_completion_flags(client);
        BridgeLabAccountingSample {
            sent_request: flags.sent_request,
            saw_bridge_close: flags.saw_bridge_close,
            response_complete: flags.response_complete,
            response_bytes: client.response.len(),
        }
    }))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BridgeLabCleanupStatus {
    active_flows: usize,
    active_bridges: usize,
    backlog_flows: usize,
    backlog_bytes: u64,
}

fn bridge_lab_cleanup_settled(status: BridgeLabCleanupStatus) -> bool {
    status.active_flows == 0
        && status.active_bridges == 0
        && status.backlog_flows == 0
        && status.backlog_bytes == 0
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BridgeLabSummaryFields {
    connections: usize,
    completed: usize,
    response_bytes: usize,
    elapsed_ms: u128,
    latency: BridgeLabLatencySummary,
    cleanup: BridgeLabCleanupStatus,
    backlog_overflow: u64,
    cleanup_iterations: usize,
}

fn bridge_lab_summary_fields(
    connections: usize,
    accounting: BridgeLabAccounting,
    elapsed: Duration,
    latency: BridgeLabLatencySummary,
    cleanup: BridgeLabCleanupStatus,
    backlog_overflow: u64,
    cleanup_iterations: usize,
) -> BridgeLabSummaryFields {
    BridgeLabSummaryFields {
        connections,
        completed: accounting.completed,
        response_bytes: accounting.response_bytes,
        elapsed_ms: elapsed.as_millis(),
        latency,
        cleanup,
        backlog_overflow,
        cleanup_iterations,
    }
}

struct BridgeLabRunState {
    flow_manager: tcp_core::FlowManager,
    clients: Vec<BridgeLabClient>,
    bridges: TcpBridgeHandles,
    pending_bridge_events: VecDeque<flow_bridge::BridgeEvent>,
    remote_backlogs: RemoteBacklogs,
    ready_flow_ids: Vec<tcp_core::FlowId>,
    opening_flow_keys: Vec<tcp_core::FlowKey>,
    bridge_starts: Vec<TcpBridgeStart>,
    flow_keys: Vec<tcp_core::FlowKey>,
    backlog_flow_ids: Vec<tcp_core::FlowId>,
    closed_flows: Vec<tcp_core::FlowKey>,
    bridge_event_closed_flows: Vec<tcp_core::FlowKey>,
    expired_flows: Vec<tcp_core::FlowKey>,
    removable_flows: Vec<tcp_core::FlowKey>,
    remote_backlog_overflows: u64,
}

impl BridgeLabRunState {
    fn new(flow_manager: tcp_core::FlowManager, clients: Vec<BridgeLabClient>) -> Self {
        Self {
            flow_manager,
            clients,
            bridges: HashMap::new(),
            pending_bridge_events: VecDeque::new(),
            remote_backlogs: RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW),
            ready_flow_ids: Vec::new(),
            opening_flow_keys: Vec::new(),
            bridge_starts: Vec::new(),
            flow_keys: Vec::new(),
            backlog_flow_ids: Vec::new(),
            closed_flows: Vec::new(),
            bridge_event_closed_flows: Vec::new(),
            expired_flows: Vec::new(),
            removable_flows: Vec::new(),
            remote_backlog_overflows: 0,
        }
    }

    fn cleanup_status(&self) -> BridgeLabCleanupStatus {
        BridgeLabCleanupStatus {
            active_flows: self.flow_manager.active_flow_count(),
            active_bridges: self.bridges.len(),
            backlog_flows: self.remote_backlogs.active_flow_count(),
            backlog_bytes: self.remote_backlogs.total_bytes(),
        }
    }
}

struct BridgeLabAdvanceContext<'a> {
    data_plane: &'a Arc<dyn DataPlane>,
    event_tx: &'a mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &'a flow_bridge::BridgeEventAccounting,
    request: &'a str,
    started_at: StdInstant,
}

fn build_bridge_lab_flow_manager(
    args: &BridgeLabArgs,
    destination: &Ipv4Destination,
) -> Result<tcp_core::FlowManager> {
    tcp_core::FlowManager::new(
        args.tun_ip,
        DEFAULT_TUN_PREFIX,
        &[tcp_core::Ipv4NetParts::new(destination.ip, 32)],
        usize::from(DEFAULT_MTU),
    )
    .context("failed to initialize bridge lab FlowManager")
}

fn build_bridge_lab_clients(
    args: &BridgeLabArgs,
    destination: &Ipv4Destination,
) -> Result<Vec<BridgeLabClient>> {
    let mut clients = Vec::with_capacity(args.connections);
    for offset in 0..args.connections {
        let client_port = BRIDGE_LAB_BASE_CLIENT_PORT + offset as u16;
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
    Ok(clients)
}

pub(crate) async fn run_bridge_lab(args: BridgeLabArgs) -> Result<()> {
    let min_completed = validate_bridge_lab_args(&args)?;
    let destination = parse_ipv4_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));
    let helper_plan = crate::control_plane::bridge_runtime_command_plan(
        args.bridge_transport,
        args.agent_command.as_deref(),
        args.agent_path.as_deref(),
    )?;
    let runtime = connect_tunnel_runtime(
        &args.ssh,
        args.bridge_transport,
        helper_plan,
        DEFAULT_MTU,
        None,
        TunnelRuntimeOptions {
            ssh_sessions: args.ssh_sessions,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: false,
        },
    )
    .await?;
    let data_plane = runtime.data_plane();

    let flow_manager = build_bridge_lab_flow_manager(&args, &destination)?;
    let clients = build_bridge_lab_clients(&args, &destination)?;
    let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let mut state = BridgeLabRunState::new(flow_manager, clients);
    let started_at = StdInstant::now();
    let deadline_secs = 30_u64.max(args.connections as u64);
    let deadline = tokio::time::Instant::now()
        + args
            .deadline_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(deadline_secs));

    loop {
        let made_progress = {
            let context = BridgeLabAdvanceContext {
                data_plane: &data_plane,
                event_tx: &event_tx,
                bridge_event_accounting: &bridge_event_accounting,
                request: &request,
                started_at,
            };
            advance_bridge_lab_once(&mut state, &context, &mut event_rx)?
        };
        let accounting = bridge_lab_client_accounting(&state.clients);
        let completed = accounting.completed;
        if completed >= min_completed {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let sent = accounting.sent_requests;
            let closed = accounting.closed;
            let response_bytes = accounting.response_bytes;
            bail!(
                "bridge lab timed out; completed={completed}/{min_completed}, sent_requests={sent}/{}, closed={closed}/{}, response_bytes={response_bytes}",
                state.clients.len(),
                state.clients.len()
            );
        }

        if !made_progress {
            tokio::select! {
                event = event_rx.recv() => {
                    if let Some(event) = event {
                        bridge_event_accounting.record_dequeued(&event);
                        state.pending_bridge_events.push_back(event);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        } else {
            tokio::task::yield_now().await;
        }
    }

    let cleanup_iterations =
        settle_bridge_lab_cleanup(started_at, &mut state, &mut event_rx).await?;
    let elapsed = started_at.elapsed();
    write_bridge_lab_result(args.summary, elapsed, &state, cleanup_iterations).await
}

fn advance_bridge_lab_once(
    state: &mut BridgeLabRunState,
    context: &BridgeLabAdvanceContext<'_>,
    event_rx: &mut mpsc::Receiver<flow_bridge::BridgeEvent>,
) -> Result<bool> {
    let now = smol_now(context.started_at);
    let mut made_progress = false;

    made_progress |=
        poll_bridge_lab_clients_to_manager(now, &mut state.clients, &mut state.flow_manager)?;
    made_progress |=
        pump_lab_manager_to_clients(now, &mut state.flow_manager, &mut state.clients)? > 0;
    start_ready_bridge_lab_bridges(state, context, now)?;
    made_progress |= send_bridge_lab_requests_and_receive(&mut state.clients, context.request)?;
    made_progress |=
        drain_bridge_lab_clients_to_manager(now, &mut state.clients, &mut state.flow_manager)?;

    let drain_stats = drain_local_bytes_to_bridges(
        &mut state.flow_manager,
        &mut state.bridges,
        &mut state.flow_keys,
        now,
    )?;
    made_progress |= drain_stats.bytes_to_bridge > 0;
    made_progress |= process_bridge_lab_events(state, event_rx, context, now)? > 0;
    made_progress |= flush_bridge_lab_remote_backlogs(state, now)?;
    made_progress |= expire_stale_flows(
        &mut state.flow_manager,
        &mut state.bridges,
        &mut state.remote_backlogs,
        now,
        &mut state.expired_flows,
    ) > 0;
    made_progress |=
        pump_lab_manager_to_clients(now, &mut state.flow_manager, &mut state.clients)? > 0;
    made_progress |= receive_bridge_lab_client_responses(&mut state.clients)?;
    made_progress |= prune_closed_flows(
        &mut state.flow_manager,
        &mut state.bridges,
        &mut state.remote_backlogs,
        &mut state.removable_flows,
    )? > 0;

    Ok(made_progress)
}

fn poll_bridge_lab_clients_to_manager(
    now: SmolInstant,
    clients: &mut [BridgeLabClient],
    flow_manager: &mut tcp_core::FlowManager,
) -> Result<bool> {
    let mut made_progress = false;
    for index in 0..clients.len() {
        let packets = {
            let client = &mut clients[index];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, flow_manager)?
        };
        made_progress |= route_lab_packets_to_clients(now, packets, clients, flow_manager)? > 0;
    }
    Ok(made_progress)
}

fn drain_bridge_lab_clients_to_manager(
    now: SmolInstant,
    clients: &mut [BridgeLabClient],
    flow_manager: &mut tcp_core::FlowManager,
) -> Result<bool> {
    let mut made_progress = false;
    for index in 0..clients.len() {
        let packets = {
            let client = &mut clients[index];
            drain_lab_client_to_manager(now, client, flow_manager)?
        };
        made_progress |= route_lab_packets_to_clients(now, packets, clients, flow_manager)? > 0;
    }
    Ok(made_progress)
}

fn start_ready_bridge_lab_bridges(
    state: &mut BridgeLabRunState,
    context: &BridgeLabAdvanceContext<'_>,
    now: SmolInstant,
) -> Result<()> {
    plan_bridge_starts(
        &mut state.flow_manager,
        &state.bridges,
        context.data_plane.admission_limits(),
        &mut state.ready_flow_ids,
        &mut state.opening_flow_keys,
        now,
        &mut state.bridge_starts,
    )?;
    for start in state.bridge_starts.drain(..) {
        let bridge = spawn_tcp_bridge_on_data_plane(
            Arc::clone(context.data_plane),
            start.id,
            start.ready_wait_ms,
            context.event_tx.clone(),
            context.bridge_event_accounting.clone(),
        );
        register_tcp_bridge(&mut state.flow_manager, &mut state.bridges, start, bridge)?;
    }
    Ok(())
}

fn send_bridge_lab_requests_and_receive(
    clients: &mut [BridgeLabClient],
    request: &str,
) -> Result<bool> {
    let mut made_progress = false;
    for lab_client in clients {
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
    Ok(made_progress)
}

fn receive_bridge_lab_client_responses(clients: &mut [BridgeLabClient]) -> Result<bool> {
    let mut made_progress = false;
    for lab_client in clients {
        made_progress |= receive_lab_client_response(lab_client)? > 0;
        made_progress |= record_bridge_lab_response_completion(lab_client, StdInstant::now());
    }
    Ok(made_progress)
}

fn process_bridge_lab_events(
    state: &mut BridgeLabRunState,
    event_rx: &mut mpsc::Receiver<flow_bridge::BridgeEvent>,
    context: &BridgeLabAdvanceContext<'_>,
    now: SmolInstant,
) -> Result<usize> {
    let mut processed_bridge_events = 0_usize;
    while processed_bridge_events < BRIDGE_LAB_EVENT_BATCH
        && !state.remote_backlogs.should_pause_bridge_events()
    {
        let event = if let Some(event) = state.pending_bridge_events.pop_front() {
            event
        } else {
            let Ok(event) = event_rx.try_recv() else {
                break;
            };
            context.bridge_event_accounting.record_dequeued(&event);
            event
        };
        processed_bridge_events += 1;
        if let Some(flow) = bridge_lab_closed_flow_from_event(&event) {
            mark_bridge_lab_closed_flow(&mut state.clients, flow);
        }
        let bridge_event_stats = handle_bridge_event_into(
            event,
            &mut state.flow_manager,
            &mut state.remote_backlogs,
            now,
            &mut state.bridge_event_closed_flows,
        )?;
        state.remote_backlog_overflows = state
            .remote_backlog_overflows
            .saturating_add(bridge_event_stats.remote_backlog_overflows);
        for closed_flow in state.bridge_event_closed_flows.drain(..) {
            state.bridges.remove(&closed_flow);
        }
    }
    Ok(processed_bridge_events)
}

fn bridge_lab_closed_flow_from_event(
    event: &flow_bridge::BridgeEvent,
) -> Option<tcp_core::FlowKey> {
    match event {
        flow_bridge::BridgeEvent::Closed { id } | flow_bridge::BridgeEvent::RemoteEof { id } => {
            Some(id.key)
        }
        _ => None,
    }
}

fn mark_bridge_lab_closed_flow(clients: &mut [BridgeLabClient], flow: tcp_core::FlowKey) -> bool {
    let Some(client) = clients.iter_mut().find(|client| client.flow == flow) else {
        return false;
    };
    client.saw_bridge_close = true;
    true
}

fn flush_bridge_lab_remote_backlogs(
    state: &mut BridgeLabRunState,
    now: SmolInstant,
) -> Result<bool> {
    let backlog_bytes_before_flush = state.remote_backlogs.total_bytes();
    state.remote_backlogs.flush_all_into(
        &mut state.flow_manager,
        now,
        &mut state.backlog_flow_ids,
        &mut state.closed_flows,
    )?;
    let mut made_progress = state.remote_backlogs.total_bytes() != backlog_bytes_before_flush;
    for closed_flow in state.closed_flows.drain(..) {
        state.bridges.remove(&closed_flow);
        made_progress = true;
    }
    Ok(made_progress)
}

async fn write_bridge_lab_result(
    summary: bool,
    elapsed: Duration,
    state: &BridgeLabRunState,
    cleanup_iterations: usize,
) -> Result<()> {
    let accounting = bridge_lab_client_accounting(&state.clients);
    if summary {
        let mut latencies_us = Vec::with_capacity(state.clients.len());
        let latency = bridge_lab_latency_summary(&state.clients, &mut latencies_us);
        let summary = bridge_lab_summary_fields(
            state.clients.len(),
            accounting,
            elapsed,
            latency,
            state.cleanup_status(),
            state.remote_backlog_overflows,
            cleanup_iterations,
        );
        println!(
            "bridge_lab_summary connections={} completed={} response_bytes={} elapsed_ms={} p50_us={} p95_us={} max_us={} active_flows={} active_bridges={} backlog_flows={} backlog_bytes={} backlog_overflow={} cleanup_iterations={}",
            summary.connections,
            summary.completed,
            summary.response_bytes,
            summary.elapsed_ms,
            summary.latency.p50_us,
            summary.latency.p95_us,
            summary.latency.max_us,
            summary.cleanup.active_flows,
            summary.cleanup.active_bridges,
            summary.cleanup.backlog_flows,
            summary.cleanup.backlog_bytes,
            summary.backlog_overflow,
            summary.cleanup_iterations,
        );
    } else {
        let mut response = Vec::with_capacity(accounting.response_bytes);
        for client in &state.clients {
            response.extend_from_slice(&client.response);
        }
        io::stdout()
            .write_all(&response)
            .await
            .context("failed to write bridge lab response to stdout")?;
    }
    Ok(())
}

async fn settle_bridge_lab_cleanup(
    started_at: StdInstant,
    state: &mut BridgeLabRunState,
    event_rx: &mut mpsc::Receiver<flow_bridge::BridgeEvent>,
) -> Result<usize> {
    for iteration in 0..64_usize {
        let now = smol_now(started_at);
        for index in 0..state.clients.len() {
            let _ = abort_bridge_lab_client_socket(&mut state.clients[index]);

            let packets = {
                let client = &mut state.clients[index];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut state.flow_manager)?
            };
            let _ = route_lab_packets_to_clients(
                now,
                packets,
                &mut state.clients,
                &mut state.flow_manager,
            )?;
        }

        let _ = pump_lab_manager_to_clients(now, &mut state.flow_manager, &mut state.clients)?;
        let mut processed_bridge_events = 0_usize;
        while processed_bridge_events < BRIDGE_LAB_EVENT_BATCH
            && !state.remote_backlogs.should_pause_bridge_events()
        {
            let Ok(event) = event_rx.try_recv() else {
                break;
            };
            processed_bridge_events += 1;
            let bridge_event_stats = handle_bridge_event_into(
                event,
                &mut state.flow_manager,
                &mut state.remote_backlogs,
                now,
                &mut state.bridge_event_closed_flows,
            )?;
            state.remote_backlog_overflows = state
                .remote_backlog_overflows
                .saturating_add(bridge_event_stats.remote_backlog_overflows);
            for closed_flow in state.bridge_event_closed_flows.drain(..) {
                state.bridges.remove(&closed_flow);
            }
        }
        state.remote_backlogs.flush_all_into(
            &mut state.flow_manager,
            now,
            &mut state.backlog_flow_ids,
            &mut state.closed_flows,
        )?;
        for closed_flow in state.closed_flows.drain(..) {
            state.bridges.remove(&closed_flow);
        }
        let _ = prune_closed_flows(
            &mut state.flow_manager,
            &mut state.bridges,
            &mut state.remote_backlogs,
            &mut state.removable_flows,
        )?;

        if bridge_lab_cleanup_settled(state.cleanup_status()) {
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
    let mut ip_addr_inserted = true;
    iface.update_ip_addrs(|ip_addrs| {
        ip_addr_inserted = ip_addrs
            .push(IpCidr::new(IpAddress::from(client_ip), DEFAULT_TUN_PREFIX))
            .is_ok();
    });
    if !ip_addr_inserted {
        bail!("failed to add synthetic lab client IP address to smoltcp interface");
    }
    let mut route_inserted = true;
    iface.routes_mut().update(|routes| {
        route_inserted = routes
            .push(Route {
                cidr: IpCidr::Ipv4(Ipv4Cidr::new(destination_ip, 32)),
                via_router: IpAddress::from(gateway),
                preferred_until: None,
                expires_at: None,
            })
            .is_ok();
    });
    if !route_inserted {
        bail!("failed to add synthetic lab destination route to smoltcp interface");
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults::{DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};

    #[test]
    fn bridge_lab_response_completion_uses_http_content_length() {
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let incomplete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";

        assert!(bridge_lab_response_complete(complete));
        assert!(!bridge_lab_response_complete(incomplete));
        assert!(!bridge_lab_response_complete(b"raw bytes"));
    }

    #[test]
    fn bridge_lab_validation_preserves_cli_bounds() {
        assert_eq!(
            validate_bridge_lab_request(3, None, Some(10), BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect("default min completed"),
            3
        );
        assert_eq!(
            validate_bridge_lab_request(3, Some(2), None, BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect("explicit min completed"),
            2
        );
        assert_eq!(
            validate_bridge_lab_request(0, None, None, BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect_err("zero connections")
                .to_string(),
            "bridge-lab --connections must be greater than zero"
        );
        assert_eq!(
            validate_bridge_lab_request(2, Some(0), None, BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect_err("zero min completed")
                .to_string(),
            "bridge-lab --min-completed must be between 1 and --connections"
        );
        assert_eq!(
            validate_bridge_lab_request(2, Some(3), None, BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect_err("min completed above connections")
                .to_string(),
            "bridge-lab --min-completed must be between 1 and --connections"
        );
        assert_eq!(
            validate_bridge_lab_request(1, None, Some(0), BRIDGE_LAB_BASE_CLIENT_PORT)
                .expect_err("zero deadline")
                .to_string(),
            "bridge-lab --deadline-ms must be greater than zero"
        );
        assert_eq!(
            validate_bridge_lab_request(3, None, None, u16::MAX - 1)
                .expect_err("port range overflow")
                .to_string(),
            "bridge-lab --connections is too large for the synthetic client port range"
        );
    }

    #[test]
    fn bridge_lab_completion_flags_require_request_response_and_close() {
        assert!(bridge_lab_completion_satisfied(BridgeLabCompletionFlags {
            sent_request: true,
            saw_bridge_close: true,
            response_complete: true,
        }));
        assert!(!bridge_lab_completion_satisfied(BridgeLabCompletionFlags {
            sent_request: false,
            saw_bridge_close: true,
            response_complete: true,
        }));
        assert!(!bridge_lab_completion_satisfied(BridgeLabCompletionFlags {
            sent_request: true,
            saw_bridge_close: false,
            response_complete: true,
        }));
        assert!(!bridge_lab_completion_satisfied(BridgeLabCompletionFlags {
            sent_request: true,
            saw_bridge_close: true,
            response_complete: false,
        }));
    }

    #[test]
    fn bridge_lab_accounting_counts_completion_independently_from_bytes() {
        let accounting = bridge_lab_accounting_from_samples([
            BridgeLabAccountingSample {
                sent_request: true,
                saw_bridge_close: true,
                response_complete: true,
                response_bytes: 10,
            },
            BridgeLabAccountingSample {
                sent_request: true,
                saw_bridge_close: false,
                response_complete: true,
                response_bytes: 7,
            },
            BridgeLabAccountingSample {
                sent_request: false,
                saw_bridge_close: true,
                response_complete: true,
                response_bytes: 5,
            },
        ]);

        assert_eq!(
            accounting,
            BridgeLabAccounting {
                completed: 1,
                sent_requests: 2,
                closed: 2,
                response_bytes: 22,
            }
        );
    }

    #[test]
    fn bridge_lab_response_completion_timestamp_is_idempotent() {
        assert!(bridge_lab_should_record_response_completion(
            true, true, false
        ));
        assert!(!bridge_lab_should_record_response_completion(
            false, true, false
        ));
        assert!(!bridge_lab_should_record_response_completion(
            true, false, false
        ));
        assert!(!bridge_lab_should_record_response_completion(
            true, true, true
        ));
    }

    #[test]
    fn bridge_lab_latency_us_requires_sent_and_completed_times() {
        let sent_at = StdInstant::now();
        let completed_at = sent_at + Duration::from_micros(42);

        assert_eq!(
            bridge_lab_latency_us(Some(sent_at), Some(completed_at)),
            Some(42)
        );
        assert_eq!(
            bridge_lab_latency_us(Some(completed_at), Some(sent_at)),
            Some(0)
        );
        assert_eq!(bridge_lab_latency_us(None, Some(completed_at)), None);
        assert_eq!(bridge_lab_latency_us(Some(sent_at), None), None);
    }

    #[test]
    fn bridge_lab_cleanup_settled_requires_empty_flows_bridges_and_backlog() {
        assert!(bridge_lab_cleanup_settled(BridgeLabCleanupStatus::default()));
        assert!(!bridge_lab_cleanup_settled(BridgeLabCleanupStatus {
            active_flows: 1,
            ..BridgeLabCleanupStatus::default()
        }));
        assert!(!bridge_lab_cleanup_settled(BridgeLabCleanupStatus {
            active_bridges: 1,
            ..BridgeLabCleanupStatus::default()
        }));
        assert!(!bridge_lab_cleanup_settled(BridgeLabCleanupStatus {
            backlog_flows: 1,
            ..BridgeLabCleanupStatus::default()
        }));
        assert!(!bridge_lab_cleanup_settled(BridgeLabCleanupStatus {
            backlog_bytes: 1,
            ..BridgeLabCleanupStatus::default()
        }));
    }

    #[test]
    fn bridge_lab_summary_fields_preserve_accounting_values() {
        let fields = bridge_lab_summary_fields(
            3,
            BridgeLabAccounting {
                completed: 2,
                sent_requests: 3,
                closed: 2,
                response_bytes: 128,
            },
            Duration::from_millis(37),
            BridgeLabLatencySummary {
                p50_us: 10,
                p95_us: 20,
                max_us: 30,
            },
            BridgeLabCleanupStatus {
                active_flows: 1,
                active_bridges: 2,
                backlog_flows: 3,
                backlog_bytes: 4,
            },
            5,
            6,
        );

        assert_eq!(
            fields,
            BridgeLabSummaryFields {
                connections: 3,
                completed: 2,
                response_bytes: 128,
                elapsed_ms: 37,
                latency: BridgeLabLatencySummary {
                    p50_us: 10,
                    p95_us: 20,
                    max_us: 30,
                },
                cleanup: BridgeLabCleanupStatus {
                    active_flows: 1,
                    active_bridges: 2,
                    backlog_flows: 3,
                    backlog_bytes: 4,
                },
                backlog_overflow: 5,
                cleanup_iterations: 6,
            }
        );
    }

    #[test]
    fn bridge_lab_cleanup_aborts_incomplete_client_socket() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 8080;
        let client_port = 50_000;
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut client = BridgeLabClient {
            flow: tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port),
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: true,
            request_sent_at: Some(StdInstant::now()),
            response_complete_at: None,
            saw_bridge_close: false,
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec(),
        };

        assert!(!bridge_lab_completion_satisfied(
            bridge_lab_client_completion_flags(&client)
        ));
        assert!(client
            .sockets
            .get_mut::<tcp::Socket>(client.handle)
            .is_active());

        assert!(abort_bridge_lab_client_socket(&mut client));
        assert!(!client
            .sockets
            .get_mut::<tcp::Socket>(client.handle)
            .is_active());
        assert!(!abort_bridge_lab_client_socket(&mut client));
    }

    #[test]
    fn bridge_lab_latency_percentiles_use_nearest_rank() {
        let mut latencies = vec![900_u128, 100, 300, 500];

        assert_eq!(
            bridge_lab_latency_percentiles(&mut latencies),
            BridgeLabLatencySummary {
                p50_us: 300,
                p95_us: 900,
                max_us: 900,
            }
        );
    }

    #[test]
    fn bridge_lab_synthetic_client_models_proxy_response_window() {
        let (_iface, _device, sockets, handle) = synthetic_lab_client(
            Ipv4Addr::new(10, 255, 255, 2),
            DEFAULT_TUN_IP,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
            49152,
        )
        .expect("synthetic client");
        let socket = sockets.get::<tcp::Socket>(handle);

        assert_eq!(socket.recv_capacity(), tcp_core::TCP_SEND_BUFFER_BYTES);
        assert_eq!(socket.send_capacity(), tcp_core::TCP_RECV_BUFFER_BYTES);
        assert_eq!(socket.ack_delay(), None);
        assert!(!socket.nagle_enabled());
    }

    #[test]
    fn bridge_lab_router_recycles_client_packet_buffers_for_full_send_window() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
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
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        let payload = vec![0x42; tcp_core::TCP_SEND_BUFFER_BYTES];
        let sent = manager
            .send_flow_bytes_at(flow, &payload, now)
            .expect("enqueue full send window");
        assert_eq!(sent, payload.len());

        pump_lab_manager_to_clients(now, &mut manager, &mut clients)
            .expect("full send window should route without exhausting packet buffers");
        assert_eq!(clients[0].response.len(), payload.len());
        assert_eq!(clients[0].response, payload);
    }
}
