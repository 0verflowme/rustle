use std::collections::{hash_map::Entry, HashMap};

use anyhow::Result;
use smoltcp::time::Instant as SmolInstant;
use tokio::sync::mpsc;

use crate::transport_model::{
    bridge_admission_decision, BridgeAdmissionDecision, BridgeAdmissionLimits,
};
use crate::{ssh_bridge, tcp_core};

use super::backlog::{RemoteBacklogPush, RemoteBacklogs};

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct BridgeAdmissionStats {
    pub(crate) deferred_active_limit: u64,
    pub(crate) deferred_open_limit: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpBridgeStart {
    pub(crate) id: tcp_core::FlowId,
    pub(crate) ready_wait_ms: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct LocalDrainStats {
    pub(crate) bytes_to_bridge: u64,
    pub(crate) bridge_backpressure_events: u64,
    pub(crate) bridge_send_failures: u64,
    pub(crate) tcp_recv_queue_wait_us: u64,
    pub(crate) tcp_recv_queue_wait_max_us: u64,
    pub(crate) tcp_recv_queue_waits: u64,
}

#[cfg(test)]
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct BridgeEventOutcome {
    pub(crate) closed_flows: Vec<tcp_core::FlowKey>,
    pub(crate) remote_backlog_overflows: u64,
    pub(crate) stale_bridge_events: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct BridgeEventStats {
    pub(crate) remote_backlog_overflows: u64,
    pub(crate) stale_bridge_events: u64,
}

pub(crate) fn ensure_bridges<F>(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    limits: BridgeAdmissionLimits,
    mut spawn_bridge: F,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ready_flow_ids: &mut Vec<tcp_core::FlowId>,
    now: SmolInstant,
) -> Result<BridgeAdmissionStats>
where
    F: FnMut(TcpBridgeStart, mpsc::Sender<ssh_bridge::BridgeEvent>) -> ssh_bridge::FlowBridge,
{
    let mut starts = Vec::new();
    let mut opening_flow_keys = Vec::new();
    let stats = plan_bridge_starts(
        flow_manager,
        bridges,
        limits,
        ready_flow_ids,
        &mut opening_flow_keys,
        now,
        &mut starts,
    )?;
    for start in starts.drain(..) {
        let bridge = spawn_bridge(start, event_tx.clone());
        register_tcp_bridge(flow_manager, bridges, start, bridge)?;
    }
    Ok(stats)
}

pub(crate) fn plan_bridge_starts(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    limits: BridgeAdmissionLimits,
    ready_flow_ids: &mut Vec<tcp_core::FlowId>,
    opening_flow_keys: &mut Vec<tcp_core::FlowKey>,
    now: SmolInstant,
    starts: &mut Vec<TcpBridgeStart>,
) -> Result<BridgeAdmissionStats> {
    let mut stats = BridgeAdmissionStats::default();
    let mut active_channels = active_bridge_reservations(flow_manager, bridges, opening_flow_keys);
    let mut opening_channels = flow_manager.opening_flow_count();

    flow_manager.ready_to_bridge_flow_ids_into(ready_flow_ids);
    for id in ready_flow_ids.drain(..) {
        let flow = id.key;
        if bridges.contains_key(&flow) {
            continue;
        }
        match bridge_admission_decision(active_channels, opening_channels, limits) {
            BridgeAdmissionDecision::Admit => {}
            BridgeAdmissionDecision::DeferActive => {
                stats.deferred_active_limit = stats.deferred_active_limit.saturating_add(1);
                continue;
            }
            BridgeAdmissionDecision::DeferOpening => {
                stats.deferred_open_limit = stats.deferred_open_limit.saturating_add(1);
                continue;
            }
        }

        let ready_wait_ms = flow_manager.flow_state_elapsed_ms(flow, now)?;
        flow_manager.mark_flow_state_at(flow, tcp_core::FlowState::SshOpening, now)?;
        starts.push(TcpBridgeStart { id, ready_wait_ms });
        active_channels += 1;
        opening_channels += 1;
    }
    Ok(stats)
}

fn active_bridge_reservations(
    flow_manager: &tcp_core::FlowManager,
    bridges: &HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    opening_flow_keys: &mut Vec<tcp_core::FlowKey>,
) -> usize {
    flow_manager.opening_flow_keys_into(opening_flow_keys);
    let unregistered_opening = opening_flow_keys
        .iter()
        .filter(|flow| !bridges.contains_key(flow))
        .count();
    bridges.len().saturating_add(unregistered_opening)
}

pub(crate) fn register_tcp_bridge(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    start: TcpBridgeStart,
    bridge: ssh_bridge::FlowBridge,
) -> Result<()> {
    if bridge.id != start.id {
        anyhow::bail!(
            "bridge registration mismatch: planned {:?}, spawned {:?}",
            start.id,
            bridge.id
        );
    }
    if !flow_manager.contains_flow_id(start.id) {
        anyhow::bail!("bridge registration for missing flow {:?}", start.id);
    }
    match bridges.entry(bridge.id.key) {
        Entry::Occupied(_) => {
            anyhow::bail!("bridge already registered for flow {:?}", bridge.id.key);
        }
        Entry::Vacant(entry) => {
            entry.insert(bridge);
        }
    }
    Ok(())
}

pub(crate) fn drain_local_bytes_to_bridges(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    flow_keys: &mut Vec<tcp_core::FlowKey>,
    now: SmolInstant,
) -> Result<LocalDrainStats> {
    let mut stats = LocalDrainStats::default();
    flow_manager.flow_keys_into(flow_keys);
    for flow in flow_keys.drain(..) {
        if flow_manager.recv_queue_len(flow)? == 0 {
            continue;
        }

        let Some(bridge) = bridges.get(&flow) else {
            if matches!(
                flow_manager.flow_state(flow)?,
                tcp_core::FlowState::TcpEstablished | tcp_core::FlowState::SshOpening
            ) {
                stats.bridge_backpressure_events =
                    stats.bridge_backpressure_events.saturating_add(1);
                continue;
            }
            eprintln!(
                "ssh: missing bridge while draining local bytes for {flow:?}; resetting flow"
            );
            flow_manager.abort_flow(flow)?;
            stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            continue;
        };

        let remaining_bridge_bytes = bridge.local_queue_remaining_bytes();
        if bridge.local_queue_capacity() == 0 || remaining_bridge_bytes == 0 {
            stats.bridge_backpressure_events = stats.bridge_backpressure_events.saturating_add(1);
            continue;
        }

        let flow_bytes = flow_manager.recv_flow_bytes_with_metrics(
            flow,
            remaining_bridge_bytes.min(16 * 1024),
            now,
        )?;
        let bytes = flow_bytes.bytes;
        if bytes.is_empty() {
            continue;
        }

        let len = bytes.len() as u64;
        match bridge.try_send_local_data_with_metrics(bytes, flow_bytes.tcp_recv_queue_wait_us) {
            Ok(true) => {
                stats.bytes_to_bridge = stats.bytes_to_bridge.saturating_add(len);
                if let Some(wait_us) = flow_bytes.tcp_recv_queue_wait_us {
                    stats.tcp_recv_queue_wait_us =
                        stats.tcp_recv_queue_wait_us.saturating_add(wait_us);
                    stats.tcp_recv_queue_wait_max_us =
                        stats.tcp_recv_queue_wait_max_us.max(wait_us);
                    stats.tcp_recv_queue_waits = stats.tcp_recv_queue_waits.saturating_add(1);
                }
            }
            Ok(false) => {
                eprintln!(
                    "ssh: bridge queue filled while draining local bytes for {flow:?}; resetting flow"
                );
                bridges.remove(&flow);
                flow_manager.abort_flow(flow)?;
                stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            }
            Err(err) => {
                eprintln!("ssh: bridge task closed while sending local bytes for {flow:?}: {err}");
                bridges.remove(&flow);
                flow_manager.abort_flow(flow)?;
                stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
pub(crate) fn handle_bridge_event(
    event: ssh_bridge::BridgeEvent,
    flow_manager: &mut tcp_core::FlowManager,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
) -> Result<BridgeEventOutcome> {
    let mut closed_flows = Vec::new();
    let stats =
        handle_bridge_event_into(event, flow_manager, remote_backlogs, now, &mut closed_flows)?;
    Ok(BridgeEventOutcome {
        closed_flows,
        remote_backlog_overflows: stats.remote_backlog_overflows,
        stale_bridge_events: stats.stale_bridge_events,
    })
}

pub(crate) fn handle_bridge_event_into(
    event: ssh_bridge::BridgeEvent,
    flow_manager: &mut tcp_core::FlowManager,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
    closed_flows: &mut Vec<tcp_core::FlowKey>,
) -> Result<BridgeEventStats> {
    closed_flows.clear();
    let id = bridge_event_id(&event);
    let flow = id.key;
    if !flow_manager.contains_flow(flow) {
        if should_log_stale_bridge_event(&event) {
            eprintln!(
                "ssh: ignoring stale {} event for removed {flow:?}",
                bridge_event_name(&event)
            );
        }
        remote_backlogs.remove_id(id);
        return Ok(BridgeEventStats {
            stale_bridge_events: 1,
            ..BridgeEventStats::default()
        });
    }
    if !flow_manager.contains_flow_id(id) {
        if should_log_stale_bridge_event(&event) {
            eprintln!(
                "ssh: ignoring stale {} event for reused {flow:?} generation={}",
                bridge_event_name(&event),
                id.generation
            );
        }
        remote_backlogs.remove_id(id);
        return Ok(BridgeEventStats {
            stale_bridge_events: 1,
            ..BridgeEventStats::default()
        });
    }

    match event {
        ssh_bridge::BridgeEvent::Opened { id, open_ms } => {
            let flow = id.key;
            flow_manager.mark_flow_state_at(flow, tcp_core::FlowState::Relaying, now)?;
            eprintln!(
                "bridge: open for {flow:?} generation={} in {open_ms}ms",
                id.generation
            );
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::RemoteData { id, bytes } => {
            let flow = id.key;
            match remote_backlogs.push(id, bytes) {
                RemoteBacklogPush::Accepted => {}
                RemoteBacklogPush::FlowLimit => {
                    eprintln!(
                        "tcp: remote backlog exceeded {} bytes for {flow:?}; resetting flow",
                        remote_backlogs.max_bytes_per_flow()
                    );
                    remote_backlogs.remove_id(id);
                    flow_manager.abort_flow(flow)?;
                    closed_flows.push(flow);
                    return Ok(BridgeEventStats {
                        remote_backlog_overflows: 1,
                        ..BridgeEventStats::default()
                    });
                }
                RemoteBacklogPush::TotalLimit => {
                    eprintln!(
                        "tcp: total remote backlog exceeded {} bytes; resetting {flow:?}",
                        remote_backlogs.max_total_bytes()
                    );
                    remote_backlogs.remove_id(id);
                    flow_manager.abort_flow(flow)?;
                    closed_flows.push(flow);
                    return Ok(BridgeEventStats {
                        remote_backlog_overflows: 1,
                        ..BridgeEventStats::default()
                    });
                }
            }
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::RemoteEof { id } => {
            remote_backlogs.close_after_flush(id);
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::Closed { id } => {
            let flow = id.key;
            remote_backlogs.close_after_flush(id);
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            if !closed_flows.contains(&flow) {
                closed_flows.push(flow);
            }
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::Failed { id, phase, message } => {
            let flow = id.key;
            eprintln!("bridge: {phase:?} failed for {flow:?}: {message}");
            remote_backlogs.remove_id(id);
            flow_manager.abort_flow(flow)?;
            closed_flows.push(flow);
            Ok(BridgeEventStats::default())
        }
    }
}

pub(crate) fn should_log_stale_bridge_event(event: &ssh_bridge::BridgeEvent) -> bool {
    !matches!(event, ssh_bridge::BridgeEvent::RemoteData { .. })
}

pub(crate) fn bridge_event_id(event: &ssh_bridge::BridgeEvent) -> tcp_core::FlowId {
    match event {
        ssh_bridge::BridgeEvent::Opened { id, .. }
        | ssh_bridge::BridgeEvent::RemoteData { id, .. }
        | ssh_bridge::BridgeEvent::RemoteEof { id }
        | ssh_bridge::BridgeEvent::Closed { id }
        | ssh_bridge::BridgeEvent::Failed { id, .. } => *id,
    }
}

pub(crate) fn bridge_event_name(event: &ssh_bridge::BridgeEvent) -> &'static str {
    match event {
        ssh_bridge::BridgeEvent::Opened { .. } => "opened",
        ssh_bridge::BridgeEvent::RemoteData { .. } => "remote-data",
        ssh_bridge::BridgeEvent::RemoteEof { .. } => "remote-eof",
        ssh_bridge::BridgeEvent::Closed { .. } => "closed",
        ssh_bridge::BridgeEvent::Failed { .. } => "failed",
    }
}

pub(crate) fn expire_stale_flows(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
    expired: &mut Vec<tcp_core::FlowKey>,
) -> usize {
    flow_manager.expire_stale_flows_into(now, expired);
    let count = expired.len();
    for flow in expired.drain(..) {
        eprintln!("tcp: expiring stale flow {flow:?}");
        bridges.remove(&flow);
        remote_backlogs.remove_flow(flow);
    }
    count
}

pub(crate) fn prune_closed_flows(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    removable: &mut Vec<tcp_core::FlowKey>,
) -> Result<usize> {
    flow_manager.removable_flows_into(removable);
    let count = removable.len();
    for flow in removable.drain(..) {
        bridges.remove(&flow);
        remote_backlogs.remove_flow(flow);
        flow_manager.remove_flow(flow)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use bytes::Bytes;
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant as SmolInstant;
    use tokio::sync::{mpsc, oneshot};

    use super::super::backlog::REMOTE_BACKLOG_BYTES_PER_FLOW;
    use super::*;
    use crate::bridge_lab::{
        drain_lab_client_to_manager, pump_lab_manager_to_clients, route_lab_packets_to_clients,
        synthetic_lab_client, BridgeLabClient,
    };
    use crate::defaults::{DEFAULT_MTU, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};
    use crate::transport_model::{
        bridge_admission_decision, BridgeAdmissionDecision, MAX_AGENT_ACTIVE_STREAMS,
        MAX_AGENT_OPENING_STREAMS, MAX_DIRECT_ACTIVE_CHANNELS, MAX_DIRECT_OPENING_CHANNELS,
    };

    #[test]
    fn agent_bridge_admission_budget_exceeds_direct_tcpip_channel_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(direct.active, MAX_DIRECT_ACTIVE_CHANNELS);
        assert_eq!(direct.opening, MAX_DIRECT_OPENING_CHANNELS);
        assert_eq!(agent.active, tcp_core::DEFAULT_MAX_ACTIVE_FLOWS);
        assert!(agent.active > direct.active);
        assert!(agent.opening > direct.opening);
    }

    #[test]
    fn bridge_admission_decision_uses_transport_specific_opening_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS - 1, direct),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, direct),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, agent),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_AGENT_OPENING_STREAMS, agent),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(MAX_AGENT_ACTIVE_STREAMS, 0, agent),
            BridgeAdmissionDecision::DeferActive
        );
    }

    #[test]
    fn planned_bridge_start_marks_flow_ssh_opening() {
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
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
        let mut ready_flow_ids = Vec::new();
        let mut opening_flow_keys = Vec::new();
        let mut starts = Vec::new();

        let stats = plan_bridge_starts(
            &mut manager,
            &bridges,
            BridgeAdmissionLimits {
                active: 16,
                opening: 16,
            },
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            SmolInstant::from_millis(10),
            &mut starts,
        )
        .expect("plan bridge starts");

        assert_eq!(stats, BridgeAdmissionStats::default());
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].id, id);
        assert!(starts[0].ready_wait_ms <= 10);
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::SshOpening
        );
        assert!(bridges.is_empty());
    }

    #[test]
    fn planned_bridge_start_records_ready_wait_after_deferred_admission() {
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
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
        let mut ready_flow_ids = Vec::new();
        let mut opening_flow_keys = Vec::new();
        let mut starts = Vec::new();

        let deferred = plan_bridge_starts(
            &mut manager,
            &bridges,
            BridgeAdmissionLimits {
                active: 0,
                opening: 16,
            },
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            SmolInstant::from_millis(10),
            &mut starts,
        )
        .expect("defer bridge starts");

        assert_eq!(
            deferred,
            BridgeAdmissionStats {
                deferred_active_limit: 1,
                deferred_open_limit: 0,
            }
        );
        assert!(starts.is_empty());
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::TcpEstablished
        );

        let plan_now = SmolInstant::from_millis(25);
        let expected_ready_wait_ms = manager
            .flow_state_elapsed_ms(flow, plan_now)
            .expect("flow ready age");
        let admitted = plan_bridge_starts(
            &mut manager,
            &bridges,
            BridgeAdmissionLimits {
                active: 16,
                opening: 16,
            },
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            plan_now,
            &mut starts,
        )
        .expect("admit bridge starts");

        assert_eq!(admitted, BridgeAdmissionStats::default());
        assert_eq!(
            starts,
            vec![TcpBridgeStart {
                id,
                ready_wait_ms: expected_ready_wait_ms,
            }]
        );
        assert!(starts[0].ready_wait_ms >= 15);
    }

    #[tokio::test]
    async fn planned_bridge_registration_inserts_spawned_bridge() {
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
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
        let mut ready_flow_ids = Vec::new();
        let mut opening_flow_keys = Vec::new();
        let mut starts = Vec::new();
        plan_bridge_starts(
            &mut manager,
            &bridges,
            BridgeAdmissionLimits {
                active: 16,
                opening: 16,
            },
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            SmolInstant::from_millis(10),
            &mut starts,
        )
        .expect("plan bridge starts");
        let start = starts.pop().expect("planned start");
        assert_eq!(start.id, id);

        let (event_tx, _event_rx) = mpsc::channel(1);
        let bridge =
            ssh_bridge::spawn_bridge_task(start.id, event_tx, |_id, _local_rx, _event_tx| async {
                std::future::pending::<()>().await;
            });
        register_tcp_bridge(&mut manager, &mut bridges, start, bridge)
            .expect("register planned bridge");

        assert_eq!(bridges.len(), 1);
        assert!(bridges.contains_key(&flow));
    }

    #[test]
    fn unregistered_opening_start_reserves_active_admission_slot() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let first_client_port = 49152;
        let second_client_port = 49153;
        let first_flow = tcp_core::FlowKey::tcp(
            client_ip,
            first_client_port,
            destination_ip,
            destination_port,
        );
        let second_flow = tcp_core::FlowKey::tcp(
            client_ip,
            second_client_port,
            destination_ip,
            destination_port,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            first_client_port,
        );
        establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            second_client_port,
        );
        let bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
        let limits = BridgeAdmissionLimits {
            active: 1,
            opening: 128,
        };
        let mut ready_flow_ids = Vec::new();
        let mut opening_flow_keys = Vec::new();
        let mut starts = Vec::new();

        let first_stats = plan_bridge_starts(
            &mut manager,
            &bridges,
            limits,
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            SmolInstant::from_millis(10),
            &mut starts,
        )
        .expect("first bridge start plan");

        assert_eq!(starts.len(), 1);
        assert_eq!(
            first_stats,
            BridgeAdmissionStats {
                deferred_active_limit: 1,
                deferred_open_limit: 0,
            }
        );
        assert_eq!(manager.opening_flow_count(), 1);
        assert!(matches!(
            manager.flow_state(first_flow).expect("first flow state"),
            tcp_core::FlowState::SshOpening | tcp_core::FlowState::TcpEstablished
        ));
        assert!(matches!(
            manager.flow_state(second_flow).expect("second flow state"),
            tcp_core::FlowState::SshOpening | tcp_core::FlowState::TcpEstablished
        ));

        starts.clear();
        let second_stats = plan_bridge_starts(
            &mut manager,
            &bridges,
            limits,
            &mut ready_flow_ids,
            &mut opening_flow_keys,
            SmolInstant::from_millis(11),
            &mut starts,
        )
        .expect("second bridge start plan");

        assert!(starts.is_empty());
        assert_eq!(
            second_stats,
            BridgeAdmissionStats {
                deferred_active_limit: 1,
                deferred_open_limit: 0,
            }
        );
        assert_eq!(manager.opening_flow_count(), 1);
    }

    #[test]
    fn stale_bridge_event_for_removed_flow_is_not_fatal() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(
                Ipv4Addr::new(192, 168, 1, 10),
                32,
            )],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed {
                id: tcp_core::FlowId::new(flow, 1),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale bridge event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
    }

    #[test]
    fn stale_remote_data_storm_after_flow_removal_is_bounded() {
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
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager
            .remove_flow(flow)
            .expect("remove flow before stale storm");

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        let closed_capacity = closed_flows.capacity();
        let payload = Bytes::from(vec![0x5a; 16 * 1024]);
        let mut stale_events = 0_u64;
        let mut overflows = 0_u64;

        for tick in 0..2048 {
            let stats = handle_bridge_event_into(
                ssh_bridge::BridgeEvent::RemoteData {
                    id,
                    bytes: payload.clone(),
                },
                &mut manager,
                &mut backlogs,
                SmolInstant::from_millis(tick),
                &mut closed_flows,
            )
            .expect("stale remote-data event should not fail");
            stale_events = stale_events.saturating_add(stats.stale_bridge_events);
            overflows = overflows.saturating_add(stats.remote_backlog_overflows);

            assert!(closed_flows.is_empty());
            assert_eq!(closed_flows.capacity(), closed_capacity);
            assert_eq!(backlogs.active_flow_count(), 0);
            assert_eq!(backlogs.total_bytes(), 0);
        }

        assert_eq!(stale_events, 2048);
        assert_eq!(overflows, 0);
    }

    #[test]
    fn high_fanout_stale_remote_data_after_removal_is_bounded() {
        const FLOWS: usize = 32;
        const STALE_ROUNDS: usize = 64;

        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let mut ids = Vec::with_capacity(FLOWS);

        for index in 0..FLOWS {
            let client_port = 49152 + index as u16;
            ids.push(establish_lab_flow(
                &mut manager,
                client_ip,
                destination_ip,
                destination_port,
                client_port,
            ));
        }

        for id in &ids {
            manager
                .remove_flow(id.key)
                .expect("remove flow before high-fanout stale storm");
        }
        assert_eq!(manager.active_flow_count(), 0);

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(FLOWS);
        let closed_capacity = closed_flows.capacity();
        let payload = Bytes::from(vec![0x5a; 1024]);
        let mut stale_events = 0_u64;
        let mut overflows = 0_u64;

        for round in 0..STALE_ROUNDS {
            for id in &ids {
                let stats = handle_bridge_event_into(
                    ssh_bridge::BridgeEvent::RemoteData {
                        id: *id,
                        bytes: payload.clone(),
                    },
                    &mut manager,
                    &mut backlogs,
                    SmolInstant::from_millis(round as i64),
                    &mut closed_flows,
                )
                .expect("high-fanout stale remote-data event should not fail");

                stale_events = stale_events.saturating_add(stats.stale_bridge_events);
                overflows = overflows.saturating_add(stats.remote_backlog_overflows);
                assert!(closed_flows.is_empty());
                assert_eq!(closed_flows.capacity(), closed_capacity);
                assert_eq!(backlogs.active_flow_count(), 0);
                assert_eq!(backlogs.total_bytes(), 0);
            }
        }

        assert_eq!(stale_events, (FLOWS * STALE_ROUNDS) as u64);
        assert_eq!(overflows, 0);
    }

    #[test]
    fn stale_remote_data_events_are_counted_without_per_chunk_log() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 7);

        assert!(!should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"stale")
            }
        ));
        assert!(should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::Closed { id }
        ));
    }

    #[test]
    fn stale_bridge_event_for_reused_tuple_does_not_touch_new_flow() {
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

        let old_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager.remove_flow(flow).expect("remove old flow");
        let new_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(old_id.key, new_id.key);
        assert_ne!(old_id.generation, new_id.generation);

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(new_id, b"new-flow-data".to_vec()),
            RemoteBacklogPush::Accepted
        );
        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id: old_id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale generation event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
        assert!(manager.contains_flow_id(new_id));
        assert_eq!(backlogs.total_bytes(), b"new-flow-data".len() as u64);
    }

    #[test]
    fn remote_close_defers_flow_close_for_late_remote_data() {
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
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let close_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
        )
        .expect("remote close event");
        assert_eq!(close_outcome.closed_flows, vec![flow]);
        assert_eq!(close_outcome.stale_bridge_events, 0);
        assert!(manager.contains_flow_id(id));
        assert_eq!(backlogs.active_flow_count(), 1);

        let late_bytes = Bytes::from_static(b"late remote bytes after close marker");
        let expected_len = late_bytes.len() as u64;
        let data_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: late_bytes,
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(2),
        )
        .expect("late remote data event");
        assert!(data_outcome.closed_flows.is_empty());
        assert_eq!(data_outcome.stale_bridge_events, 0);
        assert_eq!(backlogs.total_bytes(), 0);

        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(snapshot.remote_to_local_bytes, expected_len);
        assert_eq!(snapshot.state, tcp_core::FlowState::TcpEstablished);

        let mut flow_keys = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(3),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("first deferred flush");
        assert!(manager.contains_flow_id(id));
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::TcpEstablished
        );

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(4),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("second deferred flush");
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::HalfClosedRemote
        );
        assert_eq!(backlogs.active_flow_count(), 0);
    }

    #[test]
    fn bridge_event_handler_into_reuses_closed_flow_scratch_vector() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let stale = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(id.key, flow);
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale);
        let capacity = closed_flows.capacity();

        let stats = handle_bridge_event_into(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"remote bytes"),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
            &mut closed_flows,
        )
        .expect("remote data event");

        assert_eq!(stats, BridgeEventStats::default());
        assert!(closed_flows.is_empty());
        assert_eq!(closed_flows.capacity(), capacity);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[tokio::test]
    async fn missing_bridge_during_local_drain_resets_flow() {
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

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET / HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys, now)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 1);
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Reset
        }));
    }

    #[tokio::test]
    async fn local_drain_records_tcp_recv_queue_wait() {
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

        let request = b"GET /queued HTTP/1.1\r\n\r\n";
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket.send_slice(request).expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            request.len()
        );

        let id = manager.flow_id(flow).expect("flow id");
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (received_tx, received_rx) = oneshot::channel();
        let bridge = ssh_bridge::spawn_bridge_task(
            id,
            event_tx,
            move |_id, mut local_rx, _event_tx| async move {
                let local = local_rx
                    .recv_with_metrics()
                    .await
                    .expect("queued local data");
                received_tx
                    .send((local.bytes, local.tcp_recv_queue_wait_us))
                    .expect("report local data");
                std::future::pending::<()>().await;
            },
        );
        let mut bridges = HashMap::from([(flow, bridge)]);
        let mut flow_keys = Vec::new();
        now += smoltcp::time::Duration::from_millis(7);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys, now)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, request.len() as u64);
        assert_eq!(stats.tcp_recv_queue_wait_us, 7_000);
        assert_eq!(stats.tcp_recv_queue_wait_max_us, 7_000);
        assert_eq!(stats.tcp_recv_queue_waits, 1);
        let (bytes, wait_us) = tokio::time::timeout(std::time::Duration::from_secs(1), received_rx)
            .await
            .expect("bridge should receive local data")
            .expect("bridge should report local data");
        assert_eq!(bytes, Bytes::copy_from_slice(request));
        assert_eq!(wait_us, Some(7_000));
    }

    #[tokio::test]
    async fn deferred_bridge_admission_leaves_local_bytes_buffered() {
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

        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /deferred HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys, now)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(stats.bridge_backpressure_events, 1);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
        }));
    }

    #[tokio::test]
    async fn saturated_bridge_queue_leaves_local_bytes_buffered() {
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

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /slow HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let (event_tx, _event_rx) = mpsc::channel(1);
        let id = manager.flow_id(flow).expect("flow id");
        let bridge =
            ssh_bridge::spawn_bridge_task(id, event_tx, |_id, local_rx, _event_tx| async {
                let _local_rx = local_rx;
                std::future::pending::<()>().await;
            });
        for index in 0..ssh_bridge::FLOW_CHANNEL_DEPTH {
            assert!(
                bridge
                    .try_send_local_data(vec![index as u8])
                    .expect("pre-fill bridge queue"),
                "bridge queue should accept pre-fill item {index}"
            );
        }
        assert_eq!(bridge.local_queue_capacity(), 0);

        let mut bridges = HashMap::from([(flow, bridge)]);
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys, now)
            .expect("drain should not block or fail");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Relaying
        }));
    }

    fn establish_lab_flow(
        manager: &mut tcp_core::FlowManager,
        client_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        client_port: u16,
    ) -> tcp_core::FlowId {
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
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
                drain_lab_client_to_manager(now, client, manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                return manager.flow_id(flow).expect("flow id");
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        panic!("synthetic flow did not reach TcpEstablished");
    }
}
