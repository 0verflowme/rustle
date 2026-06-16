use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
use bytes::Bytes;
use smoltcp::time::Instant as SmolInstant;
use tokio::sync::mpsc;

use crate::transport_model::{
    bridge_admission_decision, BridgeAdmissionDecision, BridgeAdmissionLimits,
    DataPlaneRuntimeSnapshot, UdpAssociation, UdpAssociationEvents, UdpFlowKey,
    UDP_DATAGRAMS_PER_ASSOCIATION,
};
use crate::{dns, ssh_bridge, tcp_core};

pub(crate) const PACKET_BUF_SIZE: usize = 2048;
pub(crate) const REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW: usize = 8;
pub(crate) const REMOTE_BACKLOG_BYTES_PER_FLOW: usize =
    tcp_core::TCP_SEND_BUFFER_BYTES * REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW;
pub(crate) const REMOTE_BACKLOG_BYTES_TOTAL: usize = 128 * 1024 * 1024;
pub(crate) const MAX_IN_FLIGHT_DNS_QUERIES: usize = 128;
pub(crate) const MAX_ACTIVE_UDP_ASSOCIATIONS: usize = 512;
const REMOTE_CLOSE_DEFER_FLUSHES: u8 = 2;

pub(crate) fn smol_now(started_at: StdInstant) -> SmolInstant {
    let millis = started_at.elapsed().as_millis().min(i64::MAX as u128) as i64;
    SmolInstant::from_millis(millis)
}

pub(crate) fn parse_dns_request_for_tunnel(packet: &[u8]) -> Option<dns::UdpDnsRequest> {
    match dns::parse_udp_dns_request(packet) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("dns: packet parse failed: {err}");
            None
        }
    }
}

pub(crate) fn tun_ipv4_packet(packet: &[u8]) -> Option<&[u8]> {
    const LINUX_PI_IPV4: [u8; 4] = [0x00, 0x00, 0x08, 0x00];
    const LINUX_PI_IPV6: [u8; 4] = [0x00, 0x00, 0x86, 0xdd];

    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(packet),
        Some(6) => None,
        _ if packet.len() >= LINUX_PI_IPV4.len()
            && packet[..LINUX_PI_IPV4.len()] == LINUX_PI_IPV4
            && packet[LINUX_PI_IPV4.len()] >> 4 == 4 =>
        {
            Some(&packet[LINUX_PI_IPV4.len()..])
        }
        _ if packet.len() >= LINUX_PI_IPV6.len()
            && packet[..LINUX_PI_IPV6.len()] == LINUX_PI_IPV6 =>
        {
            None
        }
        _ => None,
    }
}

pub(crate) fn parse_udp_request_for_agent_tunnel(packet: &[u8]) -> Option<dns::UdpPacket> {
    match dns::parse_ipv4_udp_packet(packet) {
        Ok(Some(request)) if request.dst_port != dns::DNS_PORT => Some(request),
        Ok(_) => None,
        Err(err) => {
            eprintln!("udp: packet parse failed: {err}");
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TunWriteStats {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
    pub(crate) dropped_packets: u64,
    pub(crate) dropped_bytes: u64,
}

impl TunWriteStats {
    pub(crate) fn record_written(&mut self, len: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
    }

    pub(crate) fn record_dropped(&mut self, len: usize) {
        self.dropped_packets = self.dropped_packets.saturating_add(1);
        self.dropped_bytes = self.dropped_bytes.saturating_add(len as u64);
    }

    pub(crate) fn combine(&mut self, other: Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.dropped_packets = self.dropped_packets.saturating_add(other.dropped_packets);
        self.dropped_bytes = self.dropped_bytes.saturating_add(other.dropped_bytes);
    }

    pub(crate) fn delivered_at_least_one_packet_without_drop(&self) -> bool {
        self.packets > 0 && self.dropped_packets == 0
    }
}

#[derive(Debug)]
pub(crate) struct DnsInflight {
    max: usize,
    current: usize,
    dropped: u64,
    completed: u64,
}

impl DnsInflight {
    pub(crate) fn new(max: usize) -> Self {
        assert!(max > 0, "in-flight limit must be greater than zero");
        Self {
            max,
            current: 0,
            dropped: 0,
            completed: 0,
        }
    }

    pub(crate) fn max(&self) -> usize {
        self.max
    }

    pub(crate) fn current(&self) -> usize {
        self.current
    }

    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    #[cfg(test)]
    pub(crate) fn completed(&self) -> u64 {
        self.completed
    }

    pub(crate) fn try_admit(&mut self) -> bool {
        if self.current >= self.max {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }

        self.current += 1;
        true
    }

    pub(crate) fn complete(&mut self) {
        if self.current > 0 {
            self.current -= 1;
            self.completed = self.completed.saturating_add(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct TunnelStats {
    pub(crate) started_at: StdInstant,
    pub(crate) tun_rx_packets: u64,
    pub(crate) tun_rx_bytes: u64,
    pub(crate) tun_tx_packets: u64,
    pub(crate) tun_tx_bytes: u64,
    pub(crate) tun_tx_dropped_packets: u64,
    pub(crate) tun_tx_dropped_bytes: u64,
    pub(crate) local_to_remote_bytes: u64,
    pub(crate) remote_to_local_bytes: u64,
    pub(crate) ssh_opened: u64,
    pub(crate) ssh_failed: u64,
    pub(crate) ssh_closed: u64,
    pub(crate) ssh_remote_eof: u64,
    pub(crate) ssh_open_latency_total_ms: u64,
    pub(crate) ssh_open_latency_max_ms: u64,
    pub(crate) ssh_open_deferred_active_limit: u64,
    pub(crate) ssh_open_deferred_open_limit: u64,
    pub(crate) dns_forwarded: u64,
    pub(crate) dns_ok: u64,
    pub(crate) dns_failed: u64,
    pub(crate) dns_dropped: u64,
    pub(crate) udp_forwarded: u64,
    pub(crate) udp_ok: u64,
    pub(crate) udp_failed: u64,
    pub(crate) udp_dropped: u64,
    pub(crate) expired_flows: u64,
    pub(crate) pruned_flows: u64,
    pub(crate) bridge_backpressure_events: u64,
    pub(crate) bridge_send_failures: u64,
    pub(crate) remote_backlog_overflows: u64,
    pub(crate) stale_bridge_events: u64,
}

impl TunnelStats {
    pub(crate) fn new() -> Self {
        Self {
            started_at: StdInstant::now(),
            tun_rx_packets: 0,
            tun_rx_bytes: 0,
            tun_tx_packets: 0,
            tun_tx_bytes: 0,
            tun_tx_dropped_packets: 0,
            tun_tx_dropped_bytes: 0,
            local_to_remote_bytes: 0,
            remote_to_local_bytes: 0,
            ssh_opened: 0,
            ssh_failed: 0,
            ssh_closed: 0,
            ssh_remote_eof: 0,
            ssh_open_latency_total_ms: 0,
            ssh_open_latency_max_ms: 0,
            ssh_open_deferred_active_limit: 0,
            ssh_open_deferred_open_limit: 0,
            dns_forwarded: 0,
            dns_ok: 0,
            dns_failed: 0,
            dns_dropped: 0,
            udp_forwarded: 0,
            udp_ok: 0,
            udp_failed: 0,
            udp_dropped: 0,
            expired_flows: 0,
            pruned_flows: 0,
            bridge_backpressure_events: 0,
            bridge_send_failures: 0,
            remote_backlog_overflows: 0,
            stale_bridge_events: 0,
        }
    }

    pub(crate) fn record_tun_rx(&mut self, len: usize) {
        self.tun_rx_packets = self.tun_rx_packets.saturating_add(1);
        self.tun_rx_bytes = self.tun_rx_bytes.saturating_add(len as u64);
    }

    pub(crate) fn record_tun_write(&mut self, write: TunWriteStats) {
        self.tun_tx_packets = self.tun_tx_packets.saturating_add(write.packets);
        self.tun_tx_bytes = self.tun_tx_bytes.saturating_add(write.bytes);
        self.tun_tx_dropped_packets = self
            .tun_tx_dropped_packets
            .saturating_add(write.dropped_packets);
        self.tun_tx_dropped_bytes = self
            .tun_tx_dropped_bytes
            .saturating_add(write.dropped_bytes);
    }

    pub(crate) fn record_dns_delivery(&mut self, remote_ok: bool, write: TunWriteStats) {
        let delivered = write.delivered_at_least_one_packet_without_drop();
        self.record_tun_write(write);
        self.record_dns_response(remote_ok && delivered);
    }

    pub(crate) fn record_udp_delivery(&mut self, write: TunWriteStats) {
        let delivered = write.delivered_at_least_one_packet_without_drop();
        self.record_tun_write(write);
        self.record_udp_response(delivered);
    }

    pub(crate) fn record_bridge_event(&mut self, event: &ssh_bridge::BridgeEvent) {
        match event {
            ssh_bridge::BridgeEvent::Opened { open_ms, .. } => {
                self.ssh_opened = self.ssh_opened.saturating_add(1);
                self.ssh_open_latency_total_ms =
                    self.ssh_open_latency_total_ms.saturating_add(*open_ms);
                self.ssh_open_latency_max_ms = self.ssh_open_latency_max_ms.max(*open_ms);
            }
            ssh_bridge::BridgeEvent::RemoteData { bytes, .. } => {
                self.remote_to_local_bytes = self
                    .remote_to_local_bytes
                    .saturating_add(bytes.len() as u64);
            }
            ssh_bridge::BridgeEvent::RemoteEof { .. } => {
                self.ssh_remote_eof = self.ssh_remote_eof.saturating_add(1);
            }
            ssh_bridge::BridgeEvent::Closed { .. } => {
                self.ssh_closed = self.ssh_closed.saturating_add(1);
            }
            ssh_bridge::BridgeEvent::Failed { .. } => {
                self.ssh_failed = self.ssh_failed.saturating_add(1);
            }
        }
    }

    pub(crate) fn record_local_drain(&mut self, stats: LocalDrainStats) {
        self.local_to_remote_bytes = self
            .local_to_remote_bytes
            .saturating_add(stats.bytes_to_bridge);
        self.bridge_backpressure_events = self
            .bridge_backpressure_events
            .saturating_add(stats.bridge_backpressure_events);
        self.bridge_send_failures = self
            .bridge_send_failures
            .saturating_add(stats.bridge_send_failures);
    }

    pub(crate) fn record_bridge_admission(&mut self, stats: BridgeAdmissionStats) {
        self.ssh_open_deferred_active_limit = self
            .ssh_open_deferred_active_limit
            .saturating_add(stats.deferred_active_limit);
        self.ssh_open_deferred_open_limit = self
            .ssh_open_deferred_open_limit
            .saturating_add(stats.deferred_open_limit);
    }

    pub(crate) fn record_dns_response(&mut self, remote_ok: bool) {
        if remote_ok {
            self.dns_ok = self.dns_ok.saturating_add(1);
        } else {
            self.dns_failed = self.dns_failed.saturating_add(1);
        }
    }

    pub(crate) fn record_udp_response(&mut self, remote_ok: bool) {
        if remote_ok {
            self.udp_ok = self.udp_ok.saturating_add(1);
        } else {
            self.udp_failed = self.udp_failed.saturating_add(1);
        }
    }

    pub(crate) fn status_line(
        &self,
        active_flows: usize,
        ssh_channels: usize,
        remote_backlogs: &RemoteBacklogs,
        dns_inflight: &DnsInflight,
        udp_inflight: &DnsInflight,
        agent: DataPlaneRuntimeSnapshot,
    ) -> String {
        let avg_open_ms = if self.ssh_opened == 0 {
            0
        } else {
            self.ssh_open_latency_total_ms / self.ssh_opened
        };

        format!(
            "uptime={} active_flows={} ssh_channels={} backlog_flows={} backlog_bytes={} tun_rx={}/{} tun_tx={}/{} tun_drop={}/{} tcp_l2r={} tcp_r2l={} dns=fwd:{} ok:{} fail:{} drop:{} inflight:{} udp=fwd:{} ok:{} fail:{} drop:{} active:{} ssh=open:{} fail:{} eof:{} close:{} open_ms=avg:{} max:{} defer=active:{} open:{} agent_reconnect=attempt:{} ok:{} fail:{} agent_lanes=total:{} desired:{} ok:{} fail:{} missing:{} quarantine:{} repairing:{} active:{} max_load:{} max_quarantine_ms:{} flow=expired:{} pruned:{} bridge_backpressure:{} bridge_send_fail:{} backlog_overflow:{} stale_bridge:{}",
            format_duration(self.started_at.elapsed()),
            active_flows,
            ssh_channels,
            remote_backlogs.active_flow_count(),
            format_bytes(remote_backlogs.total_bytes()),
            self.tun_rx_packets,
            format_bytes(self.tun_rx_bytes),
            self.tun_tx_packets,
            format_bytes(self.tun_tx_bytes),
            self.tun_tx_dropped_packets,
            format_bytes(self.tun_tx_dropped_bytes),
            format_bytes(self.local_to_remote_bytes),
            format_bytes(self.remote_to_local_bytes),
            self.dns_forwarded,
            self.dns_ok,
            self.dns_failed,
            self.dns_dropped,
            dns_inflight.current(),
            self.udp_forwarded,
            self.udp_ok,
            self.udp_failed,
            self.udp_dropped,
            udp_inflight.current(),
            self.ssh_opened,
            self.ssh_failed,
            self.ssh_remote_eof,
            self.ssh_closed,
            avg_open_ms,
            self.ssh_open_latency_max_ms,
            self.ssh_open_deferred_active_limit,
            self.ssh_open_deferred_open_limit,
            agent.reconnects.attempts,
            agent.reconnects.successes,
            agent.reconnects.failures,
            agent.lanes_total,
            agent.lanes_desired,
            agent.lanes_available,
            agent.lanes_failed,
            agent.lanes_missing,
            agent.lanes_quarantined,
            agent.lanes_repairing,
            agent.active_streams,
            agent.max_lane_load,
            agent.max_quarantine_ms,
            self.expired_flows,
            self.pruned_flows,
            self.bridge_backpressure_events,
            self.bridge_send_failures,
            self.remote_backlog_overflows,
            self.stale_bridge_events,
        )
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct BridgeAdmissionStats {
    pub(crate) deferred_active_limit: u64,
    pub(crate) deferred_open_limit: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct LocalDrainStats {
    pub(crate) bytes_to_bridge: u64,
    pub(crate) bridge_backpressure_events: u64,
    pub(crate) bridge_send_failures: u64,
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

pub(crate) struct UdpAssociationTransportPlan<T> {
    pub(crate) label: &'static str,
    pub(crate) transport: T,
}

impl<T> UdpAssociationTransportPlan<T> {
    pub(crate) fn new(label: &'static str, transport: T) -> Self {
        Self { label, transport }
    }
}

pub(crate) enum UdpIngressAction<T> {
    StartAssociation {
        transport: T,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    },
    SendDatagram {
        key: UdpFlowKey,
        to_remote: mpsc::Sender<Bytes>,
        payload: Bytes,
        transport_label: &'static str,
    },
    DropDatagram {
        key: UdpFlowKey,
        reason: UdpDropReason,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum UdpDropReason {
    UnsupportedTransport,
    AssociationLimitReached { max: usize },
    AssociationQueueFull,
    AssociationClosed,
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let millis = duration.subsec_millis();
    format!("{seconds}.{millis:03}s")
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

pub(crate) fn plan_udp_datagram_actions<T>(
    transport: Option<UdpAssociationTransportPlan<T>>,
    request: dns::UdpPacket,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
    actions: &mut Vec<UdpIngressAction<T>>,
) {
    let key = UdpFlowKey::from_packet(&request);
    let Some(transport) = transport else {
        actions.push(UdpIngressAction::DropDatagram {
            key,
            reason: UdpDropReason::UnsupportedTransport,
        });
        return;
    };
    let transport_label = transport.label;
    let association = match associations.entry(key) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            if !association_limit.try_admit() {
                actions.push(UdpIngressAction::DropDatagram {
                    key,
                    reason: UdpDropReason::AssociationLimitReached {
                        max: association_limit.max(),
                    },
                });
                return;
            }

            let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
            actions.push(UdpIngressAction::StartAssociation {
                transport: transport.transport,
                key,
                from_local,
                events: events.clone(),
                idle_timeout,
            });
            entry.insert(UdpAssociation {
                to_remote: to_remote.clone(),
            })
        }
    };

    actions.push(UdpIngressAction::SendDatagram {
        key,
        to_remote: association.to_remote.clone(),
        payload: request.payload,
        transport_label,
    });
}

pub(crate) fn execute_udp_ingress_actions<T, F>(
    actions: &mut Vec<UdpIngressAction<T>>,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    stats: &mut TunnelStats,
    spawn_association: &mut F,
) where
    F: FnMut(T, UdpFlowKey, mpsc::Receiver<Bytes>, UdpAssociationEvents, Duration),
{
    for action in actions.drain(..) {
        execute_udp_ingress_action(
            action,
            associations,
            association_limit,
            stats,
            spawn_association,
        );
    }
}

pub(crate) fn execute_udp_ingress_action<T, F>(
    action: UdpIngressAction<T>,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    stats: &mut TunnelStats,
    spawn_association: &mut F,
) where
    F: FnMut(T, UdpFlowKey, mpsc::Receiver<Bytes>, UdpAssociationEvents, Duration),
{
    match action {
        UdpIngressAction::StartAssociation {
            transport,
            key,
            from_local,
            events,
            idle_timeout,
        } => {
            spawn_association(transport, key, from_local, events, idle_timeout);
        }
        UdpIngressAction::SendDatagram {
            key,
            to_remote,
            payload,
            transport_label,
        } => match to_remote.try_send(payload) {
            Ok(()) => {
                stats.udp_forwarded = stats.udp_forwarded.saturating_add(1);
                eprintln!(
                    "udp: forwarding datagram {}:{} -> {}:{} over {}",
                    key.src_ip, key.src_port, key.dst_ip, key.dst_port, transport_label,
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => drop_udp_datagram(
                key,
                UdpDropReason::AssociationQueueFull,
                associations,
                association_limit,
                stats,
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => drop_udp_datagram(
                key,
                UdpDropReason::AssociationClosed,
                associations,
                association_limit,
                stats,
            ),
        },
        UdpIngressAction::DropDatagram { key, reason } => {
            drop_udp_datagram(key, reason, associations, association_limit, stats);
        }
    }
}

#[cfg(test)]
pub(crate) fn drop_unsupported_direct_udp(request: &dns::UdpPacket, stats: &mut TunnelStats) {
    let mut associations = HashMap::new();
    let mut association_limit = DnsInflight::new(1);
    let mut spawn_association = |(), _, _, _, _| {};
    execute_udp_ingress_action(
        UdpIngressAction::DropDatagram {
            key: UdpFlowKey::from_packet(request),
            reason: UdpDropReason::UnsupportedTransport,
        },
        &mut associations,
        &mut association_limit,
        stats,
        &mut spawn_association,
    );
}

fn drop_udp_datagram(
    key: UdpFlowKey,
    reason: UdpDropReason,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    stats: &mut TunnelStats,
) {
    if reason == UdpDropReason::AssociationClosed {
        associations.remove(&key);
        association_limit.complete();
    }
    match reason {
        UdpDropReason::UnsupportedTransport => {
            eprintln!(
                "udp: dropping datagram {}:{} -> {}:{} because direct-tcpip transport does not support generic UDP",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
        }
        UdpDropReason::AssociationLimitReached { max } => {
            eprintln!("udp: dropping datagram because {max} UDP associations are already active",);
        }
        UdpDropReason::AssociationQueueFull => {
            eprintln!(
                "udp: dropping datagram {}:{} -> {}:{} because the association queue is full",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
        }
        UdpDropReason::AssociationClosed => {
            eprintln!(
                "udp: dropping datagram {}:{} -> {}:{} because the association is closed",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
        }
    }
    stats.udp_dropped = stats.udp_dropped.saturating_add(1);
    stats.record_udp_response(false);
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
    F: FnMut(tcp_core::FlowId, mpsc::Sender<ssh_bridge::BridgeEvent>) -> ssh_bridge::FlowBridge,
{
    let mut stats = BridgeAdmissionStats::default();
    let mut active_channels = bridges.len();
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

        flow_manager.mark_flow_state_at(flow, tcp_core::FlowState::SshOpening, now)?;
        let bridge = spawn_bridge(id, event_tx.clone());
        bridges.insert(bridge.id.key, bridge);
        active_channels += 1;
        opening_channels += 1;
    }
    Ok(stats)
}

pub(crate) fn drain_local_bytes_to_bridges(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    flow_keys: &mut Vec<tcp_core::FlowKey>,
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

        let bytes = flow_manager.recv_flow_bytes(flow, remaining_bridge_bytes.min(16 * 1024))?;
        if bytes.is_empty() {
            continue;
        }

        let len = bytes.len() as u64;
        match bridge.try_send_local_data(bytes) {
            Ok(true) => {
                stats.bytes_to_bridge = stats.bytes_to_bridge.saturating_add(len);
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

#[derive(Debug)]
pub(crate) struct RemoteBacklogs {
    max_bytes_per_flow: usize,
    max_total_bytes: usize,
    total_bytes: usize,
    pub(crate) flows: HashMap<tcp_core::FlowId, RemoteBacklog>,
}

#[derive(Debug, Default)]
pub(crate) struct RemoteBacklog {
    pub(crate) chunks: VecDeque<Bytes>,
    pub(crate) front_offset: usize,
    pub(crate) bytes: usize,
    pub(crate) close_after_flush: bool,
    pub(crate) close_defer_flushes: u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RemoteBacklogPush {
    Accepted,
    FlowLimit,
    TotalLimit,
}

impl RemoteBacklogs {
    pub(crate) fn new(max_bytes_per_flow: usize) -> Self {
        Self::with_limits(max_bytes_per_flow, REMOTE_BACKLOG_BYTES_TOTAL)
    }

    pub(crate) fn with_limits(max_bytes_per_flow: usize, max_total_bytes: usize) -> Self {
        Self {
            max_bytes_per_flow,
            max_total_bytes,
            total_bytes: 0,
            flows: HashMap::new(),
        }
    }

    pub(crate) fn max_bytes_per_flow(&self) -> usize {
        self.max_bytes_per_flow
    }

    pub(crate) fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    pub(crate) fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub(crate) fn total_bytes(&self) -> u64 {
        self.total_bytes as u64
    }

    pub(crate) fn should_pause_bridge_events(&self) -> bool {
        self.total_bytes >= self.bridge_event_pause_threshold()
    }

    pub(crate) fn bridge_event_pause_threshold(&self) -> usize {
        self.max_total_bytes
            .saturating_sub(self.max_total_bytes / 4)
    }

    pub(crate) fn push(
        &mut self,
        id: tcp_core::FlowId,
        bytes: impl Into<Bytes>,
    ) -> RemoteBacklogPush {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return RemoteBacklogPush::Accepted;
        }
        if self.total_bytes.saturating_add(bytes.len()) > self.max_total_bytes {
            return RemoteBacklogPush::TotalLimit;
        }
        let backlog = self.flows.entry(id).or_default();
        if backlog.bytes.saturating_add(bytes.len()) > self.max_bytes_per_flow {
            return RemoteBacklogPush::FlowLimit;
        }
        backlog.bytes += bytes.len();
        self.total_bytes += bytes.len();
        backlog.chunks.push_back(bytes);
        if backlog.close_after_flush {
            backlog.close_defer_flushes = REMOTE_CLOSE_DEFER_FLUSHES;
        }
        RemoteBacklogPush::Accepted
    }

    pub(crate) fn close_after_flush(&mut self, id: tcp_core::FlowId) {
        let backlog = self.flows.entry(id).or_default();
        backlog.close_after_flush = true;
        backlog.close_defer_flushes = REMOTE_CLOSE_DEFER_FLUSHES;
    }

    pub(crate) fn remove_id(&mut self, id: tcp_core::FlowId) {
        if let Some(backlog) = self.flows.remove(&id) {
            self.total_bytes = self.total_bytes.saturating_sub(backlog.bytes);
        }
    }

    pub(crate) fn remove_flow(&mut self, flow: tcp_core::FlowKey) {
        let mut removed_bytes = 0_usize;
        self.flows.retain(|id, backlog| {
            if id.key == flow {
                removed_bytes = removed_bytes.saturating_add(backlog.bytes);
                false
            } else {
                true
            }
        });
        self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
    }

    pub(crate) fn flush_all_into(
        &mut self,
        flow_manager: &mut tcp_core::FlowManager,
        now: SmolInstant,
        flows: &mut Vec<tcp_core::FlowId>,
        closed: &mut Vec<tcp_core::FlowKey>,
    ) -> Result<()> {
        flows.clear();
        flows.reserve(self.flows.len());
        flows.extend(self.flows.keys().copied());
        closed.clear();
        closed.reserve(flows.len());
        for id in flows.drain(..) {
            self.flush_flow_into(flow_manager, id, now, closed)?;
        }
        Ok(())
    }

    pub(crate) fn flush_flow_into(
        &mut self,
        flow_manager: &mut tcp_core::FlowManager,
        id: tcp_core::FlowId,
        now: SmolInstant,
        closed: &mut Vec<tcp_core::FlowKey>,
    ) -> Result<()> {
        let flow = id.key;
        if !flow_manager.contains_flow_id(id) {
            eprintln!(
                "tcp: dropping stale remote backlog for {flow:?} generation={}",
                id.generation
            );
            self.remove_id(id);
            return Ok(());
        }

        let Some(backlog) = self.flows.get_mut(&id) else {
            return Ok(());
        };

        let mut abort_flow = false;
        while let Some(chunk) = backlog.chunks.front() {
            let pending = &chunk[backlog.front_offset..];
            let Some(sent) = flow_manager.try_send_flow_bytes_at(flow, pending, now)? else {
                eprintln!(
                    "tcp: remote backlog cannot flush because local flow closed for {flow:?}; resetting flow"
                );
                abort_flow = true;
                break;
            };

            if sent == 0 {
                return Ok(());
            }

            backlog.front_offset += sent;
            backlog.bytes = backlog.bytes.saturating_sub(sent);
            self.total_bytes = self.total_bytes.saturating_sub(sent);
            if backlog.front_offset == chunk.len() {
                backlog.chunks.pop_front();
                backlog.front_offset = 0;
            }
        }

        if abort_flow {
            self.remove_id(id);
            flow_manager.abort_flow(flow)?;
            closed.push(flow);
            return Ok(());
        }

        if backlog.close_after_flush {
            if backlog.close_defer_flushes > 0 {
                backlog.close_defer_flushes -= 1;
                return Ok(());
            }
            self.flows.remove(&id);
            flow_manager.close_flow(flow, tcp_core::FlowState::HalfClosedRemote)?;
        } else if backlog.bytes == 0 {
            self.flows.remove(&id);
        }

        Ok(())
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
