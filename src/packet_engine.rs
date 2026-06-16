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

pub(crate) struct TunnelEngine {
    flow_manager: tcp_core::FlowManager,
    bridges: HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    udp_associations: HashMap<UdpFlowKey, UdpAssociation>,
    remote_backlogs: RemoteBacklogs,
    dns_inflight: DnsInflight,
    udp_inflight: DnsInflight,
    stats: TunnelStats,
    started_at: StdInstant,
    outbound_packets: Vec<tcp_core::PacketBuf>,
    ready_flow_ids: Vec<tcp_core::FlowId>,
    opening_flow_keys: Vec<tcp_core::FlowKey>,
    flow_keys: Vec<tcp_core::FlowKey>,
    backlog_flow_ids: Vec<tcp_core::FlowId>,
    backlog_closed_flows: Vec<tcp_core::FlowKey>,
    bridge_event_closed_flows: Vec<tcp_core::FlowKey>,
    expired_flows: Vec<tcp_core::FlowKey>,
    removable_flows: Vec<tcp_core::FlowKey>,
}

impl TunnelEngine {
    pub(crate) fn new(flow_manager: tcp_core::FlowManager) -> Self {
        Self {
            flow_manager,
            bridges: HashMap::new(),
            udp_associations: HashMap::new(),
            remote_backlogs: RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW),
            dns_inflight: DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES),
            udp_inflight: DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS),
            stats: TunnelStats::new(),
            started_at: StdInstant::now(),
            outbound_packets: Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY),
            ready_flow_ids: Vec::new(),
            opening_flow_keys: Vec::new(),
            flow_keys: Vec::new(),
            backlog_flow_ids: Vec::new(),
            backlog_closed_flows: Vec::new(),
            bridge_event_closed_flows: Vec::new(),
            expired_flows: Vec::new(),
            removable_flows: Vec::new(),
        }
    }

    pub(crate) fn record_tun_rx(&mut self, len: usize) {
        self.stats.record_tun_rx(len);
    }

    pub(crate) fn record_tun_write(&mut self, write: TunWriteStats) {
        self.stats.record_tun_write(write);
    }

    pub(crate) fn outbound_packets_mut(&mut self) -> &mut Vec<tcp_core::PacketBuf> {
        &mut self.outbound_packets
    }

    pub(crate) fn try_admit_dns(&mut self) -> bool {
        self.dns_inflight.try_admit()
    }

    pub(crate) fn complete_dns(&mut self) {
        self.dns_inflight.complete();
    }

    pub(crate) fn dns_inflight_limit(&self) -> usize {
        self.dns_inflight.max()
    }

    pub(crate) fn record_dns_forwarded(&mut self) {
        self.stats.dns_forwarded = self.stats.dns_forwarded.saturating_add(1);
    }

    pub(crate) fn record_dns_drop(&mut self) {
        self.stats.dns_dropped = self.stats.dns_dropped.saturating_add(1);
        self.stats.record_dns_response(false);
    }

    pub(crate) fn record_dns_delivery(&mut self, remote_ok: bool, write: TunWriteStats) {
        self.stats.record_dns_delivery(remote_ok, write);
    }

    pub(crate) fn record_udp_delivery(&mut self, write: TunWriteStats) {
        self.stats.record_udp_delivery(write);
    }

    pub(crate) fn close_udp_association(&mut self, key: UdpFlowKey) {
        self.udp_associations.remove(&key);
        self.udp_inflight.complete();
    }

    pub(crate) fn record_udp_close_error(&mut self) {
        self.stats.record_udp_response(false);
    }

    pub(crate) fn should_pause_bridge_events(&self) -> bool {
        self.remote_backlogs.should_pause_bridge_events()
    }

    pub(crate) fn status_line(&self, agent: DataPlaneRuntimeSnapshot) -> String {
        self.stats.status_line(
            self.flow_manager.active_flow_count(),
            self.bridges.len(),
            &self.remote_backlogs,
            &self.dns_inflight,
            &self.udp_inflight,
            agent,
        )
    }

    pub(crate) fn ingest_tcp_packet(&mut self, packet: &[u8]) -> Result<()> {
        let now = self.now();
        self.flow_manager
            .ingest_packet_into(now, packet, &mut self.outbound_packets)?;
        Ok(())
    }

    pub(crate) fn poll_tcp(&mut self) {
        let now = self.now();
        self.flow_manager.poll_into(now, &mut self.outbound_packets);
    }

    pub(crate) fn plan_bridge_starts(
        &mut self,
        limits: BridgeAdmissionLimits,
        starts: &mut Vec<TcpBridgeStart>,
    ) -> Result<BridgeAdmissionStats> {
        let now = self.now();
        let admission_stats = plan_bridge_starts(
            &mut self.flow_manager,
            &self.bridges,
            limits,
            &mut self.ready_flow_ids,
            &mut self.opening_flow_keys,
            now,
            starts,
        )?;
        self.stats.record_bridge_admission(admission_stats);
        Ok(admission_stats)
    }

    pub(crate) fn register_tcp_bridge(
        &mut self,
        start: TcpBridgeStart,
        bridge: ssh_bridge::FlowBridge,
    ) -> Result<()> {
        register_tcp_bridge(&mut self.flow_manager, &mut self.bridges, start, bridge)
    }

    pub(crate) fn drain_local_bytes_to_bridges(&mut self) -> Result<LocalDrainStats> {
        let drain_stats = drain_local_bytes_to_bridges(
            &mut self.flow_manager,
            &mut self.bridges,
            &mut self.flow_keys,
        )?;
        self.stats.record_local_drain(drain_stats);
        Ok(drain_stats)
    }

    pub(crate) fn flush_remote_backlogs(&mut self) -> Result<()> {
        let now = self.now();
        self.remote_backlogs.flush_all_into(
            &mut self.flow_manager,
            now,
            &mut self.backlog_flow_ids,
            &mut self.backlog_closed_flows,
        )?;
        for closed_flow in self.backlog_closed_flows.drain(..) {
            self.bridges.remove(&closed_flow);
        }
        self.flow_manager.poll_into(now, &mut self.outbound_packets);
        Ok(())
    }

    pub(crate) fn expire_and_prune(&mut self) -> Result<()> {
        let now = self.now();
        self.stats.expired_flows = self.stats.expired_flows.saturating_add(expire_stale_flows(
            &mut self.flow_manager,
            &mut self.bridges,
            &mut self.remote_backlogs,
            now,
            &mut self.expired_flows,
        ) as u64);
        self.stats.pruned_flows = self.stats.pruned_flows.saturating_add(prune_closed_flows(
            &mut self.flow_manager,
            &mut self.bridges,
            &mut self.remote_backlogs,
            &mut self.removable_flows,
        )? as u64);
        Ok(())
    }

    pub(crate) fn handle_bridge_event(
        &mut self,
        event: ssh_bridge::BridgeEvent,
    ) -> Result<BridgeEventStats> {
        self.stats.record_bridge_event(&event);
        let now = self.now();
        let outcome = handle_bridge_event_into(
            event,
            &mut self.flow_manager,
            &mut self.remote_backlogs,
            now,
            &mut self.bridge_event_closed_flows,
        )?;
        self.stats.remote_backlog_overflows = self
            .stats
            .remote_backlog_overflows
            .saturating_add(outcome.remote_backlog_overflows);
        self.stats.stale_bridge_events = self
            .stats
            .stale_bridge_events
            .saturating_add(outcome.stale_bridge_events);
        for flow in self.bridge_event_closed_flows.drain(..) {
            self.bridges.remove(&flow);
        }
        Ok(outcome)
    }

    pub(crate) fn plan_udp_datagram<T>(
        &mut self,
        transport: Option<UdpAssociationTransportPlan<T>>,
        request: dns::UdpPacket,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
        actions: &mut Vec<UdpIngressAction<T>>,
    ) {
        plan_udp_datagram_actions(
            transport,
            request,
            &mut self.udp_associations,
            &mut self.udp_inflight,
            events,
            idle_timeout,
            actions,
        );
    }

    pub(crate) fn apply_udp_ingress_action<T>(
        &mut self,
        action: UdpIngressAction<T>,
    ) -> Option<UdpAssociationStart<T>> {
        apply_udp_ingress_action(
            action,
            &mut self.udp_associations,
            &mut self.udp_inflight,
            &mut self.stats,
        )
    }

    fn now(&self) -> SmolInstant {
        smol_now(self.started_at)
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct BridgeAdmissionStats {
    pub(crate) deferred_active_limit: u64,
    pub(crate) deferred_open_limit: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpBridgeStart {
    pub(crate) id: tcp_core::FlowId,
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

pub(crate) struct UdpAssociationStart<T> {
    pub(crate) transport: T,
    pub(crate) key: UdpFlowKey,
    pub(crate) from_local: mpsc::Receiver<Bytes>,
    pub(crate) events: UdpAssociationEvents,
    pub(crate) idle_timeout: Duration,
}

pub(crate) enum UdpIngressAction<T> {
    StartAssociation(UdpAssociationStart<T>),
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

impl<T> UdpIngressAction<T> {
    fn start_association(
        transport: T,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) -> Self {
        Self::StartAssociation(UdpAssociationStart {
            transport,
            key,
            from_local,
            events,
            idle_timeout,
        })
    }
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
            actions.push(UdpIngressAction::start_association(
                transport.transport,
                key,
                from_local,
                events.clone(),
                idle_timeout,
            ));
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

#[cfg(test)]
pub(crate) fn apply_udp_ingress_actions<T>(
    actions: &mut Vec<UdpIngressAction<T>>,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    stats: &mut TunnelStats,
    starts: &mut Vec<UdpAssociationStart<T>>,
) {
    for action in actions.drain(..) {
        if let Some(start) =
            apply_udp_ingress_action(action, associations, association_limit, stats)
        {
            starts.push(start);
        }
    }
}

pub(crate) fn apply_udp_ingress_action<T>(
    action: UdpIngressAction<T>,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    stats: &mut TunnelStats,
) -> Option<UdpAssociationStart<T>> {
    match action {
        UdpIngressAction::StartAssociation(start) => {
            return Some(start);
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
    None
}

#[cfg(test)]
pub(crate) fn drop_unsupported_direct_udp(request: &dns::UdpPacket, stats: &mut TunnelStats) {
    let mut associations = HashMap::new();
    let mut association_limit = DnsInflight::new(1);
    let start = apply_udp_ingress_action::<()>(
        UdpIngressAction::DropDatagram {
            key: UdpFlowKey::from_packet(request),
            reason: UdpDropReason::UnsupportedTransport,
        },
        &mut associations,
        &mut association_limit,
        stats,
    );
    debug_assert!(start.is_none());
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
        let bridge = spawn_bridge(start.id, event_tx.clone());
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

        flow_manager.mark_flow_state_at(flow, tcp_core::FlowState::SshOpening, now)?;
        starts.push(TcpBridgeStart { id });
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use smoltcp::socket::tcp;

    use super::*;
    use crate::agent_window;
    use crate::bridge_lab::{
        drain_lab_client_to_manager, pump_lab_manager_to_clients, route_lab_packets_to_clients,
        synthetic_lab_client, BridgeLabClient,
    };
    use crate::defaults::{
        DEFAULT_MTU, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX, DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
    };
    use crate::transport_model::{
        DataPlaneReconnectSnapshot, MAX_AGENT_ACTIVE_STREAMS, MAX_AGENT_OPENING_STREAMS,
        MAX_DIRECT_ACTIVE_CHANNELS, MAX_DIRECT_OPENING_CHANNELS,
    };

    const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
        Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);

    #[test]
    fn dns_inflight_caps_queries_and_tracks_releases() {
        let mut inflight = DnsInflight::new(2);

        assert_eq!(inflight.current(), 0);
        assert!(inflight.try_admit());
        assert!(inflight.try_admit());
        assert!(!inflight.try_admit());
        assert_eq!(inflight.current(), 2);
        assert_eq!(inflight.dropped(), 1);

        inflight.complete();
        assert_eq!(inflight.current(), 1);
        assert_eq!(inflight.completed(), 1);

        assert!(inflight.try_admit());
        assert_eq!(inflight.current(), 2);

        inflight.complete();
        inflight.complete();
        inflight.complete();
        assert_eq!(inflight.current(), 0);
        assert_eq!(inflight.completed(), 3);
    }

    #[test]
    fn udp_response_backpressure_cannot_block_close_accounting() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        assert!(events.try_send_response(key, Bytes::from_static(b"first")));
        assert!(!events.try_send_response(key, Bytes::from_static(b"second")));
        assert!(events.try_send_closed(key, None));

        let response = response_rx.try_recv().expect("queued UDP response");
        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"first");
        assert!(response_rx.try_recv().is_err());

        let closed = close_rx.try_recv().expect("queued UDP close");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
    }

    #[test]
    fn udp_response_event_keeps_agent_payload_as_bytes() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let payload = Bytes::from_static(b"agent-response");
        let ptr = payload.as_ptr();

        assert!(events.try_send_response(key, payload));
        let response = response_rx.try_recv().expect("queued UDP response");

        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"agent-response");
        assert_eq!(response.payload.as_ptr(), ptr);
    }

    #[test]
    fn udp_planner_drops_unsupported_transport_without_admission() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        let mut association_limit = DnsInflight::new(1);
        let mut actions: Vec<UdpIngressAction<()>> = Vec::new();

        plan_udp_datagram_actions(
            None,
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload: Bytes::from_static(b"unsupported"),
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert!(associations.is_empty());
        assert_eq!(association_limit.current(), 0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            UdpIngressAction::DropDatagram {
                key: action_key,
                reason,
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(*reason, UdpDropReason::UnsupportedTransport);
            }
            _ => panic!("expected unsupported UDP drop action"),
        }
    }

    fn admit_udp_datagram_for_test(
        request: dns::UdpPacket,
        associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
        association_limit: &mut DnsInflight,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
        stats: &mut TunnelStats,
    ) {
        let mut actions = Vec::new();
        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent", ())),
            request,
            associations,
            association_limit,
            events,
            idle_timeout,
            &mut actions,
        );
        let mut starts = Vec::new();
        apply_udp_ingress_actions(
            &mut actions,
            associations,
            association_limit,
            stats,
            &mut starts,
        );
    }

    #[tokio::test]
    async fn udp_admission_moves_parsed_payload_bytes_into_association_queue() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"client-datagram");
        let payload_ptr = payload.as_ptr();
        let (to_remote, mut from_local) = mpsc::channel(1);
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut association_limit = DnsInflight::new(1);
        let mut stats = TunnelStats::new();

        admit_udp_datagram_for_test(
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut stats,
        );

        let queued = from_local.try_recv().expect("queued UDP payload");
        assert_eq!(queued.as_ref(), b"client-datagram");
        assert_eq!(queued.as_ptr(), payload_ptr);
        assert_eq!(stats.udp_forwarded, 1);
        assert_eq!(stats.udp_dropped, 0);
    }

    #[tokio::test]
    async fn udp_planner_starts_vacant_association_before_send() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"first-datagram");
        let payload_ptr = payload.as_ptr();
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        let mut association_limit = DnsInflight::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent", ())),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert_eq!(association_limit.current(), 1);
        assert!(associations.contains_key(&key));
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            UdpIngressAction::StartAssociation(start) => {
                assert_eq!(start.key, key);
            }
            _ => panic!("expected association start action first"),
        }
        match &actions[1] {
            UdpIngressAction::SendDatagram {
                key: action_key,
                payload,
                transport_label,
                ..
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(payload.as_ref(), b"first-datagram");
                assert_eq!(payload.as_ptr(), payload_ptr);
                assert_eq!(*transport_label, "agent");
            }
            _ => panic!("expected UDP send action second"),
        }
    }

    #[tokio::test]
    async fn udp_executor_surfaces_start_effect_before_first_send() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"first-datagram");
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        let mut association_limit = DnsInflight::new(1);
        let mut actions = Vec::new();
        let mut stats = TunnelStats::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent", ())),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        let mut start = None;
        for action in actions.drain(..) {
            let effect = apply_udp_ingress_action(
                action,
                &mut associations,
                &mut association_limit,
                &mut stats,
            );
            if let Some(effect) = effect {
                assert!(start.is_none(), "only one association should start");
                assert_eq!(effect.key, key);
                start = Some(effect);
            }
        }

        let mut start = start.expect("first action should surface a start effect");
        let queued = start
            .from_local
            .try_recv()
            .expect("first datagram should be queued after start effect is held");
        assert_eq!(queued.as_ref(), b"first-datagram");
        assert_eq!(stats.udp_forwarded, 1);
        assert_eq!(stats.udp_dropped, 0);
    }

    #[tokio::test]
    async fn udp_planner_reuses_existing_association_without_restarting() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (to_remote, _from_local) = mpsc::channel(1);
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = DnsInflight::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent", ())),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload: Bytes::from_static(b"existing"),
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert_eq!(association_limit.current(), 0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            UdpIngressAction::SendDatagram {
                key: action_key,
                payload,
                ..
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(payload.as_ref(), b"existing");
            }
            _ => panic!("expected existing association to emit only a send action"),
        }
    }

    #[test]
    fn udp_executor_closed_sender_releases_association_slot() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (to_remote, from_local) = mpsc::channel(1);
        drop(from_local);
        let mut associations = HashMap::new();
        associations.insert(
            key,
            UdpAssociation {
                to_remote: to_remote.clone(),
            },
        );
        let mut association_limit = DnsInflight::new(1);
        assert!(association_limit.try_admit());
        let mut stats = TunnelStats::new();
        let start = apply_udp_ingress_action::<()>(
            UdpIngressAction::SendDatagram {
                key,
                to_remote,
                payload: Bytes::from_static(b"closed"),
                transport_label: "agent",
            },
            &mut associations,
            &mut association_limit,
            &mut stats,
        );

        assert!(start.is_none());
        assert!(associations.is_empty());
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert_eq!(stats.udp_forwarded, 0);
        assert_eq!(stats.udp_dropped, 1);
        assert_eq!(stats.udp_failed, 1);
    }

    #[test]
    fn direct_tcpip_generic_udp_drop_is_counted_without_admission() {
        let mut stats = TunnelStats::new();
        let request = dns::UdpPacket {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
            payload: Bytes::from_static(b"generic-udp"),
        };

        drop_unsupported_direct_udp(&request, &mut stats);

        assert_eq!(stats.udp_forwarded, 0);
        assert_eq!(stats.udp_dropped, 1);
        assert_eq!(stats.udp_ok, 0);
        assert_eq!(stats.udp_failed, 1);
    }

    #[test]
    fn stats_formatting_uses_stable_units() {
        assert_eq!(format_bytes(999), "999B");
        assert_eq!(format_bytes(1024), "1.0KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MiB");
        assert_eq!(format_duration(Duration::from_millis(1234)), "1.234s");
    }

    #[test]
    fn stats_report_bridge_pressure_and_open_latency() {
        let mut stats = TunnelStats::new();
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 21 });
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 43 });
        stats.record_bridge_admission(BridgeAdmissionStats {
            deferred_active_limit: 2,
            deferred_open_limit: 3,
        });
        stats.record_local_drain(LocalDrainStats {
            bytes_to_bridge: 1024,
            bridge_backpressure_events: 4,
            bridge_send_failures: 0,
        });
        stats.record_tun_write(TunWriteStats {
            packets: 2,
            bytes: 2048,
            dropped_packets: 1,
            dropped_bytes: 512,
        });

        let line = stats.status_line(
            1,
            1,
            &RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW),
            &DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES),
            &DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS),
            DataPlaneRuntimeSnapshot {
                reconnects: DataPlaneReconnectSnapshot {
                    attempts: 5,
                    successes: 4,
                    failures: 1,
                },
                lanes_total: 4,
                lanes_desired: 4,
                lanes_available: 1,
                lanes_failed: 1,
                lanes_missing: 1,
                lanes_quarantined: 1,
                lanes_repairing: 1,
                active_streams: 7,
                max_lane_load: 4,
                max_quarantine_ms: 250,
            },
        );

        assert!(line.contains("tun_tx=2/2.0KiB"));
        assert!(line.contains("tun_drop=1/512B"));
        assert!(line.contains("ssh=open:2 fail:0 eof:0 close:0"));
        assert!(line.contains("open_ms=avg:32 max:43"));
        assert!(line.contains("defer=active:2 open:3"));
        assert!(line.contains("agent_reconnect=attempt:5 ok:4 fail:1"));
        assert!(line.contains(
            "agent_lanes=total:4 desired:4 ok:1 fail:1 missing:1 quarantine:1 repairing:1 active:7 max_load:4 max_quarantine_ms:250"
        ));
        assert!(line.contains("bridge_backpressure:4"));
    }

    #[test]
    fn dns_and_udp_success_require_local_tun_delivery() {
        let mut stats = TunnelStats::new();

        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );
        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 0,
                bytes: 0,
                dropped_packets: 1,
                dropped_bytes: 96,
            },
        );
        stats.record_dns_delivery(
            false,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );

        stats.record_udp_delivery(TunWriteStats {
            packets: 1,
            bytes: 128,
            dropped_packets: 0,
            dropped_bytes: 0,
        });
        stats.record_udp_delivery(TunWriteStats {
            packets: 0,
            bytes: 0,
            dropped_packets: 1,
            dropped_bytes: 128,
        });

        assert_eq!(stats.dns_ok, 1);
        assert_eq!(stats.dns_failed, 2);
        assert_eq!(stats.udp_ok, 1);
        assert_eq!(stats.udp_failed, 1);
        assert_eq!(stats.tun_tx_packets, 3);
        assert_eq!(stats.tun_tx_dropped_packets, 2);
    }

    #[test]
    fn tun_ipv4_packet_accepts_raw_ipv4() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];

        assert_eq!(tun_ipv4_packet(&packet), Some(packet.as_slice()));
    }

    #[test]
    fn tun_ipv4_packet_strips_linux_pi_ipv4_header() {
        let packet = [
            0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];

        assert_eq!(tun_ipv4_packet(&packet), Some(&packet[4..]));
    }

    #[test]
    fn tun_ipv4_packet_ignores_non_ipv4() {
        assert_eq!(tun_ipv4_packet(&[0x60, 0, 0, 0]), None);
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x86, 0xdd, 0x60]), None);
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x08, 0x00, 0x60]), None);
        assert_eq!(tun_ipv4_packet(&[]), None);
    }

    #[test]
    fn remote_backlog_is_bounded_per_flow() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        let mut backlogs = RemoteBacklogs::new(8);

        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"world")),
            RemoteBacklogPush::FlowLimit
        );
        assert_eq!(backlogs.active_flow_count(), 1);
        assert_eq!(backlogs.total_bytes(), 5);
        assert_eq!(
            backlogs.flows.get(&id).map(|backlog| backlog.bytes),
            Some(5)
        );

        backlogs.close_after_flush(id);
        assert_eq!(
            backlogs
                .flows
                .get(&id)
                .map(|backlog| backlog.close_after_flush),
            Some(true)
        );

        backlogs.remove_flow(flow);
        assert!(!backlogs.flows.contains_key(&id));
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_is_bounded_globally() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::TotalLimit
        );
        assert_eq!(backlogs.total_bytes(), 5);

        backlogs.remove_flow(first);
        assert_eq!(backlogs.total_bytes(), 0);
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::Accepted
        );
    }

    #[test]
    fn remote_backlog_pauses_bridge_events_at_high_watermark() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"!")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(backlogs.total_bytes(), 6);
        assert!(backlogs.should_pause_bridge_events());

        backlogs.remove_flow(first);
        assert!(!backlogs.should_pause_bridge_events());
    }

    #[test]
    fn remote_backlogs_flush_all_into_reuses_scratch_vectors() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let stale = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(192, 0, 2, 1),
                1,
                Ipv4Addr::new(192, 0, 2, 2),
                2,
            ),
            99,
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
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"remote bytes")),
            RemoteBacklogPush::Accepted
        );

        let mut flow_keys = Vec::with_capacity(8);
        flow_keys.push(stale);
        let flow_keys_capacity = flow_keys.capacity();
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale.key);
        let closed_flows_capacity = closed_flows.capacity();

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("flush backlogs");

        assert!(flow_keys.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(flow_keys.capacity(), flow_keys_capacity);
        assert_eq!(closed_flows.capacity(), closed_flows_capacity);
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_per_flow_has_agent_window_frame_headroom() {
        let backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        assert_eq!(
            backlogs.max_bytes_per_flow(),
            tcp_core::TCP_SEND_BUFFER_BYTES * REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW
        );
        assert!(backlogs.max_bytes_per_flow() > agent_window::AGENT_STREAM_MAX_WINDOW_BYTES);
        assert!(backlogs.max_bytes_per_flow() < REMOTE_BACKLOG_BYTES_TOTAL);
    }

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
    fn remote_backlog_for_removed_flow_is_dropped_without_failing() {
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
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"stale remote bytes")),
            RemoteBacklogPush::Accepted
        );
        manager.remove_flow(flow).expect("remove flow before flush");

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("stale queued backlog should not fail");

        assert!(flow_ids.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_for_old_generation_does_not_touch_reused_flow() {
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
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(old_id, Bytes::from_static(b"old-generation bytes")),
            RemoteBacklogPush::Accepted
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

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("old queued backlog should be dropped");

        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
        assert!(manager.contains_flow_id(new_id));
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("new flow snapshot");
        assert_eq!(snapshot.generation, new_id.generation);
        assert_eq!(snapshot.remote_to_local_bytes, 0);
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
        assert_eq!(starts, vec![TcpBridgeStart { id }]);
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::SshOpening
        );
        assert!(bridges.is_empty());
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
        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 1);
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Reset
        }));
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

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
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

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
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
}
