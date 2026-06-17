use std::collections::HashMap;
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
use smoltcp::time::Instant as SmolInstant;

use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneRuntimeSnapshot, UdpAssociation, UdpAssociationEvents,
    UdpFlowKey,
};
use crate::{dns, ssh_bridge, tcp_core};

use super::admission::AdmissionCounter;
use super::backlog::{RemoteBacklogs, REMOTE_BACKLOG_BYTES_PER_FLOW};
use super::clock::smol_now;
use super::dns_ingress::MAX_IN_FLIGHT_DNS_QUERIES;
use super::status::{TcpRuntimeSnapshot, TunnelStats, TunnelStatusSnapshot};
use super::tcp_bridge::{
    drain_local_bytes_to_bridges, expire_stale_flows, handle_bridge_event_into, plan_bridge_starts,
    prune_closed_flows, register_tcp_bridge, BridgeAdmissionStats, BridgeEventStats,
    LocalDrainStats, TcpBridgeStart,
};
use super::tun::TunWriteStats;
use super::udp::{
    apply_udp_ingress_action, plan_udp_datagram_actions, UdpAssociationStart,
    UdpAssociationTransportPlan, UdpIngressAction, MAX_ACTIVE_UDP_ASSOCIATIONS,
};

pub(crate) struct TunnelEngine {
    flow_manager: tcp_core::FlowManager,
    bridges: HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    udp_associations: HashMap<UdpFlowKey, UdpAssociation>,
    remote_backlogs: RemoteBacklogs,
    dns_admission: AdmissionCounter,
    udp_admission: AdmissionCounter,
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
            dns_admission: AdmissionCounter::new(MAX_IN_FLIGHT_DNS_QUERIES),
            udp_admission: AdmissionCounter::new(MAX_ACTIVE_UDP_ASSOCIATIONS),
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
        self.dns_admission.try_admit()
    }

    pub(crate) fn complete_dns(&mut self) {
        self.dns_admission.complete();
    }

    pub(crate) fn dns_admission_limit(&self) -> usize {
        self.dns_admission.max()
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
        self.udp_admission.complete();
    }

    pub(crate) fn record_udp_close_error(&mut self) {
        self.stats.record_udp_response(false);
    }

    pub(crate) fn should_pause_bridge_events(&self) -> bool {
        self.remote_backlogs.should_pause_bridge_events()
    }

    pub(crate) fn status_line(
        &self,
        agent: DataPlaneRuntimeSnapshot,
        bridge_events: ssh_bridge::BridgeEventQueueSnapshot,
    ) -> String {
        self.stats.status_line(TunnelStatusSnapshot {
            tcp: TcpRuntimeSnapshot {
                active_flows: self.flow_manager.active_flow_count(),
                ssh_channels: self.bridges.len(),
                backlog_flows: self.remote_backlogs.active_flow_count(),
                backlog_bytes: self.remote_backlogs.total_bytes(),
                backlog_bytes_max: self.remote_backlogs.total_bytes_max(),
            },
            dns: self.dns_admission.snapshot(),
            udp: self.udp_admission.snapshot(),
            agent,
            bridge_events,
        })
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
        let now = self.now();
        let drain_stats = drain_local_bytes_to_bridges(
            &mut self.flow_manager,
            &mut self.bridges,
            &mut self.flow_keys,
            now,
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

    pub(crate) fn record_bridge_event_batch(
        &mut self,
        handled: usize,
        elapsed: Duration,
        paused_by_backlog: bool,
    ) {
        self.stats
            .record_bridge_event_batch(handled, elapsed, paused_by_backlog);
    }

    pub(crate) fn plan_udp_datagram(
        &mut self,
        transport: Option<UdpAssociationTransportPlan>,
        request: dns::UdpPacket,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
        actions: &mut Vec<UdpIngressAction>,
    ) {
        plan_udp_datagram_actions(
            transport,
            request,
            &mut self.udp_associations,
            &mut self.udp_admission,
            events,
            idle_timeout,
            actions,
        );
    }

    pub(crate) fn apply_udp_ingress_action(
        &mut self,
        action: UdpIngressAction,
    ) -> Option<UdpAssociationStart> {
        apply_udp_ingress_action(
            action,
            &mut self.udp_associations,
            &mut self.udp_admission,
            &mut self.stats,
        )
    }

    fn now(&self) -> SmolInstant {
        smol_now(self.started_at)
    }

    #[cfg(test)]
    pub(crate) fn stats_for_test(&self) -> &TunnelStats {
        &self.stats
    }
}
