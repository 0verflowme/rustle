use std::collections::HashMap;
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
use smoltcp::time::Instant as SmolInstant;

use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneRuntimeSnapshot, UdpAssociation, UdpAssociationEvents,
    UdpFlowKey,
};
use crate::{dns, ssh_bridge, tcp_core};

mod admission;
mod backlog;
mod clock;
mod dns_ingress;
mod status;
mod tcp_bridge;
mod tun;
mod udp;

pub(crate) use admission::AdmissionCounter;
#[cfg(test)]
pub(crate) use backlog::{
    RemoteBacklogPush, REMOTE_BACKLOG_BYTES_TOTAL, REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW,
};
pub(crate) use backlog::{RemoteBacklogs, REMOTE_BACKLOG_BYTES_PER_FLOW};
pub(crate) use clock::smol_now;
pub(crate) use dns_ingress::{parse_dns_request_for_tunnel, MAX_IN_FLIGHT_DNS_QUERIES};
pub(crate) use status::{TcpRuntimeSnapshot, TunnelStats, TunnelStatusSnapshot};
pub(crate) use tcp_bridge::{
    drain_local_bytes_to_bridges, ensure_bridges, expire_stale_flows, handle_bridge_event_into,
    plan_bridge_starts, prune_closed_flows, register_tcp_bridge, BridgeAdmissionStats,
    BridgeEventStats, LocalDrainStats, TcpBridgeStart,
};
#[cfg(test)]
pub(crate) use tcp_bridge::{handle_bridge_event, should_log_stale_bridge_event};
pub(crate) use tun::{tun_ipv4_packet, TunWriteStats, PACKET_BUF_SIZE};
pub(crate) use udp::{
    apply_udp_ingress_action, parse_udp_request_for_agent_tunnel, plan_udp_datagram_actions,
    UdpAssociationStart, UdpAssociationTransportPlan, UdpIngressAction,
    MAX_ACTIVE_UDP_ASSOCIATIONS,
};
#[cfg(test)]
pub(crate) use udp::{apply_udp_ingress_actions, drop_unsupported_direct_udp, UdpDropReason};

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

    pub(crate) fn record_bridge_event_batch(
        &mut self,
        handled: usize,
        elapsed: Duration,
        paused_by_backlog: bool,
    ) {
        self.stats
            .record_bridge_event_batch(handled, elapsed, paused_by_backlog);
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

    pub(crate) fn status_line(&self, agent: DataPlaneRuntimeSnapshot) -> String {
        self.stats.status_line(TunnelStatusSnapshot {
            tcp: TcpRuntimeSnapshot {
                active_flows: self.flow_manager.active_flow_count(),
                ssh_channels: self.bridges.len(),
                backlog_flows: self.remote_backlogs.active_flow_count(),
                backlog_bytes: self.remote_backlogs.total_bytes(),
            },
            dns: self.dns_admission.snapshot(),
            udp: self.udp_admission.snapshot(),
            agent,
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
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;
    use smoltcp::socket::tcp;
    use tokio::sync::mpsc;

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
        bridge_admission_decision, BridgeAdmissionDecision, MAX_AGENT_ACTIVE_STREAMS,
        MAX_AGENT_OPENING_STREAMS, MAX_DIRECT_ACTIVE_CHANNELS, MAX_DIRECT_OPENING_CHANNELS,
    };

    const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
        Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);

    #[test]
    fn dns_admission_caps_queries_and_tracks_releases() {
        let mut inflight = AdmissionCounter::new(2);

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
        let mut association_limit = AdmissionCounter::new(1);
        let mut actions: Vec<UdpIngressAction> = Vec::new();

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
        association_limit: &mut AdmissionCounter,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
        stats: &mut TunnelStats,
    ) {
        let mut actions = Vec::new();
        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent")),
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
        let mut association_limit = AdmissionCounter::new(1);
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
        let mut association_limit = AdmissionCounter::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent")),
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
        let mut association_limit = AdmissionCounter::new(1);
        let mut actions = Vec::new();
        let mut stats = TunnelStats::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent")),
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
        let mut association_limit = AdmissionCounter::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new("agent")),
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
        let mut association_limit = AdmissionCounter::new(1);
        assert!(association_limit.try_admit());
        let mut stats = TunnelStats::new();
        let start = apply_udp_ingress_action(
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
    fn dns_and_udp_success_require_local_tun_delivery() {
        let mut stats = TunnelStats::new();

        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
                ..TunWriteStats::default()
            },
        );
        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 0,
                bytes: 0,
                dropped_packets: 1,
                dropped_bytes: 96,
                ..TunWriteStats::default()
            },
        );
        stats.record_dns_delivery(
            false,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
                ..TunWriteStats::default()
            },
        );

        stats.record_udp_delivery(TunWriteStats {
            packets: 1,
            bytes: 128,
            dropped_packets: 0,
            dropped_bytes: 0,
            ..TunWriteStats::default()
        });
        stats.record_udp_delivery(TunWriteStats {
            packets: 0,
            bytes: 0,
            dropped_packets: 1,
            dropped_bytes: 128,
            ..TunWriteStats::default()
        });

        assert_eq!(stats.dns_ok, 1);
        assert_eq!(stats.dns_failed, 2);
        assert_eq!(stats.udp_ok, 1);
        assert_eq!(stats.udp_failed, 1);
        assert_eq!(stats.tun_tx_packets, 3);
        assert_eq!(stats.tun_tx_dropped_packets, 2);
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
    fn remote_backlog_pauses_bridge_events_at_per_flow_high_watermark() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        let mut backlogs = RemoteBacklogs::with_limits(8, 128);

        assert_eq!(backlogs.bridge_event_per_flow_pause_threshold(), 6);
        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(backlogs.total_bytes(), 5);
        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"!")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(backlogs.total_bytes(), 6);
        assert!(backlogs.should_pause_bridge_events());
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
        assert_eq!(backlogs.max_bytes_per_flow(), 32 * 1024 * 1024);
        assert_eq!(REMOTE_BACKLOG_BYTES_TOTAL, 512 * 1024 * 1024);
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
