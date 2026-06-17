use std::collections::{hash_map::Entry, HashMap};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::dns;
use crate::transport_model::{
    UdpAssociation, UdpAssociationEvents, UdpFlowKey, UDP_DATAGRAMS_PER_ASSOCIATION,
};

use super::{AdmissionCounter, TunnelStats};

pub(crate) const MAX_ACTIVE_UDP_ASSOCIATIONS: usize = 512;

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

pub(crate) struct UdpAssociationTransportPlan {
    pub(crate) label: &'static str,
}

impl UdpAssociationTransportPlan {
    pub(crate) fn new(label: &'static str) -> Self {
        Self { label }
    }
}

pub(crate) struct UdpAssociationStart {
    pub(crate) transport_label: &'static str,
    pub(crate) key: UdpFlowKey,
    pub(crate) from_local: mpsc::Receiver<Bytes>,
    pub(crate) events: UdpAssociationEvents,
    pub(crate) idle_timeout: Duration,
}

pub(crate) enum UdpIngressAction {
    StartAssociation(UdpAssociationStart),
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

impl UdpIngressAction {
    fn start_association(
        transport_label: &'static str,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) -> Self {
        Self::StartAssociation(UdpAssociationStart {
            transport_label,
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

pub(crate) fn plan_udp_datagram_actions(
    transport: Option<UdpAssociationTransportPlan>,
    request: dns::UdpPacket,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut AdmissionCounter,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
    actions: &mut Vec<UdpIngressAction>,
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
                transport_label,
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
pub(crate) fn apply_udp_ingress_actions(
    actions: &mut Vec<UdpIngressAction>,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut AdmissionCounter,
    stats: &mut TunnelStats,
    starts: &mut Vec<UdpAssociationStart>,
) {
    for action in actions.drain(..) {
        if let Some(start) =
            apply_udp_ingress_action(action, associations, association_limit, stats)
        {
            starts.push(start);
        }
    }
}

pub(crate) fn apply_udp_ingress_action(
    action: UdpIngressAction,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut AdmissionCounter,
    stats: &mut TunnelStats,
) -> Option<UdpAssociationStart> {
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
    let mut association_limit = AdmissionCounter::new(1);
    let start = apply_udp_ingress_action(
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
    association_limit: &mut AdmissionCounter,
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use super::*;
    use crate::defaults::DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS;
    use crate::dns;
    use crate::transport_model::{UdpAssociation, UdpAssociationEvents, UdpFlowKey};

    const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
        Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);

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
}
