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

pub(crate) fn plan_udp_datagram_actions<T>(
    transport: Option<UdpAssociationTransportPlan<T>>,
    request: dns::UdpPacket,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut AdmissionCounter,
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
    association_limit: &mut AdmissionCounter,
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
    association_limit: &mut AdmissionCounter,
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
    let mut association_limit = AdmissionCounter::new(1);
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
