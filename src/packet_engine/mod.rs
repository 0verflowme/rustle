mod admission;
mod backlog;
mod clock;
mod dns_ingress;
mod engine;
mod status;
mod tcp_bridge;
mod tun;
mod udp;

pub(crate) use admission::AdmissionCounter;
pub(crate) use backlog::{RemoteBacklogs, REMOTE_BACKLOG_BYTES_PER_FLOW};
pub(crate) use clock::smol_now;
pub(crate) use dns_ingress::{parse_dns_request_for_tunnel, MAX_IN_FLIGHT_DNS_QUERIES};
pub(crate) use engine::TunnelEngine;
pub(crate) use status::TunnelStats;
pub(crate) use tcp_bridge::{
    drain_local_bytes_to_bridges, ensure_bridges, expire_stale_flows, handle_bridge_event_into,
    prune_closed_flows, TcpBridgeStart,
};
pub(crate) use tun::{tun_ipv4_packet, TunWriteStats, PACKET_BUF_SIZE};
pub(crate) use udp::{
    parse_udp_request_for_agent_tunnel, UdpAssociationStart, UdpAssociationTransportPlan,
    UdpIngressAction, MAX_ACTIVE_UDP_ASSOCIATIONS,
};

#[cfg(test)]
mod tests {
    use super::*;

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
}
