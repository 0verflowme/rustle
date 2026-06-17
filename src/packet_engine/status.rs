use std::time::{Duration, Instant as StdInstant};

use crate::ssh_bridge;
use crate::transport_model::DataPlaneRuntimeSnapshot;

use super::admission::AdmissionSnapshot;
use super::tcp_bridge::{BridgeAdmissionStats, LocalDrainStats};
use super::TunWriteStats;

#[derive(Debug)]
pub(crate) struct TunnelStats {
    pub(crate) started_at: StdInstant,
    pub(crate) tun_rx_packets: u64,
    pub(crate) tun_rx_bytes: u64,
    pub(crate) tun_tx_packets: u64,
    pub(crate) tun_tx_bytes: u64,
    pub(crate) tun_tx_dropped_packets: u64,
    pub(crate) tun_tx_dropped_bytes: u64,
    pub(crate) tun_tx_write_calls: u64,
    pub(crate) tun_tx_write_elapsed_us: u64,
    pub(crate) tun_tx_write_max_us: u64,
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
    pub(crate) bridge_event_batches: u64,
    pub(crate) bridge_event_batch_events: u64,
    pub(crate) bridge_event_batch_max: u64,
    pub(crate) bridge_event_batch_elapsed_us: u64,
    pub(crate) bridge_event_batch_max_us: u64,
    pub(crate) bridge_event_batch_pauses: u64,
    pub(crate) tcp_recv_queue_wait_us: u64,
    pub(crate) tcp_recv_queue_wait_max_us: u64,
    pub(crate) tcp_recv_queue_waits: u64,
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
            tun_tx_write_calls: 0,
            tun_tx_write_elapsed_us: 0,
            tun_tx_write_max_us: 0,
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
            bridge_event_batches: 0,
            bridge_event_batch_events: 0,
            bridge_event_batch_max: 0,
            bridge_event_batch_elapsed_us: 0,
            bridge_event_batch_max_us: 0,
            bridge_event_batch_pauses: 0,
            tcp_recv_queue_wait_us: 0,
            tcp_recv_queue_wait_max_us: 0,
            tcp_recv_queue_waits: 0,
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
        self.tun_tx_write_calls = self.tun_tx_write_calls.saturating_add(write.write_calls);
        self.tun_tx_write_elapsed_us = self
            .tun_tx_write_elapsed_us
            .saturating_add(write.write_elapsed_us);
        self.tun_tx_write_max_us = self.tun_tx_write_max_us.max(write.write_max_us);
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
        self.tcp_recv_queue_wait_us = self
            .tcp_recv_queue_wait_us
            .saturating_add(stats.tcp_recv_queue_wait_us);
        self.tcp_recv_queue_wait_max_us = self
            .tcp_recv_queue_wait_max_us
            .max(stats.tcp_recv_queue_wait_max_us);
        self.tcp_recv_queue_waits = self
            .tcp_recv_queue_waits
            .saturating_add(stats.tcp_recv_queue_waits);
    }

    pub(crate) fn record_bridge_admission(&mut self, stats: BridgeAdmissionStats) {
        self.ssh_open_deferred_active_limit = self
            .ssh_open_deferred_active_limit
            .saturating_add(stats.deferred_active_limit);
        self.ssh_open_deferred_open_limit = self
            .ssh_open_deferred_open_limit
            .saturating_add(stats.deferred_open_limit);
    }

    pub(crate) fn record_bridge_event_batch(
        &mut self,
        handled: usize,
        elapsed: Duration,
        paused_by_backlog: bool,
    ) {
        self.bridge_event_batches = self.bridge_event_batches.saturating_add(1);
        self.bridge_event_batch_events = self
            .bridge_event_batch_events
            .saturating_add(handled as u64);
        self.bridge_event_batch_max = self.bridge_event_batch_max.max(handled as u64);
        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.bridge_event_batch_elapsed_us = self
            .bridge_event_batch_elapsed_us
            .saturating_add(elapsed_us);
        self.bridge_event_batch_max_us = self.bridge_event_batch_max_us.max(elapsed_us);
        if paused_by_backlog {
            self.bridge_event_batch_pauses = self.bridge_event_batch_pauses.saturating_add(1);
        }
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

    pub(crate) fn status_line(&self, snapshot: TunnelStatusSnapshot) -> String {
        let avg_open_ms = self
            .ssh_open_latency_total_ms
            .checked_div(self.ssh_opened)
            .unwrap_or(0);

        format!(
            "uptime={} active_flows={} ssh_channels={} backlog_flows={} backlog_bytes={} tun_rx={}/{} tun_tx={}/{} tun_drop={}/{} tun_write=calls:{} total_us:{} max_us:{} tcp_l2r={} tcp_r2l={} dns=fwd:{} ok:{} fail:{} drop:{} inflight:{} udp=fwd:{} ok:{} fail:{} drop:{} active:{} ssh=open:{} fail:{} eof:{} close:{} open_ms=avg:{} max:{} defer=active:{} open:{} agent_reconnect=attempt:{} ok:{} fail:{} agent_lanes=total:{} desired:{} ok:{} fail:{} missing:{} quarantine:{} repairing:{} active:{} max_load:{} max_quarantine_ms:{} flow=expired:{} pruned:{} bridge_backpressure:{} bridge_send_fail:{} tcp_recv_queue_wait=count:{} total_us:{} max_us:{} bridge_event_batch=count:{} events:{} max:{} total_us:{} max_us:{} paused:{} backlog_overflow:{} stale_bridge:{}",
            format_duration(self.started_at.elapsed()),
            snapshot.tcp.active_flows,
            snapshot.tcp.ssh_channels,
            snapshot.tcp.backlog_flows,
            format_bytes(snapshot.tcp.backlog_bytes),
            self.tun_rx_packets,
            format_bytes(self.tun_rx_bytes),
            self.tun_tx_packets,
            format_bytes(self.tun_tx_bytes),
            self.tun_tx_dropped_packets,
            format_bytes(self.tun_tx_dropped_bytes),
            self.tun_tx_write_calls,
            self.tun_tx_write_elapsed_us,
            self.tun_tx_write_max_us,
            format_bytes(self.local_to_remote_bytes),
            format_bytes(self.remote_to_local_bytes),
            self.dns_forwarded,
            self.dns_ok,
            self.dns_failed,
            self.dns_dropped,
            snapshot.dns.current,
            self.udp_forwarded,
            self.udp_ok,
            self.udp_failed,
            self.udp_dropped,
            snapshot.udp.current,
            self.ssh_opened,
            self.ssh_failed,
            self.ssh_remote_eof,
            self.ssh_closed,
            avg_open_ms,
            self.ssh_open_latency_max_ms,
            self.ssh_open_deferred_active_limit,
            self.ssh_open_deferred_open_limit,
            snapshot.agent.reconnects.attempts,
            snapshot.agent.reconnects.successes,
            snapshot.agent.reconnects.failures,
            snapshot.agent.lanes_total,
            snapshot.agent.lanes_desired,
            snapshot.agent.lanes_available,
            snapshot.agent.lanes_failed,
            snapshot.agent.lanes_missing,
            snapshot.agent.lanes_quarantined,
            snapshot.agent.lanes_repairing,
            snapshot.agent.active_streams,
            snapshot.agent.max_lane_load,
            snapshot.agent.max_quarantine_ms,
            self.expired_flows,
            self.pruned_flows,
            self.bridge_backpressure_events,
            self.bridge_send_failures,
            self.tcp_recv_queue_waits,
            self.tcp_recv_queue_wait_us,
            self.tcp_recv_queue_wait_max_us,
            self.bridge_event_batches,
            self.bridge_event_batch_events,
            self.bridge_event_batch_max,
            self.bridge_event_batch_elapsed_us,
            self.bridge_event_batch_max_us,
            self.bridge_event_batch_pauses,
            self.remote_backlog_overflows,
            self.stale_bridge_events,
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpRuntimeSnapshot {
    pub(crate) active_flows: usize,
    pub(crate) ssh_channels: usize,
    pub(crate) backlog_flows: usize,
    pub(crate) backlog_bytes: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TunnelStatusSnapshot {
    pub(crate) tcp: TcpRuntimeSnapshot,
    pub(crate) dns: AdmissionSnapshot,
    pub(crate) udp: AdmissionSnapshot,
    pub(crate) agent: DataPlaneRuntimeSnapshot,
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::transport_model::DataPlaneReconnectSnapshot;
    use crate::{ssh_bridge, tcp_core};

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
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::RemoteData {
            id,
            bytes: Bytes::from_static(b"remote"),
        });
        stats.record_bridge_admission(BridgeAdmissionStats {
            deferred_active_limit: 2,
            deferred_open_limit: 3,
        });
        stats.record_local_drain(LocalDrainStats {
            bytes_to_bridge: 1024,
            bridge_backpressure_events: 4,
            bridge_send_failures: 0,
            tcp_recv_queue_wait_us: 11,
            tcp_recv_queue_wait_max_us: 7,
            tcp_recv_queue_waits: 2,
        });
        stats.record_tun_write(TunWriteStats {
            packets: 2,
            bytes: 2048,
            dropped_packets: 1,
            dropped_bytes: 512,
            write_calls: 3,
            write_elapsed_us: 77,
            write_max_us: 55,
        });
        stats.record_bridge_event_batch(31, Duration::from_micros(123), false);
        stats.record_bridge_event_batch(32, Duration::from_micros(456), true);

        let line = stats.status_line(TunnelStatusSnapshot {
            tcp: TcpRuntimeSnapshot {
                active_flows: 1,
                ssh_channels: 1,
                backlog_flows: 0,
                backlog_bytes: 0,
            },
            dns: AdmissionSnapshot {
                current: 0,
                max: 128,
            },
            udp: AdmissionSnapshot {
                current: 0,
                max: 512,
            },
            agent: DataPlaneRuntimeSnapshot {
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
        });

        assert!(line.contains("active_flows=1 ssh_channels=1 backlog_flows=0"));
        assert!(line.contains("tun_tx=2/2.0KiB"));
        assert!(line.contains("tun_drop=1/512B"));
        assert!(line.contains("tun_write=calls:3 total_us:77 max_us:55"));
        assert!(line.contains("tcp_l2r=1.0KiB tcp_r2l=6B"));
        assert!(line.contains("dns=fwd:0 ok:0 fail:0 drop:0 inflight:0"));
        assert!(line.contains("udp=fwd:0 ok:0 fail:0 drop:0 active:0"));
        assert!(line.contains("ssh=open:2 fail:0 eof:0 close:0"));
        assert!(line.contains("open_ms=avg:32 max:43"));
        assert!(line.contains("defer=active:2 open:3"));
        assert!(line.contains("agent_reconnect=attempt:5 ok:4 fail:1"));
        assert!(line.contains(
            "agent_lanes=total:4 desired:4 ok:1 fail:1 missing:1 quarantine:1 repairing:1 active:7 max_load:4 max_quarantine_ms:250"
        ));
        assert!(line.contains("bridge_backpressure:4"));
        assert!(line.contains("tcp_recv_queue_wait=count:2 total_us:11 max_us:7"));
        assert!(line.contains(
            "bridge_event_batch=count:2 events:63 max:32 total_us:579 max_us:456 paused:1"
        ));
    }
}
