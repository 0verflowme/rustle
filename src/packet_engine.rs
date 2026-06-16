use std::time::Duration;

use crate::{dns, tcp_core};
use anyhow::{Context, Result};

pub(crate) const PACKET_BUF_SIZE: usize = 2048;

const TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

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

pub(crate) async fn write_packets_to_tun(
    dev: &tun_rs::AsyncDevice,
    packets: &mut Vec<tcp_core::PacketBuf>,
) -> Result<TunWriteStats> {
    let mut stats = TunWriteStats::default();
    for packet in packets.drain(..) {
        stats.combine(write_packet_to_tun(dev, packet.as_ref(), "userspace TCP packet").await?);
    }
    Ok(stats)
}

pub(crate) async fn write_packet_to_tun(
    dev: &tun_rs::AsyncDevice,
    packet: &[u8],
    description: &'static str,
) -> Result<TunWriteStats> {
    let len = packet.len();
    let mut stats = TunWriteStats::default();
    match tokio::time::timeout(TUN_WRITE_TIMEOUT, dev.send(packet)).await {
        Ok(Ok(_)) => {
            stats.record_written(len);
        }
        Ok(Err(err)) => {
            return Err(err)
                .with_context(|| format!("failed to write {description} to TUN device"));
        }
        Err(_) => {
            eprintln!(
                "tun: dropping {len}-byte {description} after {}ms waiting for TUN write",
                TUN_WRITE_TIMEOUT.as_millis()
            );
            stats.record_dropped(len);
        }
    }
    Ok(stats)
}
