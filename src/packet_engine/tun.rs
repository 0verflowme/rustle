pub(crate) const PACKET_BUF_SIZE: usize = 2048;

pub(crate) fn tun_ipv4_packet(packet: &[u8]) -> Option<&[u8]> {
    const LINUX_PI_IPV4: [u8; 4] = [0x00, 0x00, 0x08, 0x00];
    const LINUX_PI_IPV6: [u8; 4] = [0x00, 0x00, 0x86, 0xdd];

    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(packet),
        _ if packet.len() > LINUX_PI_IPV4.len()
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

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TunWriteStats {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
    pub(crate) dropped_packets: u64,
    pub(crate) dropped_bytes: u64,
    pub(crate) write_calls: u64,
    pub(crate) write_elapsed_us: u64,
    pub(crate) write_max_us: u64,
}

impl TunWriteStats {
    pub(crate) fn record_written(&mut self, len: usize, elapsed_us: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
        self.record_write_attempt(elapsed_us);
    }

    pub(crate) fn record_dropped(&mut self, len: usize, elapsed_us: u64) {
        self.dropped_packets = self.dropped_packets.saturating_add(1);
        self.dropped_bytes = self.dropped_bytes.saturating_add(len as u64);
        self.record_write_attempt(elapsed_us);
    }

    fn record_write_attempt(&mut self, elapsed_us: u64) {
        self.write_calls = self.write_calls.saturating_add(1);
        self.write_elapsed_us = self.write_elapsed_us.saturating_add(elapsed_us);
        self.write_max_us = self.write_max_us.max(elapsed_us);
    }

    pub(crate) fn combine(&mut self, other: Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.dropped_packets = self.dropped_packets.saturating_add(other.dropped_packets);
        self.dropped_bytes = self.dropped_bytes.saturating_add(other.dropped_bytes);
        self.write_calls = self.write_calls.saturating_add(other.write_calls);
        self.write_elapsed_us = self.write_elapsed_us.saturating_add(other.write_elapsed_us);
        self.write_max_us = self.write_max_us.max(other.write_max_us);
    }

    pub(crate) fn delivered_at_least_one_packet_without_drop(&self) -> bool {
        self.packets > 0 && self.dropped_packets == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x08, 0x00]), None);
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x08]), None);
        assert_eq!(tun_ipv4_packet(&[]), None);
    }

    #[test]
    fn tun_write_stats_records_and_combines_write_accounting() {
        let mut stats = TunWriteStats::default();
        assert!(!stats.delivered_at_least_one_packet_without_drop());

        stats.record_written(64, 7);
        assert_eq!(
            stats,
            TunWriteStats {
                packets: 1,
                bytes: 64,
                dropped_packets: 0,
                dropped_bytes: 0,
                write_calls: 1,
                write_elapsed_us: 7,
                write_max_us: 7,
            }
        );
        assert!(stats.delivered_at_least_one_packet_without_drop());

        stats.record_dropped(32, 11);
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.bytes, 64);
        assert_eq!(stats.dropped_packets, 1);
        assert_eq!(stats.dropped_bytes, 32);
        assert_eq!(stats.write_calls, 2);
        assert_eq!(stats.write_elapsed_us, 18);
        assert_eq!(stats.write_max_us, 11);
        assert!(!stats.delivered_at_least_one_packet_without_drop());

        stats.combine(TunWriteStats {
            packets: 2,
            bytes: 128,
            dropped_packets: 0,
            dropped_bytes: 0,
            write_calls: 2,
            write_elapsed_us: 5,
            write_max_us: 3,
        });
        assert_eq!(stats.packets, 3);
        assert_eq!(stats.bytes, 192);
        assert_eq!(stats.dropped_packets, 1);
        assert_eq!(stats.dropped_bytes, 32);
        assert_eq!(stats.write_calls, 4);
        assert_eq!(stats.write_elapsed_us, 23);
        assert_eq!(stats.write_max_us, 11);

        assert!(!TunWriteStats {
            packets: 1,
            dropped_packets: 1,
            ..TunWriteStats::default()
        }
        .delivered_at_least_one_packet_without_drop());
    }
}
