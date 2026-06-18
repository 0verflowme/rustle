use crate::dns;

pub(crate) const MAX_IN_FLIGHT_DNS_QUERIES: usize = 128;

pub(crate) fn parse_dns_request_for_tunnel(packet: &[u8]) -> Option<dns::UdpDnsRequest> {
    match dns::parse_udp_dns_request(packet) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("dns: packet parse failed: {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn dns_tunnel_parser_admits_only_udp_dns_requests() {
        let dns_packet = ipv4_udp_packet(dns::DNS_PORT, b"dns-query");
        let request = parse_dns_request_for_tunnel(&dns_packet).expect("DNS request");

        assert_eq!(request.src_ip, Ipv4Addr::new(10, 255, 255, 2));
        assert_eq!(request.dst_ip, Ipv4Addr::new(10, 255, 255, 1));
        assert_eq!(request.src_port, 53000);
        assert_eq!(request.dst_port, dns::DNS_PORT);
        assert_eq!(request.payload.as_ref(), b"dns-query");
        assert!(parse_dns_request_for_tunnel(&ipv4_udp_packet(12345, b"generic")).is_none());
        assert!(parse_dns_request_for_tunnel(&[0_u8; 4]).is_none());
    }

    fn ipv4_udp_packet(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 255, 255, 2]);
        packet[16..20].copy_from_slice(&[10, 255, 255, 1]);

        let udp = &mut packet[20..];
        udp[0..2].copy_from_slice(&53000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        packet
    }
}
