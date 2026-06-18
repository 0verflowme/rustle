use std::net::Ipv4Addr;

use bytes::Bytes;

pub const DNS_PORT: u16 = 53;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

pub type UdpDnsRequest = UdpPacket;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    MalformedIpv4,
    FragmentedIpv4,
    MalformedUdp,
    OversizePayload,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedIpv4 => f.write_str("malformed IPv4 packet"),
            Self::FragmentedIpv4 => f.write_str("fragmented IPv4 UDP packets are not supported"),
            Self::MalformedUdp => f.write_str("malformed UDP packet"),
            Self::OversizePayload => f.write_str("payload is too large for IPv4/UDP"),
        }
    }
}

impl std::error::Error for PacketError {}

pub fn parse_udp_dns_request(packet: &[u8]) -> Result<Option<UdpDnsRequest>, PacketError> {
    let Some(packet) = parse_ipv4_udp_packet(packet)? else {
        return Ok(None);
    };
    if packet.dst_port != DNS_PORT {
        return Ok(None);
    }
    Ok(Some(packet))
}

pub fn parse_ipv4_udp_packet(packet: &[u8]) -> Result<Option<UdpPacket>, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::MalformedIpv4);
    }

    let version = packet[0] >> 4;
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if version != 4 || header_len < 20 || packet.len() < header_len {
        return Err(PacketError::MalformedIpv4);
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return Err(PacketError::MalformedIpv4);
    }
    if packet[9] != 17 {
        return Ok(None);
    }

    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_fragment & 0x3fff != 0 {
        return Err(PacketError::FragmentedIpv4);
    }

    let udp = &packet[header_len..total_len];
    if udp.len() < 8 {
        return Err(PacketError::MalformedUdp);
    }

    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);

    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return Err(PacketError::MalformedUdp);
    }

    Ok(Some(UdpPacket {
        src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        src_port,
        dst_port,
        payload: Bytes::copy_from_slice(&udp[8..udp_len]),
    }))
}

pub fn build_udp_dns_response(
    request: &UdpDnsRequest,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    build_udp_response(request, payload)
}

pub fn build_udp_response(request: &UdpPacket, payload: &[u8]) -> Result<Vec<u8>, PacketError> {
    let udp_len = 8_usize
        .checked_add(payload.len())
        .filter(|len| *len <= usize::from(u16::MAX))
        .ok_or(PacketError::OversizePayload)?;
    let total_len = 20_usize
        .checked_add(udp_len)
        .filter(|len| *len <= usize::from(u16::MAX))
        .ok_or(PacketError::OversizePayload)?;

    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&request.dst_ip.octets());
    packet[16..20].copy_from_slice(&request.src_ip.octets());

    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&request.dst_port.to_be_bytes());
    udp[2..4].copy_from_slice(&request.src_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);

    Ok(packet)
}

pub fn build_dns_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut response = query.to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let response_flags = (flags | 0x8000 | 0x0080) & 0xfff0 | 0x0002;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&0_u16.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&0_u16.to_be_bytes());
    Some(response)
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_dns_request() {
        let payload = dns_query_payload();
        let packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(10, 255, 255, 1),
            53000,
            DNS_PORT,
            &payload,
        );

        let request = parse_udp_dns_request(&packet)
            .expect("valid packet")
            .expect("DNS request");

        assert_eq!(request.src_ip, Ipv4Addr::new(10, 255, 255, 2));
        assert_eq!(request.dst_ip, Ipv4Addr::new(10, 255, 255, 1));
        assert_eq!(request.src_port, 53000);
        assert_eq!(request.dst_port, DNS_PORT);
        assert_eq!(request.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn ignores_non_dns_udp() {
        let packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(10, 255, 255, 1),
            53000,
            123,
            b"time",
        );

        assert_eq!(parse_udp_dns_request(&packet).expect("valid packet"), None);
    }

    #[test]
    fn parse_ipv4_udp_packet_accepts_exact_minimum_non_udp_ipv4_header() {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[9] = 1;

        assert_eq!(parse_ipv4_udp_packet(&packet).expect("valid IPv4"), None);
    }

    #[test]
    fn parse_ipv4_udp_packet_rejects_ipv4_total_length_boundaries() {
        let mut too_short = vec![0_u8; 20];
        too_short[0] = 0x45;
        too_short[2..4].copy_from_slice(&19_u16.to_be_bytes());
        too_short[9] = 1;
        assert_eq!(
            parse_ipv4_udp_packet(&too_short),
            Err(PacketError::MalformedIpv4)
        );

        let mut truncated = vec![0_u8; 20];
        truncated[0] = 0x45;
        truncated[2..4].copy_from_slice(&21_u16.to_be_bytes());
        truncated[9] = 1;
        assert_eq!(
            parse_ipv4_udp_packet(&truncated),
            Err(PacketError::MalformedIpv4)
        );
    }

    #[test]
    fn parse_ipv4_udp_packet_rejects_invalid_version_and_ihl() {
        let mut wrong_version = vec![0_u8; 20];
        wrong_version[0] = 0x65;
        wrong_version[2..4].copy_from_slice(&20_u16.to_be_bytes());
        wrong_version[9] = 1;
        assert_eq!(
            parse_ipv4_udp_packet(&wrong_version),
            Err(PacketError::MalformedIpv4)
        );

        let mut short_header = vec![0_u8; 20];
        short_header[0] = 0x44;
        short_header[2..4].copy_from_slice(&20_u16.to_be_bytes());
        short_header[9] = 1;
        assert_eq!(
            parse_ipv4_udp_packet(&short_header),
            Err(PacketError::MalformedIpv4)
        );
    }

    #[test]
    fn parse_ipv4_udp_packet_accepts_empty_udp_payload_at_exact_header_length() {
        let packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(10, 255, 255, 1),
            53000,
            12345,
            b"",
        );

        let request = parse_ipv4_udp_packet(&packet)
            .expect("valid packet")
            .expect("UDP packet");

        assert_eq!(request.src_port, 53000);
        assert_eq!(request.dst_port, 12345);
        assert!(request.payload.is_empty());
    }

    #[test]
    fn parse_ipv4_udp_packet_rejects_udp_length_below_header_size() {
        let mut packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(10, 255, 255, 1),
            53000,
            12345,
            b"",
        );
        packet[24..26].copy_from_slice(&7_u16.to_be_bytes());

        assert_eq!(
            parse_ipv4_udp_packet(&packet),
            Err(PacketError::MalformedUdp)
        );
    }

    #[test]
    fn parses_and_builds_generic_udp_response() {
        let packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(192, 0, 2, 10),
            53000,
            12345,
            b"ping",
        );

        let request = parse_ipv4_udp_packet(&packet)
            .expect("valid packet")
            .expect("UDP packet");
        assert_eq!(request.dst_port, 12345);
        assert_eq!(request.payload.as_ref(), b"ping");

        let response_packet = build_udp_response(&request, b"pong").unwrap();
        let response = parse_udp_packet(&response_packet);

        assert_eq!(response.src_ip, request.dst_ip);
        assert_eq!(response.dst_ip, request.src_ip);
        assert_eq!(response.src_port, request.dst_port);
        assert_eq!(response.dst_port, request.src_port);
        assert_eq!(response.payload, b"pong");
        assert_eq!(ipv4_header_checksum(&response_packet[..20]), 0);
    }

    #[test]
    fn builds_udp_dns_response_with_reversed_tuple() {
        let payload = dns_query_payload();
        let packet = udp_packet(
            Ipv4Addr::new(10, 255, 255, 2),
            Ipv4Addr::new(10, 255, 255, 1),
            53000,
            DNS_PORT,
            &payload,
        );
        let request = parse_udp_dns_request(&packet)
            .expect("valid packet")
            .expect("DNS request");

        let response_payload = build_dns_servfail_response(request.payload.as_ref()).unwrap();
        let response_packet = build_udp_dns_response(&request, &response_payload).unwrap();
        let response = parse_udp_packet(&response_packet);

        assert_eq!(response.src_ip, request.dst_ip);
        assert_eq!(response.dst_ip, request.src_ip);
        assert_eq!(response.src_port, DNS_PORT);
        assert_eq!(response.dst_port, request.src_port);
        assert_eq!(response.payload, response_payload);
        assert_eq!(ipv4_header_checksum(&response_packet[..20]), 0);
    }

    #[test]
    fn servfail_response_preserves_id_and_question_but_clears_answers() {
        let query = dns_query_payload();
        let response = build_dns_servfail_response(&query).expect("SERVFAIL response");

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x800f,
            0x8002
        );
        assert_eq!(&response[4..6], &query[4..6]);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &query[12..]);
    }

    #[test]
    fn servfail_response_preserves_length_and_sets_exact_flags() {
        for (flags, expected) in [(0x0100_u16, 0x8182_u16), (0x80ff_u16, 0x80f2_u16)] {
            let mut query = [0_u8; 12];
            query[0..2].copy_from_slice(&0xabcd_u16.to_be_bytes());
            query[2..4].copy_from_slice(&flags.to_be_bytes());
            query[4..6].copy_from_slice(&1_u16.to_be_bytes());

            let response = build_dns_servfail_response(&query).expect("SERVFAIL response");

            assert_eq!(response.len(), query.len());
            assert_eq!(&response[0..2], &query[0..2]);
            assert_eq!(u16::from_be_bytes([response[2], response[3]]), expected);
            assert_eq!(&response[4..6], &query[4..6]);
            assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn servfail_response_requires_complete_dns_header() {
        assert!(build_dns_servfail_response(&[0_u8; 11]).is_none());
        assert!(build_dns_servfail_response(&[0_u8; 12]).is_some());
    }

    #[test]
    fn ipv4_header_checksum_matches_known_vectors() {
        let header = [
            0x45, 0x00, 0x00, 0x54, 0xa6, 0xf2, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];

        assert_eq!(ipv4_header_checksum(&header), 0x1063);
        assert_eq!(ipv4_header_checksum(&[0x12, 0x34, 0x56]), 0x97cb);
        assert_eq!(ipv4_header_checksum(&[0xff, 0xff, 0x00, 0x01]), 0xfffe);
    }

    #[test]
    fn udp_dns_parsers_fuzz_random_inputs_without_panics() {
        let mut seed = 0x4453_4e5f_6675_7a7a_u64;

        for case in 0..4096 {
            let len = case % 257;
            let mut packet = vec![0_u8; len];
            for byte in &mut packet {
                *byte = next_fuzz_byte(&mut seed);
            }

            let dns_result = std::panic::catch_unwind(|| parse_udp_dns_request(&packet));
            assert!(dns_result.is_ok(), "DNS parser panicked for len={len}");

            let udp_result = std::panic::catch_unwind(|| parse_ipv4_udp_packet(&packet));
            assert!(udp_result.is_ok(), "UDP parser panicked for len={len}");

            let servfail_result = std::panic::catch_unwind(|| build_dns_servfail_response(&packet));
            assert!(
                servfail_result.is_ok(),
                "SERVFAIL builder panicked for len={len}"
            );
        }
    }

    #[test]
    fn udp_dns_parsers_fuzz_structured_length_edges_without_panics() {
        let mut seed = 0x4453_4e5f_6c65_6e73_u64;

        for ipv4_total_len in [0_u16, 19, 20, 27, 28, 64, u16::MAX] {
            for udp_len in [0_u16, 7, 8, 9, 64, u16::MAX] {
                let actual_len = usize::from(ipv4_total_len).clamp(0, 96);
                let mut packet = vec![0_u8; actual_len.max(20)];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&ipv4_total_len.to_be_bytes());
                packet[8] = 64;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&[10, 255, 255, 2]);
                packet[16..20].copy_from_slice(&[10, 255, 255, 1]);
                if packet.len() >= 28 {
                    packet[20..22].copy_from_slice(&53000_u16.to_be_bytes());
                    packet[22..24].copy_from_slice(&DNS_PORT.to_be_bytes());
                    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
                    for byte in &mut packet[28..] {
                        *byte = next_fuzz_byte(&mut seed);
                    }
                }
                packet.truncate(actual_len);

                let parsed = std::panic::catch_unwind(|| parse_udp_dns_request(&packet));
                assert!(
                    parsed.is_ok(),
                    "DNS parser panicked for total_len={ipv4_total_len} udp_len={udp_len}"
                );
            }
        }
    }

    fn dns_query_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1234_u16.to_be_bytes());
        payload.extend_from_slice(&0x0100_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&[7]);
        payload.extend_from_slice(b"example");
        payload.extend_from_slice(&[3]);
        payload.extend_from_slice(b"com");
        payload.extend_from_slice(&[0]);
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload
    }

    fn udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        let udp = &mut packet[20..];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        packet
    }

    struct ParsedUdpPacket {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    }

    fn parse_udp_packet(packet: &[u8]) -> ParsedUdpPacket {
        let udp_len = usize::from(u16::from_be_bytes([packet[24], packet[25]]));
        ParsedUdpPacket {
            src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            src_port: u16::from_be_bytes([packet[20], packet[21]]),
            dst_port: u16::from_be_bytes([packet[22], packet[23]]),
            payload: packet[28..20 + udp_len].to_vec(),
        }
    }

    fn next_fuzz_byte(seed: &mut u64) -> u8 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 32) as u8
    }
}
