use std::net::Ipv4Addr;

use anyhow::{anyhow, bail, Context, Result};

use crate::transport_model::parse_destination;

#[derive(Debug)]
pub(crate) struct Ipv4Destination {
    pub(crate) host: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) port: u16,
}

pub(crate) fn parse_ipv4_destination(input: &str) -> Result<Ipv4Destination> {
    let destination = parse_destination(input)?;
    let ip = destination
        .host
        .parse::<Ipv4Addr>()
        .with_context(|| format!("destination must use an IPv4 address for the MVP: {input}"))?;
    Ok(Ipv4Destination {
        host: destination.host,
        ip,
        port: destination.port,
    })
}

pub(crate) fn default_http_request(host: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

pub(crate) fn percentile_nearest_rank(sorted: &[u128], percentile: usize) -> u128 {
    debug_assert!(!sorted.is_empty());
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

pub(crate) fn build_dns_a_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        bail!("DNS query name must not be empty");
    }

    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());

    let mut qname_len = 1_usize;
    for label in name.split('.') {
        if label.is_empty() {
            bail!("DNS query name contains an empty label: {name}");
        }
        if label.len() > 63 {
            bail!("DNS label is too long in query name: {label}");
        }
        qname_len = qname_len
            .checked_add(1 + label.len())
            .ok_or_else(|| anyhow!("DNS query name is too long: {name}"))?;
        if qname_len > 255 {
            bail!("DNS query name is too long: {name}");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

pub(crate) fn validate_dns_response(query: &[u8], response: &[u8]) -> Result<()> {
    if query.len() < 2 || response.len() < 12 {
        bail!("DNS response is too short");
    }
    if response[0..2] != query[0..2] {
        bail!("DNS response ID does not match query ID");
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        bail!("DNS response is not marked as a response");
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        bail!("DNS response returned rcode {rcode}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_flags(id: u16, flags: u16) -> [u8; 12] {
        let mut response = [0_u8; 12];
        response[0..2].copy_from_slice(&id.to_be_bytes());
        response[2..4].copy_from_slice(&flags.to_be_bytes());
        response
    }

    #[test]
    fn default_http_request_uses_stable_http11_close_shape() {
        assert_eq!(
            default_http_request("example.com"),
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn percentile_nearest_rank_uses_ceiling_rank_and_clamps_high_percentiles() {
        let values = [10, 20, 30, 40];
        assert_eq!(percentile_nearest_rank(&values, 1), 10);
        assert_eq!(percentile_nearest_rank(&values, 25), 10);
        assert_eq!(percentile_nearest_rank(&values, 50), 20);
        assert_eq!(percentile_nearest_rank(&values, 75), 30);
        assert_eq!(percentile_nearest_rank(&values, 100), 40);
        assert_eq!(percentile_nearest_rank(&values, 150), 40);
    }

    #[test]
    fn build_dns_a_query_encodes_header_labels_and_qtype() {
        let query = build_dns_a_query(0x1234, "www.example.com.").expect("valid DNS query");
        assert_eq!(
            &query[0..12],
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        );
        assert_eq!(
            &query[12..],
            b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        );
    }

    #[test]
    fn build_dns_a_query_rejects_empty_or_oversized_names() {
        assert!(build_dns_a_query(1, ".").is_err());
        assert!(build_dns_a_query(1, "a..example").is_err());
        assert!(build_dns_a_query(1, &"a".repeat(64)).is_err());

        let label63 = "a".repeat(63);
        assert!(build_dns_a_query(1, &label63).is_ok());

        let exact_max = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(build_dns_a_query(1, &exact_max).is_ok());

        let too_long = format!("{exact_max}.e");
        assert!(build_dns_a_query(1, &too_long).is_err());
    }

    #[test]
    fn validate_dns_response_checks_id_response_bit_and_rcode() {
        let query = build_dns_a_query(0x2233, "example.com").expect("valid DNS query");
        let valid = response_with_flags(0x2233, 0x8000);
        validate_dns_response(&query, &valid).expect("valid minimal DNS response");
        validate_dns_response(&query[..2], &valid)
            .expect("two-byte query ID is sufficient for response validation");

        assert!(validate_dns_response(&query[..1], &valid).is_err());
        assert!(validate_dns_response(&query, &valid[..11]).is_err());

        let mismatched_id = response_with_flags(0x2234, 0x8000);
        assert!(validate_dns_response(&query, &mismatched_id).is_err());

        let query_not_response = response_with_flags(0x2233, 0x0000);
        assert!(validate_dns_response(&query, &query_not_response).is_err());

        let servfail = response_with_flags(0x2233, 0x8002);
        assert!(validate_dns_response(&query, &servfail).is_err());
    }
}
