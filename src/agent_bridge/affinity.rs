use std::net::Ipv4Addr;
use std::time::Duration;

use crate::agent_proto;
use crate::ssh_control::{finalize_flow_hash, fnv1a_mix};

pub(crate) const AGENT_LANE_BACKOFF_BASE: Duration = Duration::from_millis(250);
pub(crate) const AGENT_LANE_BACKOFF_MAX: Duration = Duration::from_secs(30);
pub(super) const TCP_PROTOCOL_NUMBER: u8 = 6;
pub(super) const UDP_PROTOCOL_NUMBER: u8 = 17;

const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const SECONDARY_LANE_HASH_SALT: u64 = 0x9e37_79b9_7f4a_7c15;
const LANE_BACKOFF_MAX_SHIFT: u32 = 7;
const LANE_BACKOFF_JITTER_LANE_FACTOR: u64 = 37;
const LANE_BACKOFF_JITTER_FAILURE_FACTOR: u64 = 11;
const LANE_BACKOFF_JITTER_MODULUS: u64 = 100;

#[cfg(test)]
pub(crate) fn agent_lane_index(
    open: &agent_proto::AgentOpenIpv4,
    protocol: u8,
    lanes: usize,
) -> usize {
    let (primary, _) = agent_lane_candidates(agent_ipv4_lane_hash(open, protocol), lanes);
    primary
}

pub(super) fn agent_ipv4_lane_hash(open: &agent_proto::AgentOpenIpv4, protocol: u8) -> u64 {
    mix_lane_hash_protocol(
        mix_lane_hash_u16(
            mix_lane_hash_ipv4(
                agent_lane_hash_origin(open.originator_ip, open.originator_port),
                open.destination_ip,
            ),
            open.destination_port,
        ),
        protocol,
    )
}

pub(crate) fn agent_lane_backoff_duration(
    lane_index: usize,
    consecutive_failures: u32,
) -> Duration {
    let failures = consecutive_failures.max(1);
    let shift = failures.saturating_sub(1).min(LANE_BACKOFF_MAX_SHIFT);
    let base_ms = (AGENT_LANE_BACKOFF_BASE.as_millis() as u64)
        .saturating_mul(1_u64 << shift)
        .min(AGENT_LANE_BACKOFF_MAX.as_millis() as u64);
    let jitter_ms = ((lane_index as u64).saturating_mul(LANE_BACKOFF_JITTER_LANE_FACTOR)
        + u64::from(failures) * LANE_BACKOFF_JITTER_FAILURE_FACTOR)
        % LANE_BACKOFF_JITTER_MODULUS;
    Duration::from_millis((base_ms + jitter_ms).min(AGENT_LANE_BACKOFF_MAX.as_millis() as u64))
}

#[cfg(test)]
pub(crate) fn agent_host_lane_index(
    open: &agent_proto::AgentOpenHost,
    protocol: u8,
    lanes: usize,
) -> usize {
    let (primary, _) = agent_lane_candidates(agent_host_lane_hash(open, protocol), lanes);
    primary
}

pub(super) fn agent_host_lane_hash(open: &agent_proto::AgentOpenHost, protocol: u8) -> u64 {
    mix_lane_hash_protocol(
        mix_lane_hash_u16(
            mix_lane_hash_lowercase_host(
                agent_lane_hash_origin(open.originator_ip, open.originator_port),
                &open.destination_host,
            ),
            open.destination_port,
        ),
        protocol,
    )
}

pub(super) fn agent_lane_candidates(hash: u64, lanes: usize) -> (usize, usize) {
    assert!(lanes > 0, "agent lane count must be non-zero");
    let primary = (finalize_flow_hash(hash) % lanes as u64) as usize;
    if lanes == 1 {
        return (primary, primary);
    }

    let secondary_hash = hash ^ SECONDARY_LANE_HASH_SALT;
    let mut secondary = (finalize_flow_hash(secondary_hash) % lanes as u64) as usize;
    if secondary == primary {
        secondary = (secondary + 1) % lanes;
    }
    (primary, secondary)
}

fn agent_lane_hash_origin(originator_ip: Ipv4Addr, originator_port: u16) -> u64 {
    mix_lane_hash_u16(
        mix_lane_hash_ipv4(FNV1A_OFFSET_BASIS, originator_ip),
        originator_port,
    )
}

fn mix_lane_hash_ipv4(mut hash: u64, addr: Ipv4Addr) -> u64 {
    for byte in addr.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    hash
}

fn mix_lane_hash_lowercase_host(mut hash: u64, host: &str) -> u64 {
    for byte in host.as_bytes() {
        hash = fnv1a_mix(hash, byte.to_ascii_lowercase());
    }
    hash
}

fn mix_lane_hash_u16(mut hash: u64, value: u16) -> u64 {
    for byte in value.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash
}

fn mix_lane_hash_protocol(hash: u64, protocol: u8) -> u64 {
    fnv1a_mix(hash, protocol)
}

pub(crate) fn agent_lane_bit(index: usize) -> u64 {
    assert!(
        index < u64::BITS as usize,
        "agent lane bitset supports at most 64 lanes"
    );
    1_u64 << index
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4_open() -> agent_proto::AgentOpenIpv4 {
        agent_proto::AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(192, 0, 2, 10),
            destination_port: 443,
            originator_ip: Ipv4Addr::new(10, 255, 255, 2),
            originator_port: 49152,
        }
    }

    #[test]
    fn lane_candidates_stay_in_range_and_keep_distinct_secondary() {
        let hashes = [
            0,
            1,
            FNV1A_OFFSET_BASIS,
            SECONDARY_LANE_HASH_SALT,
            u64::MAX,
            agent_ipv4_lane_hash(&sample_ipv4_open(), TCP_PROTOCOL_NUMBER),
        ];

        for lanes in 1..=16 {
            for hash in hashes {
                let (primary, secondary) = agent_lane_candidates(hash, lanes);
                assert!(primary < lanes);
                assert!(secondary < lanes);
                if lanes == 1 {
                    assert_eq!((primary, secondary), (0, 0));
                } else {
                    assert_ne!(primary, secondary);
                }
            }
        }
    }

    #[test]
    fn ipv4_lane_hash_changes_for_each_flow_identity_field_and_protocol() {
        let open = sample_ipv4_open();
        let base = agent_ipv4_lane_hash(&open, TCP_PROTOCOL_NUMBER);

        assert_ne!(
            base,
            agent_ipv4_lane_hash(
                &agent_proto::AgentOpenIpv4 {
                    destination_ip: Ipv4Addr::new(192, 0, 2, 11),
                    ..open
                },
                TCP_PROTOCOL_NUMBER,
            )
        );
        assert_ne!(
            base,
            agent_ipv4_lane_hash(
                &agent_proto::AgentOpenIpv4 {
                    destination_port: 8443,
                    ..open
                },
                TCP_PROTOCOL_NUMBER,
            )
        );
        assert_ne!(
            base,
            agent_ipv4_lane_hash(
                &agent_proto::AgentOpenIpv4 {
                    originator_ip: Ipv4Addr::new(10, 255, 255, 3),
                    ..open
                },
                TCP_PROTOCOL_NUMBER,
            )
        );
        assert_ne!(
            base,
            agent_ipv4_lane_hash(
                &agent_proto::AgentOpenIpv4 {
                    originator_port: 49153,
                    ..open
                },
                TCP_PROTOCOL_NUMBER,
            )
        );
        assert_ne!(base, agent_ipv4_lane_hash(&open, UDP_PROTOCOL_NUMBER));
    }

    #[test]
    fn host_lane_hash_is_case_insensitive_but_still_uses_host_and_protocol() {
        let upper = agent_proto::AgentOpenHost {
            destination_host: "Resolver.Internal".to_owned(),
            destination_port: 53,
            originator_ip: Ipv4Addr::new(10, 255, 255, 2),
            originator_port: 49152,
        };
        let lower = agent_proto::AgentOpenHost {
            destination_host: "resolver.internal".to_owned(),
            ..upper.clone()
        };
        let other = agent_proto::AgentOpenHost {
            destination_host: "other.internal".to_owned(),
            ..upper.clone()
        };

        let tcp_hash = agent_host_lane_hash(&upper, TCP_PROTOCOL_NUMBER);
        assert_eq!(tcp_hash, agent_host_lane_hash(&lower, TCP_PROTOCOL_NUMBER));
        assert_ne!(tcp_hash, agent_host_lane_hash(&other, TCP_PROTOCOL_NUMBER));
        assert_ne!(tcp_hash, agent_host_lane_hash(&upper, UDP_PROTOCOL_NUMBER));
    }

    #[test]
    fn lane_backoff_uses_exponential_base_jitter_and_cap() {
        assert_eq!(
            agent_lane_backoff_duration(0, 0),
            Duration::from_millis(250 + 11)
        );
        assert_eq!(
            agent_lane_backoff_duration(3, 1),
            Duration::from_millis(250 + ((3 * 37 + 11) % 100))
        );
        assert_eq!(
            agent_lane_backoff_duration(3, 2),
            Duration::from_millis(500 + ((3 * 37 + 2 * 11) % 100))
        );
        assert_eq!(
            agent_lane_backoff_duration(2, 8),
            Duration::from_millis(30_000)
        );
        assert_eq!(agent_lane_backoff_duration(63, 128), AGENT_LANE_BACKOFF_MAX);
    }
}
