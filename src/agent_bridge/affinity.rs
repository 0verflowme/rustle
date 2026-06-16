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
