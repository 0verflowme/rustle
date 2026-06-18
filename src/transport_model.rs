use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::ValueEnum;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

use crate::agent_proto;
use crate::dns;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BridgeTransportKind {
    Auto,
    AutoQuic,
    DirectTcpip,
    Agent,
    QuicAgent,
    QuicNative,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TunnelRuntimeOptions {
    pub(crate) ssh_sessions: usize,
    pub(crate) agent_sessions: usize,
    pub(crate) fast_start_auto_agent_lanes: bool,
}

pub(crate) const MAX_DIRECT_ACTIVE_CHANNELS: usize = 512;
pub(crate) const MAX_DIRECT_OPENING_CHANNELS: usize = 32;
pub(crate) const MAX_AGENT_ACTIVE_STREAMS: usize = crate::tcp_core::DEFAULT_MAX_ACTIVE_FLOWS;
pub(crate) const MAX_AGENT_OPENING_STREAMS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgeAdmissionLimits {
    pub(crate) active: usize,
    pub(crate) opening: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataPlaneCaps {
    pub(crate) udp_associations: bool,
}

impl BridgeAdmissionLimits {
    pub(crate) const fn direct_tcpip() -> Self {
        Self {
            active: MAX_DIRECT_ACTIVE_CHANNELS,
            opening: MAX_DIRECT_OPENING_CHANNELS,
        }
    }

    pub(crate) const fn agent() -> Self {
        Self {
            active: MAX_AGENT_ACTIVE_STREAMS,
            opening: MAX_AGENT_OPENING_STREAMS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BridgeAdmissionDecision {
    Admit,
    DeferActive,
    DeferOpening,
}

pub(crate) fn bridge_admission_decision(
    active: usize,
    opening: usize,
    limits: BridgeAdmissionLimits,
) -> BridgeAdmissionDecision {
    if active >= limits.active {
        BridgeAdmissionDecision::DeferActive
    } else if opening >= limits.opening {
        BridgeAdmissionDecision::DeferOpening
    } else {
        BridgeAdmissionDecision::Admit
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Destination {
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataPlaneIpv4Open {
    pub(crate) destination_ip: Ipv4Addr,
    pub(crate) destination_port: u16,
    pub(crate) originator_ip: Ipv4Addr,
    pub(crate) originator_port: u16,
    pub(crate) flow_generation: Option<u64>,
}

impl DataPlaneIpv4Open {
    pub(crate) fn into_agent_open(self) -> agent_proto::AgentOpenIpv4 {
        agent_proto::AgentOpenIpv4 {
            destination_ip: self.destination_ip,
            destination_port: self.destination_port,
            originator_ip: self.originator_ip,
            originator_port: self.originator_port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DataPlaneTcpOpen {
    Ipv4(DataPlaneIpv4Open),
    Host {
        destination_host: String,
        destination_port: u16,
        originator_ip: Ipv4Addr,
        originator_port: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataPlaneTcpOpenMode {
    Strict,
    Optimistic,
}

impl DataPlaneTcpOpen {
    pub(crate) fn destination_label(&self) -> String {
        match self {
            Self::Ipv4(open) => format!("{}:{}", open.destination_ip, open.destination_port),
            Self::Host {
                destination_host,
                destination_port,
                ..
            } => format!("{destination_host}:{destination_port}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataPlaneReconnectSnapshot {
    pub(crate) attempts: u64,
    pub(crate) successes: u64,
    pub(crate) failures: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DataPlaneRuntimeSnapshot {
    pub(crate) reconnects: DataPlaneReconnectSnapshot,
    pub(crate) lanes_total: usize,
    pub(crate) lanes_desired: usize,
    pub(crate) lanes_available: usize,
    pub(crate) lanes_failed: usize,
    pub(crate) lanes_missing: usize,
    pub(crate) lanes_quarantined: usize,
    pub(crate) lanes_repairing: usize,
    pub(crate) active_streams: usize,
    pub(crate) max_lane_load: usize,
    pub(crate) max_quarantine_ms: u64,
}

#[derive(Debug)]
pub(crate) struct DnsResponseEvent {
    pub(crate) request: dns::UdpDnsRequest,
    pub(crate) result: std::result::Result<Bytes, String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UdpFlowKey {
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) src_port: u16,
    pub(crate) dst_ip: Ipv4Addr,
    pub(crate) dst_port: u16,
}

impl UdpFlowKey {
    pub(crate) fn into_open_request(self) -> DataPlaneIpv4Open {
        DataPlaneIpv4Open {
            destination_ip: self.dst_ip,
            destination_port: self.dst_port,
            originator_ip: self.src_ip,
            originator_port: self.src_port,
            flow_generation: None,
        }
    }

    pub(crate) fn from_packet(packet: &dns::UdpPacket) -> Self {
        Self {
            src_ip: packet.src_ip,
            src_port: packet.src_port,
            dst_ip: packet.dst_ip,
            dst_port: packet.dst_port,
        }
    }

    pub(crate) fn response_template(self) -> dns::UdpPacket {
        dns::UdpPacket {
            src_ip: self.src_ip,
            src_port: self.src_port,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port,
            payload: Bytes::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpAssociation {
    pub(crate) to_remote: mpsc::Sender<Bytes>,
}

pub(crate) const UDP_DATAGRAMS_PER_ASSOCIATION: usize = 128;

#[derive(Clone)]
pub(crate) struct UdpAssociationEvents {
    pub(crate) response_tx: mpsc::Sender<UdpResponseEvent>,
    pub(crate) close_tx: mpsc::Sender<UdpClosedEvent>,
}

impl UdpAssociationEvents {
    pub(crate) fn try_send_response(&self, key: UdpFlowKey, payload: Bytes) -> bool {
        match self.response_tx.try_send(UdpResponseEvent { key, payload }) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub(crate) fn try_send_closed(&self, key: UdpFlowKey, error: Option<String>) -> bool {
        match self.close_tx.try_send(UdpClosedEvent { key, error }) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpResponseEvent {
    pub(crate) key: UdpFlowKey,
    pub(crate) payload: Bytes,
}

#[derive(Debug)]
pub(crate) struct UdpClosedEvent {
    pub(crate) key: UdpFlowKey,
    pub(crate) error: Option<String>,
}

pub(crate) fn parse_destination(input: &str) -> Result<Destination> {
    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("destination must be in host:port form"))?;
    if host.is_empty() {
        bail!("destination host must not be empty");
    }

    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid destination port in {input}"))?;
    Ok(Destination {
        host: host.to_owned(),
        port,
    })
}
