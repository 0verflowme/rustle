use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::ValueEnum;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

use crate::dns;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BridgeTransportKind {
    Auto,
    DirectTcpip,
    Agent,
    QuicAgent,
    QuicNative,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BridgeRuntimeOptions {
    pub(crate) ssh_sessions: usize,
    pub(crate) agent_sessions: usize,
    pub(crate) fast_start_auto_agent_lanes: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Destination {
    pub(crate) host: String,
    pub(crate) port: u16,
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
