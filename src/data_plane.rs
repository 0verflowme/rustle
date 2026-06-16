use clap::ValueEnum;

use crate::agent_bridge::{AgentBridgeSnapshot, QuicNativeBridge, ReconnectingAgentBridge};
use crate::SshSessionPool;

pub(crate) const MAX_DIRECT_ACTIVE_CHANNELS: usize = 512;
pub(crate) const MAX_DIRECT_OPENING_CHANNELS: usize = 32;
pub(crate) const MAX_AGENT_ACTIVE_STREAMS: usize = crate::tcp_core::DEFAULT_MAX_ACTIVE_FLOWS;
pub(crate) const MAX_AGENT_OPENING_STREAMS: usize = 128;

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

pub(crate) enum BridgeRuntime {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

impl BridgeRuntime {
    pub(crate) fn admission_limits(&self) -> BridgeAdmissionLimits {
        match self {
            Self::DirectTcpip(_) => BridgeAdmissionLimits::direct_tcpip(),
            Self::Agent(_) | Self::QuicNative(_) => BridgeAdmissionLimits::agent(),
        }
    }

    pub(crate) async fn agent_snapshot(&self) -> AgentBridgeSnapshot {
        match self {
            Self::DirectTcpip(_) | Self::QuicNative(_) => AgentBridgeSnapshot::default(),
            Self::Agent(agent) => agent.snapshot().await,
        }
    }
}

#[derive(Clone)]
pub(crate) enum DnsTransport {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

impl DnsTransport {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::DirectTcpip(_) => "SSH",
            Self::Agent(_) => "agent",
            Self::QuicNative(_) => "native QUIC",
        }
    }

    pub(crate) fn udp_transport(&self) -> Option<UdpAssociationTransport> {
        match self {
            Self::Agent(agent) => Some(UdpAssociationTransport::Agent(agent.clone())),
            Self::QuicNative(bridge) => Some(UdpAssociationTransport::QuicNative(bridge.clone())),
            Self::DirectTcpip(_) => None,
        }
    }
}

#[derive(Clone)]
pub(crate) enum UdpAssociationTransport {
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgeAdmissionLimits {
    pub(crate) active: usize,
    pub(crate) opening: usize,
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
