use crate::agent_bridge::{QuicNativeBridge, ReconnectingAgentBridge};
use crate::ssh_control::SshSessionPool;

#[derive(Clone)]
pub(crate) enum BridgeRuntime {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

#[derive(Clone)]
pub(crate) enum DnsTransport {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

#[derive(Clone)]
pub(crate) enum UdpAssociationTransport {
    Agent(ReconnectingAgentBridge),
    QuicNative(QuicNativeBridge),
}

impl UdpAssociationTransport {
    #[cfg(test)]
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::QuicNative(_) => "quic-native",
        }
    }
}
