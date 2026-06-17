use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::client::Handle;

use crate::ssh_control::Client;
use crate::{agent_proto, agent_transport, quic_agent};

#[derive(Clone)]
pub(crate) struct QuicNativeBridge {
    client: quic_agent::QuicBridgeClient,
    active_streams: Arc<AtomicUsize>,
    _carrier: Option<Arc<QuicNativeCarrier>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QuicNativeBridgeSnapshot {
    pub(crate) active_streams: usize,
}

pub(crate) struct QuicNativeBridgeStream {
    inner: Option<quic_agent::QuicBridgeStream>,
    active_streams: Arc<AtomicUsize>,
}

struct QuicNativeCarrier {
    _handle: Handle<Client>,
    drain_task: tokio::task::JoinHandle<()>,
}

impl Drop for QuicNativeCarrier {
    fn drop(&mut self) {
        self.drain_task.abort();
    }
}

impl QuicNativeBridge {
    #[cfg(test)]
    pub(crate) fn detached(client: quic_agent::QuicBridgeClient) -> Self {
        Self {
            client,
            active_streams: Arc::new(AtomicUsize::new(0)),
            _carrier: None,
        }
    }

    pub(crate) fn with_ssh_carrier(
        client: quic_agent::QuicBridgeClient,
        handle: Handle<Client>,
        drain_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            client,
            active_streams: Arc::new(AtomicUsize::new(0)),
            _carrier: Some(Arc::new(QuicNativeCarrier {
                _handle: handle,
                drain_task,
            })),
        }
    }

    pub(crate) async fn open_tcp_ipv4_optimistic(
        &self,
        open: agent_proto::AgentOpenIpv4,
    ) -> Result<QuicNativeBridgeStream> {
        self.wrap_stream(self.client.open_tcp_ipv4_optimistic(open).await?)
    }

    pub(crate) async fn open_udp_ipv4(
        &self,
        open: agent_proto::AgentOpenIpv4,
    ) -> Result<QuicNativeBridgeStream> {
        self.wrap_stream(self.client.open_udp_ipv4(open).await?)
    }

    pub(crate) async fn open_tcp_host(
        &self,
        open: agent_proto::AgentOpenHost,
    ) -> Result<QuicNativeBridgeStream> {
        self.wrap_stream(self.client.open_tcp_host(open).await?)
    }

    pub(crate) fn snapshot(&self) -> QuicNativeBridgeSnapshot {
        QuicNativeBridgeSnapshot {
            active_streams: self.active_streams.load(Ordering::Acquire),
        }
    }

    fn wrap_stream(&self, inner: quic_agent::QuicBridgeStream) -> Result<QuicNativeBridgeStream> {
        self.active_streams.fetch_add(1, Ordering::AcqRel);
        Ok(QuicNativeBridgeStream {
            inner: Some(inner),
            active_streams: Arc::clone(&self.active_streams),
        })
    }

    #[cfg(test)]
    pub(crate) fn close_for_test(&self, reason: &str) {
        self.client.close(reason);
    }
}

impl QuicNativeBridgeStream {
    pub(crate) async fn wait_opened(&mut self) -> Result<()> {
        self.inner_mut()?.wait_opened().await
    }

    pub(crate) async fn send_data(&mut self, bytes: bytes::Bytes) -> Result<()> {
        self.inner_mut()?.send_data(bytes).await
    }

    pub(crate) async fn send_datagram(&mut self, bytes: bytes::Bytes) -> Result<()> {
        self.inner_mut()?.send_datagram(bytes).await
    }

    pub(crate) async fn send_eof(&mut self) -> Result<()> {
        self.inner_mut()?.send_eof().await
    }

    pub(crate) async fn recv_chunk(&mut self, max_len: usize) -> Result<Option<bytes::Bytes>> {
        self.inner_mut()?.recv_chunk(max_len).await
    }

    pub(crate) async fn recv_datagram(&mut self) -> Result<Option<bytes::Bytes>> {
        self.inner_mut()?.recv_datagram().await
    }

    fn inner_mut(&mut self) -> Result<&mut quic_agent::QuicBridgeStream> {
        self.inner
            .as_mut()
            .context("native QUIC bridge stream is already closed")
    }
}

impl Drop for QuicNativeBridgeStream {
    fn drop(&mut self) {
        if self.inner.take().is_some() {
            self.active_streams.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

pub(crate) enum AgentBridgeCarrier {
    Ssh(Handle<Client>),
    Quic(QuicAgentCarrier),
    #[allow(dead_code)]
    Detached,
}

impl AgentBridgeCarrier {
    pub(crate) async fn disconnect(&self, reason: &str) -> Result<()> {
        match self {
            Self::Ssh(handle) => handle
                .disconnect(russh::Disconnect::ByApplication, reason, "en")
                .await
                .with_context(|| format!("failed to disconnect agent carrier: {reason}")),
            Self::Quic(carrier) => carrier.disconnect(reason).await,
            Self::Detached => Ok(()),
        }
    }
}

pub(crate) struct QuicAgentCarrier {
    handle: Handle<Client>,
    _session: quic_agent::QuicAgentSession,
    drain_task: tokio::task::JoinHandle<()>,
}

impl QuicAgentCarrier {
    fn new(
        handle: Handle<Client>,
        session: quic_agent::QuicAgentSession,
        drain_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            handle,
            _session: session,
            drain_task,
        }
    }

    async fn disconnect(&self, reason: &str) -> Result<()> {
        self.drain_task.abort();
        self.handle
            .disconnect(russh::Disconnect::ByApplication, reason, "en")
            .await
            .with_context(|| format!("failed to disconnect QUIC agent SSH carrier: {reason}"))
    }
}

pub(crate) struct AgentBridgeTransport {
    pub(super) carrier: AgentBridgeCarrier,
    pub(super) transport: agent_transport::AgentTransport,
    pub(super) agent_command: String,
}

impl AgentBridgeTransport {
    pub(crate) fn ssh(
        handle: Handle<Client>,
        transport: agent_transport::AgentTransport,
        agent_command: impl Into<String>,
    ) -> Self {
        Self {
            carrier: AgentBridgeCarrier::Ssh(handle),
            transport,
            agent_command: agent_command.into(),
        }
    }

    pub(crate) fn quic(
        handle: Handle<Client>,
        session: quic_agent::QuicAgentSession,
        drain_task: tokio::task::JoinHandle<()>,
        transport: agent_transport::AgentTransport,
        agent_command: impl Into<String>,
    ) -> Self {
        Self {
            carrier: AgentBridgeCarrier::Quic(QuicAgentCarrier::new(handle, session, drain_task)),
            transport,
            agent_command: agent_command.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn detached_for_test(
        transport: agent_transport::AgentTransport,
        agent_command: impl Into<String>,
    ) -> Self {
        Self {
            carrier: AgentBridgeCarrier::Detached,
            transport,
            agent_command: agent_command.into(),
        }
    }

    pub(crate) async fn disconnect(&self, reason: &str) -> Result<()> {
        self.carrier.disconnect(reason).await
    }

    pub(crate) fn transport(&self) -> &agent_transport::AgentTransport {
        &self.transport
    }

    pub(crate) fn agent_command(&self) -> &str {
        &self.agent_command
    }

    pub(crate) fn peer_capabilities(&self) -> u64 {
        self.transport.peer_hello().capabilities
    }
}
