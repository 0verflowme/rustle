use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use clap::ValueEnum;
use tokio::sync::mpsc;

use crate::agent_bridge::{
    AgentBridgeSnapshot, AgentBridgeStream, QuicNativeBridge, ReconnectingAgentBridge,
};
#[cfg(test)]
use crate::agent_transport;
use crate::ssh_control::SshSessionPool;
use crate::{agent_proto, dns, quic_agent, ssh_bridge};

pub(crate) const MAX_DIRECT_ACTIVE_CHANNELS: usize = 512;
pub(crate) const MAX_DIRECT_OPENING_CHANNELS: usize = 32;
pub(crate) const MAX_AGENT_ACTIVE_STREAMS: usize = crate::tcp_core::DEFAULT_MAX_ACTIVE_FLOWS;
pub(crate) const MAX_AGENT_OPENING_STREAMS: usize = 128;
pub(crate) const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const UDP_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const UDP_DATAGRAMS_PER_ASSOCIATION: usize = 128;

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

impl UdpAssociationTransport {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Agent(_) => "agent",
            Self::QuicNative(_) => "quic-native",
        }
    }
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

enum AgentIoStream {
    Bridge(AgentBridgeStream),
    QuicNativeTcp(quic_agent::QuicBridgeStream),
    QuicNativeUdp(quic_agent::QuicBridgeStream),
    #[cfg(test)]
    Raw(agent_transport::AgentStream),
}

impl AgentIoStream {
    async fn send_data(&mut self, bytes: impl Into<Bytes>) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_data(bytes).await,
            Self::QuicNativeTcp(stream) => stream.send_data(bytes.into()).await,
            Self::QuicNativeUdp(stream) => stream.send_datagram(bytes.into()).await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_data(bytes).await,
        }
    }

    async fn send_eof(&mut self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_eof().await,
            Self::QuicNativeTcp(stream) => stream.send_eof().await,
            Self::QuicNativeUdp(stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_eof().await,
        }
    }

    async fn recv(&mut self) -> Option<agent_proto::AgentFrame> {
        match self {
            Self::Bridge(stream) => stream.recv().await,
            Self::QuicNativeTcp(stream) => match stream
                .recv_chunk(agent_proto::AGENT_MAX_FRAME_PAYLOAD)
                .await
            {
                Ok(Some(payload)) => {
                    agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload).ok()
                }
                Ok(None) => None,
                Err(err) => {
                    eprintln!("quic-native: failed to read TCP data: {err:#}");
                    None
                }
            },
            Self::QuicNativeUdp(stream) => match stream.recv_datagram().await {
                Ok(Some(payload)) => {
                    agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload).ok()
                }
                Ok(None) => None,
                Err(err) => {
                    eprintln!("quic-native: failed to read UDP datagram: {err:#}");
                    None
                }
            },
            #[cfg(test)]
            Self::Raw(stream) => stream.recv().await,
        }
    }

    async fn close(self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.close().await,
            Self::QuicNativeTcp(mut stream) => stream.send_eof().await,
            Self::QuicNativeUdp(mut stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.close().await,
        }
    }
}

pub(crate) fn spawn_dns_query(
    transport: DnsTransport,
    remote: Destination,
    request: dns::UdpDnsRequest,
    event_tx: mpsc::Sender<DnsResponseEvent>,
    originator_ip: Ipv4Addr,
) {
    tokio::spawn(async move {
        let result =
            query_dns_over_transport(transport, &remote, request.payload.as_ref(), originator_ip)
                .await
                .map_err(|err| err.to_string());
        send_dns_response_event(&event_tx, DnsResponseEvent { request, result });
    });
}

pub(crate) fn send_dns_response_event(
    event_tx: &mpsc::Sender<DnsResponseEvent>,
    event: DnsResponseEvent,
) -> bool {
    match event_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            eprintln!("dns: response event queue is full despite the in-flight cap");
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

pub(crate) fn spawn_udp_association_with_idle_timeout(
    transport: UdpAssociationTransport,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) {
    tokio::spawn(async move {
        let error = run_udp_association(transport, key, from_local, events.clone(), idle_timeout)
            .await
            .err()
            .map(|err| err.to_string());
        if !events.try_send_closed(key, error) {
            eprintln!(
                "udp: failed to enqueue close event for association {}:{} -> {}:{}",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port
            );
        }
    });
}

pub(crate) async fn query_dns_over_transport(
    transport: DnsTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    match transport {
        DnsTransport::DirectTcpip(ssh) => query_dns_over_ssh(ssh, remote, query).await,
        DnsTransport::Agent(agent) => {
            query_dns_over_reconnecting_agent(agent, remote, query, originator_ip).await
        }
        DnsTransport::QuicNative(bridge) => {
            query_dns_over_quic_native(bridge, remote, query, originator_ip).await
        }
    }
}

async fn query_dns_over_ssh(
    ssh: SshSessionPool,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    if query.len() > usize::from(u16::MAX) {
        bail!("DNS query exceeds TCP DNS length limit");
    }

    let mut channel = tokio::time::timeout(
        ssh_bridge::DNS_DIRECT_OPEN_TIMEOUT,
        ssh.open_background_direct_tcpip(
            remote.host.clone(),
            u32::from(remote.port),
            "127.0.0.1".to_owned(),
            0,
        ),
    )
    .await
    .context("timed out opening SSH direct-tcpip channel to DNS resolver")?
    .with_context(|| {
        format!(
            "failed to open SSH direct-tcpip channel to DNS resolver {}:{}",
            remote.host, remote.port
        )
    })?;

    let mut frame = BytesMut::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    channel
        .data_bytes(frame.freeze())
        .await
        .context("failed to write DNS TCP query over SSH")?;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        let mut received = BytesMut::with_capacity(512);
        let mut expected_len = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    received.extend_from_slice(data.as_ref());
                    if expected_len.is_none() && received.len() >= 2 {
                        expected_len =
                            Some(usize::from(u16::from_be_bytes([received[0], received[1]])));
                    }
                    if let Some(len) = expected_len {
                        if received.len() >= len + 2 {
                            let frame = received.split_to(len + 2).freeze();
                            return Ok(frame.slice(2..));
                        }
                    }
                }
                russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a complete TCP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS TCP response")??;

    let _ = channel.close().await;
    Ok(response)
}

async fn query_dns_over_reconnecting_agent(
    agent: ReconnectingAgentBridge,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        let stream = agent
            .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent UDP DNS association to {}:{}",
                    remote.host, remote.port
                )
            })?;
        query_dns_over_agent_udp_stream(AgentIoStream::Bridge(stream), query).await
    } else {
        let stream = open_dns_agent_stream(agent, remote, originator_ip).await?;
        query_dns_over_agent_tcp_stream(stream, query).await
    }
}

async fn query_dns_over_quic_native(
    bridge: QuicNativeBridge,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        let stream = bridge
            .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open native QUIC UDP DNS association to {}:{}",
                    remote.host, remote.port
                )
            })?;
        query_dns_over_agent_udp_stream(AgentIoStream::QuicNativeUdp(stream), query).await
    } else {
        let stream = bridge
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: remote.host.clone(),
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open native QUIC hostname DNS stream to {}:{}",
                    remote.host, remote.port
                )
            })?;
        query_dns_over_agent_tcp_stream(AgentIoStream::QuicNativeTcp(stream), query).await
    }
}

#[cfg(test)]
pub(crate) async fn query_dns_over_agent(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    let stream = open_dns_agent_transport_stream(agent, remote, originator_ip).await?;
    query_dns_over_agent_tcp_stream(stream, query).await
}

#[cfg(test)]
pub(crate) async fn query_dns_over_agent_udp(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    let remote_ip = remote
        .host
        .parse::<Ipv4Addr>()
        .with_context(|| format!("test UDP DNS remote must be IPv4, got {}", remote.host))?;
    let stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: remote_ip,
            destination_port: remote.port,
            originator_ip,
            originator_port: 0,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP DNS association to {}:{}",
                remote.host, remote.port
            )
        })?;
    query_dns_over_agent_udp_stream(AgentIoStream::Raw(stream), query).await
}

async fn open_dns_agent_stream(
    agent: ReconnectingAgentBridge,
    remote: &Destination,
    originator_ip: Ipv4Addr,
) -> Result<AgentIoStream> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        agent
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Bridge)
    } else {
        agent
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: remote.host.clone(),
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent hostname stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Bridge)
    }
}

#[cfg(test)]
async fn open_dns_agent_transport_stream(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    originator_ip: Ipv4Addr,
) -> Result<AgentIoStream> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        agent
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Raw)
    } else {
        agent
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: remote.host.clone(),
                destination_port: remote.port,
                originator_ip,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent hostname stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Raw)
    }
}

async fn query_dns_over_agent_tcp_stream(mut stream: AgentIoStream, query: &[u8]) -> Result<Bytes> {
    if query.len() > usize::from(u16::MAX) {
        bail!("DNS query exceeds TCP DNS length limit");
    }
    let mut frame = BytesMut::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    stream
        .send_data(frame.freeze())
        .await
        .context("failed to write DNS TCP query over agent")?;
    let _ = stream.send_eof().await;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        let mut received = BytesMut::with_capacity(512);
        let mut expected_len = None;

        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => {
                    received.extend_from_slice(frame.payload.as_ref());
                    if expected_len.is_none() && received.len() >= 2 {
                        expected_len =
                            Some(usize::from(u16::from_be_bytes([received[0], received[1]])));
                    }
                    if let Some(len) = expected_len {
                        if received.len() >= len + 2 {
                            let frame = received.split_to(len + 2).freeze();
                            return Ok(frame.slice(2..));
                        }
                    }
                }
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent DNS stream reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a complete TCP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS TCP response over agent")??;

    let _ = stream.close().await;
    Ok(response)
}

async fn query_dns_over_agent_udp_stream(mut stream: AgentIoStream, query: &[u8]) -> Result<Bytes> {
    stream
        .send_data(Bytes::copy_from_slice(query))
        .await
        .context("failed to write DNS UDP query over agent")?;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => return Ok(frame.payload),
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent DNS UDP association reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a UDP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS UDP response over agent")??;

    let _ = stream.close().await;
    Ok(response)
}

pub(crate) async fn run_udp_association(
    transport: UdpAssociationTransport,
    key: UdpFlowKey,
    mut from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let open = agent_proto::AgentOpenIpv4 {
        destination_ip: key.dst_ip,
        destination_port: key.dst_port,
        originator_ip: key.src_ip,
        originator_port: key.src_port,
    };
    let stream = match transport {
        UdpAssociationTransport::Agent(agent) => agent
            .open_udp_ipv4(open)
            .await
            .map(AgentIoStream::Bridge)
            .with_context(|| {
                format!(
                    "failed to open agent UDP association to {}:{}",
                    key.dst_ip, key.dst_port
                )
            })?,
        UdpAssociationTransport::QuicNative(bridge) => bridge
            .open_udp_ipv4(open)
            .await
            .map(AgentIoStream::QuicNativeUdp)
            .with_context(|| {
                format!(
                    "failed to open native QUIC UDP association to {}:{}",
                    key.dst_ip, key.dst_port
                )
            })?,
    };

    run_udp_association_stream(stream, key, &mut from_local, events, idle_timeout).await
}

#[cfg(test)]
pub(crate) async fn run_udp_association_transport(
    agent: agent_transport::AgentTransport,
    key: UdpFlowKey,
    mut from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: key.dst_ip,
            destination_port: key.dst_port,
            originator_ip: key.src_ip,
            originator_port: key.src_port,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP association to {}:{}",
                key.dst_ip, key.dst_port
            )
        })?;

    run_udp_association_stream(
        AgentIoStream::Raw(stream),
        key,
        &mut from_local,
        events,
        idle_timeout,
    )
    .await
}

async fn run_udp_association_stream(
    mut stream: AgentIoStream,
    key: UdpFlowKey,
    from_local: &mut mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            maybe_payload = from_local.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                stream
                    .send_data(payload)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to write UDP datagram over agent to {}:{}",
                            key.dst_ip, key.dst_port
                        )
                    })?;
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            maybe_frame = stream.recv() => {
                let Some(frame) = maybe_frame else {
                    break;
                };
                match frame.kind {
                    agent_proto::AgentFrameKind::Data => {
                        if !events.try_send_response(key, frame.payload) {
                            eprintln!(
                                "udp: dropping response datagram for {}:{} -> {}:{} because the response event queue is full or closed",
                                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                            );
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                    agent_proto::AgentFrameKind::Reset => {
                        let message = String::from_utf8_lossy(&frame.payload);
                        bail!("agent UDP association reset: {message}");
                    }
                    _ => {}
                }
            }
            _ = &mut idle => {
                break;
            }
        }
    }

    let _ = stream.close().await;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn query_udp_over_agent(
    agent: agent_transport::AgentTransport,
    request: &dns::UdpPacket,
) -> Result<Vec<u8>> {
    let mut stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: request.dst_ip,
            destination_port: request.dst_port,
            originator_ip: request.src_ip,
            originator_port: request.src_port,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP stream to {}:{}",
                request.dst_ip, request.dst_port
            )
        })?;

    stream
        .send_data(request.payload.clone())
        .await
        .with_context(|| {
            format!(
                "failed to write UDP datagram over agent to {}:{}",
                request.dst_ip, request.dst_port
            )
        })?;

    let response = tokio::time::timeout(UDP_DATAGRAM_TIMEOUT, async {
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => return Ok(frame.payload.to_vec()),
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent UDP stream reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote UDP socket closed before sending a response datagram")
    })
    .await;

    let _ = stream.close().await;
    response.with_context(|| {
        format!(
            "timed out waiting for UDP response over agent from {}:{}",
            request.dst_ip, request.dst_port
        )
    })?
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
