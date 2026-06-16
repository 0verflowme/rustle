use std::collections::VecDeque;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::agent_bridge::{
    AgentBridgeSnapshot, AgentBridgeStream, QuicNativeBridge, ReconnectingAgentBridge,
};
#[cfg(test)]
use crate::agent_transport;
use crate::ssh_control::SshSessionPool;
use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneCaps, DataPlaneReconnectSnapshot, DataPlaneRuntimeSnapshot,
    Destination, DnsResponseEvent, UdpAssociationEvents, UdpFlowKey,
};
use crate::{agent_proto, dns, quic_agent, ssh_bridge, tcp_core};

pub(crate) const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const UDP_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);
const AGENT_PRE_OPEN_RETRY_LIMIT: usize = 1;

pub(crate) type DataPlaneSnapshotFuture<'a> =
    Pin<Box<dyn Future<Output = DataPlaneRuntimeSnapshot> + Send + 'a>>;
pub(crate) type DataPlaneDnsFuture<'a> = Pin<Box<dyn Future<Output = Result<Bytes>> + Send + 'a>>;

pub(crate) trait DataPlane: Send + Sync {
    fn label(&self) -> &'static str;
    fn udp_label(&self) -> Option<&'static str>;
    fn caps(&self) -> DataPlaneCaps;
    fn admission_limits(&self) -> BridgeAdmissionLimits;
    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_>;
    fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge;
    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_>;
    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    );
}

#[derive(Clone)]
pub(crate) enum RuntimeDataPlane {
    DirectTcpip(DirectTcpipDataPlane),
    FramedAgent(FramedAgentDataPlane),
    QuicNative(QuicNativeDataPlane),
}

impl RuntimeDataPlane {
    pub(crate) fn from_bridge_runtime(bridge: BridgeRuntime) -> Self {
        match bridge {
            BridgeRuntime::DirectTcpip(ssh) => Self::DirectTcpip(DirectTcpipDataPlane::new(ssh)),
            BridgeRuntime::Agent(agent) => Self::FramedAgent(FramedAgentDataPlane::new(agent)),
            BridgeRuntime::QuicNative(bridge) => Self::QuicNative(QuicNativeDataPlane::new(bridge)),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DirectTcpipDataPlane {
    ssh: SshSessionPool,
}

impl DirectTcpipDataPlane {
    fn new(ssh: SshSessionPool) -> Self {
        Self { ssh }
    }
}

#[derive(Clone)]
pub(crate) struct FramedAgentDataPlane {
    agent: ReconnectingAgentBridge,
}

impl FramedAgentDataPlane {
    fn new(agent: ReconnectingAgentBridge) -> Self {
        Self { agent }
    }
}

#[derive(Clone)]
pub(crate) struct QuicNativeDataPlane {
    bridge: QuicNativeBridge,
}

impl QuicNativeDataPlane {
    fn new(bridge: QuicNativeBridge) -> Self {
        Self { bridge }
    }
}

fn data_plane_runtime_snapshot_from_agent(
    snapshot: AgentBridgeSnapshot,
) -> DataPlaneRuntimeSnapshot {
    DataPlaneRuntimeSnapshot {
        reconnects: DataPlaneReconnectSnapshot {
            attempts: snapshot.reconnects.attempts,
            successes: snapshot.reconnects.successes,
            failures: snapshot.reconnects.failures,
        },
        lanes_total: snapshot.lanes_total,
        lanes_desired: snapshot.lanes_desired,
        lanes_available: snapshot.lanes_available,
        lanes_failed: snapshot.lanes_failed,
        lanes_missing: snapshot.lanes_missing,
        lanes_quarantined: snapshot.lanes_quarantined,
        lanes_repairing: snapshot.lanes_repairing,
        active_streams: snapshot.active_streams,
        max_lane_load: snapshot.max_lane_load,
        max_quarantine_ms: snapshot.max_quarantine_ms,
    }
}

#[derive(Clone)]
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

    pub(crate) fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge {
        let flow = id.key;
        match self {
            Self::DirectTcpip(ssh) => spawn_direct_tcpip_bridge(id, event_tx, ssh.clone()),
            Self::Agent(agent) => {
                let agent = agent.clone();
                eprintln!(
                    "agent: opening stream {}:{} for local {}:{} generation={}",
                    flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
                );
                spawn_agent_tcp_bridge(id, event_tx, agent)
            }
            Self::QuicNative(bridge) => {
                let bridge = bridge.clone();
                eprintln!(
                    "quic-native: opening stream {}:{} for local {}:{} generation={}",
                    flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
                );
                spawn_quic_native_tcp_bridge(id, event_tx, bridge)
            }
        }
    }
}

impl DataPlane for DirectTcpipDataPlane {
    fn label(&self) -> &'static str {
        "SSH"
    }

    fn udp_label(&self) -> Option<&'static str> {
        None
    }

    fn caps(&self) -> DataPlaneCaps {
        DataPlaneCaps {
            udp_associations: false,
        }
    }

    fn admission_limits(&self) -> BridgeAdmissionLimits {
        BridgeAdmissionLimits::direct_tcpip()
    }

    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_> {
        Box::pin(async { DataPlaneRuntimeSnapshot::default() })
    }

    fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge {
        spawn_direct_tcpip_bridge(id, event_tx, self.ssh.clone())
    }

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        _originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        let ssh = self.ssh.clone();
        Box::pin(async move { query_dns_over_ssh(ssh, &remote, query.as_ref()).await })
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        _from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        _idle_timeout: Duration,
    ) {
        let _ = events.try_send_closed(
            key,
            Some("data plane does not support generic UDP associations".to_owned()),
        );
    }
}

impl DataPlane for FramedAgentDataPlane {
    fn label(&self) -> &'static str {
        "agent"
    }

    fn udp_label(&self) -> Option<&'static str> {
        Some("agent")
    }

    fn caps(&self) -> DataPlaneCaps {
        DataPlaneCaps {
            udp_associations: true,
        }
    }

    fn admission_limits(&self) -> BridgeAdmissionLimits {
        BridgeAdmissionLimits::agent()
    }

    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_> {
        let agent = self.agent.clone();
        Box::pin(async move { data_plane_runtime_snapshot_from_agent(agent.snapshot().await) })
    }

    fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge {
        let flow = id.key;
        eprintln!(
            "agent: opening stream {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
        spawn_agent_tcp_bridge(id, event_tx, self.agent.clone())
    }

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        let agent = self.agent.clone();
        Box::pin(async move {
            query_dns_over_reconnecting_agent(agent, &remote, query.as_ref(), originator_ip).await
        })
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) {
        spawn_udp_association_with_idle_timeout(
            UdpAssociationTransport::Agent(self.agent.clone()),
            key,
            from_local,
            events,
            idle_timeout,
        );
    }
}

impl DataPlane for QuicNativeDataPlane {
    fn label(&self) -> &'static str {
        "native QUIC"
    }

    fn udp_label(&self) -> Option<&'static str> {
        Some("quic-native")
    }

    fn caps(&self) -> DataPlaneCaps {
        DataPlaneCaps {
            udp_associations: true,
        }
    }

    fn admission_limits(&self) -> BridgeAdmissionLimits {
        BridgeAdmissionLimits::agent()
    }

    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_> {
        Box::pin(async { DataPlaneRuntimeSnapshot::default() })
    }

    fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge {
        let flow = id.key;
        eprintln!(
            "quic-native: opening stream {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
        spawn_quic_native_tcp_bridge(id, event_tx, self.bridge.clone())
    }

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        let bridge = self.bridge.clone();
        Box::pin(async move {
            query_dns_over_quic_native(bridge, &remote, query.as_ref(), originator_ip).await
        })
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) {
        spawn_udp_association_with_idle_timeout(
            UdpAssociationTransport::QuicNative(self.bridge.clone()),
            key,
            from_local,
            events,
            idle_timeout,
        );
    }
}

impl DataPlane for RuntimeDataPlane {
    fn label(&self) -> &'static str {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.label(),
            Self::FramedAgent(data_plane) => data_plane.label(),
            Self::QuicNative(data_plane) => data_plane.label(),
        }
    }

    fn udp_label(&self) -> Option<&'static str> {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.udp_label(),
            Self::FramedAgent(data_plane) => data_plane.udp_label(),
            Self::QuicNative(data_plane) => data_plane.udp_label(),
        }
    }

    fn caps(&self) -> DataPlaneCaps {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.caps(),
            Self::FramedAgent(data_plane) => data_plane.caps(),
            Self::QuicNative(data_plane) => data_plane.caps(),
        }
    }

    fn admission_limits(&self) -> BridgeAdmissionLimits {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.admission_limits(),
            Self::FramedAgent(data_plane) => data_plane.admission_limits(),
            Self::QuicNative(data_plane) => data_plane.admission_limits(),
        }
    }

    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_> {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.snapshot(),
            Self::FramedAgent(data_plane) => data_plane.snapshot(),
            Self::QuicNative(data_plane) => data_plane.snapshot(),
        }
    }

    fn spawn_tcp_bridge(
        &self,
        id: tcp_core::FlowId,
        event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ) -> ssh_bridge::FlowBridge {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.spawn_tcp_bridge(id, event_tx),
            Self::FramedAgent(data_plane) => data_plane.spawn_tcp_bridge(id, event_tx),
            Self::QuicNative(data_plane) => data_plane.spawn_tcp_bridge(id, event_tx),
        }
    }

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        match self {
            Self::DirectTcpip(data_plane) => data_plane.query_dns(remote, query, originator_ip),
            Self::FramedAgent(data_plane) => data_plane.query_dns(remote, query, originator_ip),
            Self::QuicNative(data_plane) => data_plane.query_dns(remote, query, originator_ip),
        }
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) {
        match self {
            Self::DirectTcpip(data_plane) => {
                data_plane.spawn_udp_association(key, from_local, events, idle_timeout);
            }
            Self::FramedAgent(data_plane) => {
                data_plane.spawn_udp_association(key, from_local, events, idle_timeout);
            }
            Self::QuicNative(data_plane) => {
                data_plane.spawn_udp_association(key, from_local, events, idle_timeout);
            }
        }
    }
}

fn spawn_direct_tcpip_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ssh: SshSessionPool,
) -> ssh_bridge::FlowBridge {
    let flow = id.key;
    eprintln!(
        "ssh: opening direct-tcpip {}:{} for local {}:{} generation={}",
        flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
    );
    ssh_bridge::spawn_direct_tcpip_bridge_with_opener(id, event_tx, move |id| {
        let ssh = ssh.clone();
        async move { ssh.open_direct_tcpip_for_flow(id).await }
    })
}

pub(crate) fn spawn_agent_tcp_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    agent: ReconnectingAgentBridge,
) -> ssh_bridge::FlowBridge {
    ssh_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let open_started_at = StdInstant::now();
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: id.key.dst_ip,
            destination_port: id.key.dst_port,
            originator_ip: id.key.src_ip,
            originator_port: id.key.src_port,
        };
        let mut stream = match agent.open_tcp_ipv4_optimistic(open).await {
            Ok(stream) => stream,
            Err(err) => {
                let _ = ssh_bridge::send_bridge_event(
                    &event_tx,
                    ssh_bridge::BridgeEvent::Failed {
                        id,
                        phase: ssh_bridge::BridgeFailurePhase::Open,
                        message: format!("failed to open agent stream: {err:#}"),
                    },
                )
                .await;
                return;
            }
        };
        let mut open_reported = false;
        let mut pre_open_local = VecDeque::<Bytes>::new();
        let mut pre_open_retries = 0_usize;
        let open_timeout = tokio::time::sleep(ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT);
        tokio::pin!(open_timeout);

        loop {
            tokio::select! {
                _ = &mut open_timeout, if !open_reported => {
                    let _ = ssh_bridge::send_bridge_event(
                        &event_tx,
                        ssh_bridge::BridgeEvent::Failed {
                            id,
                            phase: ssh_bridge::BridgeFailurePhase::Open,
                            message: format!(
                                "timed out after {}ms waiting for agent stream open confirmation",
                                ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT.as_millis()
                            ),
                        },
                    )
                    .await;
                    break;
                }
                local = local_rx.recv() => {
                    match local {
                        Some(bytes) => {
                            if !open_reported {
                                pre_open_local.push_back(bytes.clone());
                            }
                            match tokio::time::timeout(
                                ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data(bytes.clone()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => {
                                    if !open_reported && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                        pre_open_retries += 1;
                                        match retry_agent_pre_open_stream(
                                            &agent,
                                            open,
                                            stream,
                                            &pre_open_local,
                                        ).await {
                                            Ok(replacement) => {
                                                stream = replacement;
                                                open_timeout.as_mut().reset(
                                                    tokio::time::Instant::now()
                                                        + ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                                );
                                                continue;
                                            }
                                            Err(retry_err) => {
                                                let _ = ssh_bridge::send_bridge_event(
                                                    &event_tx,
                                                    ssh_bridge::BridgeEvent::Failed {
                                                        id,
                                                        phase: ssh_bridge::BridgeFailurePhase::Open,
                                                        message: format!(
                                                            "failed to reopen agent stream after pre-open write failure ({err:#}): {retry_err:#}"
                                                        ),
                                                    },
                                                )
                                                .await;
                                                return;
                                            }
                                        }
                                    }
                                    let phase = if open_reported {
                                        ssh_bridge::BridgeFailurePhase::Write
                                    } else {
                                        ssh_bridge::BridgeFailurePhase::Open
                                    };
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase,
                                            message: format!("failed to write to agent stream: {err:#}"),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                                Err(_) => {
                                    let phase = if open_reported {
                                        ssh_bridge::BridgeFailurePhase::Write
                                    } else {
                                        ssh_bridge::BridgeFailurePhase::Open
                                    };
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase,
                                            message: format!(
                                                "timed out after {}ms writing to agent stream",
                                                ssh_bridge::BRIDGE_WRITE_TIMEOUT.as_millis()
                                            ),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                            }
                        }
                        None => {
                            let _ = stream.send_eof().await;
                            break;
                        }
                    }
                }
                remote = stream.recv() => {
                    match remote {
                        Some(frame) => match frame.kind {
                            agent_proto::AgentFrameKind::Opened => {
                                if !open_reported {
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                        let _ = stream.close().await;
                                        return;
                                    }
                                    open_reported = true;
                                    pre_open_local.clear();
                                }
                            }
                            agent_proto::AgentFrameKind::Data => {
                                if !open_reported {
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                        let _ = stream.close().await;
                                        return;
                                    }
                                    open_reported = true;
                                    pre_open_local.clear();
                                }
                                if !ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::RemoteData {
                                        id,
                                        bytes: frame.payload,
                                    },
                                )
                                .await
                                {
                                    break;
                                }
                            }
                            agent_proto::AgentFrameKind::Eof => {
                                let _ = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::RemoteEof { id },
                                )
                                .await;
                                break;
                            }
                            agent_proto::AgentFrameKind::Close => {
                                if !open_reported {
                                    if pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                        pre_open_retries += 1;
                                        match retry_agent_pre_open_stream(
                                            &agent,
                                            open,
                                            stream,
                                            &pre_open_local,
                                        ).await {
                                            Ok(replacement) => {
                                                stream = replacement;
                                                open_timeout.as_mut().reset(
                                                    tokio::time::Instant::now()
                                                        + ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                                );
                                                continue;
                                            }
                                            Err(err) => {
                                                let _ = ssh_bridge::send_bridge_event(
                                                    &event_tx,
                                                    ssh_bridge::BridgeEvent::Failed {
                                                        id,
                                                        phase: ssh_bridge::BridgeFailurePhase::Open,
                                                        message: format!(
                                                            "failed to reopen agent stream after pre-open close: {err:#}"
                                                        ),
                                                    },
                                                )
                                                .await;
                                                return;
                                            }
                                        }
                                    }
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: ssh_bridge::BridgeFailurePhase::Open,
                                            message: "agent stream closed before open confirmation".to_owned(),
                                        },
                                    )
                                    .await;
                                }
                                break;
                            }
                            agent_proto::AgentFrameKind::Reset => {
                                let message = String::from_utf8_lossy(&frame.payload).to_string();
                                if !open_reported && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                    pre_open_retries += 1;
                                    match retry_agent_pre_open_stream(
                                        &agent,
                                        open,
                                        stream,
                                        &pre_open_local,
                                    ).await {
                                        Ok(replacement) => {
                                            stream = replacement;
                                            open_timeout.as_mut().reset(
                                                tokio::time::Instant::now()
                                                    + ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                            );
                                            continue;
                                        }
                                        Err(err) => {
                                            let _ = ssh_bridge::send_bridge_event(
                                                &event_tx,
                                                ssh_bridge::BridgeEvent::Failed {
                                                    id,
                                                    phase: ssh_bridge::BridgeFailurePhase::Open,
                                                    message: format!(
                                                        "failed to reopen agent stream after pre-open reset ({message}): {err:#}"
                                                    ),
                                                },
                                            )
                                            .await;
                                            return;
                                        }
                                    }
                                }
                                let phase = if open_reported {
                                    ssh_bridge::BridgeFailurePhase::Write
                                } else {
                                    ssh_bridge::BridgeFailurePhase::Open
                                };
                                let _ = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::Failed {
                                        id,
                                        phase,
                                        message: format!("agent stream reset: {message}"),
                                    },
                                )
                                .await;
                                break;
                            }
                            _ => {}
                        },
                        None => {
                            if !open_reported && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                pre_open_retries += 1;
                                match retry_agent_pre_open_stream(
                                    &agent,
                                    open,
                                    stream,
                                    &pre_open_local,
                                ).await {
                                    Ok(replacement) => {
                                        stream = replacement;
                                        open_timeout.as_mut().reset(
                                            tokio::time::Instant::now()
                                                + ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                        );
                                        continue;
                                    }
                                    Err(err) => {
                                        let _ = ssh_bridge::send_bridge_event(
                                            &event_tx,
                                            ssh_bridge::BridgeEvent::Failed {
                                                id,
                                                phase: ssh_bridge::BridgeFailurePhase::Open,
                                                message: format!(
                                                    "failed to reopen agent stream after pre-open EOF: {err:#}"
                                                ),
                                            },
                                        )
                                        .await;
                                        return;
                                    }
                                }
                            }
                            break;
                        },
                    }
                }
            }
        }

        let _ = stream.close().await;
        let _ =
            ssh_bridge::send_bridge_event(&event_tx, ssh_bridge::BridgeEvent::Closed { id }).await;
    })
}

fn spawn_quic_native_tcp_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    bridge: QuicNativeBridge,
) -> ssh_bridge::FlowBridge {
    ssh_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let open_started_at = StdInstant::now();
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: id.key.dst_ip,
            destination_port: id.key.dst_port,
            originator_ip: id.key.src_ip,
            originator_port: id.key.src_port,
        };
        let mut stream = match bridge.open_tcp_ipv4_optimistic(open).await {
            Ok(stream) => stream,
            Err(err) => {
                let _ = ssh_bridge::send_bridge_event(
                    &event_tx,
                    ssh_bridge::BridgeEvent::Failed {
                        id,
                        phase: ssh_bridge::BridgeFailurePhase::Open,
                        message: format!("failed to open native QUIC stream: {err:#}"),
                    },
                )
                .await;
                return;
            }
        };
        let mut open_reported = false;

        loop {
            if !open_reported {
                tokio::select! {
                    local = local_rx.recv() => {
                        match local {
                            Some(bytes) => {
                                match tokio::time::timeout(
                                    ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                    stream.send_data(bytes),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(err)) => {
                                        let _ = ssh_bridge::send_bridge_event(
                                            &event_tx,
                                            ssh_bridge::BridgeEvent::Failed {
                                                id,
                                                phase: ssh_bridge::BridgeFailurePhase::Open,
                                                message: format!("failed to write to pending native QUIC stream: {err:#}"),
                                            },
                                        )
                                        .await;
                                        break;
                                    }
                                    Err(_) => {
                                        let _ = ssh_bridge::send_bridge_event(
                                            &event_tx,
                                            ssh_bridge::BridgeEvent::Failed {
                                                id,
                                                phase: ssh_bridge::BridgeFailurePhase::Open,
                                                message: format!(
                                                    "timed out after {}ms writing to pending native QUIC stream",
                                                    ssh_bridge::BRIDGE_WRITE_TIMEOUT.as_millis()
                                                ),
                                            },
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }
                            None => {
                                let _ = stream.send_eof().await;
                                break;
                            }
                        }
                    }
                    opened = stream.wait_opened() => {
                        match opened {
                            Ok(()) => {
                                if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                    let _ = stream.send_eof().await;
                                    return;
                                }
                                open_reported = true;
                            }
                            Err(err) => {
                                let _ = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::Failed {
                                        id,
                                        phase: ssh_bridge::BridgeFailurePhase::Open,
                                        message: format!("failed to open native QUIC stream: {err:#}"),
                                    },
                                )
                                .await;
                                break;
                            }
                        }
                    }
                }
                continue;
            }

            tokio::select! {
                local = local_rx.recv() => {
                    match local {
                        Some(bytes) => {
                            match tokio::time::timeout(
                                ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data(bytes),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => {
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: ssh_bridge::BridgeFailurePhase::Write,
                                            message: format!("failed to write to native QUIC stream: {err:#}"),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                                Err(_) => {
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: ssh_bridge::BridgeFailurePhase::Write,
                                            message: format!(
                                                "timed out after {}ms writing to native QUIC stream",
                                                ssh_bridge::BRIDGE_WRITE_TIMEOUT.as_millis()
                                            ),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                            }
                        }
                        None => {
                            let _ = stream.send_eof().await;
                            break;
                        }
                    }
                }
                remote = stream.recv_chunk(quic_agent::QUIC_BRIDGE_TCP_CHUNK) => {
                    match remote {
                        Ok(Some(bytes)) => {
                            if !ssh_bridge::send_bridge_event(
                                &event_tx,
                                ssh_bridge::BridgeEvent::RemoteData { id, bytes },
                            )
                            .await
                            {
                                break;
                            }
                        }
                        Ok(None) => {
                            let _ = ssh_bridge::send_bridge_event(
                                &event_tx,
                                ssh_bridge::BridgeEvent::RemoteEof { id },
                            )
                            .await;
                            break;
                        }
                        Err(err) => {
                            let _ = ssh_bridge::send_bridge_event(
                                &event_tx,
                                ssh_bridge::BridgeEvent::Failed {
                                    id,
                                    phase: ssh_bridge::BridgeFailurePhase::Write,
                                    message: format!("failed to read native QUIC stream: {err:#}"),
                                },
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        }

        let _ =
            ssh_bridge::send_bridge_event(&event_tx, ssh_bridge::BridgeEvent::Closed { id }).await;
    })
}

async fn retry_agent_pre_open_stream(
    agent: &ReconnectingAgentBridge,
    open: agent_proto::AgentOpenIpv4,
    old_stream: AgentBridgeStream,
    replay: &VecDeque<Bytes>,
) -> Result<AgentBridgeStream> {
    let _ = old_stream.close().await;
    let stream = agent
        .open_tcp_ipv4_optimistic(open)
        .await
        .context("failed to reopen optimistic agent stream")?;
    for bytes in replay {
        stream
            .send_data(bytes.clone())
            .await
            .context("failed to replay pre-open agent bytes")?;
    }
    Ok(stream)
}

async fn report_agent_stream_opened(
    event_tx: &mpsc::Sender<ssh_bridge::BridgeEvent>,
    id: tcp_core::FlowId,
    open_started_at: StdInstant,
) -> bool {
    let open_ms = open_started_at
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    ssh_bridge::send_bridge_event(event_tx, ssh_bridge::BridgeEvent::Opened { id, open_ms }).await
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

pub(crate) fn spawn_dns_query_on_data_plane(
    data_plane: Arc<dyn DataPlane>,
    remote: Destination,
    request: dns::UdpDnsRequest,
    event_tx: mpsc::Sender<DnsResponseEvent>,
    originator_ip: Ipv4Addr,
) {
    tokio::spawn(async move {
        let result = data_plane
            .query_dns(
                remote,
                Bytes::copy_from_slice(request.payload.as_ref()),
                originator_ip,
            )
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;

    struct FailingAgentConnector;

    impl crate::agent_bridge::AgentBridgeConnector for FailingAgentConnector {
        fn primary_command(&self) -> &str {
            "rustle agent"
        }

        fn connect_initial(
            &self,
            _desired_sessions: usize,
        ) -> crate::agent_bridge::AgentBridgeConnectManyFuture<'_> {
            Box::pin(async { anyhow::bail!("test connector should not create initial transports") })
        }

        fn connect_primary(&self) -> crate::agent_bridge::AgentBridgeConnectFuture<'_> {
            Box::pin(async { anyhow::bail!("test connector should not reconnect primary lanes") })
        }

        fn connect_command<'a>(
            &'a self,
            _agent_command: &'a str,
        ) -> crate::agent_bridge::AgentBridgeConnectFuture<'a> {
            Box::pin(async { anyhow::bail!("test connector should not reconnect command lanes") })
        }
    }

    async fn test_agent_runtime_data_plane() -> (
        RuntimeDataPlane,
        ReconnectingAgentBridge,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent_task = tokio::spawn(crate::agent_runtime::run(
            agent_reader,
            agent_writer,
            crate::agent_runtime::AgentRuntimeConfig::new(crate::DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport = agent_transport::AgentTransport::connect(
            client_reader,
            client_writer,
            crate::DEFAULT_MTU,
        )
        .await
        .expect("connect agent transport");
        let bridge = ReconnectingAgentBridge::new(
            Arc::new(FailingAgentConnector),
            vec![
                crate::agent_bridge::AgentBridgeTransport::detached_for_test(
                    transport,
                    "rustle agent",
                ),
            ],
        );
        let runtime = RuntimeDataPlane::from_bridge_runtime(BridgeRuntime::Agent(bridge.clone()));

        (runtime, bridge, agent_task)
    }

    async fn test_quic_native_runtime() -> (
        RuntimeDataPlane,
        QuicNativeBridge,
        tokio::task::JoinHandle<()>,
    ) {
        let quic_server = quic_agent::start_quic_bridge_server(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
        .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("native QUIC address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });
        let client = quic_agent::connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("connect native QUIC bridge");
        let bridge = QuicNativeBridge::detached(client);
        let runtime =
            RuntimeDataPlane::from_bridge_runtime(BridgeRuntime::QuicNative(bridge.clone()));

        (runtime, bridge, bridge_task)
    }

    #[tokio::test]
    async fn runtime_data_plane_wraps_framed_agent_adapter_contract() {
        let (runtime, bridge, agent_task) = test_agent_runtime_data_plane().await;

        assert_eq!(runtime.label(), "agent");
        assert_eq!(runtime.udp_label(), Some("agent"));
        assert!(runtime.caps().udp_associations);
        assert_eq!(runtime.admission_limits(), BridgeAdmissionLimits::agent());
        let snapshot = runtime.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_desired, 1);
        assert_eq!(snapshot.lanes_available, 1);

        drop(runtime);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn runtime_data_plane_spawns_framed_agent_udp_association() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"agent-runtime-echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: *destination.ip(),
            dst_port: destination.port(),
        };
        let (runtime, bridge, agent_task) = test_agent_runtime_data_plane().await;
        let (to_remote, from_local) =
            mpsc::channel(crate::transport_model::UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        runtime.spawn_udp_association(key, from_local, events, std::time::Duration::from_secs(30));
        to_remote
            .send(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        to_remote
            .send(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            tokio::select! {
                event = response_rx.recv() => {
                    let event = event.expect("association response channel closed");
                    assert_eq!(event.key, key);
                    responses.push(event.payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("framed agent UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for framed agent UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"agent-runtime-echo:one"),
                Bytes::from_static(b"agent-runtime-echo:two")
            ]
        );

        drop(to_remote);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());

        drop(runtime);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn runtime_data_plane_wraps_quic_native_adapter_contract() {
        let (runtime, bridge, bridge_task) = test_quic_native_runtime().await;

        assert_eq!(runtime.label(), "native QUIC");
        assert_eq!(runtime.udp_label(), Some("quic-native"));
        assert!(runtime.caps().udp_associations);
        assert_eq!(runtime.admission_limits(), BridgeAdmissionLimits::agent());
        assert_eq!(
            runtime.snapshot().await,
            DataPlaneRuntimeSnapshot::default()
        );

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
    }

    #[tokio::test]
    async fn runtime_data_plane_spawns_quic_native_udp_association() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"runtime-echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: *destination.ip(),
            dst_port: destination.port(),
        };
        let (runtime, bridge, bridge_task) = test_quic_native_runtime().await;
        let (to_remote, from_local) =
            mpsc::channel(crate::transport_model::UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        runtime.spawn_udp_association(key, from_local, events, std::time::Duration::from_secs(30));
        to_remote
            .send(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        to_remote
            .send(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            tokio::select! {
                event = response_rx.recv() => {
                    let event = event.expect("association response channel closed");
                    assert_eq!(event.key, key);
                    responses.push(event.payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("native QUIC UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for native QUIC UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"runtime-echo:one"),
                Bytes::from_static(b"runtime-echo:two")
            ]
        );

        drop(to_remote);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        udp_server.await.expect("UDP server join");
    }
}
