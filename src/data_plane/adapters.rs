use anyhow::bail;

use crate::agent_bridge::{AgentBridgeSnapshot, QuicNativeBridge, ReconnectingAgentBridge};
use crate::ssh_control::SshSessionPool;
use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneCaps, DataPlaneIpv4Open, DataPlaneReconnectSnapshot,
    DataPlaneRuntimeSnapshot, DataPlaneTcpOpen, DataPlaneTcpOpenMode,
};
use crate::{agent_proto, flow_bridge, tcp_core};

use super::stream::AgentIoStream;
use super::{udp, DataPlane, DataPlaneSnapshotFuture, OpenTcpFuture, OpenUdpFuture};

#[derive(Clone)]
pub(crate) struct DirectTcpipDataPlane {
    ssh: SshSessionPool,
}

impl DirectTcpipDataPlane {
    pub(crate) fn new(ssh: SshSessionPool) -> Self {
        Self { ssh }
    }
}

#[derive(Clone)]
pub(crate) struct FramedAgentDataPlane {
    agent: ReconnectingAgentBridge,
}

impl FramedAgentDataPlane {
    pub(crate) fn new(agent: ReconnectingAgentBridge) -> Self {
        Self { agent }
    }
}

#[derive(Clone)]
pub(crate) struct QuicNativeDataPlane {
    bridge: QuicNativeBridge,
}

impl QuicNativeDataPlane {
    pub(crate) fn new(bridge: QuicNativeBridge) -> Self {
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
        writer_queued_frames: snapshot.writer_queued_frames,
        writer_queued_bytes: snapshot.writer_queued_bytes,
        writer_queued_frames_max: snapshot.writer_queued_frames_max,
        writer_queued_bytes_max: snapshot.writer_queued_bytes_max,
        writer_bursts: snapshot.writer_bursts,
        writer_burst_frames: snapshot.writer_burst_frames,
        writer_burst_bytes: snapshot.writer_burst_bytes,
        writer_burst_frames_max: snapshot.writer_burst_frames_max,
        writer_burst_bytes_max: snapshot.writer_burst_bytes_max,
        writer_enqueue_to_write_us: snapshot.writer_enqueue_to_write_us,
        writer_enqueue_to_write_max_us: snapshot.writer_enqueue_to_write_max_us,
        writer_enqueue_to_write_samples: snapshot.writer_enqueue_to_write_samples,
        writer_write_us: snapshot.writer_write_us,
        writer_write_max_us: snapshot.writer_write_max_us,
        writer_flush_us: snapshot.writer_flush_us,
        writer_flush_max_us: snapshot.writer_flush_max_us,
    }
}

fn data_plane_runtime_snapshot_from_quic_native(
    snapshot: crate::agent_bridge::QuicNativeBridgeSnapshot,
) -> DataPlaneRuntimeSnapshot {
    DataPlaneRuntimeSnapshot {
        lanes_total: 1,
        lanes_desired: 1,
        lanes_available: 1,
        active_streams: snapshot.active_streams,
        max_lane_load: snapshot.active_streams,
        ..DataPlaneRuntimeSnapshot::default()
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

    fn open_tcp(
        &self,
        open: DataPlaneTcpOpen,
        _mode: DataPlaneTcpOpenMode,
    ) -> OpenTcpFuture<'static> {
        let ssh = self.ssh.clone();
        Box::pin(async move {
            let destination_label = open.destination_label();
            let channel = match open {
                DataPlaneTcpOpen::Ipv4(open) if open.flow_generation.is_some() => {
                    let flow = tcp_core::FlowKey::tcp(
                        open.originator_ip,
                        open.originator_port,
                        open.destination_ip,
                        open.destination_port,
                    );
                    let id = tcp_core::FlowId::new(
                        flow,
                        open.flow_generation.expect("checked flow generation"),
                    );
                    tokio::time::timeout(
                        flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
                        ssh.open_direct_tcpip_for_flow(id),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "timed out after {}ms opening direct-tcpip stream to {destination_label}",
                            flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
                        )
                    })??
                }
                DataPlaneTcpOpen::Ipv4(open) => tokio::time::timeout(
                    flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
                    ssh.open_background_direct_tcpip(
                        open.destination_ip.to_string(),
                        u32::from(open.destination_port),
                        open.originator_ip.to_string(),
                        u32::from(open.originator_port),
                    ),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "timed out after {}ms opening direct-tcpip stream to {destination_label}",
                        flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
                    )
                })??,
                DataPlaneTcpOpen::Host {
                    destination_host,
                    destination_port,
                    originator_ip,
                    originator_port,
                } => tokio::time::timeout(
                    flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
                    ssh.open_background_direct_tcpip(
                        destination_host,
                        u32::from(destination_port),
                        originator_ip.to_string(),
                        u32::from(originator_port),
                    ),
                )
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "timed out after {}ms opening direct-tcpip stream to {destination_label}",
                        flow_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
                    )
                })??,
            };
            Ok(AgentIoStream::direct_tcpip(channel))
        })
    }

    fn open_udp_ipv4(&self, open: DataPlaneIpv4Open) -> OpenUdpFuture<'static> {
        Box::pin(async move {
            bail!(
                "data plane does not support generic UDP associations to {}:{}",
                open.destination_ip,
                open.destination_port
            )
        })
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

    fn open_tcp(
        &self,
        open: DataPlaneTcpOpen,
        mode: DataPlaneTcpOpenMode,
    ) -> OpenTcpFuture<'static> {
        let agent = self.agent.clone();
        Box::pin(async move {
            match open {
                DataPlaneTcpOpen::Ipv4(open) => {
                    let stream = match mode {
                        DataPlaneTcpOpenMode::Strict => {
                            agent.open_tcp_ipv4(open.into_agent_open()).await?
                        }
                        DataPlaneTcpOpenMode::Optimistic => {
                            agent
                                .open_tcp_ipv4_optimistic(open.into_agent_open())
                                .await?
                        }
                    };
                    let retry_agent =
                        (mode == DataPlaneTcpOpenMode::Optimistic).then(|| agent.clone());
                    Ok(AgentIoStream::agent_bridge_with_retry(stream, retry_agent))
                }
                DataPlaneTcpOpen::Host {
                    destination_host,
                    destination_port,
                    originator_ip,
                    originator_port,
                } => {
                    let stream = agent
                        .open_tcp_host(agent_proto::AgentOpenHost {
                            destination_host,
                            destination_port,
                            originator_ip,
                            originator_port,
                        })
                        .await?;
                    Ok(AgentIoStream::agent_bridge(stream))
                }
            }
        })
    }

    fn open_udp_ipv4(&self, open: DataPlaneIpv4Open) -> OpenUdpFuture<'static> {
        Box::pin(udp::open_agent_udp_association(self.agent.clone(), open))
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
        let bridge = self.bridge.clone();
        Box::pin(async move { data_plane_runtime_snapshot_from_quic_native(bridge.snapshot()) })
    }

    fn open_tcp(
        &self,
        open: DataPlaneTcpOpen,
        mode: DataPlaneTcpOpenMode,
    ) -> OpenTcpFuture<'static> {
        let bridge = self.bridge.clone();
        Box::pin(async move {
            match open {
                DataPlaneTcpOpen::Ipv4(open) => {
                    let mut stream = bridge
                        .open_tcp_ipv4_optimistic(open.into_agent_open())
                        .await?;
                    match mode {
                        DataPlaneTcpOpenMode::Strict => {
                            stream.wait_opened().await?;
                            Ok(AgentIoStream::quic_native_tcp_opened(stream))
                        }
                        DataPlaneTcpOpenMode::Optimistic => {
                            Ok(AgentIoStream::quic_native_tcp(stream))
                        }
                    }
                }
                DataPlaneTcpOpen::Host {
                    destination_host,
                    destination_port,
                    originator_ip,
                    originator_port,
                } => bridge
                    .open_tcp_host(agent_proto::AgentOpenHost {
                        destination_host,
                        destination_port,
                        originator_ip,
                        originator_port,
                    })
                    .await
                    .map(AgentIoStream::quic_native_tcp_opened),
            }
        })
    }

    fn open_udp_ipv4(&self, open: DataPlaneIpv4Open) -> OpenUdpFuture<'static> {
        Box::pin(udp::open_quic_native_udp_association(
            self.bridge.clone(),
            open,
        ))
    }
}
