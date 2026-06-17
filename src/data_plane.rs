use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_bridge::{AgentBridgeSnapshot, QuicNativeBridge, ReconnectingAgentBridge};
#[cfg(test)]
use crate::agent_transport;
#[cfg(test)]
use crate::quic_agent;
use crate::ssh_control::SshSessionPool;
use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneCaps, DataPlaneReconnectSnapshot, DataPlaneRuntimeSnapshot,
    Destination, UdpAssociationEvents, UdpFlowKey,
};
use crate::{ssh_bridge, tcp_core};

mod dns;
mod stream;
mod tcp;
#[cfg(test)]
mod test_support;
mod udp;

pub(crate) use dns::spawn_dns_query_on_data_plane;
pub(crate) use tcp::spawn_agent_tcp_bridge;
use tcp::{spawn_direct_tcpip_bridge, spawn_quic_native_tcp_bridge};
use udp::{
    spawn_agent_udp_association_with_idle_timeout,
    spawn_quic_native_udp_association_with_idle_timeout,
};

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
        dns::query_dns_over_ssh_future(self.ssh.clone(), remote, query)
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
        dns::query_dns_over_agent_future(self.agent.clone(), remote, query, originator_ip)
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) {
        spawn_agent_udp_association_with_idle_timeout(
            self.agent.clone(),
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
        let bridge = self.bridge.clone();
        Box::pin(async move { data_plane_runtime_snapshot_from_quic_native(bridge.snapshot()) })
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
        dns::query_dns_over_quic_native_future(self.bridge.clone(), remote, query, originator_ip)
    }

    fn spawn_udp_association(
        &self,
        key: UdpFlowKey,
        from_local: mpsc::Receiver<Bytes>,
        events: UdpAssociationEvents,
        idle_timeout: Duration,
    ) {
        spawn_quic_native_udp_association_with_idle_timeout(
            self.bridge.clone(),
            key,
            from_local,
            events,
            idle_timeout,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

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

    async fn test_agent_data_plane() -> (
        FramedAgentDataPlane,
        ReconnectingAgentBridge,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent_task = tokio::spawn(crate::agent_runtime::run(
            agent_reader,
            agent_writer,
            crate::agent_runtime::AgentRuntimeConfig::new(crate::defaults::DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport = agent_transport::AgentTransport::connect(
            client_reader,
            client_writer,
            crate::defaults::DEFAULT_MTU,
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
        let data_plane = FramedAgentDataPlane::new(bridge.clone());

        (data_plane, bridge, agent_task)
    }

    async fn test_quic_native_runtime() -> (
        QuicNativeDataPlane,
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
        let data_plane = QuicNativeDataPlane::new(bridge.clone());

        (data_plane, bridge, bridge_task)
    }

    #[tokio::test]
    async fn framed_agent_data_plane_contract_matches_agent_adapter() {
        let (data_plane, bridge, agent_task) = test_agent_data_plane().await;

        assert_eq!(data_plane.label(), "agent");
        assert_eq!(data_plane.udp_label(), Some("agent"));
        assert!(data_plane.caps().udp_associations);
        assert_eq!(
            data_plane.admission_limits(),
            BridgeAdmissionLimits::agent()
        );
        let snapshot = data_plane.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_desired, 1);
        assert_eq!(snapshot.lanes_available, 1);

        drop(data_plane);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn framed_agent_data_plane_spawns_udp_association() {
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
        let (data_plane, bridge, agent_task) = test_agent_data_plane().await;
        let (to_remote, from_local) =
            mpsc::channel(crate::transport_model::UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        data_plane.spawn_udp_association(
            key,
            from_local,
            events,
            std::time::Duration::from_secs(30),
        );
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

        drop(data_plane);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn quic_native_data_plane_contract_matches_native_adapter() {
        let (data_plane, bridge, bridge_task) = test_quic_native_runtime().await;

        assert_eq!(data_plane.label(), "native QUIC");
        assert_eq!(data_plane.udp_label(), Some("quic-native"));
        assert!(data_plane.caps().udp_associations);
        assert_eq!(
            data_plane.admission_limits(),
            BridgeAdmissionLimits::agent()
        );
        assert_eq!(
            data_plane.snapshot().await,
            DataPlaneRuntimeSnapshot {
                lanes_total: 1,
                lanes_desired: 1,
                lanes_available: 1,
                ..DataPlaneRuntimeSnapshot::default()
            }
        );

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
    }

    #[tokio::test]
    async fn quic_native_data_plane_spawns_udp_association() {
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
        let (data_plane, bridge, bridge_task) = test_quic_native_runtime().await;
        let (to_remote, from_local) =
            mpsc::channel(crate::transport_model::UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        data_plane.spawn_udp_association(
            key,
            from_local,
            events,
            std::time::Duration::from_secs(30),
        );
        eventually_assert_quic_native_active_streams(&data_plane, 1).await;
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
        eventually_assert_quic_native_active_streams(&data_plane, 0).await;

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        udp_server.await.expect("UDP server join");
    }

    async fn eventually_assert_quic_native_active_streams(
        data_plane: &QuicNativeDataPlane,
        expected: usize,
    ) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let snapshot = data_plane.snapshot().await;
            if snapshot.active_streams == expected {
                assert_eq!(snapshot.lanes_total, 1);
                assert_eq!(snapshot.lanes_desired, 1);
                assert_eq!(snapshot.lanes_available, 1);
                assert_eq!(snapshot.max_lane_load, expected);
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for quic-native active_streams={expected}, last snapshot={snapshot:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
