use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_bridge::{AgentBridgeSnapshot, QuicNativeBridge, ReconnectingAgentBridge};
#[cfg(test)]
use crate::agent_transport;
#[cfg(test)]
use crate::quic_agent;
use crate::ssh_control::SshSessionPool;
use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneCaps, DataPlaneIpv4Open, DataPlaneReconnectSnapshot,
    DataPlaneRuntimeSnapshot, DataPlaneTcpOpen, DataPlaneTcpOpenMode, Destination,
    UdpAssociationEvents, UdpFlowKey,
};
use crate::{ssh_bridge, tcp_core};

mod dns;
mod stream;
mod tcp;
#[cfg(test)]
mod test_support;
mod udp;

pub(crate) use dns::spawn_dns_query_on_data_plane;
use stream::AgentIoStream;
use tcp::spawn_data_plane_tcp_bridge_with_open;

pub(crate) type DataPlaneSnapshotFuture<'a> =
    Pin<Box<dyn Future<Output = DataPlaneRuntimeSnapshot> + Send + 'a>>;
pub(crate) type DataPlaneDnsFuture<'a> = Pin<Box<dyn Future<Output = Result<Bytes>> + Send + 'a>>;
pub(crate) type OpenTcpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentIoStream>> + Send + 'a>>;
pub(crate) type OpenUdpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentIoStream>> + Send + 'a>>;

pub(crate) trait DataPlane: Send + Sync {
    fn label(&self) -> &'static str;
    fn udp_label(&self) -> Option<&'static str>;
    fn caps(&self) -> DataPlaneCaps;
    fn admission_limits(&self) -> BridgeAdmissionLimits;
    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_>;
    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_>;
    fn open_tcp(
        &self,
        open: DataPlaneTcpOpen,
        mode: DataPlaneTcpOpenMode,
    ) -> OpenTcpFuture<'static>;
    fn open_udp_ipv4(&self, open: DataPlaneIpv4Open) -> OpenUdpFuture<'static>;
}

pub(crate) fn spawn_tcp_bridge_on_data_plane(
    data_plane: Arc<dyn DataPlane>,
    id: tcp_core::FlowId,
    ready_wait_ms: u64,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
) -> ssh_bridge::FlowBridge {
    let flow = id.key;
    let label = data_plane.udp_label().unwrap_or_else(|| data_plane.label());
    if data_plane.caps().udp_associations {
        eprintln!(
            "{label}: opening stream {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
    } else {
        eprintln!(
            "ssh: opening direct-tcpip {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
    }
    let open = DataPlaneIpv4Open {
        destination_ip: flow.dst_ip,
        destination_port: flow.dst_port,
        originator_ip: flow.src_ip,
        originator_port: flow.src_port,
        flow_generation: Some(id.generation),
    };
    spawn_data_plane_tcp_bridge_with_open(
        id,
        event_tx,
        ready_wait_ms,
        label,
        data_plane.open_tcp(
            DataPlaneTcpOpen::Ipv4(open),
            DataPlaneTcpOpenMode::Optimistic,
        ),
    )
}

pub(crate) fn spawn_udp_association(
    open_stream: OpenUdpFuture<'static>,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) {
    udp::spawn_udp_association_with_idle_timeout(
        open_stream,
        key,
        from_local,
        events,
        idle_timeout,
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

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        _originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        dns::query_dns_over_ssh_future(self.ssh.clone(), remote, query)
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
                        ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
                        ssh.open_direct_tcpip_for_flow(id),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "timed out after {}ms opening direct-tcpip stream to {destination_label}",
                            ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
                        )
                    })??
                }
                DataPlaneTcpOpen::Ipv4(open) => tokio::time::timeout(
                    ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
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
                        ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
                    )
                })??,
                DataPlaneTcpOpen::Host {
                    destination_host,
                    destination_port,
                    originator_ip,
                    originator_port,
                } => tokio::time::timeout(
                    ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT,
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
                        ssh_bridge::DIRECT_TCPIP_OPEN_TIMEOUT.as_millis()
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

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        dns::query_dns_over_stream_data_plane_future(self.clone(), remote, query, originator_ip)
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
                        .open_tcp_host(crate::agent_proto::AgentOpenHost {
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

    fn query_dns(
        &self,
        remote: Destination,
        query: Bytes,
        originator_ip: Ipv4Addr,
    ) -> DataPlaneDnsFuture<'_> {
        dns::query_dns_over_stream_data_plane_future(self.clone(), remote, query, originator_ip)
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
                    .open_tcp_host(crate::agent_proto::AgentOpenHost {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use super::*;
    use crate::agent_proto;

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

    fn data_plane_ipv4_open(destination: SocketAddr) -> DataPlaneIpv4Open {
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        DataPlaneIpv4Open {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
            flow_generation: None,
        }
    }

    async fn recv_data_payload(stream: &mut AgentIoStream) -> Bytes {
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("timed out waiting for data frame")
                .expect("read data frame")
                .expect("stream closed before data frame");
            if frame.kind == agent_proto::AgentFrameKind::Data {
                return frame.payload;
            }
        }
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

        spawn_udp_association(
            data_plane.open_udp_ipv4(key.into_open_request()),
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
    async fn framed_agent_data_plane_open_udp_ipv4_future_is_spawnable() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
            assert_eq!(&buf[..len], b"trait-udp");
            socket
                .send_to(b"trait-udp-ok", peer)
                .await
                .expect("write UDP response");
        });
        let (data_plane, bridge, agent_task) = test_agent_data_plane().await;
        let data_plane: Arc<dyn DataPlane> = Arc::new(data_plane);

        let open_task = tokio::spawn(data_plane.open_udp_ipv4(data_plane_ipv4_open(destination)));
        let mut stream = open_task
            .await
            .expect("open task joins")
            .expect("open UDP stream");
        stream
            .send_data(Bytes::from_static(b"trait-udp"))
            .await
            .expect("write UDP datagram");
        assert_eq!(
            recv_data_payload(&mut stream).await,
            Bytes::from_static(b"trait-udp-ok")
        );
        stream.close().await.expect("close UDP stream");

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
    async fn framed_agent_data_plane_open_tcp_ipv4_optimistic_round_trips() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let tcp_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut buf = [0_u8; 9];
            socket.read_exact(&mut buf).await.expect("read TCP request");
            assert_eq!(&buf, b"trait-tcp");
            socket
                .write_all(b"trait-tcp-ok")
                .await
                .expect("write TCP response");
        });
        let (data_plane, bridge, agent_task) = test_agent_data_plane().await;
        let data_plane: Arc<dyn DataPlane> = Arc::new(data_plane);

        let mut stream = data_plane
            .open_tcp(
                DataPlaneTcpOpen::Ipv4(data_plane_ipv4_open(destination)),
                DataPlaneTcpOpenMode::Optimistic,
            )
            .await
            .expect("open optimistic TCP stream");
        stream
            .send_data(Bytes::from_static(b"trait-tcp"))
            .await
            .expect("write TCP request");
        assert_eq!(
            recv_data_payload(&mut stream).await,
            Bytes::from_static(b"trait-tcp-ok")
        );
        stream.close().await.expect("close TCP stream");

        drop(data_plane);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        tcp_server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn framed_agent_data_plane_open_tcp_host_strict_round_trips() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let tcp_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut buf = [0_u8; 10];
            socket.read_exact(&mut buf).await.expect("read TCP request");
            assert_eq!(&buf, b"trait-host");
            socket
                .write_all(b"trait-host-ok")
                .await
                .expect("write TCP response");
        });
        let (data_plane, bridge, agent_task) = test_agent_data_plane().await;
        let data_plane: Arc<dyn DataPlane> = Arc::new(data_plane);

        let mut stream = data_plane
            .open_tcp(
                DataPlaneTcpOpen::Host {
                    destination_host: "localhost".to_owned(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                },
                DataPlaneTcpOpenMode::Strict,
            )
            .await
            .expect("open strict hostname TCP stream");
        stream
            .send_data(Bytes::from_static(b"trait-host"))
            .await
            .expect("write TCP request");
        assert_eq!(
            recv_data_payload(&mut stream).await,
            Bytes::from_static(b"trait-host-ok")
        );
        stream.close().await.expect("close TCP stream");

        drop(data_plane);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent_task)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        tcp_server.await.expect("TCP server join");
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
    async fn quic_native_data_plane_open_tcp_host_strict_round_trips() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let tcp_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut buf = [0_u8; 16];
            socket
                .read_exact(&mut buf)
                .await
                .expect("read native TCP request");
            assert_eq!(&buf, b"native-host-open");
            socket
                .write_all(b"native-host-ok")
                .await
                .expect("write native TCP response");
        });
        let (data_plane, bridge, bridge_task) = test_quic_native_runtime().await;
        let data_plane_snapshot = data_plane.clone();
        let data_plane: Arc<dyn DataPlane> = Arc::new(data_plane);

        let mut stream = data_plane
            .open_tcp(
                DataPlaneTcpOpen::Host {
                    destination_host: "localhost".to_owned(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                },
                DataPlaneTcpOpenMode::Strict,
            )
            .await
            .expect("open native strict hostname TCP stream");
        stream
            .send_data(Bytes::from_static(b"native-host-open"))
            .await
            .expect("write native TCP request");
        assert_eq!(
            recv_data_payload(&mut stream).await,
            Bytes::from_static(b"native-host-ok")
        );
        stream.close().await.expect("close native TCP stream");

        drop(data_plane);
        tcp_server.await.expect("TCP server join");
        eventually_assert_quic_native_active_streams(&data_plane_snapshot, 0).await;
        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
    }

    #[tokio::test]
    async fn quic_native_data_plane_spawn_tcp_bridge_round_trips() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let tcp_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut buf = [0_u8; 10];
            socket.read_exact(&mut buf).await.expect("read TCP request");
            assert_eq!(&buf, b"bridge-tcp");
            socket
                .write_all(b"bridge-tcp-ok")
                .await
                .expect("write TCP response");
            socket.shutdown().await.expect("shutdown TCP target");
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let (data_plane, bridge, bridge_task) = test_quic_native_runtime().await;
        let id = crate::tcp_core::FlowId::new(
            crate::tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 1),
                49152,
                *destination.ip(),
                destination.port(),
            ),
            1,
        );
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let flow = spawn_tcp_bridge_on_data_plane(Arc::new(data_plane.clone()), id, 0, event_tx);

        assert!(
            flow.try_send_local_data(Bytes::from_static(b"bridge-tcp"))
                .expect("queue local TCP data"),
            "bridge should accept local TCP data"
        );

        let mut opened = false;
        let mut response = Vec::new();
        while !opened || response.len() < b"bridge-tcp-ok".len() {
            let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
                .await
                .expect("timed out waiting for bridge event")
                .expect("bridge event channel closed");
            match event {
                crate::ssh_bridge::BridgeEvent::Opened { id: event_id, .. } => {
                    assert_eq!(event_id, id);
                    opened = true;
                }
                crate::ssh_bridge::BridgeEvent::RemoteData {
                    id: event_id,
                    bytes,
                } => {
                    assert_eq!(event_id, id);
                    response.extend_from_slice(bytes.as_ref());
                }
                crate::ssh_bridge::BridgeEvent::Failed { message, .. } => {
                    panic!("native QUIC TCP bridge failed: {message}");
                }
                _ => {}
            }
        }
        assert_eq!(response.as_slice(), b"bridge-tcp-ok");

        drop(flow);
        tcp_server.await.expect("TCP server join");
        eventually_assert_quic_native_active_streams(&data_plane, 0).await;
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

        spawn_udp_association(
            data_plane.open_udp_ipv4(key.into_open_request()),
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
