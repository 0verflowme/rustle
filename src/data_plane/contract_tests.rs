use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use super::stream::AgentIoStream;
use super::test_support::{
    detached_reconnecting_agent_bridge, test_agent_transport, test_quic_native_bridge,
};
use super::*;
use crate::agent_bridge::{QuicNativeBridge, ReconnectingAgentBridge};
use crate::agent_proto;

async fn test_agent_data_plane() -> (
    FramedAgentDataPlane,
    ReconnectingAgentBridge,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (transport, agent_task) = test_agent_transport().await;
    let bridge = detached_reconnecting_agent_bridge(transport);
    let data_plane = FramedAgentDataPlane::new(bridge.clone());

    (data_plane, bridge, agent_task)
}

async fn test_quic_native_runtime() -> (
    QuicNativeDataPlane,
    QuicNativeBridge,
    tokio::task::JoinHandle<()>,
) {
    let (bridge, bridge_task) = test_quic_native_bridge().await;
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
    let flow = spawn_tcp_bridge_on_data_plane(
        Arc::new(data_plane.clone()),
        id,
        0,
        event_tx,
        crate::ssh_bridge::BridgeEventAccounting::new(),
    );

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
