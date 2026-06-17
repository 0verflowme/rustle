use std::future::Future;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_bridge::{QuicNativeBridge, ReconnectingAgentBridge};
use crate::agent_proto;
#[cfg(test)]
use crate::agent_transport;
#[cfg(test)]
use crate::dns;
use crate::transport_model::{DataPlaneIpv4Open, UdpAssociationEvents, UdpFlowKey};

use super::stream::AgentIoStream;

#[cfg(test)]
pub(crate) const UDP_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn spawn_udp_association_with_idle_timeout<Fut>(
    open_stream: Fut,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) where
    Fut: Future<Output = Result<AgentIoStream>> + Send + 'static,
{
    tokio::spawn(async move {
        let error = run_udp_association(open_stream, key, from_local, events.clone(), idle_timeout)
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

async fn run_udp_association<Fut>(
    open_stream: Fut,
    key: UdpFlowKey,
    mut from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()>
where
    Fut: Future<Output = Result<AgentIoStream>>,
{
    let stream = open_stream.await?;
    run_udp_association_stream(stream, key, &mut from_local, events, idle_timeout).await
}

pub(super) fn udp_open_request(key: UdpFlowKey) -> DataPlaneIpv4Open {
    key.into_open_request()
}

pub(super) async fn open_agent_udp_association(
    agent: ReconnectingAgentBridge,
    open: DataPlaneIpv4Open,
) -> Result<AgentIoStream> {
    agent
        .open_udp_ipv4(open.into_agent_open())
        .await
        .map(AgentIoStream::Bridge)
        .with_context(|| {
            format!(
                "failed to open agent UDP association to {}:{}",
                open.destination_ip, open.destination_port
            )
        })
}

pub(super) async fn open_quic_native_udp_association(
    bridge: QuicNativeBridge,
    open: DataPlaneIpv4Open,
) -> Result<AgentIoStream> {
    bridge
        .open_udp_ipv4(open.into_agent_open())
        .await
        .map(AgentIoStream::QuicNativeUdp)
        .with_context(|| {
            format!(
                "failed to open native QUIC UDP association to {}:{}",
                open.destination_ip, open.destination_port
            )
        })
}

#[cfg(test)]
async fn run_quic_native_udp_association(
    bridge: QuicNativeBridge,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    run_udp_association(
        open_quic_native_udp_association(bridge, udp_open_request(key)),
        key,
        from_local,
        events,
        idle_timeout,
    )
    .await
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
                let Some(frame) = maybe_frame.with_context(|| {
                    format!(
                        "failed to read UDP datagram over agent from {}:{}",
                        key.dst_ip, key.dst_port
                    )
                })? else {
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
    use super::super::test_support::{
        detached_reconnecting_agent_bridge, test_agent_transport, test_quic_native_bridge,
    };
    use super::*;
    use crate::defaults::DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS;
    use crate::dns as dns_proto;
    use crate::packet_engine::AdmissionCounter;
    use crate::transport_model::{UdpAssociation, UDP_DATAGRAMS_PER_ASSOCIATION};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};

    const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
        Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);

    #[tokio::test]
    async fn udp_over_agent_round_trips_datagram() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
            assert_eq!(&buf[..len], b"ping");
            socket
                .send_to(b"pong", peer)
                .await
                .expect("write UDP response");
        });

        let (transport, agent) = test_agent_transport().await;
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };

        let response = query_udp_over_agent(
            transport.clone(),
            &dns_proto::UdpPacket {
                src_ip: Ipv4Addr::new(10, 255, 255, 1),
                dst_ip: *destination.ip(),
                src_port: 49152,
                dst_port: destination.port(),
                payload: Bytes::from_static(b"ping"),
            },
        )
        .await
        .expect("query UDP over agent");
        assert_eq!(response, b"pong");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_reuses_agent_stream_for_multiple_datagrams() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });

        let (transport, agent) = test_agent_transport().await;
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

        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let association = tokio::spawn(run_udp_association_transport(
            transport.clone(),
            key,
            from_local,
            events,
            UDP_ASSOCIATION_IDLE_TIMEOUT,
        ));

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
                    let event_key = event.key;
                    let payload = event.payload;
                    assert_eq!(event_key, key);
                    responses.push(payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"echo:one"),
                Bytes::from_static(b"echo:two")
            ]
        );

        drop(to_remote);
        tokio::time::timeout(std::time::Duration::from_secs(1), association)
            .await
            .expect("association exits")
            .expect("association join")
            .expect("association run");
        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_reuses_quic_native_stream_for_multiple_datagrams() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"native-echo:".to_vec();
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
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let association = tokio::spawn(run_quic_native_udp_association(
            bridge.clone(),
            key,
            from_local,
            events,
            UDP_ASSOCIATION_IDLE_TIMEOUT,
        ));

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
                Bytes::from_static(b"native-echo:one"),
                Bytes::from_static(b"native-echo:two")
            ]
        );

        drop(to_remote);
        tokio::time::timeout(std::time::Duration::from_secs(1), association)
            .await
            .expect("association exits")
            .expect("association join")
            .expect("association run");
        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_idle_timeout_emits_close_for_accounting() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = detached_reconnecting_agent_bridge(transport);
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(127, 0, 0, 1),
            dst_port: 5353,
        };
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = AdmissionCounter::new(1);
        assert!(association_limit.try_admit());

        spawn_udp_association_with_idle_timeout(
            open_agent_udp_association(bridge.clone(), udp_open_request(key)),
            key,
            from_local,
            events,
            std::time::Duration::from_millis(10),
        );

        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("idle association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
        assert!(response_rx.try_recv().is_err());

        associations.remove(&closed.key);
        association_limit.complete();
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert!(associations.is_empty());

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn quic_native_udp_association_idle_timeout_emits_close_for_accounting() {
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: Ipv4Addr::LOCALHOST,
            dst_port: 5353,
        };
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = AdmissionCounter::new(1);
        assert!(association_limit.try_admit());

        spawn_udp_association_with_idle_timeout(
            open_quic_native_udp_association(bridge.clone(), udp_open_request(key)),
            key,
            from_local,
            events,
            std::time::Duration::from_millis(10),
        );

        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("idle association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
        assert!(response_rx.try_recv().is_err());

        associations.remove(&closed.key);
        association_limit.complete();
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert!(associations.is_empty());

        drop(bridge);
        bridge_task.await.expect("native bridge task");
    }
}
