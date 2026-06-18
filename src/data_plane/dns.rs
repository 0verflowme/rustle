use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use super::DataPlane;
#[cfg(test)]
use crate::agent_transport;
use crate::transport_model::{
    DataPlaneIpv4Open, DataPlaneTcpOpen, DataPlaneTcpOpenMode, Destination, DnsResponseEvent,
};
use crate::{agent_proto, dns};

use super::stream::AgentIoStream;

pub(crate) const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn spawn_dns_query_on_data_plane(
    data_plane: Arc<dyn DataPlane>,
    remote: Destination,
    request: dns::UdpDnsRequest,
    event_tx: mpsc::Sender<DnsResponseEvent>,
    originator_ip: Ipv4Addr,
) {
    tokio::spawn(async move {
        let result = query_dns_on_data_plane(
            data_plane.as_ref(),
            &remote,
            request.payload.as_ref(),
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

pub(crate) async fn query_dns_on_data_plane(
    data_plane: &dyn DataPlane,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    if data_plane.caps().udp_associations {
        if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
            let stream = data_plane
                .open_udp_ipv4(DataPlaneIpv4Open {
                    destination_ip: remote_ip,
                    destination_port: remote.port,
                    originator_ip,
                    originator_port: 0,
                    flow_generation: None,
                })
                .await
                .with_context(|| {
                    format!(
                        "failed to open {} UDP DNS association to {}:{}",
                        data_plane.label(),
                        remote.host,
                        remote.port
                    )
                })?;
            return query_dns_over_agent_udp_stream(stream, query).await;
        }
    }

    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        let stream = data_plane
            .open_tcp(
                DataPlaneTcpOpen::Ipv4(DataPlaneIpv4Open {
                    destination_ip: remote_ip,
                    destination_port: remote.port,
                    originator_ip,
                    originator_port: 0,
                    flow_generation: None,
                }),
                DataPlaneTcpOpenMode::Strict,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to open {} TCP DNS stream to {}:{}",
                    data_plane.label(),
                    remote.host,
                    remote.port
                )
            })?;
        query_dns_over_agent_tcp_stream(stream, query).await
    } else {
        let stream = data_plane
            .open_tcp(
                DataPlaneTcpOpen::Host {
                    destination_host: remote.host.clone(),
                    destination_port: remote.port,
                    originator_ip,
                    originator_port: 0,
                },
                DataPlaneTcpOpenMode::Strict,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to open {} hostname DNS stream to {}:{}",
                    data_plane.label(),
                    remote.host,
                    remote.port
                )
            })?;
        query_dns_over_agent_tcp_stream(stream, query).await
    }
}

#[cfg(test)]
async fn query_dns_over_agent_transport(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    let stream = open_dns_agent_transport_stream(agent, remote, originator_ip).await?;
    query_dns_over_agent_tcp_stream(stream, query).await
}

#[cfg(test)]
async fn query_dns_over_agent_transport_udp(
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

#[cfg(test)]
pub(crate) async fn query_dns_over_agent(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    query_dns_over_agent_transport(agent, remote, query, originator_ip).await
}

#[cfg(test)]
pub(crate) async fn query_dns_over_agent_udp(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
    originator_ip: Ipv4Addr,
) -> Result<Bytes> {
    query_dns_over_agent_transport_udp(agent, remote, query, originator_ip).await
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

        while let Some(frame) = stream
            .recv()
            .await
            .context("failed to read DNS TCP response over agent")?
        {
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
        while let Some(frame) = stream
            .recv()
            .await
            .context("failed to read DNS UDP response over agent")?
        {
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

#[cfg(test)]
mod tests {
    use super::super::test_support::{test_agent_transport, test_quic_native_bridge};
    use super::*;
    use crate::defaults::{DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};
    use crate::dns as dns_proto;
    use crate::supervisor::lifecycle::virtual_dns_ip;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn dns_response_event_keeps_remote_payload_as_bytes() {
        let request = dns_proto::UdpDnsRequest {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            dst_ip: virtual_dns_ip(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX).unwrap(),
            src_port: 49152,
            dst_port: dns_proto::DNS_PORT,
            payload: Bytes::from_static(b"\x12\x34query"),
        };
        let payload = Bytes::from_static(b"\x12\x34answer");
        let ptr = payload.as_ptr();
        let (event_tx, mut event_rx) = mpsc::channel(1);

        assert!(send_dns_response_event(
            &event_tx,
            DnsResponseEvent {
                request: request.clone(),
                result: Ok(payload),
            },
        ));
        let event = event_rx.try_recv().expect("queued DNS response");

        assert_eq!(event.request, request);
        let response = event.result.expect("DNS response payload");
        assert_eq!(response.as_ref(), b"\x12\x34answer");
        assert_eq!(response.as_ptr(), ptr);
    }

    #[tokio::test]
    async fn dns_over_agent_round_trips_tcp_dns_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\x12\x34query");

            let response = b"\x12\x34answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

        let (transport, agent) = test_agent_transport().await;
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response =
            query_dns_over_agent(transport.clone(), &remote, b"\x12\x34query", DEFAULT_TUN_IP)
                .await
                .expect("query DNS over agent");
        assert_eq!(response.as_ref(), b"\x12\x34answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    #[tokio::test]
    async fn dns_over_agent_prefers_udp_for_ipv4_remote() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP DNS socket");
        let destination = socket.local_addr().expect("UDP DNS socket address");
        let dns_server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("recv UDP DNS query");
            assert_eq!(&buf[..len], b"\x12\x34udp-query");
            socket
                .send_to(b"\x12\x34udp-answer", peer)
                .await
                .expect("send UDP DNS response");
        });

        let (transport, agent) = test_agent_transport().await;
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response = query_dns_over_agent_udp(
            transport.clone(),
            &remote,
            b"\x12\x34udp-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over agent UDP");
        assert_eq!(response.as_ref(), b"\x12\x34udp-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS UDP server join");
    }

    #[tokio::test]
    async fn dns_over_quic_native_uses_udp_for_ipv4_remote() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP DNS socket");
        let destination = socket.local_addr().expect("UDP DNS socket address");
        let dns_server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("recv native QUIC UDP DNS query");
            assert_eq!(&buf[..len], b"\x12\x34native-query");
            socket
                .send_to(b"\x12\x34native-answer", peer)
                .await
                .expect("send native QUIC UDP DNS response");
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let data_plane = super::super::QuicNativeDataPlane::new(bridge.clone());

        let response = query_dns_on_data_plane(
            &data_plane,
            &remote,
            b"\x12\x34native-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over native QUIC UDP");
        assert_eq!(response.as_ref(), b"\x12\x34native-answer");

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        dns_server.await.expect("DNS UDP server join");
    }

    #[tokio::test]
    async fn dns_over_agent_accepts_hostname_remote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\xab\xcdname-query");

            let response = b"\xab\xcdname-answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

        let (transport, agent) = test_agent_transport().await;
        let remote = Destination {
            host: "localhost".to_owned(),
            port: destination.port(),
        };

        let response = query_dns_over_agent(
            transport.clone(),
            &remote,
            b"\xab\xcdname-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over agent hostname");
        assert_eq!(response.as_ref(), b"\xab\xcdname-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    #[tokio::test]
    async fn dns_over_quic_native_accepts_hostname_remote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("accept native QUIC TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read native QUIC TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read native QUIC TCP DNS query");
            assert_eq!(query, b"\xab\xcdnative-name-query");

            let response = b"\xab\xcdnative-name-answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write native QUIC TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write native QUIC TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });
        let remote = Destination {
            host: "localhost".to_owned(),
            port: destination.port(),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let data_plane = super::super::QuicNativeDataPlane::new(bridge.clone());

        let response = query_dns_on_data_plane(
            &data_plane,
            &remote,
            b"\xab\xcdnative-name-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over native QUIC hostname");
        assert_eq!(response.as_ref(), b"\xab\xcdnative-name-answer");

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        dns_server.await.expect("DNS server join");
    }
}
