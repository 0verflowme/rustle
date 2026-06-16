use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_proto;
#[cfg(test)]
use crate::agent_transport;
use crate::bridge_runtime::UdpAssociationTransport;
#[cfg(test)]
use crate::dns;
use crate::transport_model::{UdpAssociationEvents, UdpFlowKey};

use super::stream::AgentIoStream;

#[cfg(test)]
pub(crate) const UDP_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);

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
