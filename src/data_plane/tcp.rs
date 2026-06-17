use std::collections::VecDeque;
use std::future::Future;
use std::time::Instant as StdInstant;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_bridge::{AgentBridgeStream, QuicNativeBridge, ReconnectingAgentBridge};
use crate::hotpath_trace::TcpFlowTrace;
use crate::ssh_control::SshSessionPool;
use crate::transport_model::DataPlaneIpv4Open;
use crate::{agent_proto, quic_agent, ssh_bridge, tcp_core};

use super::stream::AgentIoStream;

const AGENT_PRE_OPEN_RETRY_LIMIT: usize = 1;

pub(super) fn spawn_direct_tcpip_bridge(
    id: tcp_core::FlowId,
    _ready_wait_ms: u64,
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

#[cfg(test)]
pub(crate) fn spawn_agent_tcp_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    agent: ReconnectingAgentBridge,
) -> ssh_bridge::FlowBridge {
    let open = tcp_open_request(id);
    spawn_agent_tcp_bridge_with_open(
        id,
        event_tx,
        0,
        agent.clone(),
        open_agent_tcp_stream(agent, open),
    )
}

pub(super) fn spawn_agent_tcp_bridge_with_open<Fut>(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ready_wait_ms: u64,
    agent: ReconnectingAgentBridge,
    open_stream: Fut,
) -> ssh_bridge::FlowBridge
where
    Fut: Future<Output = Result<AgentIoStream>> + Send + 'static,
{
    ssh_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let mut trace = TcpFlowTrace::new("agent", id, ready_wait_ms);
        let open_started_at = StdInstant::now();
        let open = tcp_open_request(id);
        let mut stream = match open_stream.await {
            Ok(AgentIoStream::Bridge(stream)) => stream,
            Ok(_) => {
                trace.finish("open_wrong_stream");
                let _ = ssh_bridge::send_bridge_event(
                    &event_tx,
                    ssh_bridge::BridgeEvent::Failed {
                        id,
                        phase: ssh_bridge::BridgeFailurePhase::Open,
                        message: "agent data plane returned a non-agent TCP stream".to_owned(),
                    },
                )
                .await;
                return;
            }
            Err(err) => {
                trace.finish("open_error");
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
        trace.stream_ready();
        let mut open_reported = false;
        let mut pre_open_local = VecDeque::<Bytes>::new();
        let mut pre_open_retries = 0_usize;
        let open_timeout = tokio::time::sleep(ssh_bridge::AGENT_STREAM_OPEN_TIMEOUT);
        tokio::pin!(open_timeout);

        loop {
            tokio::select! {
                _ = &mut open_timeout, if !open_reported => {
                    trace.finish("open_timeout");
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
                local = local_rx.recv_with_metrics() => {
                    match local {
                        Some(local) => {
                            let bytes = local.bytes;
                            trace.local_queue_wait(local.queue_wait_us);
                            trace.local_bytes(bytes.len());
                            if !open_reported {
                                pre_open_local.push_back(bytes.clone());
                            }
                            let send_started_at = StdInstant::now();
                            let send_result = tokio::time::timeout(
                                ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data_with_metrics(bytes.clone()),
                            )
                            .await;
                            trace.local_send_wait(send_started_at);
                            match send_result {
                                Ok(Ok(metrics)) => {
                                    trace.agent_send_waits(
                                        metrics.credit_wait_us,
                                        metrics.outbound_wait_us,
                                        metrics.frames,
                                    );
                                    trace.local_sent();
                                }
                                Ok(Err(err)) => {
                                    if !open_reported && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                        pre_open_retries += 1;
                                        match retry_agent_pre_open_stream(
                                            &agent,
                                            open.into_agent_open(),
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
                                                trace.finish("pre_open_reopen_error");
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
                                    trace.finish("write_error");
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
                                    trace.finish("write_timeout");
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
                            trace.outcome("local_eof");
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
                                    trace.opened();
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                        trace.finish("event_channel_closed");
                                        let _ = stream.close().await;
                                        return;
                                    }
                                    open_reported = true;
                                    pre_open_local.clear();
                                }
                            }
                            agent_proto::AgentFrameKind::Data => {
                                if !open_reported {
                                    trace.opened();
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                        trace.finish("event_channel_closed");
                                        let _ = stream.close().await;
                                        return;
                                    }
                                    open_reported = true;
                                    pre_open_local.clear();
                                }
                                trace.remote_bytes(frame.payload.len());
                                let event_started_at = StdInstant::now();
                                let event_sent = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::RemoteData {
                                        id,
                                        bytes: frame.payload,
                                    },
                                )
                                .await;
                                trace.remote_event_wait(event_started_at);
                                if !event_sent {
                                    trace.finish("event_channel_closed");
                                    break;
                                }
                            }
                            agent_proto::AgentFrameKind::Eof => {
                                trace.outcome("remote_eof");
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
                                            open.into_agent_open(),
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
                                                trace.finish("pre_open_reopen_error");
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
                                    trace.finish("remote_close_before_open");
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
                                trace.outcome("remote_close");
                                break;
                            }
                            agent_proto::AgentFrameKind::Reset => {
                                let message = String::from_utf8_lossy(&frame.payload).to_string();
                                if !open_reported && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT {
                                    pre_open_retries += 1;
                                    match retry_agent_pre_open_stream(
                                        &agent,
                                        open.into_agent_open(),
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
                                            trace.finish("pre_open_reopen_error");
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
                                trace.finish("remote_reset");
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
                                    open.into_agent_open(),
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
                                        trace.finish("pre_open_reopen_error");
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
                            trace.outcome("remote_stream_closed");
                            break;
                        },
                    }
                }
            }
        }

        let _ = stream.close().await;
        trace.finish_current_or("closed");
        let _ =
            ssh_bridge::send_bridge_event(&event_tx, ssh_bridge::BridgeEvent::Closed { id }).await;
    })
}

fn tcp_open_request(id: tcp_core::FlowId) -> DataPlaneIpv4Open {
    DataPlaneIpv4Open {
        destination_ip: id.key.dst_ip,
        destination_port: id.key.dst_port,
        originator_ip: id.key.src_ip,
        originator_port: id.key.src_port,
    }
}

#[cfg(test)]
async fn open_agent_tcp_stream(
    agent: ReconnectingAgentBridge,
    open: DataPlaneIpv4Open,
) -> Result<AgentIoStream> {
    agent
        .open_tcp_ipv4_optimistic(open.into_agent_open())
        .await
        .map(AgentIoStream::Bridge)
}

pub(super) fn spawn_quic_native_tcp_bridge(
    id: tcp_core::FlowId,
    ready_wait_ms: u64,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    bridge: QuicNativeBridge,
) -> ssh_bridge::FlowBridge {
    ssh_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let mut trace = TcpFlowTrace::new("quic-native", id, ready_wait_ms);
        let open_started_at = StdInstant::now();
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: id.key.dst_ip,
            destination_port: id.key.dst_port,
            originator_ip: id.key.src_ip,
            originator_port: id.key.src_port,
        };
        let mut stream = match bridge.open_tcp_ipv4_optimistic(open).await {
            Ok(stream) => {
                trace.stream_ready();
                stream
            }
            Err(err) => {
                trace.finish("open_error");
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
                    local = local_rx.recv_with_metrics() => {
                        match local {
                            Some(local) => {
                                let bytes = local.bytes;
                                trace.local_queue_wait(local.queue_wait_us);
                                trace.local_bytes(bytes.len());
                                let send_started_at = StdInstant::now();
                                let send_result = tokio::time::timeout(
                                    ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                    stream.send_data(bytes),
                                )
                                .await;
                                trace.local_send_wait(send_started_at);
                                match send_result {
                                    Ok(Ok(())) => {
                                        trace.local_sent();
                                    }
                                    Ok(Err(err)) => {
                                        trace.finish("pending_write_error");
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
                                        trace.finish("pending_write_timeout");
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
                                trace.outcome("local_eof");
                                let _ = stream.send_eof().await;
                                break;
                            }
                        }
                    }
                    opened = stream.wait_opened() => {
                        match opened {
                            Ok(()) => {
                                trace.opened();
                                if !report_agent_stream_opened(&event_tx, id, open_started_at).await {
                                    trace.finish("event_channel_closed");
                                    let _ = stream.send_eof().await;
                                    return;
                                }
                                open_reported = true;
                            }
                            Err(err) => {
                                trace.finish("open_error");
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
                local = local_rx.recv_with_metrics() => {
                    match local {
                        Some(local) => {
                            let bytes = local.bytes;
                            trace.local_queue_wait(local.queue_wait_us);
                            trace.local_bytes(bytes.len());
                            let send_started_at = StdInstant::now();
                            let send_result = tokio::time::timeout(
                                ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data(bytes),
                            )
                            .await;
                            trace.local_send_wait(send_started_at);
                            match send_result {
                                Ok(Ok(())) => {
                                    trace.local_sent();
                                }
                                Ok(Err(err)) => {
                                    trace.finish("write_error");
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
                                    trace.finish("write_timeout");
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
                            trace.outcome("local_eof");
                            let _ = stream.send_eof().await;
                            break;
                        }
                    }
                }
                remote = stream.recv_chunk(quic_agent::QUIC_BRIDGE_TCP_CHUNK) => {
                    match remote {
                        Ok(Some(bytes)) => {
                            trace.remote_bytes(bytes.len());
                            let event_started_at = StdInstant::now();
                            let event_sent = ssh_bridge::send_bridge_event(
                                &event_tx,
                                ssh_bridge::BridgeEvent::RemoteData { id, bytes },
                            )
                            .await;
                            trace.remote_event_wait(event_started_at);
                            if !event_sent {
                                trace.finish("event_channel_closed");
                                break;
                            }
                        }
                        Ok(None) => {
                            trace.outcome("remote_eof");
                            let _ = ssh_bridge::send_bridge_event(
                                &event_tx,
                                ssh_bridge::BridgeEvent::RemoteEof { id },
                            )
                            .await;
                            break;
                        }
                        Err(err) => {
                            trace.finish("read_error");
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

        trace.finish_current_or("closed");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_bridge::{
        test_support::{detached_bridge_transport, QueuedAgentConnector},
        ReconnectingAgentBridge,
    };
    use crate::defaults::DEFAULT_MTU;
    use crate::{agent_proto, agent_transport, ssh_bridge, tcp_core};
    use bytes::{Bytes, BytesMut};
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn agent_tcp_bridge_sends_local_data_before_agent_opened() {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

        async fn read_test_agent_frame<R: AsyncRead + Unpin>(
            reader: &mut R,
            inbound: &mut BytesMut,
        ) -> agent_proto::AgentFrame {
            loop {
                if let Some(frame) =
                    agent_proto::try_decode_frame(inbound).expect("decode test agent frame")
                {
                    return frame;
                }

                let mut buf = [0_u8; 8192];
                let read = reader.read(&mut buf).await.expect("read test agent frame");
                assert_ne!(read, 0, "test agent stream closed before next frame");
                inbound.extend_from_slice(&buf[..read]);
            }
        }

        async fn write_test_agent_frame<W: AsyncWrite + Unpin>(
            writer: &mut W,
            frame: agent_proto::AgentFrame,
        ) {
            let encoded = agent_proto::encode_frame(&frame).expect("encode test agent frame");
            writer
                .write_all(&encoded)
                .await
                .expect("write test agent frame");
            writer.flush().await.expect("flush test agent frame");
        }

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (data_seen_tx, data_seen_rx) = tokio::sync::oneshot::channel();
        let (send_opened_tx, send_opened_rx) = tokio::sync::oneshot::channel();
        let fake_agent = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(agent_io);
            let mut inbound = BytesMut::new();

            let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
            write_test_agent_frame(
                &mut writer,
                agent_proto::AgentFrame::new(
                    agent_proto::AgentFrameKind::Hello,
                    0,
                    agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
                )
                .expect("test hello frame"),
            )
            .await;

            let open = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

            let window = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
            assert_eq!(window.stream_id, open.stream_id);

            let data = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
            assert_eq!(data.stream_id, open.stream_id);
            assert_eq!(&data.payload[..], b"hello");
            data_seen_tx.send(()).expect("report optimistic data");

            send_opened_rx.await.expect("release opened frame");
            write_test_agent_frame(
                &mut writer,
                agent_proto::AgentFrame::new(
                    agent_proto::AgentFrameKind::Opened,
                    open.stream_id,
                    Bytes::new(),
                )
                .expect("opened frame")
                .with_credit((1024 * 1024) as u32),
            )
            .await;
        });

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect fake agent transport");
        let agent = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 1),
                49152,
                Ipv4Addr::new(192, 0, 2, 10),
                443,
            ),
            1,
        );
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let bridge = spawn_agent_tcp_bridge(id, event_tx, agent);

        assert!(
            bridge
                .try_send_local_data(Bytes::from_static(b"hello"))
                .expect("queue local data"),
            "bridge should accept first local payload"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), data_seen_rx)
            .await
            .expect("agent sees data before opened")
            .expect("data seen notification");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "bridge must not report opened before the agent sends Opened"
        );

        send_opened_tx.send(()).expect("release fake opened");
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
            .await
            .expect("opened event")
            .expect("bridge event");
        assert!(
            matches!(event, ssh_bridge::BridgeEvent::Opened { id: event_id, .. } if event_id == id)
        );

        drop(bridge);
        fake_agent.await.expect("fake agent join");
    }
}
