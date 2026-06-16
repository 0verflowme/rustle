use std::collections::VecDeque;
use std::time::Instant as StdInstant;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::agent_bridge::{AgentBridgeStream, QuicNativeBridge, ReconnectingAgentBridge};
use crate::ssh_control::SshSessionPool;
use crate::{agent_proto, quic_agent, ssh_bridge, tcp_core};

const AGENT_PRE_OPEN_RETRY_LIMIT: usize = 1;

pub(super) fn spawn_direct_tcpip_bridge(
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

pub(super) fn spawn_quic_native_tcp_bridge(
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
