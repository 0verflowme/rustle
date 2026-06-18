use std::collections::VecDeque;
use std::future::Future;
use std::time::Instant as StdInstant;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::agent_bridge::ReconnectingAgentBridge;
use crate::hotpath_trace::TcpFlowTrace;
use crate::transport_model::DataPlaneIpv4Open;
use crate::{agent_proto, flow_bridge, tcp_core};

use super::stream::AgentIoStream;

const AGENT_PRE_OPEN_RETRY_LIMIT: usize = 1;
const REMOTE_DATA_COALESCE_MAX_FRAMES: usize = 8;
const REMOTE_DATA_COALESCE_MAX_BYTES: usize = 512 * 1024;

enum BridgeInput {
    OpenTimeout,
    Remote(Result<Option<agent_proto::AgentFrame>>),
    Local(Option<flow_bridge::ReceivedLocalData>),
}

#[cfg(test)]
pub(crate) fn spawn_agent_tcp_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<flow_bridge::BridgeEvent>,
    agent: ReconnectingAgentBridge,
) -> flow_bridge::FlowBridge {
    let open = tcp_open_request(id);
    spawn_data_plane_tcp_bridge_with_open(
        id,
        event_tx,
        flow_bridge::BridgeEventAccounting::new(),
        0,
        "agent",
        open_agent_tcp_stream(agent, open),
    )
}

pub(super) fn spawn_data_plane_tcp_bridge_with_open<Fut>(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<flow_bridge::BridgeEvent>,
    event_accounting: flow_bridge::BridgeEventAccounting,
    ready_wait_ms: u64,
    transport_label: &'static str,
    open_stream: Fut,
) -> flow_bridge::FlowBridge
where
    Fut: Future<Output = Result<AgentIoStream>> + Send + 'static,
{
    flow_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let mut trace = TcpFlowTrace::new(transport_label, id, ready_wait_ms);
        let open_started_at = StdInstant::now();
        let open = tcp_open_request(id);
        let mut stream = match open_stream.await {
            Ok(stream) => stream,
            Err(err) => {
                trace.finish("open_error");
                let _ = flow_bridge::send_bridge_event(
                    &event_tx,
                    flow_bridge::BridgeEvent::Failed {
                        id,
                        phase: flow_bridge::BridgeFailurePhase::Open,
                        message: format!("failed to open {transport_label} stream: {err:#}"),
                    },
                )
                .await;
                return;
            }
        };
        trace.stream_ready();
        let retry_agent = stream.pre_open_retry_agent();
        let mut open_reported = false;
        let mut pre_open_local = VecDeque::<Bytes>::new();
        let mut pre_open_retries = 0_usize;
        let mut prefer_local_after_remote = false;
        let mut pending_remote: Option<Result<Option<agent_proto::AgentFrame>>> = None;
        let open_timeout = tokio::time::sleep(flow_bridge::AGENT_STREAM_OPEN_TIMEOUT);
        tokio::pin!(open_timeout);

        loop {
            let input = if let Some(remote) = pending_remote.take() {
                BridgeInput::Remote(remote)
            } else if prefer_local_after_remote {
                tokio::select! {
                    biased;
                    _ = &mut open_timeout, if !open_reported => BridgeInput::OpenTimeout,
                    local = local_rx.recv_with_metrics() => BridgeInput::Local(local),
                    remote = stream.recv() => BridgeInput::Remote(remote),
                }
            } else {
                tokio::select! {
                    biased;
                    _ = &mut open_timeout, if !open_reported => BridgeInput::OpenTimeout,
                    remote = stream.recv() => BridgeInput::Remote(remote),
                    local = local_rx.recv_with_metrics() => BridgeInput::Local(local),
                }
            };

            match input {
                BridgeInput::OpenTimeout => {
                    trace.finish("open_timeout");
                    let _ = flow_bridge::send_bridge_event(
                        &event_tx,
                        flow_bridge::BridgeEvent::Failed {
                            id,
                            phase: flow_bridge::BridgeFailurePhase::Open,
                            message: format!(
                                "timed out after {}ms waiting for {transport_label} stream open confirmation",
                                flow_bridge::AGENT_STREAM_OPEN_TIMEOUT.as_millis()
                            ),
                        },
                    )
                    .await;
                    break;
                }
                BridgeInput::Remote(remote) => {
                    prefer_local_after_remote = true;
                    match remote {
                        Ok(Some(frame)) => match frame.kind {
                            agent_proto::AgentFrameKind::Opened => {
                                if !open_reported {
                                    record_agent_opened_timing(&mut trace, &frame);
                                    trace.opened();
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at)
                                        .await
                                    {
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
                                    if !report_agent_stream_opened(&event_tx, id, open_started_at)
                                        .await
                                    {
                                        trace.finish("event_channel_closed");
                                        let _ = stream.close().await;
                                        return;
                                    }
                                    open_reported = true;
                                    pre_open_local.clear();
                                }
                                let (payload, pending) =
                                    coalesce_remote_data(&mut stream, frame.payload, &mut trace)
                                        .await;
                                pending_remote = pending;
                                let event_started_at = StdInstant::now();
                                let event_sent = flow_bridge::send_bridge_event_accounted(
                                    &event_tx,
                                    &event_accounting,
                                    flow_bridge::BridgeEvent::RemoteData { id, bytes: payload },
                                )
                                .await;
                                trace.remote_event_wait(event_started_at);
                                if !event_sent {
                                    trace.finish("event_channel_closed");
                                    break;
                                }
                            }
                            agent_proto::AgentFrameKind::Eof => {
                                record_agent_eof_timing(&mut trace, &frame);
                                trace.outcome("remote_eof");
                                let _ = flow_bridge::send_bridge_event(
                                    &event_tx,
                                    flow_bridge::BridgeEvent::RemoteEof { id },
                                )
                                .await;
                                break;
                            }
                            agent_proto::AgentFrameKind::Close => {
                                if !open_reported {
                                    if retry_agent.is_some()
                                        && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT
                                    {
                                        pre_open_retries += 1;
                                        match retry_agent_pre_open_stream(
                                            retry_agent.as_ref(),
                                            open.into_agent_open(),
                                            stream,
                                            &pre_open_local,
                                        )
                                        .await
                                        {
                                            Ok(replacement) => {
                                                stream = replacement;
                                                open_timeout.as_mut().reset(
                                                    tokio::time::Instant::now()
                                                        + flow_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                                );
                                                continue;
                                            }
                                            Err(err) => {
                                                trace.finish("pre_open_reopen_error");
                                                let _ = flow_bridge::send_bridge_event(
                                                    &event_tx,
                                                    flow_bridge::BridgeEvent::Failed {
                                                        id,
                                                        phase: flow_bridge::BridgeFailurePhase::Open,
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
                                    let _ = flow_bridge::send_bridge_event(
                                        &event_tx,
                                        flow_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: flow_bridge::BridgeFailurePhase::Open,
                                            message: format!("{transport_label} stream closed before open confirmation"),
                                        },
                                    )
                                    .await;
                                }
                                trace.outcome("remote_close");
                                break;
                            }
                            agent_proto::AgentFrameKind::Reset => {
                                let message = String::from_utf8_lossy(&frame.payload).to_string();
                                if !open_reported
                                    && retry_agent.is_some()
                                    && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT
                                {
                                    pre_open_retries += 1;
                                    match retry_agent_pre_open_stream(
                                        retry_agent.as_ref(),
                                        open.into_agent_open(),
                                        stream,
                                        &pre_open_local,
                                    )
                                    .await
                                    {
                                        Ok(replacement) => {
                                            stream = replacement;
                                            open_timeout.as_mut().reset(
                                                tokio::time::Instant::now()
                                                    + flow_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                            );
                                            continue;
                                        }
                                        Err(err) => {
                                            trace.finish("pre_open_reopen_error");
                                            let _ = flow_bridge::send_bridge_event(
                                                &event_tx,
                                                flow_bridge::BridgeEvent::Failed {
                                                    id,
                                                    phase: flow_bridge::BridgeFailurePhase::Open,
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
                                    flow_bridge::BridgeFailurePhase::Write
                                } else {
                                    flow_bridge::BridgeFailurePhase::Open
                                };
                                trace.finish("remote_reset");
                                let _ = flow_bridge::send_bridge_event(
                                    &event_tx,
                                    flow_bridge::BridgeEvent::Failed {
                                        id,
                                        phase,
                                        message: format!(
                                            "{transport_label} stream reset: {message}"
                                        ),
                                    },
                                )
                                .await;
                                break;
                            }
                            _ => {}
                        },
                        Ok(None) => {
                            if !open_reported
                                && retry_agent.is_some()
                                && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT
                            {
                                pre_open_retries += 1;
                                match retry_agent_pre_open_stream(
                                    retry_agent.as_ref(),
                                    open.into_agent_open(),
                                    stream,
                                    &pre_open_local,
                                )
                                .await
                                {
                                    Ok(replacement) => {
                                        stream = replacement;
                                        open_timeout.as_mut().reset(
                                            tokio::time::Instant::now()
                                                + flow_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                        );
                                        continue;
                                    }
                                    Err(err) => {
                                        trace.finish("pre_open_reopen_error");
                                        let _ = flow_bridge::send_bridge_event(
                                            &event_tx,
                                            flow_bridge::BridgeEvent::Failed {
                                                id,
                                                phase: flow_bridge::BridgeFailurePhase::Open,
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
                        }
                        Err(err) => {
                            let phase = if open_reported {
                                flow_bridge::BridgeFailurePhase::Write
                            } else {
                                flow_bridge::BridgeFailurePhase::Open
                            };
                            trace.finish("read_error");
                            let _ = flow_bridge::send_bridge_event(
                                &event_tx,
                                flow_bridge::BridgeEvent::Failed {
                                    id,
                                    phase,
                                    message: format!(
                                        "failed to read {transport_label} stream: {err:#}"
                                    ),
                                },
                            )
                            .await;
                            break;
                        }
                    }
                }
                BridgeInput::Local(local) => {
                    prefer_local_after_remote = false;
                    match local {
                        Some(local) => {
                            let bytes = local.bytes;
                            trace.tcp_recv_queue_wait(local.tcp_recv_queue_wait_us);
                            trace.local_queue_wait(local.queue_wait_us);
                            trace.local_bytes(bytes.len());
                            if !open_reported {
                                pre_open_local.push_back(bytes.clone());
                            }
                            let send_started_at = StdInstant::now();
                            let send_result = tokio::time::timeout(
                                flow_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data_with_metrics(bytes.clone()),
                            )
                            .await;
                            trace.local_send_wait(send_started_at);
                            match send_result {
                                Ok(Ok(metrics)) => {
                                    trace.agent_send_waits(
                                        metrics.agent_credit_wait_us,
                                        metrics.agent_outbound_wait_us,
                                        metrics.agent_outbound_frames,
                                    );
                                    trace.local_sent();
                                }
                                Ok(Err(err)) => {
                                    if !open_reported
                                        && retry_agent.is_some()
                                        && pre_open_retries < AGENT_PRE_OPEN_RETRY_LIMIT
                                    {
                                        pre_open_retries += 1;
                                        match retry_agent_pre_open_stream(
                                            retry_agent.as_ref(),
                                            open.into_agent_open(),
                                            stream,
                                            &pre_open_local,
                                        )
                                        .await
                                        {
                                            Ok(replacement) => {
                                                stream = replacement;
                                                open_timeout.as_mut().reset(
                                                    tokio::time::Instant::now()
                                                        + flow_bridge::AGENT_STREAM_OPEN_TIMEOUT,
                                                );
                                                continue;
                                            }
                                            Err(retry_err) => {
                                                trace.finish("pre_open_reopen_error");
                                                let _ = flow_bridge::send_bridge_event(
                                                    &event_tx,
                                                    flow_bridge::BridgeEvent::Failed {
                                                        id,
                                                        phase: flow_bridge::BridgeFailurePhase::Open,
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
                                        flow_bridge::BridgeFailurePhase::Write
                                    } else {
                                        flow_bridge::BridgeFailurePhase::Open
                                    };
                                    trace.finish("write_error");
                                    let _ = flow_bridge::send_bridge_event(
                                        &event_tx,
                                        flow_bridge::BridgeEvent::Failed {
                                            id,
                                            phase,
                                        message: format!("failed to write to {transport_label} stream: {err:#}"),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                                Err(_) => {
                                    let phase = if open_reported {
                                        flow_bridge::BridgeFailurePhase::Write
                                    } else {
                                        flow_bridge::BridgeFailurePhase::Open
                                    };
                                    trace.finish("write_timeout");
                                    let _ = flow_bridge::send_bridge_event(
                                        &event_tx,
                                        flow_bridge::BridgeEvent::Failed {
                                            id,
                                            phase,
                                            message: format!(
                                                "timed out after {}ms writing to {transport_label} stream",
                                                flow_bridge::BRIDGE_WRITE_TIMEOUT.as_millis()
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
            }
        }

        let _ = stream.close().await;
        trace.finish_current_or("closed");
        let _ = flow_bridge::send_bridge_event(&event_tx, flow_bridge::BridgeEvent::Closed { id })
            .await;
    })
}

fn tcp_open_request(id: tcp_core::FlowId) -> DataPlaneIpv4Open {
    DataPlaneIpv4Open {
        destination_ip: id.key.dst_ip,
        destination_port: id.key.dst_port,
        originator_ip: id.key.src_ip,
        originator_port: id.key.src_port,
        flow_generation: Some(id.generation),
    }
}

fn record_agent_opened_timing(trace: &mut TcpFlowTrace, frame: &agent_proto::AgentFrame) {
    if let Ok(Some(timing)) = agent_proto::AgentOpenedTiming::decode_optional(&frame.payload) {
        trace.agent_remote_connect(timing.remote_connect_us);
    }
}

fn record_agent_eof_timing(trace: &mut TcpFlowTrace, frame: &agent_proto::AgentFrame) {
    if let Ok(Some(timing)) = agent_proto::AgentEofTiming::decode_optional(&frame.payload) {
        trace.agent_remote_output_timing(timing);
    }
}

async fn coalesce_remote_data(
    stream: &mut AgentIoStream,
    first_payload: Bytes,
    trace: &mut TcpFlowTrace,
) -> (Bytes, Option<Result<Option<agent_proto::AgentFrame>>>) {
    trace.remote_bytes(first_payload.len());
    let mut frames = 1_usize;
    let mut total_bytes = first_payload.len();
    let mut chunks = vec![first_payload];

    while frames < REMOTE_DATA_COALESCE_MAX_FRAMES && total_bytes < REMOTE_DATA_COALESCE_MAX_BYTES {
        match stream.try_recv().await {
            Ok(Some(frame)) if frame.kind == agent_proto::AgentFrameKind::Data => {
                trace.remote_bytes(frame.payload.len());
                total_bytes = total_bytes.saturating_add(frame.payload.len());
                chunks.push(frame.payload);
                frames += 1;
            }
            Ok(Some(frame)) => {
                return (
                    join_remote_data_chunks(chunks, total_bytes),
                    Some(Ok(Some(frame))),
                )
            }
            Ok(None) => break,
            Err(err) => return (join_remote_data_chunks(chunks, total_bytes), Some(Err(err))),
        }
    }

    (join_remote_data_chunks(chunks, total_bytes), None)
}

fn join_remote_data_chunks(mut chunks: Vec<Bytes>, total_bytes: usize) -> Bytes {
    if chunks.len() == 1 {
        return chunks.pop().expect("remote data chunks must not be empty");
    }
    let mut output = BytesMut::with_capacity(total_bytes);
    for chunk in chunks {
        output.extend_from_slice(&chunk);
    }
    output.freeze()
}

#[cfg(test)]
async fn open_agent_tcp_stream(
    agent: ReconnectingAgentBridge,
    open: DataPlaneIpv4Open,
) -> Result<AgentIoStream> {
    let retry_agent = agent.clone();
    agent
        .open_tcp_ipv4_optimistic(open.into_agent_open())
        .await
        .map(|stream| AgentIoStream::agent_bridge_with_retry(stream, Some(retry_agent)))
}

async fn retry_agent_pre_open_stream(
    agent: Option<&ReconnectingAgentBridge>,
    open: agent_proto::AgentOpenIpv4,
    old_stream: AgentIoStream,
    replay: &VecDeque<Bytes>,
) -> Result<AgentIoStream> {
    let _ = old_stream.close().await;
    let Some(agent) = agent else {
        bail!("pre-open retry is not supported for this data plane");
    };
    let stream = agent
        .open_tcp_ipv4_optimistic(open)
        .await
        .context("failed to reopen optimistic agent stream")?;
    let mut stream = AgentIoStream::agent_bridge_with_retry(stream, Some(agent.clone()));
    for bytes in replay {
        stream
            .send_data(bytes.clone())
            .await
            .context("failed to replay pre-open agent bytes")?;
    }
    Ok(stream)
}

async fn report_agent_stream_opened(
    event_tx: &mpsc::Sender<flow_bridge::BridgeEvent>,
    id: tcp_core::FlowId,
    open_started_at: StdInstant,
) -> bool {
    let open_ms = open_started_at
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    flow_bridge::send_bridge_event(event_tx, flow_bridge::BridgeEvent::Opened { id, open_ms }).await
}
