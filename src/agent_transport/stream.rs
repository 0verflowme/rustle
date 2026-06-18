use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use tokio::sync::{mpsc, Semaphore};

use super::{ensure_agent_ready, mark_agent_failed, FailureState, StreamMap, WriterMetrics};
use crate::agent_io::AgentFrameWriteItem;
use crate::agent_proto::{AgentFrame, AgentFrameKind};
use crate::agent_window::AgentCreditWindow;

pub(super) const AGENT_FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
pub(super) struct AgentFrameSendContext<'a> {
    pub(super) outbound: &'a mpsc::Sender<AgentFrameWriteItem>,
    pub(super) streams: &'a StreamMap,
    pub(super) failure: &'a FailureState,
    pub(super) writer_metrics: &'a super::AgentWriterMetrics,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AgentStreamSendMetrics {
    pub(crate) credit_wait_us: u128,
    pub(crate) outbound_wait_us: u128,
    pub(crate) frames: u64,
}

impl AgentStreamSendMetrics {
    fn record_credit_wait(&mut self, started_at: Instant) {
        self.credit_wait_us = self
            .credit_wait_us
            .saturating_add(started_at.elapsed().as_micros());
    }

    fn record_outbound_wait(&mut self, started_at: Instant) {
        self.outbound_wait_us = self
            .outbound_wait_us
            .saturating_add(started_at.elapsed().as_micros());
        self.frames = self.frames.saturating_add(1);
    }
}

#[derive(Debug)]
pub struct AgentStream {
    pub(super) stream_id: u64,
    pub(super) outbound: mpsc::Sender<AgentFrameWriteItem>,
    pub(super) inbound: mpsc::Receiver<AgentFrame>,
    pub(super) streams: StreamMap,
    pub(super) failure: FailureState,
    pub(super) writer_metrics: WriterMetrics,
    pub(super) send_credit: Arc<Semaphore>,
    pub(super) max_frame_payload: usize,
    pub(super) receive_window: AgentCreditWindow,
    pub(super) initial_receive_credit_granted: bool,
}

impl AgentStream {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub async fn transport_failure_message(&self) -> Option<String> {
        self.failure.lock().await.clone()
    }

    fn send_context(&self) -> AgentFrameSendContext<'_> {
        AgentFrameSendContext {
            outbound: &self.outbound,
            streams: &self.streams,
            failure: &self.failure,
            writer_metrics: &self.writer_metrics,
        }
    }

    pub async fn send_data(&self, bytes: impl Into<Bytes>) -> Result<()> {
        self.send_data_with_metrics(bytes).await.map(|_| ())
    }

    pub(crate) async fn send_data_with_metrics(
        &self,
        bytes: impl Into<Bytes>,
    ) -> Result<AgentStreamSendMetrics> {
        let mut metrics = AgentStreamSendMetrics::default();
        let bytes = bytes.into();
        if bytes.is_empty() {
            self.send_data_frame(bytes, &mut metrics).await?;
            return Ok(metrics);
        }

        let mut offset = 0;
        while offset < bytes.len() {
            let end = offset
                .saturating_add(self.max_frame_payload)
                .min(bytes.len());
            self.send_data_frame(bytes.slice(offset..end), &mut metrics)
                .await?;
            offset = end;
        }
        Ok(metrics)
    }

    async fn send_data_frame(
        &self,
        bytes: Bytes,
        metrics: &mut AgentStreamSendMetrics,
    ) -> Result<()> {
        ensure_agent_ready(&self.failure).await?;
        let frame = AgentFrame::new(AgentFrameKind::Data, self.stream_id, bytes)?;
        let credit_started_at = Instant::now();
        let permits = if frame.payload.is_empty() {
            None
        } else {
            Some(
                self.send_credit
                    .clone()
                    .acquire_many_owned(frame.payload.len() as u32)
                    .await
                    .context("agent stream send window is closed")?,
            )
        };
        if permits.is_some() {
            metrics.record_credit_wait(credit_started_at);
        }
        self.send_frame_with_metrics(frame, metrics).await?;
        if let Some(permits) = permits {
            permits.forget();
        }
        Ok(())
    }

    pub async fn send_eof(&self) -> Result<()> {
        self.send_frame(AgentFrame::new(
            AgentFrameKind::Eof,
            self.stream_id,
            Bytes::new(),
        )?)
        .await
    }

    pub async fn recv(&mut self) -> Option<AgentFrame> {
        let frame = self.inbound.recv().await?;
        match frame.kind {
            AgentFrameKind::Opened => {
                if !self.initial_receive_credit_granted {
                    if self
                        .grant_receive_credit(AgentCreditWindow::initial_credit())
                        .await
                        .is_err()
                    {
                        return None;
                    }
                    self.initial_receive_credit_granted = true;
                }
            }
            AgentFrameKind::Data if !frame.payload.is_empty() => {
                if self
                    .record_received_data_credit(frame.payload.len())
                    .await
                    .is_err()
                {
                    return None;
                }
            }
            AgentFrameKind::Close | AgentFrameKind::Reset => {
                self.close_credit_and_unregister().await;
            }
            _ => {}
        }
        Some(frame)
    }

    pub async fn close(self) -> Result<()> {
        let frame = AgentFrame::new(AgentFrameKind::Close, self.stream_id, Bytes::new())?;
        self.close_credit_and_unregister().await;
        send_agent_transport_frame(
            self.send_context(),
            frame,
            AGENT_FRAME_SEND_TIMEOUT,
            "agent close frame",
        )
        .await
    }

    async fn send_frame(&self, frame: AgentFrame) -> Result<()> {
        self.send_frame_with_timeout(frame, AGENT_FRAME_SEND_TIMEOUT)
            .await
    }

    pub(super) async fn send_frame_with_timeout(
        &self,
        frame: AgentFrame,
        timeout: Duration,
    ) -> Result<()> {
        send_agent_transport_frame(self.send_context(), frame, timeout, "agent stream frame").await
    }

    async fn send_frame_with_metrics(
        &self,
        frame: AgentFrame,
        metrics: &mut AgentStreamSendMetrics,
    ) -> Result<()> {
        send_agent_transport_frame_with_metrics(
            self.send_context(),
            frame,
            AGENT_FRAME_SEND_TIMEOUT,
            "agent stream frame",
            metrics,
        )
        .await
    }

    async fn record_received_data_credit(&mut self, bytes: usize) -> Result<()> {
        if let Some(credit) = self.receive_window.record_consumed(bytes) {
            self.grant_receive_credit(credit).await?;
        }
        Ok(())
    }

    pub(super) async fn grant_receive_credit(&self, bytes: usize) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let credit = u32::try_from(bytes).context("agent receive credit exceeds u32")?;
        self.send_frame(
            AgentFrame::new(AgentFrameKind::Window, self.stream_id, Bytes::new())?
                .with_credit(credit),
        )
        .await
    }

    pub(super) async fn close_credit_and_unregister(&self) {
        self.send_credit.close();
        self.streams.lock().await.remove(&self.stream_id);
    }
}

pub(super) async fn send_agent_transport_frame(
    send: AgentFrameSendContext<'_>,
    frame: AgentFrame,
    timeout: Duration,
    context: &str,
) -> Result<()> {
    let mut metrics = AgentStreamSendMetrics::default();
    send_agent_transport_frame_with_metrics(send, frame, timeout, context, &mut metrics).await
}

async fn send_agent_transport_frame_with_metrics(
    send: AgentFrameSendContext<'_>,
    frame: AgentFrame,
    timeout: Duration,
    context: &str,
    metrics: &mut AgentStreamSendMetrics,
) -> Result<()> {
    ensure_agent_ready(send.failure).await?;
    let outbound_started_at = Instant::now();
    match tokio::time::timeout(timeout, send.outbound.clone().reserve_owned()).await {
        Ok(Ok(permit)) => {
            let queued = AgentFrameWriteItem::new(frame)?;
            send.writer_metrics.record_enqueued(queued.encoded_len());
            permit.send(queued);
            metrics.record_outbound_wait(outbound_started_at);
            Ok(())
        }
        Ok(Err(_)) => {
            metrics.record_outbound_wait(outbound_started_at);
            let message = "agent writer task is closed".to_owned();
            mark_agent_failed(send.failure, send.streams, message.clone()).await;
            Err(anyhow!(message))
        }
        Err(_) => {
            metrics.record_outbound_wait(outbound_started_at);
            let message = format!(
                "timed out after {}ms enqueueing {context}",
                timeout.as_millis()
            );
            mark_agent_failed(send.failure, send.streams, message.clone()).await;
            Err(anyhow!(message))
        }
    }
}
