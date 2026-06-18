use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use tokio::sync::{mpsc, Semaphore};

use super::{ensure_agent_ready, mark_agent_failed, AgentStream, AgentTransport, StreamEntry};
use crate::agent_io::AgentFrameWriteItem;
use crate::agent_proto::{
    AgentFrame, AgentFrameKind, AgentOpenHost, AgentOpenIpv4, AGENT_MAX_FRAME_PAYLOAD,
    CAP_TCP_CONNECT_HOST,
};
use crate::agent_window::{AgentCreditWindow, AGENT_STREAM_MAX_WINDOW_BYTES};

const AGENT_INBOUND_FRAMES_PER_STREAM: usize = 128;
const AGENT_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const _: () = assert!(
    AGENT_STREAM_MAX_WINDOW_BYTES <= AGENT_INBOUND_FRAMES_PER_STREAM * AGENT_MAX_FRAME_PAYLOAD
);

impl AgentTransport {
    pub async fn open_tcp_ipv4(&self, open: AgentOpenIpv4) -> Result<AgentStream> {
        self.open_ipv4(AgentFrameKind::OpenTcp, open).await
    }

    pub async fn open_tcp_ipv4_optimistic(&self, open: AgentOpenIpv4) -> Result<AgentStream> {
        self.open_ipv4_optimistic_with_timeout(open, AGENT_STREAM_OPEN_TIMEOUT)
            .await
    }

    pub async fn open_tcp_host(&self, open: AgentOpenHost) -> Result<AgentStream> {
        if self.peer.capabilities & CAP_TCP_CONNECT_HOST == 0 {
            bail!("agent does not advertise hostname TCP connect support");
        }
        self.open_with_payload(
            AgentFrameKind::OpenTcpHost,
            open.encode()?,
            AGENT_STREAM_OPEN_TIMEOUT,
        )
        .await
    }

    pub async fn open_udp_ipv4(&self, open: AgentOpenIpv4) -> Result<AgentStream> {
        self.open_ipv4(AgentFrameKind::OpenUdp, open).await
    }

    async fn open_ipv4(&self, kind: AgentFrameKind, open: AgentOpenIpv4) -> Result<AgentStream> {
        self.open_ipv4_with_timeout(kind, open, AGENT_STREAM_OPEN_TIMEOUT)
            .await
    }

    pub(super) async fn open_ipv4_with_timeout(
        &self,
        kind: AgentFrameKind,
        open: AgentOpenIpv4,
        open_timeout: Duration,
    ) -> Result<AgentStream> {
        self.open_with_payload(kind, open.encode(), open_timeout)
            .await
    }

    async fn open_ipv4_optimistic_with_timeout(
        &self,
        open: AgentOpenIpv4,
        open_timeout: Duration,
    ) -> Result<AgentStream> {
        self.open_optimistic_with_payload(AgentFrameKind::OpenTcp, open.encode(), open_timeout)
            .await
    }

    async fn open_with_payload(
        &self,
        kind: AgentFrameKind,
        payload: Bytes,
        open_timeout: Duration,
    ) -> Result<AgentStream> {
        ensure_agent_ready(&self.failure).await?;
        let stream_id = self.allocate_stream_id()?;
        let open_frame = AgentFrame::new(kind, stream_id, payload)?;
        let outbound_permit = match tokio::time::timeout(
            open_timeout,
            self.outbound.clone().reserve_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                let message = "agent writer task is closed".to_owned();
                mark_agent_failed(&self.failure, &self.streams, message.clone()).await;
                return Err(anyhow!(message));
            }
            Err(_) => {
                let message = format!(
                    "timed out after {}ms waiting for agent outbound capacity to open stream {stream_id}",
                    open_timeout.as_millis()
                );
                mark_agent_failed(&self.failure, &self.streams, message.clone()).await;
                return Err(anyhow!(message));
            }
        };
        let (inbound_tx, mut inbound_rx) = mpsc::channel(AGENT_INBOUND_FRAMES_PER_STREAM);
        let send_credit = Arc::new(Semaphore::new(0));
        {
            let mut streams = self.streams.lock().await;
            streams.insert(
                stream_id,
                StreamEntry {
                    inbound: inbound_tx,
                    send_credit: Arc::clone(&send_credit),
                    optimistic_open_credit: 0,
                },
            );
        }
        if let Err(err) = ensure_agent_ready(&self.failure).await {
            self.unregister_stream(stream_id).await;
            return Err(err);
        }

        let queued_open = AgentFrameWriteItem::new(open_frame)?;
        self.writer_metrics
            .record_enqueued(queued_open.encoded_len());
        outbound_permit.send(queued_open);

        let maybe_frame = match tokio::time::timeout(open_timeout, inbound_rx.recv()).await {
            Ok(frame) => frame,
            Err(_) => {
                self.unregister_stream(stream_id).await;
                bail!(
                    "timed out after {}ms opening agent stream {stream_id}",
                    open_timeout.as_millis()
                );
            }
        };
        let Some(frame) = maybe_frame else {
            self.unregister_stream(stream_id).await;
            bail!("agent stream dispatcher closed while opening stream {stream_id}");
        };
        match frame.kind {
            AgentFrameKind::Opened => {
                if frame.credit > 0 {
                    send_credit.add_permits(frame.credit as usize);
                }
                let mut stream = AgentStream {
                    stream_id,
                    outbound: self.outbound.clone(),
                    inbound: inbound_rx,
                    streams: Arc::clone(&self.streams),
                    failure: Arc::clone(&self.failure),
                    writer_metrics: Arc::clone(&self.writer_metrics),
                    send_credit,
                    max_frame_payload: (self.peer.max_frame_payload as usize)
                        .min(AGENT_MAX_FRAME_PAYLOAD),
                    receive_window: AgentCreditWindow::new(),
                    initial_receive_credit_granted: false,
                };
                if let Err(err) = stream
                    .grant_receive_credit(AgentCreditWindow::initial_credit())
                    .await
                {
                    stream.close_credit_and_unregister().await;
                    return Err(err);
                }
                stream.initial_receive_credit_granted = true;
                Ok(stream)
            }
            AgentFrameKind::Reset => {
                self.unregister_stream(stream_id).await;
                let message = String::from_utf8_lossy(&frame.payload);
                bail!("agent failed to open stream {stream_id}: {message}");
            }
            other => {
                self.unregister_stream(stream_id).await;
                bail!("agent expected opened/reset for stream {stream_id}, got {other:?}");
            }
        }
    }

    async fn open_optimistic_with_payload(
        &self,
        kind: AgentFrameKind,
        payload: Bytes,
        open_timeout: Duration,
    ) -> Result<AgentStream> {
        ensure_agent_ready(&self.failure).await?;
        let stream_id = self.allocate_stream_id()?;
        let open_frame = AgentFrame::new(kind, stream_id, payload)?;
        let initial_receive_credit = AgentCreditWindow::initial_credit();
        let initial_receive_window =
            AgentFrame::new(AgentFrameKind::Window, stream_id, Bytes::new())?
                .with_credit(u32::try_from(initial_receive_credit)?);
        let mut outbound_permits = match tokio::time::timeout(
            open_timeout,
            self.outbound.reserve_many(2),
        )
        .await
        {
            Ok(Ok(permits)) => permits,
            Ok(Err(_)) => {
                let message = "agent writer task is closed".to_owned();
                mark_agent_failed(&self.failure, &self.streams, message.clone()).await;
                return Err(anyhow!(message));
            }
            Err(_) => {
                let message = format!(
                    "timed out after {}ms waiting for agent outbound capacity to open stream {stream_id}",
                    open_timeout.as_millis()
                );
                mark_agent_failed(&self.failure, &self.streams, message.clone()).await;
                return Err(anyhow!(message));
            }
        };
        let (inbound_tx, inbound_rx) = mpsc::channel(AGENT_INBOUND_FRAMES_PER_STREAM);
        let send_credit = Arc::new(Semaphore::new(initial_receive_credit));
        {
            let mut streams = self.streams.lock().await;
            streams.insert(
                stream_id,
                StreamEntry {
                    inbound: inbound_tx,
                    send_credit: Arc::clone(&send_credit),
                    optimistic_open_credit: initial_receive_credit,
                },
            );
        }
        if let Err(err) = ensure_agent_ready(&self.failure).await {
            self.unregister_stream(stream_id).await;
            return Err(err);
        }

        let queued_open = AgentFrameWriteItem::new(open_frame)?;
        let queued_initial_receive_window = AgentFrameWriteItem::new(initial_receive_window)?;
        self.writer_metrics
            .record_enqueued(queued_open.encoded_len());
        self.writer_metrics
            .record_enqueued(queued_initial_receive_window.encoded_len());
        outbound_permits
            .next()
            .expect("open frame capacity was reserved")
            .send(queued_open);
        outbound_permits
            .next()
            .expect("initial receive window capacity was reserved")
            .send(queued_initial_receive_window);
        debug_assert!(outbound_permits.next().is_none());

        let stream = AgentStream {
            stream_id,
            outbound: self.outbound.clone(),
            inbound: inbound_rx,
            streams: Arc::clone(&self.streams),
            failure: Arc::clone(&self.failure),
            writer_metrics: Arc::clone(&self.writer_metrics),
            send_credit,
            max_frame_payload: (self.peer.max_frame_payload as usize).min(AGENT_MAX_FRAME_PAYLOAD),
            receive_window: AgentCreditWindow::new(),
            initial_receive_credit_granted: true,
        };
        Ok(stream)
    }

    async fn unregister_stream(&self, stream_id: u64) {
        self.streams.lock().await.remove(&stream_id);
    }

    fn allocate_stream_id(&self) -> Result<u64> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::AcqRel);
        if stream_id == 0 || stream_id > u64::MAX - 2 {
            bail!("agent stream id counter exhausted");
        }
        Ok(stream_id)
    }
}
