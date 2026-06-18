use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{mark_agent_failed, FailureState, StreamMap, WriterMetrics};
use crate::agent_io::{
    write_agent_frame_unflushed, AgentFrameBurstWriter, AgentFrameWriteItem,
    AGENT_FRAME_WRITE_BURST, AGENT_FRAME_WRITE_BURST_BYTES,
};
use crate::agent_proto::AgentFrame;

pub(super) async fn write_agent_frames<W>(
    mut writer: W,
    mut outbound_rx: mpsc::Receiver<AgentFrameWriteItem>,
    streams: StreamMap,
    failure: FailureState,
    writer_metrics: WriterMetrics,
) where
    W: AsyncWrite + Unpin,
{
    let mut burst_writer = AgentFrameBurstWriter::new();
    let mut burst_items = Vec::with_capacity(AGENT_FRAME_WRITE_BURST);
    while let Some(first) = outbound_rx.recv().await {
        burst_items.clear();
        let mut burst_bytes = first.encoded_len();
        burst_items.push(first);
        for _ in 1..AGENT_FRAME_WRITE_BURST {
            if burst_bytes >= AGENT_FRAME_WRITE_BURST_BYTES {
                break;
            }
            match outbound_rx.try_recv() {
                Ok(item) => {
                    burst_bytes = burst_bytes.saturating_add(item.encoded_len());
                    burst_items.push(item);
                }
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        writer_metrics.record_dequeued(&burst_items);
        match burst_writer.write_items(&mut writer, &burst_items).await {
            Ok(stats) => writer_metrics.record_burst(stats),
            Err(err) => {
                mark_agent_failed(&failure, &streams, err.to_string()).await;
                return;
            }
        }
    }
    let _ = writer.shutdown().await;
}

pub(super) async fn write_agent_frame<W>(writer: &mut W, frame: &AgentFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_agent_frame_unflushed(writer, frame).await?;
    writer.flush().await.context("failed to flush agent frame")
}
