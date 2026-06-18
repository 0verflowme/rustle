use std::collections::VecDeque;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::agent_proto::{
    encode_frame_into, encoded_frame_len, encoded_frames_len, try_decode_frame, AgentFrame,
    AgentFrameKind, AGENT_CARRIER_READ_BUFFER_BYTES, AGENT_MAX_FRAME_PAYLOAD,
};

pub(crate) const AGENT_FRAME_WRITE_BURST: usize = 64;
pub(crate) const AGENT_FRAME_WRITE_BURST_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct AgentFrameWriteQueue {
    priority_tx: mpsc::Sender<AgentFrameWriteItem>,
    data_tx: mpsc::Sender<AgentFrameWriteItem>,
}

pub(crate) struct AgentFrameWriteReceiver {
    priority_rx: mpsc::Receiver<AgentFrameWriteItem>,
    data_rx: mpsc::Receiver<AgentFrameWriteItem>,
    priority_closed: bool,
    data_closed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AgentFrameWriteItem {
    pub(crate) frame: AgentFrame,
    enqueued_at: Instant,
    encoded_len: usize,
}

impl AgentFrameWriteItem {
    pub(crate) fn new(frame: AgentFrame) -> Result<Self> {
        let encoded_len = encoded_frame_len(&frame)?;
        Ok(Self {
            frame,
            enqueued_at: Instant::now(),
            encoded_len,
        })
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    fn enqueue_wait_us(&self, write_started_at: Instant) -> u128 {
        write_started_at
            .checked_duration_since(self.enqueued_at)
            .unwrap_or_default()
            .as_micros()
    }
}

impl AgentFrameWriteQueue {
    pub(crate) fn channel(capacity: usize) -> (Self, AgentFrameWriteReceiver) {
        let (priority_tx, priority_rx) = mpsc::channel(capacity);
        let (data_tx, data_rx) = mpsc::channel(capacity);
        (
            Self {
                priority_tx,
                data_tx,
            },
            AgentFrameWriteReceiver {
                priority_rx,
                data_rx,
                priority_closed: false,
                data_closed: false,
            },
        )
    }

    pub(crate) async fn reserve_owned(
        &self,
        item: &AgentFrameWriteItem,
    ) -> Result<mpsc::OwnedPermit<AgentFrameWriteItem>, mpsc::error::SendError<()>> {
        self.sender_for(&item.frame).clone().reserve_owned().await
    }

    fn sender_for(&self, frame: &AgentFrame) -> &mpsc::Sender<AgentFrameWriteItem> {
        if frame.kind.is_priority_control() {
            &self.priority_tx
        } else {
            &self.data_tx
        }
    }
}

impl AgentFrameWriteReceiver {
    pub(crate) async fn recv(&mut self) -> Option<AgentFrameWriteItem> {
        loop {
            if let Some(item) = self.try_recv_priority() {
                return Some(item);
            }

            match (self.priority_closed, self.data_closed) {
                (true, true) => return None,
                (true, false) => return self.data_rx.recv().await,
                (false, true) => {
                    let item = self.priority_rx.recv().await;
                    if item.is_none() {
                        self.priority_closed = true;
                    }
                    return item;
                }
                (false, false) => {}
            }

            tokio::select! {
                biased;
                priority = self.priority_rx.recv() => {
                    match priority {
                        Some(item) => return Some(item),
                        None => self.priority_closed = true,
                    }
                }
                data = self.data_rx.recv() => {
                    match data {
                        Some(item) => return Some(item),
                        None => self.data_closed = true,
                    }
                }
            }
        }
    }

    pub(crate) fn try_recv_priority(&mut self) -> Option<AgentFrameWriteItem> {
        if self.priority_closed {
            return None;
        }
        match self.priority_rx.try_recv() {
            Ok(item) => Some(item),
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.priority_closed = true;
                None
            }
        }
    }

    pub(crate) fn try_recv_data(&mut self) -> Option<AgentFrameWriteItem> {
        if self.data_closed {
            return None;
        }
        match self.data_rx.try_recv() {
            Ok(item) => Some(item),
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.data_closed = true;
                None
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AgentFrameBurstWriteStats {
    pub(crate) frames: usize,
    pub(crate) bytes: usize,
    pub(crate) enqueue_to_write_us: u128,
    pub(crate) enqueue_to_write_max_us: u128,
    pub(crate) write_us: u128,
    pub(crate) flush_us: u128,
}

pub(crate) struct AgentFrameReader {
    input: BytesMut,
    read_buf: Vec<u8>,
}

impl AgentFrameReader {
    pub(crate) fn new() -> Self {
        Self::from_input(BytesMut::with_capacity(AGENT_MAX_FRAME_PAYLOAD))
    }

    pub(crate) fn from_input(input: BytesMut) -> Self {
        Self {
            input,
            read_buf: vec![0_u8; AGENT_CARRIER_READ_BUFFER_BYTES],
        }
    }

    #[cfg(test)]
    pub(crate) fn into_input(self) -> BytesMut {
        self.input
    }

    pub(crate) fn try_next_frame(&mut self) -> Result<Option<AgentFrame>> {
        try_decode_frame(&mut self.input)
    }

    pub(crate) async fn read_more<R>(
        &mut self,
        reader: &mut R,
        context: &'static str,
    ) -> Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        let read = reader.read(&mut self.read_buf).await.context(context)?;
        if read != 0 {
            self.input.extend_from_slice(&self.read_buf[..read]);
        }
        Ok(read)
    }

    pub(crate) async fn read_frame<R>(
        &mut self,
        reader: &mut R,
        read_context: &'static str,
        closed_context: &'static str,
    ) -> Result<AgentFrame>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some(frame) = self.try_next_frame()? {
                return Ok(frame);
            }
            if self.read_more(reader, read_context).await? == 0 {
                bail!("{closed_context}");
            }
        }
    }
}

pub(crate) struct AgentFrameBurstWriter {
    frames: Vec<AgentFrame>,
    encoded: BytesMut,
}

impl AgentFrameBurstWriter {
    pub(crate) fn new() -> Self {
        Self {
            frames: Vec::with_capacity(AGENT_FRAME_WRITE_BURST),
            encoded: BytesMut::new(),
        }
    }

    pub(crate) async fn write_items<W>(
        &mut self,
        writer: &mut W,
        items: &[AgentFrameWriteItem],
    ) -> Result<AgentFrameBurstWriteStats>
    where
        W: AsyncWrite + Unpin,
    {
        self.frames.clear();
        self.frames
            .extend(items.iter().map(|item| item.frame.clone()));
        let mut stats = AgentFrameBurstWriteStats {
            frames: items.len(),
            bytes: items.iter().map(AgentFrameWriteItem::encoded_len).sum(),
            ..AgentFrameBurstWriteStats::default()
        };
        let write_started_at = Instant::now();
        for item in items {
            let wait_us = item.enqueue_wait_us(write_started_at);
            stats.enqueue_to_write_us = stats.enqueue_to_write_us.saturating_add(wait_us);
            stats.enqueue_to_write_max_us = stats.enqueue_to_write_max_us.max(wait_us);
        }
        let io_stats = self.write_frames(writer).await?;
        stats.write_us = io_stats.write_us;
        stats.flush_us = io_stats.flush_us;
        Ok(stats)
    }

    async fn write_frames<W>(&mut self, writer: &mut W) -> Result<AgentFrameBurstWriteStats>
    where
        W: AsyncWrite + Unpin,
    {
        let mut stats = AgentFrameBurstWriteStats {
            frames: self.frames.len(),
            bytes: encoded_frames_len(self.frames.iter())?,
            ..AgentFrameBurstWriteStats::default()
        };
        let write_started_at = Instant::now();
        write_agent_frame_burst_ordered(writer, &self.frames, &mut self.encoded).await?;
        stats.write_us = write_started_at.elapsed().as_micros();
        let flush_started_at = Instant::now();
        writer
            .flush()
            .await
            .context("failed to flush agent frame")?;
        stats.flush_us = flush_started_at.elapsed().as_micros();
        Ok(stats)
    }
}

pub(crate) async fn write_agent_frame_unflushed<W>(writer: &mut W, frame: &AgentFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = BytesMut::with_capacity(encoded_frames_len([frame])?);
    encode_frame_into(frame, &mut encoded).context("failed to encode agent frame")?;
    writer
        .write_all(&encoded)
        .await
        .context("failed to write agent frame")
}

async fn write_agent_frame_burst_ordered<W>(
    writer: &mut W,
    frames: &[AgentFrame],
    encoded: &mut BytesMut,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    encoded.clear();
    encoded.reserve(encoded_frames_len(frames.iter())?);

    if frames
        .first()
        .is_some_and(|frame| frame.kind == AgentFrameKind::Hello)
    {
        for frame in frames {
            encode_frame_into(frame, &mut *encoded).context("failed to encode agent frame")?;
        }
    } else {
        for frame in frames.iter().filter(|frame| is_priority_control(frame)) {
            encode_frame_into(frame, &mut *encoded).context("failed to encode agent frame")?;
        }
        encode_non_priority_frames_fairly(frames, encoded)?;
    }

    writer
        .write_all(encoded)
        .await
        .context("failed to write agent frame")
}

fn encode_non_priority_frames_fairly(frames: &[AgentFrame], encoded: &mut BytesMut) -> Result<()> {
    let mut queues: Vec<(u64, VecDeque<&AgentFrame>)> = Vec::new();
    let mut queued = 0_usize;
    for frame in frames.iter().filter(|frame| !is_priority_control(frame)) {
        queued = queued.saturating_add(1);
        if let Some((_, queue)) = queues
            .iter_mut()
            .find(|(stream_id, _)| *stream_id == frame.stream_id)
        {
            queue.push_back(frame);
        } else {
            queues.push((frame.stream_id, VecDeque::from([frame])));
        }
    }

    while queued > 0 {
        for (_, queue) in &mut queues {
            if let Some(frame) = queue.pop_front() {
                encode_frame_into(frame, &mut *encoded).context("failed to encode agent frame")?;
                queued -= 1;
            }
        }
    }
    Ok(())
}

fn is_priority_control(frame: &AgentFrame) -> bool {
    frame.kind.is_priority_control()
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
    use tokio::io::AsyncWrite;

    use super::*;

    #[derive(Default)]
    struct VecWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl AsyncWrite for VecWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn burst_writer_reports_exact_frame_byte_and_wait_stats() {
        let frames = [
            AgentFrame::new(AgentFrameKind::Window, 7, Bytes::new())
                .unwrap()
                .with_credit(32),
            AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from_static(b"abc")).unwrap(),
        ];
        let items = frames
            .iter()
            .cloned()
            .map(AgentFrameWriteItem::new)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;

        let mut writer = VecWriter::default();
        let mut burst = AgentFrameBurstWriter::new();
        let stats = burst
            .write_items(&mut writer, &items)
            .await
            .expect("write burst");

        assert_eq!(stats.frames, frames.len());
        assert_eq!(stats.bytes, encoded_frames_len(frames.iter()).unwrap());
        assert!(stats.enqueue_to_write_us > 1);
        assert!(stats.enqueue_to_write_max_us > 1);
        assert_eq!(writer.flushes, 1);

        let mut encoded = BytesMut::from(writer.bytes.as_slice());
        assert_eq!(try_decode_frame(&mut encoded).unwrap().unwrap(), frames[0]);
        assert_eq!(try_decode_frame(&mut encoded).unwrap().unwrap(), frames[1]);
        assert!(encoded.is_empty());
    }
}
