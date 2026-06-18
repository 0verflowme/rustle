use std::sync::atomic::{AtomicU64, Ordering};

use crate::agent_io::{AgentFrameBurstWriteStats, AgentFrameWriteItem};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AgentWriterSnapshot {
    pub(crate) queued_frames: usize,
    pub(crate) queued_bytes: usize,
    pub(crate) queued_frames_max: usize,
    pub(crate) queued_bytes_max: usize,
    pub(crate) bursts: u64,
    pub(crate) burst_frames: u64,
    pub(crate) burst_bytes: u64,
    pub(crate) burst_frames_max: u64,
    pub(crate) burst_bytes_max: u64,
    pub(crate) enqueue_to_write_us: u64,
    pub(crate) enqueue_to_write_max_us: u64,
    pub(crate) enqueue_to_write_samples: u64,
    pub(crate) write_us: u64,
    pub(crate) write_max_us: u64,
    pub(crate) flush_us: u64,
    pub(crate) flush_max_us: u64,
}

#[derive(Debug, Default)]
pub(super) struct AgentWriterMetrics {
    queued_frames: AtomicU64,
    queued_bytes: AtomicU64,
    queued_frames_max: AtomicU64,
    queued_bytes_max: AtomicU64,
    bursts: AtomicU64,
    burst_frames: AtomicU64,
    burst_bytes: AtomicU64,
    burst_frames_max: AtomicU64,
    burst_bytes_max: AtomicU64,
    enqueue_to_write_us: AtomicU64,
    enqueue_to_write_max_us: AtomicU64,
    enqueue_to_write_samples: AtomicU64,
    write_us: AtomicU64,
    write_max_us: AtomicU64,
    flush_us: AtomicU64,
    flush_max_us: AtomicU64,
}

impl AgentWriterMetrics {
    pub(super) fn record_enqueued(&self, encoded_len: usize) {
        let frames = self
            .queued_frames
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let bytes = self
            .queued_bytes
            .fetch_add(encoded_len as u64, Ordering::AcqRel)
            .saturating_add(encoded_len as u64);
        self.queued_frames_max.fetch_max(frames, Ordering::AcqRel);
        self.queued_bytes_max.fetch_max(bytes, Ordering::AcqRel);
    }

    pub(super) fn record_dequeued(&self, items: &[AgentFrameWriteItem]) {
        let frames = items.len() as u64;
        let bytes = items
            .iter()
            .map(|item| item.encoded_len() as u64)
            .sum::<u64>();
        if frames > 0 {
            self.queued_frames.fetch_sub(frames, Ordering::AcqRel);
        }
        if bytes > 0 {
            self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    pub(super) fn record_burst(&self, stats: AgentFrameBurstWriteStats) {
        let frames = stats.frames as u64;
        let bytes = stats.bytes as u64;
        self.bursts.fetch_add(1, Ordering::AcqRel);
        self.burst_frames.fetch_add(frames, Ordering::AcqRel);
        self.burst_bytes.fetch_add(bytes, Ordering::AcqRel);
        self.burst_frames_max.fetch_max(frames, Ordering::AcqRel);
        self.burst_bytes_max.fetch_max(bytes, Ordering::AcqRel);

        let enqueue_to_write_us = duration_micros_to_u64(stats.enqueue_to_write_us);
        let enqueue_to_write_max_us = duration_micros_to_u64(stats.enqueue_to_write_max_us);
        self.enqueue_to_write_us
            .fetch_add(enqueue_to_write_us, Ordering::AcqRel);
        self.enqueue_to_write_max_us
            .fetch_max(enqueue_to_write_max_us, Ordering::AcqRel);
        self.enqueue_to_write_samples
            .fetch_add(frames, Ordering::AcqRel);

        let write_us = duration_micros_to_u64(stats.write_us);
        let flush_us = duration_micros_to_u64(stats.flush_us);
        self.write_us.fetch_add(write_us, Ordering::AcqRel);
        self.write_max_us.fetch_max(write_us, Ordering::AcqRel);
        self.flush_us.fetch_add(flush_us, Ordering::AcqRel);
        self.flush_max_us.fetch_max(flush_us, Ordering::AcqRel);
    }

    pub(super) fn snapshot(&self) -> AgentWriterSnapshot {
        AgentWriterSnapshot {
            queued_frames: usize::try_from(self.queued_frames.load(Ordering::Acquire))
                .unwrap_or(usize::MAX),
            queued_bytes: usize::try_from(self.queued_bytes.load(Ordering::Acquire))
                .unwrap_or(usize::MAX),
            queued_frames_max: usize::try_from(self.queued_frames_max.load(Ordering::Acquire))
                .unwrap_or(usize::MAX),
            queued_bytes_max: usize::try_from(self.queued_bytes_max.load(Ordering::Acquire))
                .unwrap_or(usize::MAX),
            bursts: self.bursts.load(Ordering::Acquire),
            burst_frames: self.burst_frames.load(Ordering::Acquire),
            burst_bytes: self.burst_bytes.load(Ordering::Acquire),
            burst_frames_max: self.burst_frames_max.load(Ordering::Acquire),
            burst_bytes_max: self.burst_bytes_max.load(Ordering::Acquire),
            enqueue_to_write_us: self.enqueue_to_write_us.load(Ordering::Acquire),
            enqueue_to_write_max_us: self.enqueue_to_write_max_us.load(Ordering::Acquire),
            enqueue_to_write_samples: self.enqueue_to_write_samples.load(Ordering::Acquire),
            write_us: self.write_us.load(Ordering::Acquire),
            write_max_us: self.write_max_us.load(Ordering::Acquire),
            flush_us: self.flush_us.load(Ordering::Acquire),
            flush_max_us: self.flush_max_us.load(Ordering::Acquire),
        }
    }
}

fn duration_micros_to_u64(micros: u128) -> u64 {
    u64::try_from(micros).unwrap_or(u64::MAX)
}
