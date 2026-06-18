use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::anyhow;
use tokio::sync::Mutex;

use super::affinity::agent_lane_backoff_duration;
use super::carrier::AgentBridgeTransport;
use crate::agent_transport;

pub(super) struct AgentBridgeLane {
    pub(super) index: usize,
    pub(super) agent_command: Mutex<String>,
    pub(super) inner: Mutex<Option<AgentBridgeTransport>>,
    health: Mutex<AgentLaneHealth>,
    load: Arc<AtomicUsize>,
}

impl AgentBridgeLane {
    pub(super) fn new(
        index: usize,
        agent_command: impl Into<String>,
        transport: Option<AgentBridgeTransport>,
    ) -> Self {
        Self {
            index,
            agent_command: Mutex::new(agent_command.into()),
            inner: Mutex::new(transport),
            health: Mutex::new(AgentLaneHealth::default()),
            load: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) async fn current_transport(&self) -> Option<agent_transport::AgentTransport> {
        self.inner
            .lock()
            .await
            .as_ref()
            .map(|inner| inner.transport.clone())
    }

    pub(super) fn load(&self) -> usize {
        self.load.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn set_load(&self, load: usize) {
        self.load.store(load, Ordering::Release);
    }

    pub(super) fn load_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.load)
    }

    pub(super) async fn selection_status(&self) -> AgentLaneSelectionStatus {
        if self.quarantine_remaining().await.is_some() {
            return AgentLaneSelectionStatus::Quarantined;
        }
        if self.is_repairing().await {
            return AgentLaneSelectionStatus::Repairing;
        }
        match self.current_transport().await {
            Some(transport) => {
                if let Some(failure) = transport.failure_message().await {
                    AgentLaneSelectionStatus::Failed { failure }
                } else {
                    AgentLaneSelectionStatus::Available { load: self.load() }
                }
            }
            None => AgentLaneSelectionStatus::Missing,
        }
    }

    pub(super) async fn is_repairing(&self) -> bool {
        self.health.lock().await.background_repair_in_progress
    }

    pub(super) fn try_start_background_repair(&self) -> bool {
        let Ok(mut health) = self.health.try_lock() else {
            return false;
        };
        if health.background_repair_in_progress || health.quarantine_until.is_some() {
            return false;
        }
        health.background_repair_in_progress = true;
        true
    }

    pub(super) async fn finish_background_repair(&self) {
        let mut health = self.health.lock().await;
        health.background_repair_in_progress = false;
    }

    pub(super) async fn snapshot_health(&self) -> (Option<u64>, bool) {
        let mut health = self.health.lock().await;
        let quarantine_ms = match health.quarantine_until {
            Some(until) => match until.checked_duration_since(StdInstant::now()) {
                Some(remaining) if remaining.as_nanos() > 0 => {
                    Some(remaining.as_millis().try_into().unwrap_or(u64::MAX))
                }
                _ => {
                    health.quarantine_until = None;
                    None
                }
            },
            None => None,
        };
        (quarantine_ms, health.background_repair_in_progress)
    }

    pub(super) async fn quarantined_error(&self) -> Option<anyhow::Error> {
        self.quarantine_remaining().await.map(|remaining| {
            anyhow!(
                "agent lane {} is quarantined for {}ms after reconnect failures",
                self.index,
                remaining.as_millis()
            )
        })
    }

    pub(super) async fn quarantine_remaining(&self) -> Option<Duration> {
        let mut health = self.health.lock().await;
        let until = health.quarantine_until?;
        match until.checked_duration_since(StdInstant::now()) {
            Some(remaining) if remaining.as_nanos() > 0 => Some(remaining),
            _ => {
                health.quarantine_until = None;
                None
            }
        }
    }

    pub(super) async fn mark_open_success(&self) {
        let mut health = self.health.lock().await;
        health.consecutive_reconnect_failures = 0;
        health.quarantine_until = None;
        health.background_repair_in_progress = false;
    }

    pub(super) async fn mark_reconnect_failure(&self) -> Duration {
        let mut health = self.health.lock().await;
        health.consecutive_reconnect_failures =
            health.consecutive_reconnect_failures.saturating_add(1);
        let backoff =
            agent_lane_backoff_duration(self.index, health.consecutive_reconnect_failures);
        health.quarantine_until = Some(StdInstant::now() + backoff);
        backoff
    }
}

#[derive(Debug, Default)]
struct AgentLaneHealth {
    consecutive_reconnect_failures: u32,
    quarantine_until: Option<StdInstant>,
    background_repair_in_progress: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AgentLaneSelectionStatus {
    Available { load: usize },
    Failed { failure: String },
    Missing,
    Repairing,
    Quarantined,
}

#[derive(Debug, Default)]
pub(super) struct AgentReconnectCounters {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
}

impl AgentReconnectCounters {
    pub(super) fn snapshot(&self) -> AgentReconnectSnapshot {
        AgentReconnectSnapshot {
            attempts: self.attempts.load(Ordering::Acquire),
            successes: self.successes.load(Ordering::Acquire),
            failures: self.failures.load(Ordering::Acquire),
        }
    }

    pub(super) fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AgentReconnectSnapshot {
    pub(crate) attempts: u64,
    pub(crate) successes: u64,
    pub(crate) failures: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AgentBridgeSnapshot {
    pub(crate) reconnects: AgentReconnectSnapshot,
    pub(crate) lanes_total: usize,
    pub(crate) lanes_desired: usize,
    pub(crate) lanes_available: usize,
    pub(crate) lanes_failed: usize,
    pub(crate) lanes_missing: usize,
    pub(crate) lanes_quarantined: usize,
    pub(crate) lanes_repairing: usize,
    pub(crate) max_quarantine_ms: u64,
    pub(crate) active_streams: usize,
    pub(crate) max_lane_load: usize,
    pub(crate) writer_queued_frames: usize,
    pub(crate) writer_queued_bytes: usize,
    pub(crate) writer_queued_frames_max: usize,
    pub(crate) writer_queued_bytes_max: usize,
    pub(crate) writer_bursts: u64,
    pub(crate) writer_burst_frames: u64,
    pub(crate) writer_burst_bytes: u64,
    pub(crate) writer_burst_frames_max: u64,
    pub(crate) writer_burst_bytes_max: u64,
    pub(crate) writer_enqueue_to_write_us: u64,
    pub(crate) writer_enqueue_to_write_max_us: u64,
    pub(crate) writer_enqueue_to_write_samples: u64,
    pub(crate) writer_write_us: u64,
    pub(crate) writer_write_max_us: u64,
    pub(crate) writer_flush_us: u64,
    pub(crate) writer_flush_max_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lane_repair_flag_blocks_duplicates_and_drives_selection_status() {
        let lane = AgentBridgeLane::new(0, "rustle agent", None);

        assert!(!lane.is_repairing().await);
        assert!(lane.try_start_background_repair());
        assert!(lane.is_repairing().await);
        assert_eq!(
            lane.selection_status().await,
            AgentLaneSelectionStatus::Repairing
        );
        assert!(
            !lane.try_start_background_repair(),
            "duplicate repair should be coalesced while one is in progress"
        );

        lane.finish_background_repair().await;
        assert!(!lane.is_repairing().await);
        assert_eq!(
            lane.selection_status().await,
            AgentLaneSelectionStatus::Missing
        );
    }

    #[tokio::test]
    async fn reconnect_failure_quarantines_lane_until_open_success_clears_health() {
        let lane = AgentBridgeLane::new(2, "rustle agent", None);
        let expected = agent_lane_backoff_duration(2, 1);

        assert_eq!(lane.mark_reconnect_failure().await, expected);
        let remaining = lane
            .quarantine_remaining()
            .await
            .expect("lane should be quarantined");
        assert!(remaining > Duration::ZERO);
        assert!(remaining <= expected);
        assert_eq!(
            lane.selection_status().await,
            AgentLaneSelectionStatus::Quarantined
        );
        let err = lane.quarantined_error().await.expect("quarantined error");
        assert!(err.to_string().contains("lane 2"));
        let (quarantine_ms, repairing) = lane.snapshot_health().await;
        assert!(quarantine_ms.is_some());
        assert!(!repairing);

        lane.mark_open_success().await;
        assert!(lane.quarantine_remaining().await.is_none());
        assert_eq!(
            lane.selection_status().await,
            AgentLaneSelectionStatus::Missing
        );
        let (quarantine_ms, repairing) = lane.snapshot_health().await;
        assert_eq!(quarantine_ms, None);
        assert!(!repairing);
    }

    #[tokio::test]
    async fn open_success_resets_repairing_and_failure_backoff_state() {
        let lane = AgentBridgeLane::new(1, "rustle agent", None);

        assert!(lane.try_start_background_repair());
        let first = lane.mark_reconnect_failure().await;
        lane.finish_background_repair().await;
        let second = lane.mark_reconnect_failure().await;
        assert!(second > first);

        {
            let mut health = lane.health.lock().await;
            health.background_repair_in_progress = true;
        }
        lane.mark_open_success().await;
        assert!(!lane.is_repairing().await);
        assert!(lane.quarantine_remaining().await.is_none());
        assert_eq!(lane.mark_reconnect_failure().await, first);
    }
}
