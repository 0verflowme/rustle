use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    ensure_agent_ready, mark_agent_failed, send_agent_transport_frame, AgentFrameSendContext,
    FailureState, HeartbeatState, StreamMap, WriterMetrics, AGENT_FRAME_SEND_TIMEOUT,
};
use crate::agent_io::AgentFrameWriteQueue;
use crate::agent_proto::{AgentFrame, AgentFrameKind};

const AGENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const AGENT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
thread_local! {
    static AGENT_HEARTBEAT_INTERVAL_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

fn agent_heartbeat_interval() -> Duration {
    #[cfg(test)]
    if let Some(interval) = AGENT_HEARTBEAT_INTERVAL_OVERRIDE.with(|override_| override_.get()) {
        return interval;
    }

    AGENT_HEARTBEAT_INTERVAL
}

#[derive(Clone, Debug)]
pub(super) struct AgentHeartbeat {
    pub(super) last_peer_activity: Instant,
    pub(super) sent: u64,
    pub(super) received_pongs: u64,
}

impl AgentHeartbeat {
    pub(super) fn new() -> Self {
        Self {
            last_peer_activity: Instant::now(),
            sent: 0,
            received_pongs: 0,
        }
    }
}

pub(super) async fn run_agent_heartbeat(
    outbound: AgentFrameWriteQueue,
    streams: StreamMap,
    failure: FailureState,
    writer_metrics: WriterMetrics,
    heartbeat: HeartbeatState,
) {
    let heartbeat_interval = agent_heartbeat_interval();
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + heartbeat_interval,
        heartbeat_interval,
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tick.tick().await;
        if ensure_agent_ready(&failure).await.is_err() {
            return;
        }

        let elapsed = {
            let heartbeat = heartbeat.lock().await;
            heartbeat.last_peer_activity.elapsed()
        };
        if elapsed > AGENT_HEARTBEAT_TIMEOUT {
            mark_agent_failed(
                &failure,
                &streams,
                format!(
                    "agent heartbeat timed out after {}s without peer activity",
                    AGENT_HEARTBEAT_TIMEOUT.as_secs()
                ),
            )
            .await;
            return;
        }

        {
            let mut heartbeat = heartbeat.lock().await;
            heartbeat.sent = heartbeat.sent.saturating_add(1);
        }
        let frame = match AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()) {
            Ok(frame) => frame,
            Err(err) => {
                mark_agent_failed(
                    &failure,
                    &streams,
                    format!("failed to build agent heartbeat ping: {err}"),
                )
                .await;
                return;
            }
        };
        if send_agent_transport_frame(
            AgentFrameSendContext {
                outbound: &outbound,
                streams: &streams,
                failure: &failure,
                writer_metrics: &writer_metrics,
            },
            frame,
            AGENT_FRAME_SEND_TIMEOUT,
            "agent heartbeat ping",
        )
        .await
        .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Mutex;
    use tokio::time::timeout;

    use super::super::{FailureState, HeartbeatState, StreamMap, WriterMetrics};
    use super::{run_agent_heartbeat, AgentHeartbeat, AGENT_HEARTBEAT_INTERVAL_OVERRIDE};
    use crate::agent_io::AgentFrameWriteQueue;
    use crate::agent_proto::AgentFrameKind;

    struct HeartbeatIntervalOverride {
        previous: Option<Duration>,
    }

    impl HeartbeatIntervalOverride {
        fn set(interval: Duration) -> Self {
            let previous = AGENT_HEARTBEAT_INTERVAL_OVERRIDE.with(|override_| {
                let previous = override_.get();
                override_.set(Some(interval));
                previous
            });
            Self { previous }
        }
    }

    impl Drop for HeartbeatIntervalOverride {
        fn drop(&mut self) {
            AGENT_HEARTBEAT_INTERVAL_OVERRIDE.with(|override_| {
                override_.set(self.previous);
            });
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_agent_heartbeat_queues_ping_and_counts_sent() {
        let _interval_override = HeartbeatIntervalOverride::set(Duration::from_millis(5));
        let (outbound, mut outbound_rx) = AgentFrameWriteQueue::channel(4);
        let streams: StreamMap = Arc::new(Mutex::new(HashMap::new()));
        let failure: FailureState = Arc::new(Mutex::new(None));
        let writer_metrics: WriterMetrics = Arc::new(Default::default());
        let heartbeat: HeartbeatState = Arc::new(Mutex::new(AgentHeartbeat::new()));

        let task = tokio::spawn(run_agent_heartbeat(
            outbound,
            streams,
            failure,
            Arc::clone(&writer_metrics),
            Arc::clone(&heartbeat),
        ));

        let item = timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("heartbeat should queue a ping")
            .expect("heartbeat writer queue should stay open");
        task.abort();
        let _ = task.await;

        assert_eq!(item.frame.kind, AgentFrameKind::Ping);
        assert_eq!(item.frame.stream_id, 0);
        assert!(item.frame.payload.is_empty());
        assert!(
            heartbeat.lock().await.sent >= 1,
            "heartbeat sent counter should increment"
        );
        assert!(
            writer_metrics.snapshot().queued_frames >= 1,
            "writer metrics should record the queued heartbeat ping"
        );
    }
}
