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
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + AGENT_HEARTBEAT_INTERVAL,
        AGENT_HEARTBEAT_INTERVAL,
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
        let frame =
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).expect("empty heartbeat frame");
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
