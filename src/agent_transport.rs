use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, Semaphore};

mod connect;
mod failure;
mod heartbeat;
mod open;
mod reader_task;
mod stream;
mod writer_metrics;
mod writer_task;

use crate::agent_io::AgentFrameWriteItem;
use crate::agent_proto::{AgentFrame, AgentHello};

use failure::{ensure_agent_ready, mark_agent_failed};
use heartbeat::{run_agent_heartbeat, AgentHeartbeat};
#[cfg(test)]
use reader_task::dispatch_agent_frame;
use reader_task::read_agent_frames;
pub use stream::AgentStream;
pub(crate) use stream::AgentStreamSendMetrics;
use stream::{send_agent_transport_frame, AgentFrameSendContext, AGENT_FRAME_SEND_TIMEOUT};
use writer_metrics::AgentWriterMetrics;
pub(crate) use writer_metrics::AgentWriterSnapshot;
use writer_task::{write_agent_frame, write_agent_frames};

type StreamMap = Arc<Mutex<HashMap<u64, StreamEntry>>>;
type FailureState = Arc<Mutex<Option<String>>>;
type HeartbeatState = Arc<Mutex<AgentHeartbeat>>;
type WriterMetrics = Arc<AgentWriterMetrics>;

#[derive(Clone, Debug)]
struct StreamEntry {
    inbound: mpsc::Sender<AgentFrame>,
    send_credit: Arc<Semaphore>,
    optimistic_open_credit: usize,
}

#[derive(Clone, Debug)]
pub struct AgentTransport {
    outbound: mpsc::Sender<AgentFrameWriteItem>,
    streams: StreamMap,
    failure: FailureState,
    writer_metrics: WriterMetrics,
    peer: AgentHello,
    next_stream_id: Arc<AtomicU64>,
    _heartbeat_guard: Option<Arc<AgentHeartbeatGuard>>,
}

#[derive(Debug)]
struct AgentHeartbeatGuard {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AgentHeartbeatGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
