use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::{
    read_agent_frames, run_agent_heartbeat, write_agent_frame, write_agent_frames, AgentHeartbeat,
    AgentHeartbeatGuard, AgentTransport,
};
use crate::agent_io::{AgentFrameReader, AgentFrameWriteQueue};
use crate::agent_proto::{
    AgentFrame, AgentFrameKind, AgentHello, AGENT_PROTOCOL_VERSION, CAP_FLOW_CONTROL, CAP_HEARTBEAT,
};

const AGENT_OUTBOUND_FRAMES: usize = 1024;

impl AgentTransport {
    pub async fn connect<R, W>(mut reader: R, mut writer: W, mtu: u16) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        write_agent_frame(
            &mut writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(mtu).encode())?,
        )
        .await?;

        let mut frame_reader = AgentFrameReader::new();
        let hello = frame_reader
            .read_frame(
                &mut reader,
                "failed to read agent frame",
                "agent stream closed before next frame",
            )
            .await?;
        if hello.kind != AgentFrameKind::Hello {
            bail!("agent expected hello response, got {:?}", hello.kind);
        }
        let peer = AgentHello::decode(&hello.payload)?;
        if peer.protocol_version != AGENT_PROTOCOL_VERSION {
            bail!(
                "unsupported agent protocol version {}",
                peer.protocol_version
            );
        }
        if peer.capabilities & CAP_FLOW_CONTROL == 0 {
            bail!("agent does not advertise flow-control support");
        }
        if peer.max_frame_payload == 0 {
            bail!("agent advertised zero max frame payload");
        }

        let (outbound, outbound_rx) = AgentFrameWriteQueue::channel(AGENT_OUTBOUND_FRAMES);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let failure = Arc::new(Mutex::new(None));
        let writer_metrics = Arc::new(super::AgentWriterMetrics::default());
        let heartbeat = Arc::new(Mutex::new(AgentHeartbeat::new()));
        let heartbeat_enabled = peer.capabilities & CAP_HEARTBEAT != 0;
        tokio::spawn(write_agent_frames(
            writer,
            outbound_rx,
            Arc::clone(&streams),
            Arc::clone(&failure),
            Arc::clone(&writer_metrics),
        ));
        tokio::spawn(read_agent_frames(
            reader,
            frame_reader,
            Arc::clone(&streams),
            Arc::clone(&failure),
            heartbeat_enabled.then(|| Arc::clone(&heartbeat)),
        ));
        let heartbeat_guard = if heartbeat_enabled {
            let task = tokio::spawn(run_agent_heartbeat(
                outbound.clone(),
                Arc::clone(&streams),
                Arc::clone(&failure),
                Arc::clone(&writer_metrics),
                heartbeat,
            ));
            Some(Arc::new(AgentHeartbeatGuard { task }))
        } else {
            None
        };

        Ok(Self {
            outbound,
            streams,
            failure,
            writer_metrics,
            peer,
            next_stream_id: Arc::new(AtomicU64::new(1)),
            _heartbeat_guard: heartbeat_guard,
        })
    }

    pub fn peer_hello(&self) -> AgentHello {
        self.peer
    }

    pub async fn failure_message(&self) -> Option<String> {
        self.failure.lock().await.clone()
    }

    pub(crate) fn writer_snapshot(&self) -> super::AgentWriterSnapshot {
        self.writer_metrics.snapshot()
    }
}
