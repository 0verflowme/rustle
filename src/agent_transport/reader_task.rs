use std::time::Instant;

use tokio::io::AsyncRead;

use super::{mark_agent_failed, FailureState, HeartbeatState, StreamMap};
use crate::agent_io::AgentFrameReader;
use crate::agent_proto::{AgentFrame, AgentFrameKind};

pub(super) async fn read_agent_frames<R>(
    mut reader: R,
    mut frame_reader: AgentFrameReader,
    streams: StreamMap,
    failure: FailureState,
    heartbeat: Option<HeartbeatState>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        match frame_reader
            .read_frame(
                &mut reader,
                "failed to read agent frame",
                "agent stream closed before next frame",
            )
            .await
        {
            Ok(frame) => dispatch_agent_frame(&streams, heartbeat.as_ref(), frame).await,
            Err(err) => {
                mark_agent_failed(&failure, &streams, err.to_string()).await;
                return;
            }
        }
    }
}

pub(super) async fn dispatch_agent_frame(
    streams: &StreamMap,
    heartbeat: Option<&HeartbeatState>,
    frame: AgentFrame,
) {
    if let Some(heartbeat) = heartbeat {
        let mut heartbeat = heartbeat.lock().await;
        heartbeat.last_peer_activity = Instant::now();
        if frame.kind == AgentFrameKind::Pong && frame.stream_id == 0 {
            heartbeat.received_pongs = heartbeat.received_pongs.saturating_add(1);
        }
    }

    if frame.stream_id == 0 {
        return;
    }

    let entry = {
        let streams = streams.lock().await;
        streams.get(&frame.stream_id).cloned()
    };
    let Some(entry) = entry else {
        return;
    };

    if frame.kind == AgentFrameKind::Window {
        if frame.credit > 0 {
            entry.send_credit.add_permits(frame.credit as usize);
        }
        return;
    }
    if frame.kind == AgentFrameKind::Opened && entry.optimistic_open_credit > 0 {
        let additional_credit =
            (frame.credit as usize).saturating_sub(entry.optimistic_open_credit);
        if additional_credit > 0 {
            entry.send_credit.add_permits(additional_credit);
        }
    }
    if matches!(frame.kind, AgentFrameKind::Close | AgentFrameKind::Reset) {
        entry.send_credit.close();
    }

    let stream_id = frame.stream_id;
    if entry.inbound.try_send(frame).is_err() {
        entry.send_credit.close();
        let mut streams = streams.lock().await;
        streams.remove(&stream_id);
    }
}
