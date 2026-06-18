use anyhow::{bail, Result};
use bytes::Bytes;

use super::{FailureState, StreamEntry, StreamMap};
use crate::agent_proto::{AgentFrame, AgentFrameKind};

pub(super) const AGENT_STREAM_RESET_BYTES: usize = 512;

async fn reset_all_streams(streams: &StreamMap, message: String) {
    let entries: Vec<(u64, StreamEntry)> = {
        let mut streams = streams.lock().await;
        streams.drain().collect()
    };
    let payload = Bytes::copy_from_slice(truncate_reset_message(&message).as_bytes());

    for (stream_id, entry) in entries {
        entry.send_credit.close();
        let _ = entry.inbound.try_send(
            AgentFrame::new(AgentFrameKind::Reset, stream_id, payload.clone())
                .expect("reset frame payload is bounded"),
        );
    }
}

pub(super) async fn mark_agent_failed(
    failure: &FailureState,
    streams: &StreamMap,
    message: String,
) {
    let should_reset = {
        let mut failure = failure.lock().await;
        if failure.is_some() {
            false
        } else {
            *failure = Some(message.clone());
            true
        }
    };

    if should_reset {
        reset_all_streams(streams, message).await;
    }
}

pub(super) async fn ensure_agent_ready(failure: &FailureState) -> Result<()> {
    if let Some(message) = failure.lock().await.clone() {
        bail!("agent transport closed: {message}");
    }
    Ok(())
}

pub(super) fn truncate_reset_message(message: &str) -> String {
    if message.len() <= AGENT_STREAM_RESET_BYTES {
        return message.to_owned();
    }
    let mut truncated = String::with_capacity(AGENT_STREAM_RESET_BYTES);
    for ch in message.chars() {
        if truncated.len() + ch.len_utf8() > AGENT_STREAM_RESET_BYTES {
            break;
        }
        truncated.push(ch);
    }
    truncated
}
