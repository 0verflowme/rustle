use std::sync::OnceLock;
use std::time::Instant;

use crate::tcp_core;

const HOTPATH_TRACE_ENV: &str = "RUSTLE_HOTPATH_TRACE";

static HOTPATH_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();

pub(crate) struct TcpFlowTrace {
    enabled: bool,
    transport: &'static str,
    id: tcp_core::FlowId,
    started_at: Instant,
    ready_wait_us: u128,
    stream_ready_us: Option<u128>,
    opened_us: Option<u128>,
    agent_remote_connect_us: Option<u128>,
    first_local_us: Option<u128>,
    first_local_sent_us: Option<u128>,
    first_remote_us: Option<u128>,
    local_send_wait_us: u128,
    local_send_wait_max_us: u128,
    local_send_waits: u64,
    tcp_recv_queue_wait_us: u128,
    tcp_recv_queue_wait_max_us: u128,
    tcp_recv_queue_waits: u64,
    local_queue_wait_us: u128,
    local_queue_wait_max_us: u128,
    local_queue_waits: u64,
    agent_send_credit_wait_us: u128,
    agent_send_credit_wait_max_us: u128,
    agent_send_outbound_wait_us: u128,
    agent_send_outbound_wait_max_us: u128,
    agent_send_frames: u64,
    remote_event_wait_us: u128,
    remote_event_wait_max_us: u128,
    remote_event_waits: u64,
    local_bytes: u64,
    remote_bytes: u64,
    outcome: &'static str,
    emitted: bool,
}

struct TcpFlowTraceSummary {
    transport: &'static str,
    id: tcp_core::FlowId,
    ready_wait_us: u128,
    stream_ready_us: Option<u128>,
    opened_us: Option<u128>,
    agent_remote_connect_us: Option<u128>,
    first_local_us: Option<u128>,
    first_local_sent_us: Option<u128>,
    first_remote_us: Option<u128>,
    local_send_wait_us: u128,
    local_send_wait_max_us: u128,
    local_send_waits: u64,
    tcp_recv_queue_wait_us: u128,
    tcp_recv_queue_wait_max_us: u128,
    tcp_recv_queue_waits: u64,
    local_queue_wait_us: u128,
    local_queue_wait_max_us: u128,
    local_queue_waits: u64,
    agent_send_credit_wait_us: u128,
    agent_send_credit_wait_max_us: u128,
    agent_send_outbound_wait_us: u128,
    agent_send_outbound_wait_max_us: u128,
    agent_send_frames: u64,
    remote_event_wait_us: u128,
    remote_event_wait_max_us: u128,
    remote_event_waits: u64,
    duration_us: u128,
    local_bytes: u64,
    remote_bytes: u64,
    outcome: &'static str,
}

impl TcpFlowTrace {
    pub(crate) fn new(transport: &'static str, id: tcp_core::FlowId, ready_wait_ms: u64) -> Self {
        Self {
            enabled: hotpath_trace_enabled(),
            transport,
            id,
            started_at: Instant::now(),
            ready_wait_us: u128::from(ready_wait_ms).saturating_mul(1000),
            stream_ready_us: None,
            opened_us: None,
            agent_remote_connect_us: None,
            first_local_us: None,
            first_local_sent_us: None,
            first_remote_us: None,
            local_send_wait_us: 0,
            local_send_wait_max_us: 0,
            local_send_waits: 0,
            tcp_recv_queue_wait_us: 0,
            tcp_recv_queue_wait_max_us: 0,
            tcp_recv_queue_waits: 0,
            local_queue_wait_us: 0,
            local_queue_wait_max_us: 0,
            local_queue_waits: 0,
            agent_send_credit_wait_us: 0,
            agent_send_credit_wait_max_us: 0,
            agent_send_outbound_wait_us: 0,
            agent_send_outbound_wait_max_us: 0,
            agent_send_frames: 0,
            remote_event_wait_us: 0,
            remote_event_wait_max_us: 0,
            remote_event_waits: 0,
            local_bytes: 0,
            remote_bytes: 0,
            outcome: "dropped",
            emitted: false,
        }
    }

    pub(crate) fn stream_ready(&mut self) {
        self.record_elapsed_if_enabled(TraceField::StreamReady);
    }

    pub(crate) fn opened(&mut self) {
        self.record_elapsed_if_enabled(TraceField::Opened);
    }

    pub(crate) fn agent_remote_connect(&mut self, remote_connect_us: u64) {
        if self.enabled {
            self.agent_remote_connect_us
                .get_or_insert(u128::from(remote_connect_us));
        }
    }

    pub(crate) fn local_bytes(&mut self, bytes: usize) {
        if !self.enabled {
            return;
        }
        self.local_bytes = self.local_bytes.saturating_add(bytes as u64);
        if self.first_local_us.is_none() {
            self.first_local_us = Some(self.elapsed_us());
        }
    }

    pub(crate) fn local_sent(&mut self) {
        self.record_elapsed_if_enabled(TraceField::FirstLocalSent);
    }

    pub(crate) fn local_send_wait(&mut self, started_at: Instant) {
        if !self.enabled {
            return;
        }
        let elapsed_us = started_at.elapsed().as_micros();
        self.local_send_wait_us = self.local_send_wait_us.saturating_add(elapsed_us);
        self.local_send_wait_max_us = self.local_send_wait_max_us.max(elapsed_us);
        self.local_send_waits = self.local_send_waits.saturating_add(1);
    }

    pub(crate) fn tcp_recv_queue_wait(&mut self, queue_wait_us: Option<u64>) {
        if !self.enabled {
            return;
        }
        let Some(queue_wait_us) = queue_wait_us else {
            return;
        };
        let queue_wait_us = u128::from(queue_wait_us);
        self.tcp_recv_queue_wait_us = self.tcp_recv_queue_wait_us.saturating_add(queue_wait_us);
        self.tcp_recv_queue_wait_max_us = self.tcp_recv_queue_wait_max_us.max(queue_wait_us);
        self.tcp_recv_queue_waits = self.tcp_recv_queue_waits.saturating_add(1);
    }

    pub(crate) fn local_queue_wait(&mut self, queue_wait_us: u128) {
        if !self.enabled {
            return;
        }
        self.local_queue_wait_us = self.local_queue_wait_us.saturating_add(queue_wait_us);
        self.local_queue_wait_max_us = self.local_queue_wait_max_us.max(queue_wait_us);
        self.local_queue_waits = self.local_queue_waits.saturating_add(1);
    }

    pub(crate) fn agent_send_waits(
        &mut self,
        credit_wait_us: u128,
        outbound_wait_us: u128,
        frames: u64,
    ) {
        if !self.enabled {
            return;
        }
        self.agent_send_credit_wait_us = self
            .agent_send_credit_wait_us
            .saturating_add(credit_wait_us);
        self.agent_send_credit_wait_max_us = self.agent_send_credit_wait_max_us.max(credit_wait_us);
        self.agent_send_outbound_wait_us = self
            .agent_send_outbound_wait_us
            .saturating_add(outbound_wait_us);
        self.agent_send_outbound_wait_max_us =
            self.agent_send_outbound_wait_max_us.max(outbound_wait_us);
        self.agent_send_frames = self.agent_send_frames.saturating_add(frames);
    }

    pub(crate) fn remote_bytes(&mut self, bytes: usize) {
        if !self.enabled {
            return;
        }
        self.remote_bytes = self.remote_bytes.saturating_add(bytes as u64);
        if self.first_remote_us.is_none() {
            self.first_remote_us = Some(self.elapsed_us());
        }
    }

    pub(crate) fn remote_event_wait(&mut self, started_at: Instant) {
        if !self.enabled {
            return;
        }
        let elapsed_us = started_at.elapsed().as_micros();
        self.remote_event_wait_us = self.remote_event_wait_us.saturating_add(elapsed_us);
        self.remote_event_wait_max_us = self.remote_event_wait_max_us.max(elapsed_us);
        self.remote_event_waits = self.remote_event_waits.saturating_add(1);
    }

    pub(crate) fn outcome(&mut self, outcome: &'static str) {
        if self.enabled {
            self.outcome = outcome;
        }
    }

    pub(crate) fn finish(&mut self, outcome: &'static str) {
        self.outcome(outcome);
        self.emit();
    }

    pub(crate) fn finish_current_or(&mut self, outcome: &'static str) {
        if self.outcome == "dropped" {
            self.outcome(outcome);
        }
        self.emit();
    }

    fn record_elapsed_if_enabled(&mut self, field: TraceField) {
        if !self.enabled {
            return;
        }
        let elapsed = self.elapsed_us();
        match field {
            TraceField::StreamReady => {
                self.stream_ready_us.get_or_insert(elapsed);
            }
            TraceField::Opened => {
                self.opened_us.get_or_insert(elapsed);
            }
            TraceField::FirstLocalSent => {
                self.first_local_sent_us.get_or_insert(elapsed);
            }
        }
    }

    fn elapsed_us(&self) -> u128 {
        self.started_at.elapsed().as_micros()
    }

    fn emit(&mut self) {
        if !self.enabled || self.emitted {
            return;
        }
        self.emitted = true;
        eprintln!(
            "{}",
            format_tcp_flow_trace_summary(&TcpFlowTraceSummary {
                transport: self.transport,
                id: self.id,
                ready_wait_us: self.ready_wait_us,
                stream_ready_us: self.stream_ready_us,
                opened_us: self.opened_us,
                agent_remote_connect_us: self.agent_remote_connect_us,
                first_local_us: self.first_local_us,
                first_local_sent_us: self.first_local_sent_us,
                first_remote_us: self.first_remote_us,
                local_send_wait_us: self.local_send_wait_us,
                local_send_wait_max_us: self.local_send_wait_max_us,
                local_send_waits: self.local_send_waits,
                tcp_recv_queue_wait_us: self.tcp_recv_queue_wait_us,
                tcp_recv_queue_wait_max_us: self.tcp_recv_queue_wait_max_us,
                tcp_recv_queue_waits: self.tcp_recv_queue_waits,
                local_queue_wait_us: self.local_queue_wait_us,
                local_queue_wait_max_us: self.local_queue_wait_max_us,
                local_queue_waits: self.local_queue_waits,
                agent_send_credit_wait_us: self.agent_send_credit_wait_us,
                agent_send_credit_wait_max_us: self.agent_send_credit_wait_max_us,
                agent_send_outbound_wait_us: self.agent_send_outbound_wait_us,
                agent_send_outbound_wait_max_us: self.agent_send_outbound_wait_max_us,
                agent_send_frames: self.agent_send_frames,
                remote_event_wait_us: self.remote_event_wait_us,
                remote_event_wait_max_us: self.remote_event_wait_max_us,
                remote_event_waits: self.remote_event_waits,
                duration_us: self.elapsed_us(),
                local_bytes: self.local_bytes,
                remote_bytes: self.remote_bytes,
                outcome: self.outcome,
            })
        );
    }
}

impl Drop for TcpFlowTrace {
    fn drop(&mut self) {
        self.emit();
    }
}

enum TraceField {
    StreamReady,
    Opened,
    FirstLocalSent,
}

fn hotpath_trace_enabled() -> bool {
    *HOTPATH_TRACE_ENABLED.get_or_init(|| {
        std::env::var_os(HOTPATH_TRACE_ENV)
            .and_then(|value| value.into_string().ok())
            .is_some_and(|value| {
                let value = value.trim();
                !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
            })
    })
}

fn format_tcp_flow_trace_summary(summary: &TcpFlowTraceSummary) -> String {
    let key = summary.id.key;
    format!(
        "rustle_hotpath_tcp\ttransport={}\tflow={}:{}->{}:{}\tgeneration={}\tready_wait_us={}\tstream_ready_us={}\topened_us={}\tagent_remote_connect_us={}\tfirst_local_us={}\tfirst_local_sent_us={}\tfirst_remote_us={}\tduration_us={}\tlocal_bytes={}\tremote_bytes={}\tlocal_send_wait_us={}\tlocal_send_wait_max_us={}\tlocal_send_waits={}\ttcp_recv_queue_wait_us={}\ttcp_recv_queue_wait_max_us={}\ttcp_recv_queue_waits={}\tlocal_queue_wait_us={}\tlocal_queue_wait_max_us={}\tlocal_queue_waits={}\tagent_send_credit_wait_us={}\tagent_send_credit_wait_max_us={}\tagent_send_outbound_wait_us={}\tagent_send_outbound_wait_max_us={}\tagent_send_frames={}\tremote_event_wait_us={}\tremote_event_wait_max_us={}\tremote_event_waits={}\toutcome={}",
        summary.transport,
        key.src_ip,
        key.src_port,
        key.dst_ip,
        key.dst_port,
        summary.id.generation,
        summary.ready_wait_us,
        format_optional_us(summary.stream_ready_us),
        format_optional_us(summary.opened_us),
        format_optional_us(summary.agent_remote_connect_us),
        format_optional_us(summary.first_local_us),
        format_optional_us(summary.first_local_sent_us),
        format_optional_us(summary.first_remote_us),
        summary.duration_us,
        summary.local_bytes,
        summary.remote_bytes,
        summary.local_send_wait_us,
        summary.local_send_wait_max_us,
        summary.local_send_waits,
        summary.tcp_recv_queue_wait_us,
        summary.tcp_recv_queue_wait_max_us,
        summary.tcp_recv_queue_waits,
        summary.local_queue_wait_us,
        summary.local_queue_wait_max_us,
        summary.local_queue_waits,
        summary.agent_send_credit_wait_us,
        summary.agent_send_credit_wait_max_us,
        summary.agent_send_outbound_wait_us,
        summary.agent_send_outbound_wait_max_us,
        summary.agent_send_frames,
        summary.remote_event_wait_us,
        summary.remote_event_wait_max_us,
        summary.remote_event_waits,
        summary.outcome
    )
}

fn format_optional_us(value: Option<u128>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn tcp_flow_trace_summary_uses_stable_tsv_without_payload() {
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 0, 0, 1),
                49152,
                Ipv4Addr::new(203, 0, 113, 10),
                443,
            ),
            7,
        );
        let line = format_tcp_flow_trace_summary(&TcpFlowTraceSummary {
            transport: "agent",
            id,
            ready_wait_us: 12_000,
            stream_ready_us: Some(10),
            opened_us: Some(20),
            agent_remote_connect_us: Some(5),
            first_local_us: Some(30),
            first_local_sent_us: Some(40),
            first_remote_us: None,
            local_send_wait_us: 9,
            local_send_wait_max_us: 8,
            local_send_waits: 2,
            tcp_recv_queue_wait_us: 14,
            tcp_recv_queue_wait_max_us: 10,
            tcp_recv_queue_waits: 3,
            local_queue_wait_us: 7,
            local_queue_wait_max_us: 6,
            local_queue_waits: 1,
            agent_send_credit_wait_us: 4,
            agent_send_credit_wait_max_us: 3,
            agent_send_outbound_wait_us: 5,
            agent_send_outbound_wait_max_us: 4,
            agent_send_frames: 6,
            remote_event_wait_us: 11,
            remote_event_wait_max_us: 10,
            remote_event_waits: 3,
            duration_us: 50,
            local_bytes: 123,
            remote_bytes: 456,
            outcome: "closed",
        });

        assert_eq!(
            line,
            "rustle_hotpath_tcp\ttransport=agent\tflow=10.0.0.1:49152->203.0.113.10:443\tgeneration=7\tready_wait_us=12000\tstream_ready_us=10\topened_us=20\tagent_remote_connect_us=5\tfirst_local_us=30\tfirst_local_sent_us=40\tfirst_remote_us=-\tduration_us=50\tlocal_bytes=123\tremote_bytes=456\tlocal_send_wait_us=9\tlocal_send_wait_max_us=8\tlocal_send_waits=2\ttcp_recv_queue_wait_us=14\ttcp_recv_queue_wait_max_us=10\ttcp_recv_queue_waits=3\tlocal_queue_wait_us=7\tlocal_queue_wait_max_us=6\tlocal_queue_waits=1\tagent_send_credit_wait_us=4\tagent_send_credit_wait_max_us=3\tagent_send_outbound_wait_us=5\tagent_send_outbound_wait_max_us=4\tagent_send_frames=6\tremote_event_wait_us=11\tremote_event_wait_max_us=10\tremote_event_waits=3\toutcome=closed"
        );
        assert!(!line.contains("payload"));
    }
}
