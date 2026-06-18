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
    agent_remote_read_wait_us: u128,
    agent_remote_read_wait_max_us: u128,
    agent_remote_read_events: u64,
    agent_remote_output_credit_wait_us: u128,
    agent_remote_output_credit_wait_max_us: u128,
    agent_remote_output_send_wait_us: u128,
    agent_remote_output_send_wait_max_us: u128,
    agent_remote_output_frames: u64,
    agent_remote_output_bytes: u64,
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
    agent_remote_read_wait_us: u128,
    agent_remote_read_wait_max_us: u128,
    agent_remote_read_events: u64,
    agent_remote_output_credit_wait_us: u128,
    agent_remote_output_credit_wait_max_us: u128,
    agent_remote_output_send_wait_us: u128,
    agent_remote_output_send_wait_max_us: u128,
    agent_remote_output_frames: u64,
    agent_remote_output_bytes: u64,
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
        Self::with_enabled(hotpath_trace_enabled(), transport, id, ready_wait_ms)
    }

    fn with_enabled(
        enabled: bool,
        transport: &'static str,
        id: tcp_core::FlowId,
        ready_wait_ms: u64,
    ) -> Self {
        Self {
            enabled,
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
            agent_remote_read_wait_us: 0,
            agent_remote_read_wait_max_us: 0,
            agent_remote_read_events: 0,
            agent_remote_output_credit_wait_us: 0,
            agent_remote_output_credit_wait_max_us: 0,
            agent_remote_output_send_wait_us: 0,
            agent_remote_output_send_wait_max_us: 0,
            agent_remote_output_frames: 0,
            agent_remote_output_bytes: 0,
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

    pub(crate) fn agent_remote_output_timing(
        &mut self,
        timing: crate::agent_proto::AgentEofTiming,
    ) {
        if !self.enabled {
            return;
        }
        self.agent_remote_read_wait_us = self
            .agent_remote_read_wait_us
            .saturating_add(u128::from(timing.remote_read_wait_us));
        self.agent_remote_read_wait_max_us = self
            .agent_remote_read_wait_max_us
            .max(u128::from(timing.remote_read_wait_max_us));
        self.agent_remote_read_events = self
            .agent_remote_read_events
            .saturating_add(timing.remote_read_events);
        self.agent_remote_output_credit_wait_us = self
            .agent_remote_output_credit_wait_us
            .saturating_add(u128::from(timing.output_credit_wait_us));
        self.agent_remote_output_credit_wait_max_us = self
            .agent_remote_output_credit_wait_max_us
            .max(u128::from(timing.output_credit_wait_max_us));
        self.agent_remote_output_send_wait_us = self
            .agent_remote_output_send_wait_us
            .saturating_add(u128::from(timing.output_send_wait_us));
        self.agent_remote_output_send_wait_max_us = self
            .agent_remote_output_send_wait_max_us
            .max(u128::from(timing.output_send_wait_max_us));
        self.agent_remote_output_frames = self
            .agent_remote_output_frames
            .saturating_add(timing.output_frames);
        self.agent_remote_output_bytes = self
            .agent_remote_output_bytes
            .saturating_add(timing.remote_bytes);
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
        emit_trace_line(&format_tcp_flow_trace_summary(&self.summary()));
    }

    fn summary(&self) -> TcpFlowTraceSummary {
        self.summary_with_duration(self.elapsed_us())
    }

    fn summary_with_duration(&self, duration_us: u128) -> TcpFlowTraceSummary {
        TcpFlowTraceSummary {
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
            agent_remote_read_wait_us: self.agent_remote_read_wait_us,
            agent_remote_read_wait_max_us: self.agent_remote_read_wait_max_us,
            agent_remote_read_events: self.agent_remote_read_events,
            agent_remote_output_credit_wait_us: self.agent_remote_output_credit_wait_us,
            agent_remote_output_credit_wait_max_us: self.agent_remote_output_credit_wait_max_us,
            agent_remote_output_send_wait_us: self.agent_remote_output_send_wait_us,
            agent_remote_output_send_wait_max_us: self.agent_remote_output_send_wait_max_us,
            agent_remote_output_frames: self.agent_remote_output_frames,
            agent_remote_output_bytes: self.agent_remote_output_bytes,
            remote_event_wait_us: self.remote_event_wait_us,
            remote_event_wait_max_us: self.remote_event_wait_max_us,
            remote_event_waits: self.remote_event_waits,
            duration_us,
            local_bytes: self.local_bytes,
            remote_bytes: self.remote_bytes,
            outcome: self.outcome,
        }
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
    #[cfg(test)]
    if let Some(enabled) = test_hotpath_trace_enabled_override() {
        return enabled;
    }

    *HOTPATH_TRACE_ENABLED.get_or_init(|| {
        std::env::var_os(HOTPATH_TRACE_ENV)
            .and_then(|value| value.into_string().ok())
            .is_some_and(|value| env_flag_enabled(&value))
    })
}

fn env_flag_enabled(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
}

fn emit_trace_line(line: &str) {
    #[cfg(test)]
    {
        TEST_TRACE_LINES.with(|lines| lines.borrow_mut().push(line.to_owned()));
    }
    #[cfg(not(test))]
    {
        eprintln!("{line}");
    }
}

#[cfg(test)]
thread_local! {
    static TEST_TRACE_LINES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static TEST_HOTPATH_TRACE_ENABLED: std::cell::RefCell<Option<bool>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_hotpath_trace_enabled_override() -> Option<bool> {
    TEST_HOTPATH_TRACE_ENABLED.with(|enabled| *enabled.borrow())
}

fn format_tcp_flow_trace_summary(summary: &TcpFlowTraceSummary) -> String {
    let key = summary.id.key;
    format!(
        "rustle_hotpath_tcp\ttransport={}\tflow={}:{}->{}:{}\tgeneration={}\tready_wait_us={}\tstream_ready_us={}\topened_us={}\tagent_remote_connect_us={}\tfirst_local_us={}\tfirst_local_sent_us={}\tfirst_remote_us={}\tduration_us={}\tlocal_bytes={}\tremote_bytes={}\tlocal_send_wait_us={}\tlocal_send_wait_max_us={}\tlocal_send_waits={}\ttcp_recv_queue_wait_us={}\ttcp_recv_queue_wait_max_us={}\ttcp_recv_queue_waits={}\tlocal_queue_wait_us={}\tlocal_queue_wait_max_us={}\tlocal_queue_waits={}\tagent_send_credit_wait_us={}\tagent_send_credit_wait_max_us={}\tagent_send_outbound_wait_us={}\tagent_send_outbound_wait_max_us={}\tagent_send_frames={}\tagent_remote_read_wait_us={}\tagent_remote_read_wait_max_us={}\tagent_remote_read_events={}\tagent_remote_output_credit_wait_us={}\tagent_remote_output_credit_wait_max_us={}\tagent_remote_output_send_wait_us={}\tagent_remote_output_send_wait_max_us={}\tagent_remote_output_frames={}\tagent_remote_output_bytes={}\tremote_event_wait_us={}\tremote_event_wait_max_us={}\tremote_event_waits={}\toutcome={}",
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
        summary.agent_remote_read_wait_us,
        summary.agent_remote_read_wait_max_us,
        summary.agent_remote_read_events,
        summary.agent_remote_output_credit_wait_us,
        summary.agent_remote_output_credit_wait_max_us,
        summary.agent_remote_output_send_wait_us,
        summary.agent_remote_output_send_wait_max_us,
        summary.agent_remote_output_frames,
        summary.agent_remote_output_bytes,
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
    use std::time::Duration;

    use super::*;

    fn test_flow_id() -> tcp_core::FlowId {
        tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 0, 0, 1),
                49152,
                Ipv4Addr::new(203, 0, 113, 10),
                443,
            ),
            7,
        )
    }

    fn test_trace(enabled: bool) -> TcpFlowTrace {
        TcpFlowTrace::with_enabled(enabled, "agent", test_flow_id(), 12)
    }

    fn elapsed_instant(us: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_micros(us))
            .expect("test elapsed instant should be representable")
    }

    fn test_timing() -> crate::agent_proto::AgentEofTiming {
        crate::agent_proto::AgentEofTiming {
            remote_read_wait_us: 21,
            remote_read_wait_max_us: 12,
            remote_read_events: 7,
            output_credit_wait_us: 22,
            output_credit_wait_max_us: 13,
            output_send_wait_us: 23,
            output_send_wait_max_us: 14,
            output_frames: 8,
            remote_bytes: 456,
        }
    }

    fn take_trace_lines() -> Vec<String> {
        TEST_TRACE_LINES.with(|lines| std::mem::take(&mut *lines.borrow_mut()))
    }

    fn set_hotpath_trace_enabled_override(enabled: Option<bool>) {
        TEST_HOTPATH_TRACE_ENABLED.with(|override_enabled| {
            *override_enabled.borrow_mut() = enabled;
        });
    }

    fn field_value(line: &str, field: &str) -> String {
        let prefix = format!("{field}=");
        line.split('\t')
            .find_map(|part| part.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing field {field} in {line}"))
            .to_owned()
    }

    fn assert_field(line: &str, field: &str, expected: impl ToString) {
        assert_eq!(field_value(line, field), expected.to_string(), "{field}");
    }

    #[test]
    fn tcp_flow_trace_summary_uses_stable_tsv_without_payload() {
        let line = format_tcp_flow_trace_summary(&TcpFlowTraceSummary {
            transport: "agent",
            id: test_flow_id(),
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
            agent_remote_read_wait_us: 21,
            agent_remote_read_wait_max_us: 12,
            agent_remote_read_events: 7,
            agent_remote_output_credit_wait_us: 22,
            agent_remote_output_credit_wait_max_us: 13,
            agent_remote_output_send_wait_us: 23,
            agent_remote_output_send_wait_max_us: 14,
            agent_remote_output_frames: 8,
            agent_remote_output_bytes: 456,
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
            "rustle_hotpath_tcp\ttransport=agent\tflow=10.0.0.1:49152->203.0.113.10:443\tgeneration=7\tready_wait_us=12000\tstream_ready_us=10\topened_us=20\tagent_remote_connect_us=5\tfirst_local_us=30\tfirst_local_sent_us=40\tfirst_remote_us=-\tduration_us=50\tlocal_bytes=123\tremote_bytes=456\tlocal_send_wait_us=9\tlocal_send_wait_max_us=8\tlocal_send_waits=2\ttcp_recv_queue_wait_us=14\ttcp_recv_queue_wait_max_us=10\ttcp_recv_queue_waits=3\tlocal_queue_wait_us=7\tlocal_queue_wait_max_us=6\tlocal_queue_waits=1\tagent_send_credit_wait_us=4\tagent_send_credit_wait_max_us=3\tagent_send_outbound_wait_us=5\tagent_send_outbound_wait_max_us=4\tagent_send_frames=6\tagent_remote_read_wait_us=21\tagent_remote_read_wait_max_us=12\tagent_remote_read_events=7\tagent_remote_output_credit_wait_us=22\tagent_remote_output_credit_wait_max_us=13\tagent_remote_output_send_wait_us=23\tagent_remote_output_send_wait_max_us=14\tagent_remote_output_frames=8\tagent_remote_output_bytes=456\tremote_event_wait_us=11\tremote_event_wait_max_us=10\tremote_event_waits=3\toutcome=closed"
        );
        assert!(!line.contains("payload"));
    }

    #[test]
    fn env_flag_parsing_matches_opt_in_contract() {
        for value in ["", " ", "\t", "0", " 0 ", "false", "FALSE", " False "] {
            assert!(!env_flag_enabled(value), "{value:?} should disable tracing");
        }

        for value in ["1", "true", "yes", "debug", " 2 "] {
            assert!(env_flag_enabled(value), "{value:?} should enable tracing");
        }
    }

    #[test]
    fn new_uses_hotpath_trace_enabled_decision() {
        take_trace_lines();

        set_hotpath_trace_enabled_override(Some(true));
        let mut trace = TcpFlowTrace::new("agent", test_flow_id(), 12);
        assert!(trace.enabled);
        trace.enabled = false;
        drop(trace);

        set_hotpath_trace_enabled_override(Some(false));
        let trace = TcpFlowTrace::new("agent", test_flow_id(), 12);
        assert!(!trace.enabled);
        drop(trace);

        set_hotpath_trace_enabled_override(None);
        assert!(take_trace_lines().is_empty());
    }

    #[test]
    fn disabled_trace_is_noop_and_emits_nothing() {
        take_trace_lines();
        let mut trace = test_trace(false);

        trace.stream_ready();
        trace.opened();
        trace.agent_remote_connect(5);
        trace.local_bytes(123);
        trace.local_sent();
        trace.local_send_wait(elapsed_instant(20));
        trace.tcp_recv_queue_wait(Some(14));
        trace.tcp_recv_queue_wait(None);
        trace.local_queue_wait(7);
        trace.agent_send_waits(4, 5, 6);
        trace.agent_remote_output_timing(test_timing());
        trace.remote_bytes(456);
        trace.remote_event_wait(elapsed_instant(20));
        trace.outcome("closed");
        trace.finish("finished");
        trace.finish_current_or("fallback");

        let summary = trace.summary_with_duration(99);
        assert_eq!(summary.ready_wait_us, 12_000);
        assert_eq!(summary.stream_ready_us, None);
        assert_eq!(summary.opened_us, None);
        assert_eq!(summary.agent_remote_connect_us, None);
        assert_eq!(summary.first_local_us, None);
        assert_eq!(summary.first_local_sent_us, None);
        assert_eq!(summary.first_remote_us, None);
        assert_eq!(summary.local_bytes, 0);
        assert_eq!(summary.remote_bytes, 0);
        assert_eq!(summary.local_send_wait_us, 0);
        assert_eq!(summary.local_send_wait_max_us, 0);
        assert_eq!(summary.local_send_waits, 0);
        assert_eq!(summary.tcp_recv_queue_wait_us, 0);
        assert_eq!(summary.tcp_recv_queue_wait_max_us, 0);
        assert_eq!(summary.tcp_recv_queue_waits, 0);
        assert_eq!(summary.local_queue_wait_us, 0);
        assert_eq!(summary.local_queue_wait_max_us, 0);
        assert_eq!(summary.local_queue_waits, 0);
        assert_eq!(summary.agent_send_credit_wait_us, 0);
        assert_eq!(summary.agent_send_credit_wait_max_us, 0);
        assert_eq!(summary.agent_send_outbound_wait_us, 0);
        assert_eq!(summary.agent_send_outbound_wait_max_us, 0);
        assert_eq!(summary.agent_send_frames, 0);
        assert_eq!(summary.agent_remote_read_wait_us, 0);
        assert_eq!(summary.agent_remote_read_wait_max_us, 0);
        assert_eq!(summary.agent_remote_read_events, 0);
        assert_eq!(summary.agent_remote_output_credit_wait_us, 0);
        assert_eq!(summary.agent_remote_output_credit_wait_max_us, 0);
        assert_eq!(summary.agent_remote_output_send_wait_us, 0);
        assert_eq!(summary.agent_remote_output_send_wait_max_us, 0);
        assert_eq!(summary.agent_remote_output_frames, 0);
        assert_eq!(summary.agent_remote_output_bytes, 0);
        assert_eq!(summary.remote_event_wait_us, 0);
        assert_eq!(summary.remote_event_wait_max_us, 0);
        assert_eq!(summary.remote_event_waits, 0);
        assert_eq!(summary.outcome, "dropped");
        assert!(!trace.emitted);

        drop(trace);
        assert!(take_trace_lines().is_empty());
    }

    #[test]
    fn drop_emits_dropped_summary_once_when_enabled() {
        take_trace_lines();

        {
            let mut trace = test_trace(true);
            trace.local_bytes(123);
            trace.remote_bytes(456);
        }

        let lines = take_trace_lines();
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.split('\t').next(), Some("rustle_hotpath_tcp"));
        assert_field(line, "transport", "agent");
        assert_field(line, "flow", "10.0.0.1:49152->203.0.113.10:443");
        assert_field(line, "generation", 7);
        assert_field(line, "ready_wait_us", 12_000);
        assert_field(line, "local_bytes", 123);
        assert_field(line, "remote_bytes", 456);
        assert_field(line, "outcome", "dropped");
    }

    #[test]
    fn finish_emits_once_and_drop_does_not_emit_again() {
        take_trace_lines();

        {
            let mut trace = test_trace(true);
            trace.local_bytes(123);
            trace.finish("closed");
            trace.finish("ignored_after_emit");
        }

        let lines = take_trace_lines();
        assert_eq!(lines.len(), 1);
        assert_field(&lines[0], "local_bytes", 123);
        assert_field(&lines[0], "outcome", "closed");
    }

    #[test]
    fn finish_current_or_preserves_explicit_outcome_before_drop() {
        take_trace_lines();

        {
            let mut trace = test_trace(true);
            trace.outcome("reset");
            trace.finish_current_or("closed");
        }

        let lines = take_trace_lines();
        assert_eq!(lines.len(), 1);
        assert_field(&lines[0], "outcome", "reset");

        {
            let mut trace = test_trace(true);
            trace.finish_current_or("closed");
        }

        let lines = take_trace_lines();
        assert_eq!(lines.len(), 1);
        assert_field(&lines[0], "outcome", "closed");
    }

    #[test]
    fn elapsed_milestones_are_recorded_once() {
        let mut trace = test_trace(true);

        trace.started_at = elapsed_instant(10);
        trace.stream_ready();
        let stream_ready_us = trace.stream_ready_us.unwrap();
        assert!(stream_ready_us >= 10);
        trace.started_at = elapsed_instant(5_000);
        trace.stream_ready();
        assert_eq!(trace.stream_ready_us, Some(stream_ready_us));

        trace.started_at = elapsed_instant(20);
        trace.opened();
        let opened_us = trace.opened_us.unwrap();
        assert!(opened_us >= 20);
        trace.started_at = elapsed_instant(5_000);
        trace.opened();
        assert_eq!(trace.opened_us, Some(opened_us));

        trace.agent_remote_connect(55);
        trace.agent_remote_connect(99);
        assert_eq!(trace.agent_remote_connect_us, Some(55));

        trace.started_at = elapsed_instant(30);
        trace.local_bytes(100);
        let first_local_us = trace.first_local_us.unwrap();
        assert!(first_local_us >= 30);
        trace.started_at = elapsed_instant(5_000);
        trace.local_bytes(23);
        assert_eq!(trace.first_local_us, Some(first_local_us));
        assert_eq!(trace.local_bytes, 123);

        trace.started_at = elapsed_instant(40);
        trace.local_sent();
        let first_local_sent_us = trace.first_local_sent_us.unwrap();
        assert!(first_local_sent_us >= 40);
        trace.started_at = elapsed_instant(5_000);
        trace.local_sent();
        assert_eq!(trace.first_local_sent_us, Some(first_local_sent_us));

        trace.started_at = elapsed_instant(50);
        trace.remote_bytes(400);
        let first_remote_us = trace.first_remote_us.unwrap();
        assert!(first_remote_us >= 50);
        trace.started_at = elapsed_instant(5_000);
        trace.remote_bytes(56);
        assert_eq!(trace.first_remote_us, Some(first_remote_us));
        assert_eq!(trace.remote_bytes, 456);
    }

    #[test]
    fn bytes_and_wait_counters_accumulate_and_report_in_tsv() {
        let mut trace = test_trace(true);

        trace.local_bytes(123);
        trace.remote_bytes(456);

        trace.local_send_wait(elapsed_instant(25));
        trace.local_send_wait(elapsed_instant(40));
        trace.tcp_recv_queue_wait(None);
        trace.tcp_recv_queue_wait(Some(14));
        trace.tcp_recv_queue_wait(Some(9));
        trace.local_queue_wait(7);
        trace.local_queue_wait(11);
        trace.agent_send_waits(4, 5, 6);
        trace.agent_send_waits(8, 3, 2);
        trace.remote_event_wait(elapsed_instant(30));
        trace.remote_event_wait(elapsed_instant(12));

        let mut eof_timing = test_timing();
        trace.agent_remote_output_timing(eof_timing);
        eof_timing.remote_read_wait_us = 5;
        eof_timing.remote_read_wait_max_us = 30;
        eof_timing.remote_read_events = 2;
        eof_timing.output_credit_wait_us = 6;
        eof_timing.output_credit_wait_max_us = 3;
        eof_timing.output_send_wait_us = 7;
        eof_timing.output_send_wait_max_us = 40;
        eof_timing.output_frames = 4;
        eof_timing.remote_bytes = 44;
        trace.agent_remote_output_timing(eof_timing);

        let summary = trace.summary_with_duration(999);
        assert_eq!(summary.local_bytes, 123);
        assert_eq!(summary.remote_bytes, 456);
        assert!(summary.local_send_wait_us >= 65);
        assert!(summary.local_send_wait_max_us >= 40);
        assert!(summary.local_send_wait_us >= summary.local_send_wait_max_us);
        assert_eq!(summary.local_send_waits, 2);
        assert_eq!(summary.tcp_recv_queue_wait_us, 23);
        assert_eq!(summary.tcp_recv_queue_wait_max_us, 14);
        assert_eq!(summary.tcp_recv_queue_waits, 2);
        assert_eq!(summary.local_queue_wait_us, 18);
        assert_eq!(summary.local_queue_wait_max_us, 11);
        assert_eq!(summary.local_queue_waits, 2);
        assert_eq!(summary.agent_send_credit_wait_us, 12);
        assert_eq!(summary.agent_send_credit_wait_max_us, 8);
        assert_eq!(summary.agent_send_outbound_wait_us, 8);
        assert_eq!(summary.agent_send_outbound_wait_max_us, 5);
        assert_eq!(summary.agent_send_frames, 8);
        assert_eq!(summary.agent_remote_read_wait_us, 26);
        assert_eq!(summary.agent_remote_read_wait_max_us, 30);
        assert_eq!(summary.agent_remote_read_events, 9);
        assert_eq!(summary.agent_remote_output_credit_wait_us, 28);
        assert_eq!(summary.agent_remote_output_credit_wait_max_us, 13);
        assert_eq!(summary.agent_remote_output_send_wait_us, 30);
        assert_eq!(summary.agent_remote_output_send_wait_max_us, 40);
        assert_eq!(summary.agent_remote_output_frames, 12);
        assert_eq!(summary.agent_remote_output_bytes, 500);
        assert!(summary.remote_event_wait_us >= 42);
        assert!(summary.remote_event_wait_max_us >= 30);
        assert!(summary.remote_event_wait_us >= summary.remote_event_wait_max_us);
        assert_eq!(summary.remote_event_waits, 2);

        let line = format_tcp_flow_trace_summary(&summary);
        assert_field(&line, "duration_us", 999);
        assert_field(&line, "local_bytes", 123);
        assert_field(&line, "remote_bytes", 456);
        assert_field(&line, "local_send_wait_us", summary.local_send_wait_us);
        assert_field(
            &line,
            "local_send_wait_max_us",
            summary.local_send_wait_max_us,
        );
        assert_field(&line, "local_send_waits", 2);
        assert_field(&line, "tcp_recv_queue_wait_us", 23);
        assert_field(&line, "tcp_recv_queue_wait_max_us", 14);
        assert_field(&line, "tcp_recv_queue_waits", 2);
        assert_field(&line, "local_queue_wait_us", 18);
        assert_field(&line, "local_queue_wait_max_us", 11);
        assert_field(&line, "local_queue_waits", 2);
        assert_field(&line, "agent_send_credit_wait_us", 12);
        assert_field(&line, "agent_send_credit_wait_max_us", 8);
        assert_field(&line, "agent_send_outbound_wait_us", 8);
        assert_field(&line, "agent_send_outbound_wait_max_us", 5);
        assert_field(&line, "agent_send_frames", 8);
        assert_field(&line, "agent_remote_read_wait_us", 26);
        assert_field(&line, "agent_remote_read_wait_max_us", 30);
        assert_field(&line, "agent_remote_read_events", 9);
        assert_field(&line, "agent_remote_output_credit_wait_us", 28);
        assert_field(&line, "agent_remote_output_credit_wait_max_us", 13);
        assert_field(&line, "agent_remote_output_send_wait_us", 30);
        assert_field(&line, "agent_remote_output_send_wait_max_us", 40);
        assert_field(&line, "agent_remote_output_frames", 12);
        assert_field(&line, "agent_remote_output_bytes", 500);
        assert_field(&line, "remote_event_wait_us", summary.remote_event_wait_us);
        assert_field(
            &line,
            "remote_event_wait_max_us",
            summary.remote_event_wait_max_us,
        );
        assert_field(&line, "remote_event_waits", 2);
    }
}
