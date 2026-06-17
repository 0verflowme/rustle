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
    stream_ready_us: Option<u128>,
    opened_us: Option<u128>,
    first_local_us: Option<u128>,
    first_local_sent_us: Option<u128>,
    first_remote_us: Option<u128>,
    local_bytes: u64,
    remote_bytes: u64,
    outcome: &'static str,
    emitted: bool,
}

struct TcpFlowTraceSummary {
    transport: &'static str,
    id: tcp_core::FlowId,
    stream_ready_us: Option<u128>,
    opened_us: Option<u128>,
    first_local_us: Option<u128>,
    first_local_sent_us: Option<u128>,
    first_remote_us: Option<u128>,
    duration_us: u128,
    local_bytes: u64,
    remote_bytes: u64,
    outcome: &'static str,
}

impl TcpFlowTrace {
    pub(crate) fn new(transport: &'static str, id: tcp_core::FlowId) -> Self {
        Self {
            enabled: hotpath_trace_enabled(),
            transport,
            id,
            started_at: Instant::now(),
            stream_ready_us: None,
            opened_us: None,
            first_local_us: None,
            first_local_sent_us: None,
            first_remote_us: None,
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

    pub(crate) fn remote_bytes(&mut self, bytes: usize) {
        if !self.enabled {
            return;
        }
        self.remote_bytes = self.remote_bytes.saturating_add(bytes as u64);
        if self.first_remote_us.is_none() {
            self.first_remote_us = Some(self.elapsed_us());
        }
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
                stream_ready_us: self.stream_ready_us,
                opened_us: self.opened_us,
                first_local_us: self.first_local_us,
                first_local_sent_us: self.first_local_sent_us,
                first_remote_us: self.first_remote_us,
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
        "rustle_hotpath_tcp\ttransport={}\tflow={}:{}->{}:{}\tgeneration={}\tstream_ready_us={}\topened_us={}\tfirst_local_us={}\tfirst_local_sent_us={}\tfirst_remote_us={}\tduration_us={}\tlocal_bytes={}\tremote_bytes={}\toutcome={}",
        summary.transport,
        key.src_ip,
        key.src_port,
        key.dst_ip,
        key.dst_port,
        summary.id.generation,
        format_optional_us(summary.stream_ready_us),
        format_optional_us(summary.opened_us),
        format_optional_us(summary.first_local_us),
        format_optional_us(summary.first_local_sent_us),
        format_optional_us(summary.first_remote_us),
        summary.duration_us,
        summary.local_bytes,
        summary.remote_bytes,
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
            stream_ready_us: Some(10),
            opened_us: Some(20),
            first_local_us: Some(30),
            first_local_sent_us: Some(40),
            first_remote_us: None,
            duration_us: 50,
            local_bytes: 123,
            remote_bytes: 456,
            outcome: "closed",
        });

        assert_eq!(
            line,
            "rustle_hotpath_tcp\ttransport=agent\tflow=10.0.0.1:49152->203.0.113.10:443\tgeneration=7\tstream_ready_us=10\topened_us=20\tfirst_local_us=30\tfirst_local_sent_us=40\tfirst_remote_us=-\tduration_us=50\tlocal_bytes=123\tremote_bytes=456\toutcome=closed"
        );
        assert!(!line.contains("payload"));
    }
}
