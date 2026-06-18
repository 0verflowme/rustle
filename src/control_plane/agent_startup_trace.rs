use std::sync::OnceLock;
use std::time::Instant;

const AGENT_STARTUP_TRACE_ENV: &str = "RUSTLE_AGENT_STARTUP_TRACE";
const HOTPATH_TRACE_ENV: &str = "RUSTLE_HOTPATH_TRACE";

static AGENT_STARTUP_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();

pub(super) struct AgentStartupTrace {
    enabled: bool,
    mode: &'static str,
    desired: usize,
    started_at: Instant,
    established: usize,
    primary_us: Option<u128>,
    primary_ok: Option<bool>,
    extra_batches: u64,
    extra_connects: u64,
    extra_success: u64,
    extra_fail: u64,
    extra_us: u128,
    extra_max_us: u128,
    retry_batches: u64,
    retry_connects: u64,
    retry_success: u64,
    retry_fail: u64,
    retry_us: u128,
    retry_max_us: u128,
    outcome: &'static str,
    emitted: bool,
}

struct AgentStartupTraceSummary {
    mode: &'static str,
    desired: usize,
    established: usize,
    primary_us: Option<u128>,
    primary_ok: Option<bool>,
    extra_batches: u64,
    extra_connects: u64,
    extra_success: u64,
    extra_fail: u64,
    extra_us: u128,
    extra_max_us: u128,
    retry_batches: u64,
    retry_connects: u64,
    retry_success: u64,
    retry_fail: u64,
    retry_us: u128,
    retry_max_us: u128,
    duration_us: u128,
    outcome: &'static str,
}

impl AgentStartupTrace {
    pub(super) fn new(mode: &'static str, desired: usize) -> Self {
        Self {
            enabled: agent_startup_trace_enabled(),
            mode,
            desired,
            started_at: Instant::now(),
            established: 0,
            primary_us: None,
            primary_ok: None,
            extra_batches: 0,
            extra_connects: 0,
            extra_success: 0,
            extra_fail: 0,
            extra_us: 0,
            extra_max_us: 0,
            retry_batches: 0,
            retry_connects: 0,
            retry_success: 0,
            retry_fail: 0,
            retry_us: 0,
            retry_max_us: 0,
            outcome: "dropped",
            emitted: false,
        }
    }

    pub(super) fn primary_connect(&mut self, started_at: Instant, ok: bool) {
        if !self.enabled {
            return;
        }
        self.primary_us
            .get_or_insert(started_at.elapsed().as_micros());
        self.primary_ok.get_or_insert(ok);
    }

    pub(super) fn extra_batch(
        &mut self,
        started_at: Instant,
        attempted: usize,
        successes: usize,
        failures: usize,
    ) {
        if !self.enabled {
            return;
        }
        let elapsed_us = started_at.elapsed().as_micros();
        self.extra_batches = self.extra_batches.saturating_add(1);
        self.extra_connects = self.extra_connects.saturating_add(attempted as u64);
        self.extra_success = self.extra_success.saturating_add(successes as u64);
        self.extra_fail = self.extra_fail.saturating_add(failures as u64);
        self.extra_us = self.extra_us.saturating_add(elapsed_us);
        self.extra_max_us = self.extra_max_us.max(elapsed_us);
    }

    pub(super) fn retry_batch(
        &mut self,
        started_at: Instant,
        attempted: usize,
        successes: usize,
        failures: usize,
    ) {
        if !self.enabled {
            return;
        }
        let elapsed_us = started_at.elapsed().as_micros();
        self.retry_batches = self.retry_batches.saturating_add(1);
        self.retry_connects = self.retry_connects.saturating_add(attempted as u64);
        self.retry_success = self.retry_success.saturating_add(successes as u64);
        self.retry_fail = self.retry_fail.saturating_add(failures as u64);
        self.retry_us = self.retry_us.saturating_add(elapsed_us);
        self.retry_max_us = self.retry_max_us.max(elapsed_us);
    }

    pub(super) fn finish(&mut self, established: usize, outcome: &'static str) {
        if self.enabled {
            self.established = established;
            self.outcome = outcome;
        }
        self.emit();
    }

    fn emit(&mut self) {
        if !self.enabled || self.emitted {
            return;
        }
        self.emitted = true;
        eprintln!(
            "{}",
            format_agent_startup_trace_summary(&AgentStartupTraceSummary {
                mode: self.mode,
                desired: self.desired,
                established: self.established,
                primary_us: self.primary_us,
                primary_ok: self.primary_ok,
                extra_batches: self.extra_batches,
                extra_connects: self.extra_connects,
                extra_success: self.extra_success,
                extra_fail: self.extra_fail,
                extra_us: self.extra_us,
                extra_max_us: self.extra_max_us,
                retry_batches: self.retry_batches,
                retry_connects: self.retry_connects,
                retry_success: self.retry_success,
                retry_fail: self.retry_fail,
                retry_us: self.retry_us,
                retry_max_us: self.retry_max_us,
                duration_us: self.started_at.elapsed().as_micros(),
                outcome: self.outcome,
            })
        );
    }
}

impl Drop for AgentStartupTrace {
    fn drop(&mut self) {
        self.emit();
    }
}

fn agent_startup_trace_enabled() -> bool {
    *AGENT_STARTUP_TRACE_ENABLED.get_or_init(|| {
        env_flag_enabled(AGENT_STARTUP_TRACE_ENV) || env_flag_enabled(HOTPATH_TRACE_ENV)
    })
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var_os(name)
        .and_then(|value| value.into_string().ok())
        .is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
        })
}

fn format_agent_startup_trace_summary(summary: &AgentStartupTraceSummary) -> String {
    format!(
        "rustle_agent_startup\tmode={}\tdesired={}\testablished={}\tprimary_us={}\tprimary_ok={}\textra_batches={}\textra_connects={}\textra_success={}\textra_fail={}\textra_us={}\textra_max_us={}\tretry_batches={}\tretry_connects={}\tretry_success={}\tretry_fail={}\tretry_us={}\tretry_max_us={}\tduration_us={}\toutcome={}",
        summary.mode,
        summary.desired,
        summary.established,
        format_optional_us(summary.primary_us),
        format_optional_bool(summary.primary_ok),
        summary.extra_batches,
        summary.extra_connects,
        summary.extra_success,
        summary.extra_fail,
        summary.extra_us,
        summary.extra_max_us,
        summary.retry_batches,
        summary.retry_connects,
        summary.retry_success,
        summary.retry_fail,
        summary.retry_us,
        summary.retry_max_us,
        summary.duration_us,
        summary.outcome
    )
}

fn format_optional_us(value: Option<u128>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn format_optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "-",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_startup_trace_summary_uses_stable_tsv_without_command_or_host() {
        let line = format_agent_startup_trace_summary(&AgentStartupTraceSummary {
            mode: "initial",
            desired: 4,
            established: 3,
            primary_us: Some(1_000),
            primary_ok: Some(true),
            extra_batches: 1,
            extra_connects: 3,
            extra_success: 2,
            extra_fail: 1,
            extra_us: 4_000,
            extra_max_us: 4_000,
            retry_batches: 1,
            retry_connects: 1,
            retry_success: 1,
            retry_fail: 0,
            retry_us: 2_000,
            retry_max_us: 2_000,
            duration_us: 7_500,
            outcome: "degraded",
        });

        assert_eq!(
            line,
            "rustle_agent_startup\tmode=initial\tdesired=4\testablished=3\tprimary_us=1000\tprimary_ok=true\textra_batches=1\textra_connects=3\textra_success=2\textra_fail=1\textra_us=4000\textra_max_us=4000\tretry_batches=1\tretry_connects=1\tretry_success=1\tretry_fail=0\tretry_us=2000\tretry_max_us=2000\tduration_us=7500\toutcome=degraded"
        );
        assert!(!line.contains("rustle-uploaded"));
        assert!(!line.contains("contabo"));
    }

    #[test]
    fn optional_startup_trace_fields_use_dash() {
        let line = format_agent_startup_trace_summary(&AgentStartupTraceSummary {
            mode: "fast",
            desired: 2,
            established: 0,
            primary_us: None,
            primary_ok: None,
            extra_batches: 0,
            extra_connects: 0,
            extra_success: 0,
            extra_fail: 0,
            extra_us: 0,
            extra_max_us: 0,
            retry_batches: 0,
            retry_connects: 0,
            retry_success: 0,
            retry_fail: 0,
            retry_us: 0,
            retry_max_us: 0,
            duration_us: 10,
            outcome: "primary_error",
        });

        assert!(line.contains("\tprimary_us=-\tprimary_ok=-\t"));
    }
}
