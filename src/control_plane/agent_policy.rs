use anyhow::{bail, Result};

use crate::ssh_control::MAX_SSH_SESSIONS;

pub(crate) const AUTO_AGENT_SESSIONS: usize = 0;
pub(crate) const MAX_AUTO_AGENT_SESSIONS: usize = 4;

pub(crate) fn validate_agent_session_count(sessions: usize) -> Result<()> {
    if sessions == 0 {
        bail!("--agent-sessions must be greater than zero");
    }
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

pub(crate) fn validate_agent_session_request_count(sessions: usize) -> Result<()> {
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

pub(crate) fn resolve_agent_session_count(requested: usize) -> usize {
    if requested == AUTO_AGENT_SESSIONS {
        recommended_agent_session_count()
    } else {
        requested
    }
}

fn recommended_agent_session_count() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2);
    recommended_agent_session_count_for_parallelism(parallelism)
}

pub(crate) fn recommended_agent_session_count_for_parallelism(parallelism: usize) -> usize {
    let cap = MAX_AUTO_AGENT_SESSIONS.min(MAX_SSH_SESSIONS);
    let parallelism = parallelism.max(1);
    for lanes in 1..=cap {
        if parallelism <= lanes.saturating_mul(lanes) {
            return lanes;
        }
    }
    cap
}

pub(crate) fn format_agent_established_message(established: usize, desired: usize) -> String {
    format!("agent: established {established}/{desired} exec transport(s)")
}

pub(crate) fn format_agent_fast_start_message(established: usize, desired: usize) -> String {
    let message = format_agent_established_message(established, desired);
    let warming = desired.saturating_sub(established);
    if warming == 0 {
        message
    } else {
        format!("{message}; warming {warming} remaining exec transport(s) in background")
    }
}

pub(crate) fn should_fast_start_agent_lanes(
    fast_start_auto_lanes: bool,
    requested_sessions: usize,
    desired_sessions: usize,
) -> bool {
    fast_start_auto_lanes && requested_sessions == AUTO_AGENT_SESSIONS && desired_sessions > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_agent_sessions_fast_start_when_multiple_lanes_are_recommended() {
        assert!(!should_fast_start_agent_lanes(true, AUTO_AGENT_SESSIONS, 1));
        assert!(should_fast_start_agent_lanes(true, AUTO_AGENT_SESSIONS, 2));
        assert!(
            !should_fast_start_agent_lanes(false, AUTO_AGENT_SESSIONS, 2),
            "bridge-lab and other steady-state harnesses can opt out"
        );
        assert!(
            !should_fast_start_agent_lanes(true, 2, 2),
            "explicit --agent-sessions must keep full startup gating"
        );
        assert_eq!(
            format_agent_fast_start_message(1, 4),
            "agent: established 1/4 exec transport(s); warming 3 remaining exec transport(s) in background"
        );
        assert_eq!(
            format_agent_fast_start_message(1, 1),
            "agent: established 1/1 exec transport(s)"
        );
    }

    #[test]
    fn agent_session_count_validation_bounds_pool_size() {
        assert!(validate_agent_session_count(1).is_ok());
        assert!(validate_agent_session_count(MAX_AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_count(0).is_err());
        assert!(validate_agent_session_count(MAX_SSH_SESSIONS + 1).is_err());
        assert!(validate_agent_session_request_count(AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_request_count(MAX_SSH_SESSIONS + 1).is_err());
    }

    #[test]
    fn auto_agent_session_count_is_conservative_and_nonzero() {
        assert_eq!(resolve_agent_session_count(3), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(0), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(1), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(2), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(4), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(5), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(9), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(10), 4);
        assert_eq!(
            recommended_agent_session_count_for_parallelism(usize::MAX),
            MAX_AUTO_AGENT_SESSIONS
        );
        let resolved = resolve_agent_session_count(AUTO_AGENT_SESSIONS);
        assert!((1..=MAX_AUTO_AGENT_SESSIONS).contains(&resolved));
    }

    #[test]
    fn agent_established_message_reports_degraded_lane_pool() {
        assert_eq!(
            format_agent_established_message(3, 4),
            "agent: established 3/4 exec transport(s)"
        );
    }
}
