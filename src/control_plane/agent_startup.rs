use anyhow::Result;

use crate::agent_bridge::{AgentBridgeConnector, AgentBridgeTransport};
use crate::ssh_control::{
    resolve_agent_session_count, validate_agent_session_count, AUTO_AGENT_SESSIONS,
};

const AGENT_INITIAL_CONNECT_BATCH: usize = 4;
const AGENT_INITIAL_CONNECT_RETRY_ROUNDS: usize = 1;

pub(crate) async fn connect_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;
    let mut transports = Vec::with_capacity(desired_sessions);

    let first = connector.connect_primary().await?;
    let additional_agent_command = first.agent_command().to_owned();
    transports.push(first);

    let mut index = 1;
    while index < desired_sessions {
        let batch = (desired_sessions - index).min(AGENT_INITIAL_CONNECT_BATCH);
        for (offset, result) in connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            batch,
        )
        .await
        .into_iter()
        .enumerate()
        {
            match result {
                Ok(transport) => transports.push(transport),
                Err(err) => {
                    eprintln!(
                        "agent: additional exec transport {}/{} failed: {err:#}; continuing with {} transport(s)",
                        index + offset + 1,
                        desired_sessions,
                        transports.len()
                    );
                }
            }
        }
        index += batch;
    }

    for retry_round in 1..=AGENT_INITIAL_CONNECT_RETRY_ROUNDS {
        let missing = desired_sessions.saturating_sub(transports.len());
        if missing == 0 {
            break;
        }
        eprintln!(
            "agent: retrying {missing} missing exec transport(s) after partial startup (round {retry_round}/{AGENT_INITIAL_CONNECT_RETRY_ROUNDS})"
        );
        for result in connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            missing.min(AGENT_INITIAL_CONNECT_BATCH),
        )
        .await
        {
            match result {
                Ok(transport) => transports.push(transport),
                Err(err) => {
                    eprintln!(
                        "agent: retry for missing exec transport failed: {err:#}; continuing with {} transport(s)",
                        transports.len()
                    );
                }
            }
        }
    }

    eprintln!(
        "{}",
        format_agent_established_message(transports.len(), desired_sessions)
    );
    Ok(transports)
}

pub(crate) async fn connect_auto_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;

    let first = connector.connect_primary().await?;
    eprintln!("{}", format_agent_fast_start_message(1, desired_sessions));
    Ok(vec![first])
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

async fn connect_additional_agent_bridge_transport_batch(
    connector: &dyn AgentBridgeConnector,
    agent_command: &str,
    batch: usize,
) -> Vec<Result<AgentBridgeTransport>> {
    match batch {
        0 => Vec::new(),
        1 => vec![connector.connect_command(agent_command).await],
        2 => {
            let (first, second) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second]
        }
        3 => {
            let (first, second, third) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second, third]
        }
        _ => {
            let (first, second, third, fourth) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second, third, fourth]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PanicConnector {
        connect_commands: AtomicUsize,
    }

    impl PanicConnector {
        fn new() -> Self {
            Self {
                connect_commands: AtomicUsize::new(0),
            }
        }

        fn connect_command_count(&self) -> usize {
            self.connect_commands.load(Ordering::SeqCst)
        }
    }

    impl AgentBridgeConnector for PanicConnector {
        fn primary_command(&self) -> &str {
            "rustle agent"
        }

        fn connect_initial(
            &self,
            _desired_sessions: usize,
        ) -> crate::agent_bridge::AgentBridgeConnectManyFuture<'_> {
            Box::pin(async { panic!("zero-batch test must not call connect_initial") })
        }

        fn connect_primary(&self) -> crate::agent_bridge::AgentBridgeConnectFuture<'_> {
            Box::pin(async { panic!("zero-batch test must not call connect_primary") })
        }

        fn connect_command<'a>(
            &'a self,
            _agent_command: &'a str,
        ) -> crate::agent_bridge::AgentBridgeConnectFuture<'a> {
            self.connect_commands.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { panic!("zero-batch test must not call connect_command") })
        }
    }

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
    fn agent_established_message_reports_degraded_lane_pool() {
        assert_eq!(
            format_agent_established_message(3, 4),
            "agent: established 3/4 exec transport(s)"
        );
    }

    #[tokio::test]
    async fn zero_additional_lane_batch_does_not_touch_connector() {
        let connector = PanicConnector::new();

        let results =
            connect_additional_agent_bridge_transport_batch(&connector, "rustle agent", 0).await;

        assert!(results.is_empty());
        assert_eq!(connector.connect_command_count(), 0);
    }
}
