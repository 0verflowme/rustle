use anyhow::Result;

use super::agent_lane_batch::{
    connect_additional_agent_bridge_transport_batch, AGENT_INITIAL_CONNECT_BATCH,
};
use super::agent_policy::{
    format_agent_established_message, resolve_agent_session_count, validate_agent_session_count,
};
use super::agent_startup_trace::AgentStartupTrace;
use crate::agent_bridge::{AgentBridgeConnector, AgentBridgeTransport};

use std::time::Instant;

const AGENT_INITIAL_CONNECT_RETRY_ROUNDS: usize = 1;

pub(super) async fn connect_initial_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;
    let mut trace = AgentStartupTrace::new("initial", desired_sessions);
    let mut transports = Vec::with_capacity(desired_sessions);

    let primary_started_at = Instant::now();
    let first = match connector.connect_primary().await {
        Ok(first) => {
            trace.primary_connect(primary_started_at, true);
            first
        }
        Err(err) => {
            trace.primary_connect(primary_started_at, false);
            trace.finish(0, "primary_error");
            return Err(err);
        }
    };
    let additional_agent_command = first.agent_command().to_owned();
    transports.push(first);

    let mut index = 1;
    while index < desired_sessions {
        let batch = (desired_sessions - index).min(AGENT_INITIAL_CONNECT_BATCH);
        let batch_started_at = Instant::now();
        let results = connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            batch,
        )
        .await;
        let mut successes = 0;
        let mut failures = 0;
        for (offset, result) in results.into_iter().enumerate() {
            match result {
                Ok(transport) => {
                    successes += 1;
                    transports.push(transport);
                }
                Err(err) => {
                    failures += 1;
                    eprintln!(
                        "agent: additional exec transport {}/{} failed: {err:#}; continuing with {} transport(s)",
                        index + offset + 1,
                        desired_sessions,
                        transports.len()
                    );
                }
            }
        }
        trace.extra_batch(batch_started_at, batch, successes, failures);
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
        let retry_batch = missing.min(AGENT_INITIAL_CONNECT_BATCH);
        let retry_started_at = Instant::now();
        let results = connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            retry_batch,
        )
        .await;
        let mut successes = 0;
        let mut failures = 0;
        for result in results {
            match result {
                Ok(transport) => {
                    successes += 1;
                    transports.push(transport);
                }
                Err(err) => {
                    failures += 1;
                    eprintln!(
                        "agent: retry for missing exec transport failed: {err:#}; continuing with {} transport(s)",
                        transports.len()
                    );
                }
            }
        }
        trace.retry_batch(retry_started_at, retry_batch, successes, failures);
    }

    let outcome = if transports.len() == desired_sessions {
        "ok"
    } else {
        "degraded"
    };
    eprintln!(
        "{}",
        format_agent_established_message(transports.len(), desired_sessions)
    );
    trace.finish(transports.len(), outcome);
    Ok(transports)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent_bridge::{
        test_support::{agent_transport_pair, QueuedAgentConnector},
        ReconnectingAgentBridge,
    };

    #[tokio::test]
    async fn agent_initial_startup_reuses_first_effective_command_for_extra_lanes() {
        let (first_transport, first_agent) = agent_transport_pair().await;
        let (second_transport, second_agent) = agent_transport_pair().await;
        let (third_transport, third_agent) = agent_transport_pair().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                first_transport,
                "/tmp/rustle-uploaded agent".to_owned(),
            )],
            vec![
                AgentBridgeTransport::detached_for_test(
                    second_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    third_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
            ],
        );

        let transports = connector
            .connect_initial(3)
            .await
            .expect("connect initial lanes");
        assert_eq!(transports.len(), 3);
        assert_eq!(
            transports
                .iter()
                .map(|transport| transport.agent_command())
                .collect::<Vec<_>>(),
            vec![
                "/tmp/rustle-uploaded agent",
                "/tmp/rustle-uploaded agent",
                "/tmp/rustle-uploaded agent",
            ]
        );
        assert_eq!(
            connector.command_requests(),
            vec![
                "/tmp/rustle-uploaded agent".to_owned(),
                "/tmp/rustle-uploaded agent".to_owned(),
            ]
        );

        drop(transports);
        for agent in [first_agent, second_agent, third_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure() {
        let (first_transport, first_agent) = agent_transport_pair().await;
        let (second_transport, second_agent) = agent_transport_pair().await;
        let (third_transport, third_agent) = agent_transport_pair().await;
        let connector = QueuedAgentConnector::new_with_failures(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                first_transport,
                "/tmp/rustle-uploaded agent".to_owned(),
            )],
            vec![
                AgentBridgeTransport::detached_for_test(
                    second_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    third_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
            ],
            0,
            1,
        );

        let transports = connector
            .connect_initial(4)
            .await
            .expect("connect initial lanes despite one extra-lane failure");
        assert_eq!(transports.len(), 3);
        let command_requests = connector.command_requests();
        assert_eq!(command_requests.len(), 4);
        assert!(command_requests
            .iter()
            .all(|command| command == "/tmp/rustle-uploaded agent"));

        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(connector, transports, 4);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_desired, 4);

        drop(bridge);
        for agent in [first_agent, second_agent, third_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_retries_missing_extra_lanes_after_transient_failure() {
        let (first_transport, first_agent) = agent_transport_pair().await;
        let (second_transport, second_agent) = agent_transport_pair().await;
        let (third_transport, third_agent) = agent_transport_pair().await;
        let (fourth_transport, fourth_agent) = agent_transport_pair().await;
        let connector = QueuedAgentConnector::new_with_failures(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                first_transport,
                "/tmp/rustle-uploaded agent".to_owned(),
            )],
            vec![
                AgentBridgeTransport::detached_for_test(
                    second_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    third_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    fourth_transport,
                    "/tmp/rustle-uploaded agent".to_owned(),
                ),
            ],
            0,
            1,
        );

        let transports = connector
            .connect_initial(4)
            .await
            .expect("retry missing startup lane after transient failure");
        assert_eq!(transports.len(), 4);
        let command_requests = connector.command_requests();
        assert_eq!(command_requests.len(), 4);
        assert!(command_requests
            .iter()
            .all(|command| command == "/tmp/rustle-uploaded agent"));

        drop(transports);
        for agent in [first_agent, second_agent, third_agent, fourth_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }
}
