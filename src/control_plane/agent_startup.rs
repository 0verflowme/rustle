use anyhow::Result;

use super::agent_lane_batch::{
    connect_additional_agent_bridge_transport_batch, AGENT_INITIAL_CONNECT_BATCH,
};
use super::agent_policy::{
    format_agent_established_message, format_agent_fast_start_message, resolve_agent_session_count,
    validate_agent_session_count,
};
use crate::agent_bridge::{AgentBridgeConnector, AgentBridgeTransport};

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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent_bridge::{
        test_support::{agent_transport_pair, wait_for_reconnect_snapshot, QueuedAgentConnector},
        AgentReconnectSnapshot, ReconnectingAgentBridge,
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
    async fn auto_agent_startup_returns_after_primary_and_warms_extra_lanes() {
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

        let transports = connect_auto_agent_bridge_transports_from_connector(connector.as_ref(), 3)
            .await
            .expect("auto startup connects primary lane");
        assert_eq!(transports.len(), 1);
        assert!(
            connector.command_requests().is_empty(),
            "auto startup must not wait for extra lane commands before returning"
        );

        let bridge =
            ReconnectingAgentBridge::new_with_desired_lanes(connector.clone(), transports, 3);
        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 2,
                failures: 0,
            },
        )
        .await;
        assert_eq!(
            connector.command_requests(),
            vec![
                "/tmp/rustle-uploaded agent".to_owned(),
                "/tmp/rustle-uploaded agent".to_owned(),
            ]
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 3);
        assert_eq!(snapshot.lanes_desired, 3);
        assert_eq!(snapshot.lanes_available, 3);
        assert_eq!(snapshot.lanes_missing, 0);
        assert_eq!(snapshot.lanes_repairing, 0);

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
