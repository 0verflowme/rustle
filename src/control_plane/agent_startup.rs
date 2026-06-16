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

    use crate::agent_bridge::{
        test_support::{agent_transport_pair, wait_for_reconnect_snapshot, QueuedAgentConnector},
        AgentReconnectSnapshot, ReconnectingAgentBridge,
    };
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
