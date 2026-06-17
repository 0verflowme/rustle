use anyhow::Result;

use crate::agent_bridge::{AgentBridgeConnector, AgentBridgeTransport};

pub(super) const AGENT_INITIAL_CONNECT_BATCH: usize = 4;

pub(super) async fn connect_additional_agent_bridge_transport_batch(
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

    #[tokio::test]
    async fn zero_additional_lane_batch_does_not_touch_connector() {
        let connector = PanicConnector::new();

        let results =
            connect_additional_agent_bridge_transport_batch(&connector, "rustle agent", 0).await;

        assert!(results.is_empty());
        assert_eq!(connector.connect_command_count(), 0);
    }
}
