use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge, ReconnectingAgentBridge,
};
use crate::{agent_runtime, agent_transport, quic_agent, DEFAULT_MTU};

pub(crate) async fn test_agent_transport() -> (
    agent_transport::AgentTransport,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
    let (agent_reader, agent_writer) = tokio::io::split(agent_io);
    let agent = tokio::spawn(agent_runtime::run(
        agent_reader,
        agent_writer,
        agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
    ));

    let (client_reader, client_writer) = tokio::io::split(client_io);
    let transport =
        agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
            .await
            .expect("connect test agent transport");
    (transport, agent)
}

pub(crate) async fn test_quic_native_bridge() -> (QuicNativeBridge, tokio::task::JoinHandle<()>) {
    let quic_server =
        quic_agent::start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("start native QUIC bridge");
    let quic_addr = quic_server.local_addr().expect("QUIC local address");
    let bootstrap = quic_server.bootstrap().clone();
    let bridge_task =
        tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });
    let client = quic_agent::connect_quic_bridge(quic_addr, &bootstrap)
        .await
        .expect("connect native QUIC bridge");
    (QuicNativeBridge::detached(client), bridge_task)
}

pub(crate) fn detached_reconnecting_agent_bridge(
    transport: agent_transport::AgentTransport,
) -> ReconnectingAgentBridge {
    ReconnectingAgentBridge::new(
        Arc::new(FailingAgentConnector),
        vec![AgentBridgeTransport::detached_for_test(
            transport,
            "rustle agent",
        )],
    )
}

struct FailingAgentConnector;

impl AgentBridgeConnector for FailingAgentConnector {
    fn primary_command(&self) -> &str {
        "rustle agent"
    }

    fn connect_initial(&self, _desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_> {
        Box::pin(async { anyhow::bail!("test connector should not create initial transports") })
    }

    fn connect_primary(&self) -> AgentBridgeConnectFuture<'_> {
        Box::pin(async { anyhow::bail!("test connector should not reconnect primary lanes") })
    }

    fn connect_command<'a>(&'a self, _agent_command: &'a str) -> AgentBridgeConnectFuture<'a> {
        Box::pin(async { anyhow::bail!("test connector should not reconnect command lanes") })
    }
}
