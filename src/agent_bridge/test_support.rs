use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, AgentReconnectSnapshot, ReconnectingAgentBridge,
};
use crate::control_plane::connect_agent_bridge_transports_from_connector;
use crate::defaults::DEFAULT_MTU;
use crate::{agent_proto, agent_runtime, agent_transport};

pub(crate) async fn agent_transport_pair() -> (
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

pub(crate) async fn agent_transport_closes_after_first_open(
) -> (agent_transport::AgentTransport, tokio::task::JoinHandle<()>) {
    let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
    let agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        let hello = agent_proto::AgentFrame::new(
            agent_proto::AgentFrameKind::Hello,
            0,
            agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
        )
        .expect("test hello frame");
        let encoded = agent_proto::encode_frame(&hello).expect("encode test hello");
        writer.write_all(&encoded).await.expect("write test hello");
        writer.flush().await.expect("flush test hello");

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert!(
            matches!(
                open.kind,
                agent_proto::AgentFrameKind::OpenTcp
                    | agent_proto::AgentFrameKind::OpenTcpHost
                    | agent_proto::AgentFrameKind::OpenUdp
            ),
            "expected first stream open frame, got {:?}",
            open.kind
        );
    });

    let (client_reader, client_writer) = tokio::io::split(client_io);
    let transport =
        agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
            .await
            .expect("connect closing test agent transport");
    (transport, agent)
}

pub(crate) async fn agent_transport_closes_after_opened() -> (
    agent_transport::AgentTransport,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        let hello = agent_proto::AgentFrame::new(
            agent_proto::AgentFrameKind::Hello,
            0,
            agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
        )
        .expect("test hello frame");
        let encoded = agent_proto::encode_frame(&hello).expect("encode test hello");
        writer.write_all(&encoded).await.expect("write test hello");
        writer.flush().await.expect("flush test hello");

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert!(
            matches!(
                open.kind,
                agent_proto::AgentFrameKind::OpenTcp
                    | agent_proto::AgentFrameKind::OpenTcpHost
                    | agent_proto::AgentFrameKind::OpenUdp
            ),
            "expected first stream open frame, got {:?}",
            open.kind
        );
        let opened = agent_proto::AgentFrame::new(
            agent_proto::AgentFrameKind::Opened,
            open.stream_id,
            Bytes::new(),
        )
        .expect("test opened frame")
        .with_credit(1024);
        let encoded = agent_proto::encode_frame(&opened).expect("encode test opened");
        writer.write_all(&encoded).await.expect("write test opened");
        writer.flush().await.expect("flush test opened");
        let _ = close_rx.await;
    });

    let (client_reader, client_writer) = tokio::io::split(client_io);
    let transport =
        agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
            .await
            .expect("connect closing test agent transport");
    (transport, agent, close_tx)
}

async fn read_test_agent_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    inbound: &mut BytesMut,
) -> agent_proto::AgentFrame {
    loop {
        if let Some(frame) =
            agent_proto::try_decode_frame(inbound).expect("decode test agent frame")
        {
            return frame;
        }

        let mut buf = [0_u8; 8192];
        let read = reader.read(&mut buf).await.expect("read test agent frame");
        assert_ne!(read, 0, "test agent stream closed before next frame");
        inbound.extend_from_slice(&buf[..read]);
    }
}

pub(crate) struct QueuedAgentConnector {
    primary_command: String,
    forced_primary_failures: std::sync::Mutex<usize>,
    forced_command_failures: std::sync::Mutex<usize>,
    primary_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
    command_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
    command_requests: std::sync::Mutex<Vec<String>>,
}

impl QueuedAgentConnector {
    pub(crate) fn new(
        primary_command: &str,
        primary_transports: Vec<AgentBridgeTransport>,
        command_transports: Vec<AgentBridgeTransport>,
    ) -> Arc<Self> {
        Self::new_with_failures(
            primary_command,
            primary_transports,
            command_transports,
            0,
            0,
        )
    }

    pub(crate) fn new_with_primary_failures(
        primary_command: &str,
        primary_transports: Vec<AgentBridgeTransport>,
        command_transports: Vec<AgentBridgeTransport>,
        forced_primary_failures: usize,
    ) -> Arc<Self> {
        Self::new_with_failures(
            primary_command,
            primary_transports,
            command_transports,
            forced_primary_failures,
            0,
        )
    }

    pub(crate) fn new_with_failures(
        primary_command: &str,
        primary_transports: Vec<AgentBridgeTransport>,
        command_transports: Vec<AgentBridgeTransport>,
        forced_primary_failures: usize,
        forced_command_failures: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            primary_command: primary_command.to_owned(),
            forced_primary_failures: std::sync::Mutex::new(forced_primary_failures),
            forced_command_failures: std::sync::Mutex::new(forced_command_failures),
            primary_transports: std::sync::Mutex::new(VecDeque::from(primary_transports)),
            command_transports: std::sync::Mutex::new(VecDeque::from(command_transports)),
            command_requests: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn command_requests(&self) -> Vec<String> {
        self.command_requests
            .lock()
            .expect("command request lock")
            .clone()
    }
}

impl AgentBridgeConnector for QueuedAgentConnector {
    fn primary_command(&self) -> &str {
        &self.primary_command
    }

    fn connect_initial(&self, desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_> {
        Box::pin(async move {
            connect_agent_bridge_transports_from_connector(self, desired_sessions).await
        })
    }

    fn connect_primary(&self) -> AgentBridgeConnectFuture<'_> {
        Box::pin(async move {
            {
                let mut forced_failures = self
                    .forced_primary_failures
                    .lock()
                    .expect("primary failure counter lock");
                if *forced_failures > 0 {
                    *forced_failures -= 1;
                    return Err(anyhow!("test connector forced primary reconnect failure"));
                }
            }
            self.primary_transports
                .lock()
                .expect("primary transport queue lock")
                .pop_front()
                .ok_or_else(|| anyhow!("test connector has no primary transport"))
        })
    }

    fn connect_command<'a>(&'a self, agent_command: &'a str) -> AgentBridgeConnectFuture<'a> {
        Box::pin(async move {
            self.command_requests
                .lock()
                .expect("command request lock")
                .push(agent_command.to_owned());
            {
                let mut forced_failures = self
                    .forced_command_failures
                    .lock()
                    .expect("command failure counter lock");
                if *forced_failures > 0 {
                    *forced_failures -= 1;
                    return Err(anyhow!("test connector forced command lane failure"));
                }
            }
            self.command_transports
                .lock()
                .expect("command transport queue lock")
                .pop_front()
                .ok_or_else(|| {
                    anyhow!("test connector has no command transport for {agent_command}")
                })
        })
    }
}

pub(crate) async fn wait_for_transport_failure(transport: &agent_transport::AgentTransport) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if transport.failure_message().await.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test agent transport reports failure");
}

pub(crate) async fn wait_for_reconnect_snapshot(
    bridge: &ReconnectingAgentBridge,
    expected: AgentReconnectSnapshot,
) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if bridge.reconnect_snapshot() == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test agent bridge reaches reconnect snapshot");
}

pub(crate) fn detached_bridge_transport(
    transport: agent_transport::AgentTransport,
) -> AgentBridgeTransport {
    AgentBridgeTransport::detached_for_test(transport, "rustle agent")
}
