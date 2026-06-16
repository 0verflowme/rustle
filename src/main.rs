#[cfg(test)]
use std::collections::VecDeque;
use std::net::Ipv4Addr;
#[cfg(test)]
use std::time::Duration;

use anyhow::Result;
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use bytes::BytesMut;
use clap::Parser;
#[cfg(test)]
use tokio::sync::mpsc;

mod agent_bridge;
#[cfg(test)]
mod agent_client;
mod agent_lab;
#[allow(dead_code)]
mod agent_proto;
mod agent_runtime;
mod agent_transport;
mod agent_window;
mod bridge_lab;
mod bridge_runtime;
mod cli;
mod command_runtime;
mod control_plane;
mod data_plane;
mod dns;
mod helper_runtime;
mod lab_support;
mod packet_engine;
mod platform;
mod quic_agent;
mod quic_agent_runtime;
mod remote_helper;
mod routing;
mod ssh_bridge;
mod ssh_control;
mod supervisor;
#[allow(dead_code)]
mod tcp_core;
mod transport_model;
mod tun_io;
mod tunnel_lifecycle;

#[cfg(test)]
use agent_bridge::{
    agent_host_lane_index, agent_lane_backoff_duration, agent_lane_bit, agent_lane_index,
    AgentBridgeCarrier, AgentBridgeConnectFuture, AgentBridgeConnectManyFuture,
    AgentBridgeTransport, AgentReconnectSnapshot, ReconnectingAgentBridge, AGENT_LANE_BACKOFF_BASE,
    AGENT_LANE_BACKOFF_MAX,
};
use agent_lab::{run_agent_dns_lab, run_agent_lab, run_agent_udp_lab};
use bridge_lab::run_bridge_lab;
use cli::{Cli, CommandKind};
pub(crate) use cli::{SshArgs, TunCaptureArgs, TunnelArgs};
use command_runtime::{run_compact_tunnel, run_direct_tcpip};
#[cfg(test)]
use control_plane::{
    connect_agent_bridge_transports_from_connector,
    connect_auto_agent_bridge_transports_from_connector,
};
#[cfg(test)]
use data_plane::spawn_agent_tcp_bridge;
use helper_runtime::{run_agent, run_quic_agent, run_quic_bridge_agent};
use supervisor::{run_tun_capture, run_tunnel};

pub(crate) const DEFAULT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub(crate) const DEFAULT_TUN_PREFIX: u8 = 24;
pub(crate) const DEFAULT_MTU: u16 = 1300;
pub(crate) const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS: u64 = 60_000;
pub(crate) const DEFAULT_SSH_SESSIONS: usize = 4;
pub(crate) const DEFAULT_AGENT_SESSIONS: usize = 1;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(CommandKind::DirectTcpip(args)) => run_direct_tcpip(args).await,
        Some(CommandKind::TunCapture(args)) => run_tun_capture(args).await,
        Some(CommandKind::Tunnel(args)) => run_tunnel(args).await,
        Some(CommandKind::BridgeLab(args)) => run_bridge_lab(args).await,
        Some(CommandKind::AgentLab(args)) => run_agent_lab(args).await,
        Some(CommandKind::AgentUdpLab(args)) => run_agent_udp_lab(args).await,
        Some(CommandKind::AgentDnsLab(args)) => run_agent_dns_lab(args).await,
        Some(CommandKind::QuicAgent(args)) => run_quic_agent(args).await,
        Some(CommandKind::QuicBridgeAgent(args)) => run_quic_bridge_agent(args).await,
        Some(CommandKind::Agent(args)) => run_agent(args).await,
        None => run_compact_tunnel(cli.compact).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_bridge::AgentBridgeConnector;
    use anyhow::anyhow;
    use std::sync::Arc;

    #[test]
    fn agent_lane_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            seen.insert(agent_lane_index(
                &agent_proto::AgentOpenIpv4 {
                    destination_ip: Ipv4Addr::new(192, 168, 1, 10),
                    destination_port: 443,
                    originator_ip: Ipv4Addr::new(10, 255, 255, 2),
                    originator_port: 49152 + offset,
                },
                6,
                4,
            ));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn agent_host_lane_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            seen.insert(agent_host_lane_index(
                &agent_proto::AgentOpenHost {
                    destination_host: "resolver.internal".to_owned(),
                    destination_port: 53,
                    originator_ip: Ipv4Addr::new(10, 255, 255, 2),
                    originator_port: 49152 + offset,
                },
                6,
                4,
            ));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn agent_lane_backoff_is_bounded_and_progressive() {
        let first = agent_lane_backoff_duration(0, 1);
        let second = agent_lane_backoff_duration(0, 2);
        let later = agent_lane_backoff_duration(0, 32);
        let shifted_lane = agent_lane_backoff_duration(1, 1);

        assert!(first >= AGENT_LANE_BACKOFF_BASE);
        assert!(second > first);
        assert_eq!(later, AGENT_LANE_BACKOFF_MAX);
        assert!(shifted_lane > first);
        assert!(shifted_lane <= AGENT_LANE_BACKOFF_MAX);
    }

    async fn test_agent_transport() -> (
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

    async fn test_agent_transport_closes_after_first_open(
    ) -> (agent_transport::AgentTransport, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

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

    async fn test_agent_transport_closes_after_opened() -> (
        agent_transport::AgentTransport,
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

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

    struct QueuedAgentConnector {
        primary_command: String,
        forced_primary_failures: std::sync::Mutex<usize>,
        forced_command_failures: std::sync::Mutex<usize>,
        primary_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
        command_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
        command_requests: std::sync::Mutex<Vec<String>>,
    }

    impl QueuedAgentConnector {
        fn new(
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

        fn new_with_primary_failures(
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

        fn new_with_failures(
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

        fn command_requests(&self) -> Vec<String> {
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

    async fn wait_for_transport_failure(transport: &agent_transport::AgentTransport) {
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

    async fn wait_for_reconnect_snapshot(
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

    fn detached_bridge_transport(
        transport: agent_transport::AgentTransport,
    ) -> AgentBridgeTransport {
        AgentBridgeTransport::detached_for_test(transport, "rustle agent")
    }

    #[tokio::test]
    async fn detached_agent_carrier_disconnect_is_noop() {
        AgentBridgeCarrier::Detached
            .disconnect("detached test done")
            .await
            .expect("detached carrier disconnect");
    }

    #[tokio::test]
    async fn agent_tcp_bridge_sends_local_data_before_agent_opened() {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

        async fn write_test_agent_frame<W: AsyncWrite + Unpin>(
            writer: &mut W,
            frame: agent_proto::AgentFrame,
        ) {
            let encoded = agent_proto::encode_frame(&frame).expect("encode test agent frame");
            writer
                .write_all(&encoded)
                .await
                .expect("write test agent frame");
            writer.flush().await.expect("flush test agent frame");
        }

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (data_seen_tx, data_seen_rx) = tokio::sync::oneshot::channel();
        let (send_opened_tx, send_opened_rx) = tokio::sync::oneshot::channel();
        let fake_agent = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(agent_io);
            let mut inbound = BytesMut::new();

            let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
            write_test_agent_frame(
                &mut writer,
                agent_proto::AgentFrame::new(
                    agent_proto::AgentFrameKind::Hello,
                    0,
                    agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
                )
                .expect("test hello frame"),
            )
            .await;

            let open = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

            let window = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
            assert_eq!(window.stream_id, open.stream_id);

            let data = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
            assert_eq!(data.stream_id, open.stream_id);
            assert_eq!(&data.payload[..], b"hello");
            data_seen_tx.send(()).expect("report optimistic data");

            send_opened_rx.await.expect("release opened frame");
            write_test_agent_frame(
                &mut writer,
                agent_proto::AgentFrame::new(
                    agent_proto::AgentFrameKind::Opened,
                    open.stream_id,
                    Bytes::new(),
                )
                .expect("opened frame")
                .with_credit((1024 * 1024) as u32),
            )
            .await;
        });

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect fake agent transport");
        let agent = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 1),
                49152,
                Ipv4Addr::new(192, 0, 2, 10),
                443,
            ),
            1,
        );
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let bridge = spawn_agent_tcp_bridge(id, event_tx, agent);

        assert!(
            bridge
                .try_send_local_data(Bytes::from_static(b"hello"))
                .expect("queue local data"),
            "bridge should accept first local payload"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), data_seen_rx)
            .await
            .expect("agent sees data before opened")
            .expect("data seen notification");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv())
                .await
                .is_err(),
            "bridge must not report opened before the agent sends Opened"
        );

        send_opened_tx.send(()).expect("release fake opened");
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
            .await
            .expect("opened event")
            .expect("bridge event");
        assert!(
            matches!(event, ssh_bridge::BridgeEvent::Opened { id: event_id, .. } if event_id == id)
        );

        drop(bridge);
        fake_agent.await.expect("fake agent join");
    }

    #[tokio::test]
    async fn agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![detached_bridge_transport(replacement_transport)],
                Vec::new(),
            ),
            vec![
                detached_bridge_transport(first_transport.clone()),
                detached_bridge_transport(second_transport),
            ],
        );

        bridge.set_lane_load_for_test(0, 5);
        assert_eq!(bridge.choose_lane_index_for_test(0, 1).await, 1);

        bridge.set_lane_load_for_test(1, 8);
        assert_eq!(bridge.choose_lane_index_for_test(0, 1).await, 0);

        first_agent.abort();
        let _ = first_agent.await;
        wait_for_transport_failure(&first_transport).await;
        assert_eq!(bridge.choose_lane_index_for_test(0, 1).await, 1);
        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 2);
        assert_eq!(snapshot.lanes_failed, 0);

        drop(bridge);
        for agent in [second_agent, replacement_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy() {
        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        let (failed_secondary_transport, failed_secondary_agent) = test_agent_transport().await;
        let (busy_transport, busy_agent) = test_agent_transport().await;
        let (idle_transport, idle_agent) = test_agent_transport().await;
        let (primary_replacement_transport, primary_replacement_agent) =
            test_agent_transport().await;
        let (secondary_replacement_transport, secondary_replacement_agent) =
            test_agent_transport().await;

        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;
        failed_secondary_agent.abort();
        let _ = failed_secondary_agent.await;
        wait_for_transport_failure(&failed_secondary_transport).await;

        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![
                    detached_bridge_transport(primary_replacement_transport),
                    detached_bridge_transport(secondary_replacement_transport),
                ],
                Vec::new(),
            ),
            vec![
                detached_bridge_transport(failed_primary_transport),
                detached_bridge_transport(failed_secondary_transport),
                detached_bridge_transport(busy_transport),
                detached_bridge_transport(idle_transport),
            ],
        );

        bridge.set_lane_load_for_test(2, 7);
        bridge.set_lane_load_for_test(3, 1);
        assert_eq!(bridge.choose_lane_index_for_test(0, 1).await, 3);

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 2,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_available, 4);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_repairing, 0);

        drop(bridge);
        for agent in [
            busy_agent,
            idle_agent,
            primary_replacement_agent,
            secondary_replacement_agent,
        ] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn alternate_lane_selection_scans_by_load_without_snapshot_vector() {
        let (skipped_transport, skipped_agent) = test_agent_transport().await;
        let (busy_transport, busy_agent) = test_agent_transport().await;
        let (idle_transport, idle_agent) = test_agent_transport().await;
        let (middle_transport, middle_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![
                detached_bridge_transport(skipped_transport),
                detached_bridge_transport(busy_transport),
                detached_bridge_transport(idle_transport),
                detached_bridge_transport(middle_transport),
            ],
        );

        bridge.set_lane_load_for_test(1, 9);
        bridge.set_lane_load_for_test(2, 1);
        bridge.set_lane_load_for_test(3, 4);

        let first = bridge
            .next_alternate_lane_index_for_test(0, 0)
            .expect("first alternate lane");
        assert_eq!(first, 2);

        let second = bridge
            .next_alternate_lane_index_for_test(0, agent_lane_bit(first))
            .expect("second alternate lane");
        assert_eq!(second, 3);

        let tried = agent_lane_bit(first) | agent_lane_bit(second);
        let third = bridge
            .next_alternate_lane_index_for_test(0, tried)
            .expect("third alternate lane");
        assert_eq!(third, 1);

        let tried = tried | agent_lane_bit(third);
        assert!(bridge
            .next_alternate_lane_index_for_test(0, tried)
            .is_none());

        drop(bridge);
        for agent in [skipped_agent, busy_agent, idle_agent, middle_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn background_lane_repair_requests_are_coalesced() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );

        assert!(bridge.try_start_background_lane_repair_for_test(0));
        assert!(
            !bridge.try_start_background_lane_repair_for_test(0),
            "duplicate background repair request should be coalesced"
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_repairing, 1);

        bridge.finish_background_lane_repair_for_test(0).await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_repairing, 0);
        assert!(bridge.try_start_background_lane_repair_for_test(0));
        bridge.finish_background_lane_repair_for_test(0).await;

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn agent_bridge_stream_load_is_released_on_close() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            use tokio::io::AsyncReadExt;
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert!(request.is_empty());
        });

        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };

        let stream = bridge
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 49152,
            })
            .await
            .expect("open tracked agent stream");
        assert_eq!(bridge.lane_load_for_test(0), 1);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.active_streams, 1);
        assert_eq!(snapshot.max_lane_load, 1);

        stream.close().await.expect("close tracked stream");
        assert_eq!(bridge.lane_load_for_test(0), 0);

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn agent_bridge_repairs_lane_after_active_stream_transport_failure() {
        let (dying_transport, dying_agent, close_dying_transport) =
            test_agent_transport_closes_after_opened().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![detached_bridge_transport(replacement_transport)],
                Vec::new(),
            ),
            vec![detached_bridge_transport(dying_transport)],
        );

        let mut stream = bridge
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: Ipv4Addr::new(127, 0, 0, 1),
                destination_port: 443,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 49152,
            })
            .await
            .expect("open tracked agent stream");
        assert_eq!(bridge.lane_load_for_test(0), 1);

        close_dying_transport
            .send(())
            .expect("signal fake agent transport close");
        dying_agent.await.expect("dying fake agent join");
        let reset = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
            .await
            .expect("receive active stream reset after transport failure")
            .expect("stream reset frame");
        assert_eq!(reset.kind, agent_proto::AgentFrameKind::Reset);
        assert!(
            String::from_utf8_lossy(&reset.payload).contains("agent"),
            "reset payload should explain the agent transport failure"
        );

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(snapshot.active_streams, 1);

        drop(stream);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.active_streams, 0);

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
    }

    #[tokio::test]
    async fn agent_initial_startup_reuses_first_effective_command_for_extra_lanes() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
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
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
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
    async fn fast_start_missing_lane_warmup_can_be_deferred() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                first_transport,
                "/tmp/rustle-uploaded agent".to_owned(),
            )],
            vec![AgentBridgeTransport::detached_for_test(
                second_transport,
                "/tmp/rustle-uploaded agent".to_owned(),
            )],
        );

        let transports = connect_auto_agent_bridge_transports_from_connector(connector.as_ref(), 2)
            .await
            .expect("auto startup connects primary lane");
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes_and_missing_repair_delay(
            connector.clone(),
            transports,
            2,
            Some(Duration::from_millis(100)),
        );

        tokio::task::yield_now().await;
        assert!(
            connector.command_requests().is_empty(),
            "deferred warmup should not compete with the first scheduler turn"
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_missing, 1);
        assert_eq!(snapshot.lanes_repairing, 1);

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        assert_eq!(
            connector.command_requests(),
            vec!["/tmp/rustle-uploaded agent".to_owned()]
        );

        drop(bridge);
        for agent in [first_agent, second_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
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
    async fn agent_bridge_repairs_missing_startup_lane_in_background() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let (fourth_transport, fourth_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![detached_bridge_transport(fourth_transport)],
            Vec::new(),
        );
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(
            connector.clone(),
            vec![
                detached_bridge_transport(first_transport),
                detached_bridge_transport(second_transport),
                detached_bridge_transport(third_transport),
            ],
            4,
        );

        let snapshot = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let snapshot = bridge.snapshot().await;
                if snapshot.lanes_available == 4 && snapshot.lanes_missing == 0 {
                    return snapshot;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("missing startup lane is repaired");
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_desired, 4);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_quarantined, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            }
        );
        assert_eq!(connector.command_requests(), Vec::<String>::new());

        drop(bridge);
        for agent in [first_agent, second_agent, third_agent, fourth_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn background_repair_retries_missing_lane_after_quarantine() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![detached_bridge_transport(replacement_transport)],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(
            connector.clone(),
            vec![detached_bridge_transport(first_transport)],
            2,
        );

        let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let snapshot = bridge.snapshot().await;
                if snapshot.lanes_available == 2 && snapshot.lanes_missing == 0 {
                    return snapshot;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("missing lane is retried after quarantine");
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_desired, 2);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_quarantined, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );
        assert_eq!(connector.command_requests(), Vec::<String>::new());

        drop(bridge);
        for agent in [first_agent, replacement_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_retries_missing_extra_lanes_after_transient_failure() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let (fourth_transport, fourth_agent) = test_agent_transport().await;
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

    #[tokio::test]
    async fn reconnecting_agent_repairs_failed_lane_through_connector() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair");
            socket
                .write_all(b"connector:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                replacement_transport,
                "rustle agent".to_owned(),
            )],
            Vec::new(),
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![AgentBridgeTransport::detached_for_test(
                failed_transport,
                "rustle agent".to_owned(),
            )],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("open stream through repaired lane");
        stream
            .send_data(Bytes::from_static(b"repair"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"connector:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_uses_alternate_lane_when_preferred_lane_reconnect_fails() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"ping");
            socket.write_all(b"alt:pong").await.expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (healthy_transport, healthy_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport::detached_for_test(
                    failed_transport,
                    "rustle agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    healthy_transport,
                    "rustle agent".to_owned(),
                ),
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("open stream through alternate lane");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "alternate lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"alt:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 0,
                failures: 1,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), healthy_agent)
            .await
            .expect("healthy agent exits")
            .expect("healthy agent join")
            .expect("healthy agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair-alt");
            socket
                .write_all(b"repaired-alt:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;

        let (failed_alternate_transport, failed_alternate_agent) = test_agent_transport().await;
        failed_alternate_agent.abort();
        let _ = failed_alternate_agent.await;
        wait_for_transport_failure(&failed_alternate_transport).await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                replacement_transport,
                "rustle agent".to_owned(),
            )],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport::detached_for_test(
                    failed_primary_transport,
                    "rustle agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    failed_alternate_transport,
                    "rustle agent".to_owned(),
                ),
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("repair failed alternate lane after primary reconnect failure");
        stream
            .send_data(Bytes::from_static(b"repair-alt"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired alternate lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"repaired-alt:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );

        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_failed, 1);
        assert_eq!(snapshot.lanes_quarantined, 1);

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_repairs_alternate_lane_that_fails_during_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair-during-open");
            socket
                .write_all(b"repaired-open:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;

        let (dying_alternate_transport, dying_alternate_agent) =
            test_agent_transport_closes_after_first_open().await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![AgentBridgeTransport::detached_for_test(
                replacement_transport,
                "rustle agent".to_owned(),
            )],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport::detached_for_test(
                    failed_primary_transport,
                    "rustle agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    dying_alternate_transport,
                    "rustle agent".to_owned(),
                ),
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("repair alternate lane that fails during open");
        stream
            .send_data(Bytes::from_static(b"repair-during-open"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired alternate-open stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"repaired-open:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        dying_alternate_agent
            .await
            .expect("dying alternate agent join");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_quarantines_failed_lane_after_reconnect_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            for (request, response) in [
                (&b"first"[..], &b"alt:first"[..]),
                (&b"second"[..], &b"alt:second"[..]),
            ] {
                let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
                let mut received = Vec::new();
                socket
                    .read_to_end(&mut received)
                    .await
                    .expect("read request");
                assert_eq!(received, request);
                socket.write_all(response).await.expect("write response");
                socket.shutdown().await.expect("shutdown TCP stream");
            }
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (healthy_transport, healthy_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport::detached_for_test(
                    failed_transport,
                    "rustle agent".to_owned(),
                ),
                AgentBridgeTransport::detached_for_test(
                    healthy_transport,
                    "rustle agent".to_owned(),
                ),
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        for (index, (request, expected)) in [
            (&b"first"[..], &b"alt:first"[..]),
            (&b"second"[..], &b"alt:second"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut stream = bridge
                .open_tcp_ipv4(open)
                .await
                .expect("open stream through alternate lane");
            if index == 0 {
                let snapshot = bridge.snapshot().await;
                assert_eq!(snapshot.reconnects.attempts, 1);
                assert_eq!(snapshot.reconnects.successes, 0);
                assert_eq!(snapshot.reconnects.failures, 1);
                assert_eq!(snapshot.lanes_total, 2);
                assert_eq!(snapshot.lanes_available, 1);
                assert_eq!(snapshot.lanes_failed, 1);
                assert_eq!(snapshot.lanes_quarantined, 1);
                assert!(snapshot.max_quarantine_ms > 0);
                assert!(snapshot.max_quarantine_ms <= AGENT_LANE_BACKOFF_MAX.as_millis() as u64);
            }
            stream
                .send_data(Bytes::copy_from_slice(request))
                .await
                .expect("send request");
            stream.send_eof().await.expect("send EOF");

            let mut response = Vec::new();
            let mut saw_eof = false;
            loop {
                let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                    .await
                    .expect("receive agent frame")
                    .expect("agent stream frame");
                match frame.kind {
                    agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                    agent_proto::AgentFrameKind::Eof => saw_eof = true,
                    agent_proto::AgentFrameKind::Close => break,
                    agent_proto::AgentFrameKind::Reset => {
                        panic!(
                            "alternate lane stream reset: {}",
                            String::from_utf8_lossy(&frame.payload)
                        );
                    }
                    other => panic!("unexpected agent frame {other:?}"),
                }
            }
            assert!(saw_eof);
            assert_eq!(response, expected);
        }

        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 0,
                failures: 1,
            }
        );

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), healthy_agent)
            .await
            .expect("healthy agent exits")
            .expect("healthy agent join")
            .expect("healthy agent run");
        server.await.expect("TCP server join");
    }
}
