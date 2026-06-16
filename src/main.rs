#[cfg(test)]
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use bytes::BytesMut;
use clap::Parser;
#[cfg(test)]
use ipnet::Ipv4Net;
#[cfg(test)]
use smoltcp::socket::tcp;
use tokio::io::{self, AsyncWriteExt};
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
mod control_plane;
mod data_plane;
mod dns;
mod helper_runtime;
mod lab_support;
mod packet_engine;
mod platform;
mod quic_agent;
mod remote_helper;
mod routing;
mod ssh_bridge;
mod ssh_control;
mod supervisor;
#[allow(dead_code)]
mod tcp_core;
mod transport_model;

#[cfg(test)]
use agent_bridge::{
    agent_host_lane_index, agent_lane_backoff_duration, agent_lane_bit, agent_lane_index,
    AgentBridgeCarrier, AgentBridgeConnectFuture, AgentBridgeConnectManyFuture,
    AgentBridgeTransport, AgentReconnectSnapshot, QuicNativeBridge, ReconnectingAgentBridge,
    AGENT_LANE_BACKOFF_BASE, AGENT_LANE_BACKOFF_MAX,
};
use agent_lab::{run_agent_dns_lab, run_agent_lab, run_agent_udp_lab};
use bridge_lab::run_bridge_lab;
#[cfg(test)]
use bridge_lab::{
    abort_bridge_lab_client_socket, bridge_lab_client_complete, bridge_lab_latency_percentiles,
    bridge_lab_response_complete, drain_lab_client_to_manager, pump_lab_manager_to_clients,
    route_lab_packets_to_clients, synthetic_lab_client, BridgeLabClient, BridgeLabLatencySummary,
};
#[cfg(test)]
use bridge_runtime::UdpAssociationTransport;
use cli::{Cli, CommandKind, CompactTunnelArgs, DirectTcpipArgs};
pub(crate) use cli::{SshArgs, TunCaptureArgs, TunnelArgs};
#[cfg(test)]
use control_plane::{
    connect_agent_bridge_transports_from_connector,
    connect_auto_agent_bridge_transports_from_connector,
};
#[cfg(test)]
use data_plane::{
    query_dns_over_agent, query_dns_over_agent_udp, query_dns_over_transport, query_udp_over_agent,
    run_udp_association, run_udp_association_transport, send_dns_response_event,
    spawn_agent_tcp_bridge, spawn_udp_association_with_idle_timeout,
};
use helper_runtime::{run_agent, run_quic_agent, run_quic_bridge_agent};
use lab_support::default_http_request;
#[cfg(test)]
use packet_engine::{
    drain_local_bytes_to_bridges, drop_unsupported_direct_udp, execute_udp_ingress_action,
    format_bytes, format_duration, handle_bridge_event, handle_bridge_event_into,
    plan_udp_datagram_actions, should_log_stale_bridge_event, BridgeAdmissionStats,
    BridgeEventStats, DnsInflight, LocalDrainStats, RemoteBacklogPush, RemoteBacklogs,
    TunWriteStats, TunnelStats, UdpAssociationTransportPlan, UdpDropReason, UdpIngressAction,
    MAX_ACTIVE_UDP_ASSOCIATIONS, REMOTE_BACKLOG_BYTES_PER_FLOW, REMOTE_BACKLOG_BYTES_TOTAL,
    REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW,
};
#[cfg(test)]
use remote_helper::{effective_agent_command, effective_bridge_agent_command};
use ssh_control::connect_ssh;
#[cfg(test)]
use ssh_control::DEFAULT_SSH_CONNECT_TIMEOUT_SECS;
#[cfg(test)]
use ssh_control::{
    home_dir, known_hosts_entry_matches, parse_ssh_config_for_host, parse_ssh_endpoint,
    parse_ssh_target, patterns_match, prepare_ssh_connection, read_password_file,
    recommended_agent_session_count_for_parallelism, resolve_agent_session_count,
    resolve_ssh_password, resolve_ssh_target, ssh_session_index_for_flow,
    validate_agent_session_count, validate_agent_session_request_count, validate_ssh_session_count,
    HostKeyVerifier, SshConfigMatch, SshEndpoint, SshTarget, AUTO_AGENT_SESSIONS,
    MAX_AUTO_AGENT_SESSIONS, MAX_SSH_SESSIONS,
};
#[cfg(test)]
use supervisor::{
    parse_ipv4_metadata, unix_shutdown_signals, validate_tun_args, validate_tunnel_args,
    virtual_dns_ip,
};
use supervisor::{run_tun_capture, run_tunnel};
use transport_model::parse_destination;
#[cfg(test)]
use transport_model::{
    bridge_admission_decision, BridgeAdmissionDecision, BridgeAdmissionLimits,
    DataPlaneReconnectSnapshot, DataPlaneRuntimeSnapshot, Destination, DnsResponseEvent,
    UdpAssociation, UdpAssociationEvents, UdpFlowKey, MAX_AGENT_ACTIVE_STREAMS,
    MAX_AGENT_OPENING_STREAMS, MAX_DIRECT_ACTIVE_CHANNELS, MAX_DIRECT_OPENING_CHANNELS,
};
#[cfg(test)]
use transport_model::{BridgeTransportKind, UDP_DATAGRAMS_PER_ASSOCIATION};

pub(crate) const DEFAULT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub(crate) const DEFAULT_TUN_PREFIX: u8 = 24;
pub(crate) const DEFAULT_MTU: u16 = 1300;
const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS: u64 = 60_000;
#[cfg(test)]
const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
    Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);
pub(crate) const DEFAULT_SSH_SESSIONS: usize = 4;
pub(crate) const DEFAULT_AGENT_SESSIONS: usize = 1;

#[cfg(test)]
fn admit_udp_datagram(
    transport: UdpAssociationTransport,
    request: dns::UdpPacket,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
    stats: &mut TunnelStats,
) {
    let mut actions = Vec::new();
    let transport = UdpAssociationTransportPlan::new(transport.label(), transport);
    plan_udp_datagram_actions(
        Some(transport),
        request,
        associations,
        association_limit,
        events,
        idle_timeout,
        &mut actions,
    );
    packet_engine::execute_udp_ingress_actions(
        &mut actions,
        associations,
        association_limit,
        stats,
        &mut |transport, key, from_local, events, idle_timeout| {
            spawn_udp_association_with_idle_timeout(
                transport,
                key,
                from_local,
                events,
                idle_timeout,
            );
        },
    );
}

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

async fn run_direct_tcpip(args: DirectTcpipArgs) -> Result<()> {
    let destination = parse_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));

    let handle = connect_ssh(&args.ssh).await?;

    let mut channel = handle
        .channel_open_direct_tcpip(
            destination.host.clone(),
            destination.port.into(),
            "127.0.0.1",
            0,
        )
        .await
        .with_context(|| {
            format!(
                "failed to open SSH direct-tcpip channel to {}:{}",
                destination.host, destination.port
            )
        })?;

    channel
        .data(request.as_bytes())
        .await
        .context("failed to write request to SSH channel")?;
    channel
        .eof()
        .await
        .context("failed to send EOF to SSH channel")?;

    let mut stdout = io::stdout();
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                stdout
                    .write_all(&data)
                    .await
                    .context("failed to write channel data to stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, .. } => {
                stdout
                    .write_all(&data)
                    .await
                    .context("failed to write channel extended data to stdout")?;
            }
            russh::ChannelMsg::Eof => break,
            russh::ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    bail!("remote channel returned non-zero exit status {exit_status}");
                }
            }
            _ => {}
        }
    }

    stdout.flush().await.context("failed to flush stdout")?;
    handle
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await?;
    Ok(())
}

async fn run_compact_tunnel(args: CompactTunnelArgs) -> Result<()> {
    if args.targets.is_empty() {
        bail!("missing target CIDR; usage: rustle -r user@host 10.0.0.0/8 [172.16.0.0/12]");
    }

    run_tunnel(TunnelArgs {
        ssh: args.ssh,
        targets: args.targets,
        tun_ip: args.tun_ip,
        tun_prefix: args.tun_prefix,
        mtu: args.mtu,
        name: args.name,
        configure_dns: args.configure_dns,
        dns_remote: args.dns_remote,
        ssh_sessions: args.ssh_sessions,
        agent_sessions: args.agent_sessions,
        bridge_transport: args.bridge_transport,
        agent_command: args.agent_command,
        agent_path: args.agent_path,
        udp_idle_timeout_ms: args.udp_idle_timeout_ms,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_bridge::AgentBridgeConnector;
    use crate::packet_engine::MAX_IN_FLIGHT_DNS_QUERIES;
    use crate::{bridge_runtime::DnsTransport, packet_engine::tun_ipv4_packet};
    use anyhow::anyhow;
    use clap::CommandFactory;
    use ring::hmac;
    use russh::keys::{PrivateKey, PublicKey};
    use smoltcp::time::Instant as SmolInstant;
    use ssh_key::known_hosts::HostPatterns;
    use std::env;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    const TEST_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const OTHER_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    const TEST_ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
        QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
        XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
        AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
        ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
        -----END OPENSSH PRIVATE KEY-----\n";

    fn test_ssh_args(remote: &str) -> SshArgs {
        SshArgs {
            ssh_server: Some(remote.to_owned()),
            ssh_user: Some("alice".to_owned()),
            identity: None,
            password: None,
            password_file: None,
            insecure_accept_host_key: false,
            accept_new_host_key: false,
            known_hosts: None,
            ssh_config: None,
            ssh_connect_timeout_secs: DEFAULT_SSH_CONNECT_TIMEOUT_SECS,
        }
    }

    async fn test_quic_native_bridge() -> (QuicNativeBridge, tokio::task::JoinHandle<()>) {
        let quic_server = quic_agent::start_quic_bridge_server(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ))
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

    #[test]
    fn virtual_dns_ip_uses_stable_host_inside_tun_subnet() {
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 255, 255, 1), 24).unwrap(),
            Ipv4Addr::new(10, 255, 255, 53)
        );
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 30).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 31).is_err());
    }

    #[test]
    fn dns_inflight_caps_queries_and_tracks_releases() {
        let mut inflight = DnsInflight::new(2);

        assert_eq!(inflight.current(), 0);
        assert!(inflight.try_admit());
        assert!(inflight.try_admit());
        assert!(!inflight.try_admit());
        assert_eq!(inflight.current(), 2);
        assert_eq!(inflight.dropped(), 1);

        inflight.complete();
        assert_eq!(inflight.current(), 1);
        assert_eq!(inflight.completed(), 1);

        assert!(inflight.try_admit());
        assert_eq!(inflight.current(), 2);

        inflight.complete();
        inflight.complete();
        inflight.complete();
        assert_eq!(inflight.current(), 0);
        assert_eq!(inflight.completed(), 3);
    }

    #[test]
    fn udp_response_backpressure_cannot_block_close_accounting() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        assert!(events.try_send_response(key, Bytes::from_static(b"first")));
        assert!(!events.try_send_response(key, Bytes::from_static(b"second")));
        assert!(events.try_send_closed(key, None));

        let response = response_rx.try_recv().expect("queued UDP response");
        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"first");
        assert!(response_rx.try_recv().is_err());

        let closed = close_rx.try_recv().expect("queued UDP close");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
    }

    #[test]
    fn udp_response_event_keeps_agent_payload_as_bytes() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let payload = Bytes::from_static(b"agent-response");
        let ptr = payload.as_ptr();

        assert!(events.try_send_response(key, payload));
        let response = response_rx.try_recv().expect("queued UDP response");

        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"agent-response");
        assert_eq!(response.payload.as_ptr(), ptr);
    }

    #[tokio::test]
    async fn udp_admission_moves_parsed_payload_bytes_into_association_queue() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"client-datagram");
        let payload_ptr = payload.as_ptr();
        let (to_remote, mut from_local) = mpsc::channel(1);
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut association_limit = DnsInflight::new(1);
        let mut stats = TunnelStats::new();

        admit_udp_datagram(
            UdpAssociationTransport::Agent(bridge.clone()),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut stats,
        );

        let queued = from_local.try_recv().expect("queued UDP payload");
        assert_eq!(queued.as_ref(), b"client-datagram");
        assert_eq!(queued.as_ptr(), payload_ptr);
        assert_eq!(stats.udp_forwarded, 1);
        assert_eq!(stats.udp_dropped, 0);

        drop(associations);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[test]
    fn udp_planner_drops_unsupported_transport_without_admission() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        let mut association_limit = DnsInflight::new(1);
        let mut actions: Vec<UdpIngressAction<()>> = Vec::new();

        plan_udp_datagram_actions(
            None,
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload: Bytes::from_static(b"unsupported"),
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert!(associations.is_empty());
        assert_eq!(association_limit.current(), 0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            UdpIngressAction::DropDatagram {
                key: action_key,
                reason,
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(*reason, UdpDropReason::UnsupportedTransport);
            }
            _ => panic!("expected unsupported UDP drop action"),
        }
    }

    #[tokio::test]
    async fn udp_planner_starts_vacant_association_before_send() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"first-datagram");
        let payload_ptr = payload.as_ptr();
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        let mut association_limit = DnsInflight::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new(
                "agent",
                UdpAssociationTransport::Agent(bridge.clone()),
            )),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert_eq!(association_limit.current(), 1);
        assert!(associations.contains_key(&key));
        assert_eq!(actions.len(), 2);
        match &actions[0] {
            UdpIngressAction::StartAssociation {
                key: action_key, ..
            } => {
                assert_eq!(*action_key, key);
            }
            _ => panic!("expected association start action first"),
        }
        match &actions[1] {
            UdpIngressAction::SendDatagram {
                key: action_key,
                payload,
                transport_label,
                ..
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(payload.as_ref(), b"first-datagram");
                assert_eq!(payload.as_ptr(), payload_ptr);
                assert_eq!(*transport_label, "agent");
            }
            _ => panic!("expected UDP send action second"),
        }

        drop(actions);
        drop(associations);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn udp_planner_reuses_existing_association_without_restarting() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (to_remote, _from_local) = mpsc::channel(1);
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = DnsInflight::new(1);
        let mut actions = Vec::new();

        plan_udp_datagram_actions(
            Some(UdpAssociationTransportPlan::new(
                "agent",
                UdpAssociationTransport::Agent(bridge.clone()),
            )),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload: Bytes::from_static(b"existing"),
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut actions,
        );

        assert_eq!(association_limit.current(), 0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            UdpIngressAction::SendDatagram {
                key: action_key,
                payload,
                ..
            } => {
                assert_eq!(*action_key, key);
                assert_eq!(payload.as_ref(), b"existing");
            }
            _ => panic!("expected existing association to emit only a send action"),
        }

        drop(actions);
        drop(associations);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[test]
    fn udp_executor_closed_sender_releases_association_slot() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (to_remote, from_local) = mpsc::channel(1);
        drop(from_local);
        let mut associations = HashMap::new();
        associations.insert(
            key,
            UdpAssociation {
                to_remote: to_remote.clone(),
            },
        );
        let mut association_limit = DnsInflight::new(1);
        assert!(association_limit.try_admit());
        let mut stats = TunnelStats::new();
        let mut spawn_association = |(), _, _, _, _| {};

        execute_udp_ingress_action(
            UdpIngressAction::SendDatagram {
                key,
                to_remote,
                payload: Bytes::from_static(b"closed"),
                transport_label: "agent",
            },
            &mut associations,
            &mut association_limit,
            &mut stats,
            &mut spawn_association,
        );

        assert!(associations.is_empty());
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert_eq!(stats.udp_forwarded, 0);
        assert_eq!(stats.udp_dropped, 1);
        assert_eq!(stats.udp_failed, 1);
    }

    #[test]
    fn direct_tcpip_generic_udp_drop_is_counted_without_admission() {
        let mut stats = TunnelStats::new();
        let request = dns::UdpPacket {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
            payload: Bytes::from_static(b"generic-udp"),
        };

        drop_unsupported_direct_udp(&request, &mut stats);

        assert_eq!(stats.udp_forwarded, 0);
        assert_eq!(stats.udp_dropped, 1);
        assert_eq!(stats.udp_ok, 0);
        assert_eq!(stats.udp_failed, 1);
    }

    #[test]
    fn dns_response_event_keeps_remote_payload_as_bytes() {
        let request = dns::UdpDnsRequest {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            dst_ip: virtual_dns_ip(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX).unwrap(),
            src_port: 49152,
            dst_port: dns::DNS_PORT,
            payload: Bytes::from_static(b"\x12\x34query"),
        };
        let payload = Bytes::from_static(b"\x12\x34answer");
        let ptr = payload.as_ptr();
        let (event_tx, mut event_rx) = mpsc::channel(1);

        assert!(send_dns_response_event(
            &event_tx,
            DnsResponseEvent {
                request: request.clone(),
                result: Ok(payload),
            },
        ));
        let event = event_rx.try_recv().expect("queued DNS response");

        assert_eq!(event.request, request);
        let response = event.result.expect("DNS response payload");
        assert_eq!(response.as_ref(), b"\x12\x34answer");
        assert_eq!(response.as_ptr(), ptr);
    }

    #[test]
    fn password_file_reader_strips_shell_newlines_only() {
        let path = env::temp_dir().join(format!(
            "rustle-password-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, " secret value \r\n").unwrap();

        let password = read_password_file(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(password, " secret value ");
    }

    #[test]
    fn ssh_password_file_option_reads_password_without_argv_secret() {
        let path = env::temp_dir().join(format!(
            "rustle-password-file-option-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, "file secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password-file",
            path.to_str().expect("password path is UTF-8"),
            "10.0.0.0/8",
        ])
        .expect("compact CLI with password file");

        assert_eq!(cli.compact.ssh.password, None);
        assert_eq!(
            cli.compact.ssh.password_file.as_deref(),
            Some(path.as_path())
        );
        assert_eq!(
            resolve_ssh_password(&cli.compact.ssh).expect("read password file"),
            Some("file secret".to_owned())
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn ssh_password_file_authenticates_against_russh_server() {
        struct PasswordAuthServer {
            expected_user: String,
            expected_password: String,
            attempts: mpsc::Sender<(String, String)>,
        }

        impl russh::server::Handler for PasswordAuthServer {
            type Error = anyhow::Error;

            async fn auth_password(
                &mut self,
                user: &str,
                password: &str,
            ) -> Result<russh::server::Auth, Self::Error> {
                let _ = self
                    .attempts
                    .try_send((user.to_owned(), password.to_owned()));
                if user == self.expected_user && password == self.expected_password {
                    Ok(russh::server::Auth::Accept)
                } else {
                    Ok(russh::server::Auth::reject())
                }
            }
        }

        let expected_user = "alice";
        let expected_password = "file secret";
        let password_path = env::temp_dir().join(format!(
            "rustle-password-auth-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&password_path, format!("{expected_password}\n")).unwrap();

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test SSH server");
        let server_addr = listener.local_addr().expect("test SSH server address");
        let (attempts_tx, mut attempts_rx) = mpsc::channel(1);
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![PrivateKey::from_openssh(TEST_ED25519_PRIVATE_KEY)
                .expect("parse test SSH host key")],
            ..Default::default()
        });
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SSH client");
            let session = russh::server::run_stream(
                config,
                stream,
                PasswordAuthServer {
                    expected_user: expected_user.to_owned(),
                    expected_password: expected_password.to_owned(),
                    attempts: attempts_tx,
                },
            )
            .await
            .expect("start russh test session");
            let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
        });

        let mut args = test_ssh_args(&format!("127.0.0.1:{}", server_addr.port()));
        args.ssh_user = Some(expected_user.to_owned());
        args.password_file = Some(password_path.clone());
        args.insecure_accept_host_key = true;
        args.ssh_connect_timeout_secs = 2;
        let handle = connect_ssh(&args)
            .await
            .expect("connect with password-file authentication");

        let attempt = tokio::time::timeout(Duration::from_secs(3), attempts_rx.recv())
            .await
            .expect("password auth attempt")
            .expect("password auth attempt recorded");
        assert_eq!(
            attempt,
            (expected_user.to_owned(), expected_password.to_owned())
        );

        drop(handle);
        server.abort();
        std::fs::remove_file(password_path).unwrap();
    }

    #[test]
    fn stats_formatting_uses_stable_units() {
        assert_eq!(format_bytes(999), "999B");
        assert_eq!(format_bytes(1024), "1.0KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MiB");
        assert_eq!(format_duration(Duration::from_millis(1234)), "1.234s");
    }

    #[test]
    fn stats_report_bridge_pressure_and_open_latency() {
        let mut stats = TunnelStats::new();
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 21 });
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 43 });
        stats.record_bridge_admission(BridgeAdmissionStats {
            deferred_active_limit: 2,
            deferred_open_limit: 3,
        });
        stats.record_local_drain(LocalDrainStats {
            bytes_to_bridge: 1024,
            bridge_backpressure_events: 4,
            bridge_send_failures: 0,
        });
        stats.record_tun_write(TunWriteStats {
            packets: 2,
            bytes: 2048,
            dropped_packets: 1,
            dropped_bytes: 512,
        });

        let line = stats.status_line(
            1,
            1,
            &RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW),
            &DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES),
            &DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS),
            DataPlaneRuntimeSnapshot {
                reconnects: DataPlaneReconnectSnapshot {
                    attempts: 5,
                    successes: 4,
                    failures: 1,
                },
                lanes_total: 4,
                lanes_desired: 4,
                lanes_available: 1,
                lanes_failed: 1,
                lanes_missing: 1,
                lanes_quarantined: 1,
                lanes_repairing: 1,
                active_streams: 7,
                max_lane_load: 4,
                max_quarantine_ms: 250,
            },
        );

        assert!(line.contains("tun_tx=2/2.0KiB"));
        assert!(line.contains("tun_drop=1/512B"));
        assert!(line.contains("ssh=open:2 fail:0 eof:0 close:0"));
        assert!(line.contains("open_ms=avg:32 max:43"));
        assert!(line.contains("defer=active:2 open:3"));
        assert!(line.contains("agent_reconnect=attempt:5 ok:4 fail:1"));
        assert!(line.contains(
            "agent_lanes=total:4 desired:4 ok:1 fail:1 missing:1 quarantine:1 repairing:1 active:7 max_load:4 max_quarantine_ms:250"
        ));
        assert!(line.contains("bridge_backpressure:4"));
    }

    #[test]
    fn dns_and_udp_success_require_local_tun_delivery() {
        let mut stats = TunnelStats::new();

        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );
        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 0,
                bytes: 0,
                dropped_packets: 1,
                dropped_bytes: 96,
            },
        );
        stats.record_dns_delivery(
            false,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );

        stats.record_udp_delivery(TunWriteStats {
            packets: 1,
            bytes: 128,
            dropped_packets: 0,
            dropped_bytes: 0,
        });
        stats.record_udp_delivery(TunWriteStats {
            packets: 0,
            bytes: 0,
            dropped_packets: 1,
            dropped_bytes: 128,
        });

        assert_eq!(stats.dns_ok, 1);
        assert_eq!(stats.dns_failed, 2);
        assert_eq!(stats.udp_ok, 1);
        assert_eq!(stats.udp_failed, 1);
        assert_eq!(stats.tun_tx_packets, 3);
        assert_eq!(stats.tun_tx_dropped_packets, 2);
    }

    #[test]
    fn parse_ipv4_metadata_accepts_minimal_header() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 10, 10,
            0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let metadata = parse_ipv4_metadata(&packet).expect("valid packet");
        assert_eq!(metadata.total_len, 40);
        assert_eq!(metadata.protocol, 6);
        assert_eq!(metadata.src, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(metadata.dst, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn parse_ipv4_metadata_rejects_non_ipv4() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x60;
        let err = parse_ipv4_metadata(&packet).expect_err("IPv6 must not parse as IPv4");
        assert!(err.to_string().contains("not IPv4"));
    }

    #[test]
    fn tun_ipv4_packet_accepts_raw_ipv4() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];

        assert_eq!(tun_ipv4_packet(&packet), Some(packet.as_slice()));
    }

    #[test]
    fn tun_ipv4_packet_strips_linux_pi_ipv4_header() {
        let packet = [
            0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];

        assert_eq!(tun_ipv4_packet(&packet), Some(&packet[4..]));
    }

    #[test]
    fn tun_ipv4_packet_ignores_non_ipv4() {
        assert_eq!(tun_ipv4_packet(&[0x60, 0, 0, 0]), None);
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x86, 0xdd, 0x60]), None);
        assert_eq!(tun_ipv4_packet(&[0x00, 0x00, 0x08, 0x00, 0x60]), None);
        assert_eq!(tun_ipv4_packet(&[]), None);
    }

    #[cfg(unix)]
    #[test]
    fn unix_shutdown_signals_include_hangup_and_terminate() {
        let signals: Vec<_> = unix_shutdown_signals()
            .into_iter()
            .map(|signal| (signal.label(), signal.os_name()))
            .collect();

        assert_eq!(
            signals,
            vec![("terminate", "SIGTERM"), ("hangup", "SIGHUP")]
        );
    }

    #[test]
    fn validate_tun_args_accepts_full_tunnel_route() {
        let args = TunCaptureArgs {
            targets: vec!["0.0.0.0/0".parse().unwrap()],
            tun_ip: DEFAULT_TUN_IP,
            tun_prefix: DEFAULT_TUN_PREFIX,
            mtu: DEFAULT_MTU,
            name: None,
            exit_after_packets: None,
        };

        validate_tun_args(&args).expect("full tunnel should expand to split routes");
    }

    #[test]
    fn ssh_session_index_is_stable_for_same_flow_id() {
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 2),
                49152,
                Ipv4Addr::new(192, 168, 1, 10),
                443,
            ),
            7,
        );

        let first = ssh_session_index_for_flow(id, 4);
        for _ in 0..16 {
            assert_eq!(ssh_session_index_for_flow(id, 4), first);
        }
    }

    #[test]
    fn ssh_session_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            let id = tcp_core::FlowId::new(
                tcp_core::FlowKey::tcp(
                    Ipv4Addr::new(10, 255, 255, 2),
                    49152 + offset,
                    Ipv4Addr::new(192, 168, 1, 10),
                    443,
                ),
                u64::from(offset) + 1,
            );
            seen.insert(ssh_session_index_for_flow(id, 4));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

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

    #[test]
    fn ssh_session_count_validation_bounds_pool_size() {
        assert!(validate_ssh_session_count(1).is_ok());
        assert!(validate_ssh_session_count(DEFAULT_SSH_SESSIONS).is_ok());
        assert!(validate_ssh_session_count(0).is_err());
        assert!(validate_ssh_session_count(MAX_SSH_SESSIONS + 1).is_err());
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
    fn compact_cli_accepts_multiple_targets_like_sshuttle() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ])
        .expect("compact CLI with multiple targets");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.ssh.ssh_server.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            cli.compact.targets,
            vec![
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                "172.16.0.0/12".parse::<Ipv4Net>().unwrap()
            ]
        );
        assert_eq!(cli.compact.dns_remote, "127.0.0.53:53");
        assert_eq!(cli.compact.ssh_sessions, DEFAULT_SSH_SESSIONS);
        assert_eq!(cli.compact.agent_sessions, DEFAULT_AGENT_SESSIONS);
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert!(!cli.compact.configure_dns);
    }

    #[test]
    fn compact_cli_accepts_sshuttle_abbreviated_targets() {
        let cli = Cli::try_parse_from(["rustle", "-r", "alice@example.com", "0/0", "10/8"])
            .expect("compact CLI with abbreviated targets");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.targets,
            vec![
                "0.0.0.0/0".parse::<Ipv4Net>().unwrap(),
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
            ]
        );
    }

    #[test]
    fn compact_cli_accepts_accept_new_host_key_flag() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--accept-new-host-key",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with accept-new host key flag");

        assert!(cli.compact.ssh.accept_new_host_key);
        assert!(!cli.compact.ssh.insecure_accept_host_key);
    }

    #[test]
    fn compact_cli_rejects_conflicting_host_key_modes() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--accept-new-host-key",
            "--insecure-accept-host-key",
            "10.0.0.0/8",
        ])
        .expect_err("host key modes must conflict");

        assert!(err.to_string().contains("insecure-accept-host-key"));
    }

    #[test]
    fn compact_cli_accepts_hidden_ssh_sessions_override() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--ssh-sessions",
            "2",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden SSH session override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.ssh_sessions, 2);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_sessions_override() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--agent-sessions",
            "3",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent session override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.agent_sessions, 3);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent transport");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(
            cli.compact.agent_command.as_deref(),
            Some("/tmp/rustle agent")
        );
        assert!(cli.compact.agent_path.is_none());
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_path_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-path",
            "/tmp/rustle dir/rustle'bin",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent path");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert!(cli.compact.agent_command.is_none());
        assert_eq!(
            cli.compact.agent_path.as_deref(),
            Some("/tmp/rustle dir/rustle'bin")
        );
        assert_eq!(
            effective_agent_command(
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("agent path becomes effective command"),
            "'/tmp/rustle dir/rustle'\\''bin' agent"
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_quic_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "quic-agent",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden QUIC agent transport");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            effective_bridge_agent_command(
                cli.compact.bridge_transport,
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("QUIC agent path becomes effective command"),
            "'/tmp/rustle' quic-agent"
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_quic_native_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "quic-native",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden native QUIC transport");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.bridge_transport,
            BridgeTransportKind::QuicNative
        );
        assert_eq!(
            effective_bridge_agent_command(
                cli.compact.bridge_transport,
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("native QUIC bridge path becomes effective command"),
            "'/tmp/rustle' quic-bridge-agent"
        );
    }

    #[test]
    fn compact_cli_rejects_conflicting_agent_command_modes() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect_err("agent command modes must conflict");

        assert!(err.to_string().contains("agent-path"));
    }

    #[test]
    fn compact_cli_accepts_dns_remote_without_changing_target_shape() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--dns-remote",
            "127.0.0.1:5353",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with DNS override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.dns_remote, "127.0.0.1:5353");
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_sshuttle_style_dns_flag() {
        let cli = Cli::try_parse_from(["rustle", "--dns", "-r", "alice@example.com", "10.0.0.0/8"])
            .expect("compact CLI with DNS takeover");

        assert!(cli.command.is_none());
        assert!(cli.compact.configure_dns);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_bare_password_does_not_consume_target_cidr() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password",
            "10.0.0.0/8",
        ])
        .expect("bare password flag before CIDR");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.ssh.password, Some(None));
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_password_value_requires_equals() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password=secret",
            "10.0.0.0/8",
        ])
        .expect("password value with equals");

        assert_eq!(cli.compact.ssh.password, Some(Some("secret".to_owned())));
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_rejects_conflicting_password_sources() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password",
            "--password-file",
            "/tmp/rustle-password",
            "10.0.0.0/8",
        ])
        .expect_err("password sources must conflict");

        assert!(err.to_string().contains("password-file"));
    }

    #[test]
    fn compact_cli_accepts_hidden_tun_overrides() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--tun-ip",
            "10.88.0.1",
            "--tun-prefix",
            "30",
            "--mtu",
            "1200",
            "--name",
            "rustle-test0",
            "--udp-idle-timeout-ms",
            "500",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden TUN overrides");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.tun_ip, "10.88.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cli.compact.tun_prefix, 30);
        assert_eq!(cli.compact.mtu, 1200);
        assert_eq!(cli.compact.name.as_deref(), Some("rustle-test0"));
        assert_eq!(cli.compact.udp_idle_timeout_ms, 500);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn subcommand_cli_is_not_consumed_as_compact_cidr() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
        ])
        .expect("bridge-lab subcommand must parse");

        assert!(cli.compact.targets.is_empty());
        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 1);
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
    }

    #[test]
    fn bridge_lab_accepts_connection_count_for_load_smokes() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--connections",
            "8",
        ])
        .expect("bridge-lab load subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 8);
    }

    #[test]
    fn bridge_lab_accepts_hidden_summary_for_benchmarks() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "--destination",
            "127.0.0.1:8080",
            "--summary",
        ])
        .expect("bridge-lab summary subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert!(args.summary);
    }

    #[test]
    fn bridge_lab_accepts_hidden_chaos_completion_controls() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "--destination",
            "127.0.0.1:8080",
            "--connections",
            "3",
            "--min-completed",
            "2",
            "--deadline-ms",
            "1500",
        ])
        .expect("bridge-lab chaos controls must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 3);
        assert_eq!(args.min_completed, Some(2));
        assert_eq!(args.deadline_ms, Some(1500));
    }

    #[test]
    fn bridge_lab_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
        ])
        .expect("bridge-lab agent transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
    }

    #[test]
    fn bridge_lab_accepts_hidden_quic_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "quic-agent",
            "--agent-path",
            "/tmp/rustle",
        ])
        .expect("bridge-lab QUIC agent transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            effective_bridge_agent_command(
                args.bridge_transport,
                args.agent_command.as_deref(),
                args.agent_path.as_deref()
            )
            .expect("bridge-lab QUIC agent path becomes effective command"),
            "'/tmp/rustle' quic-agent"
        );
    }

    #[test]
    fn bridge_lab_accepts_hidden_quic_native_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "quic-native",
            "--agent-path",
            "/tmp/rustle",
        ])
        .expect("bridge-lab native QUIC transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicNative);
        assert_eq!(
            effective_bridge_agent_command(
                args.bridge_transport,
                args.agent_command.as_deref(),
                args.agent_path.as_deref()
            )
            .expect("bridge-lab native QUIC path becomes effective command"),
            "'/tmp/rustle' quic-bridge-agent"
        );
    }

    #[test]
    fn quic_agent_subcommand_accepts_bind_and_mtu() {
        let cli = Cli::try_parse_from([
            "rustle",
            "quic-agent",
            "--bind",
            "127.0.0.1:0",
            "--mtu",
            "1200",
        ])
        .expect("quic-agent subcommand must parse");

        let Some(CommandKind::QuicAgent(args)) = cli.command else {
            panic!("expected quic-agent subcommand");
        };
        assert_eq!(args.bind, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn quic_bridge_agent_subcommand_accepts_bind() {
        let cli = Cli::try_parse_from(["rustle", "quic-bridge-agent", "--bind", "127.0.0.1:0"])
            .expect("quic-bridge-agent subcommand must parse");

        let Some(CommandKind::QuicBridgeAgent(args)) = cli.command else {
            panic!("expected quic-bridge-agent subcommand");
        };
        assert_eq!(args.bind, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn agent_lab_accepts_hidden_exec_transport_options() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--agent-command",
            "/tmp/rustle agent",
            "--mtu",
            "1200",
        ])
        .expect("agent-lab subcommand must parse");

        let Some(CommandKind::AgentLab(args)) = cli.command else {
            panic!("expected agent-lab subcommand");
        };
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
        assert_eq!(args.destination, "127.0.0.1:8080");
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn agent_lab_accepts_agent_path_option() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--agent-path",
            "/opt/rustle dir/rustle",
        ])
        .expect("agent-lab with agent path option");

        let Some(CommandKind::AgentLab(args)) = cli.command else {
            panic!("expected agent-lab subcommand");
        };
        assert!(args.agent_command.is_none());
        assert_eq!(args.agent_path.as_deref(), Some("/opt/rustle dir/rustle"));
    }

    #[test]
    fn agent_udp_lab_accepts_hidden_exec_transport_options() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-udp-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:5353",
            "--agent-command",
            "/tmp/rustle agent",
            "--request",
            "ping",
            "--messages",
            "4",
            "--pipeline",
            "2",
            "--summary",
            "--mtu",
            "1200",
        ])
        .expect("agent-udp-lab subcommand must parse");

        let Some(CommandKind::AgentUdpLab(args)) = cli.command else {
            panic!("expected agent-udp-lab subcommand");
        };
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
        assert_eq!(args.destination, "127.0.0.1:5353");
        assert_eq!(args.request, "ping");
        assert_eq!(args.messages, 4);
        assert_eq!(args.pipeline, 2);
        assert!(args.summary);
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn agent_dns_lab_accepts_transport_queries_and_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-dns-lab",
            "-r",
            "alice@example.com",
            "--dns-remote",
            "127.0.0.1:53",
            "--name",
            "rustle-smoke.example.com",
            "--queries",
            "4",
            "--bridge-transport",
            "quic-agent",
            "--agent-command",
            "/tmp/rustle quic-agent",
            "--agent-sessions",
            "1",
            "--mtu",
            "1200",
        ])
        .expect("agent-dns-lab subcommand must parse");

        let Some(CommandKind::AgentDnsLab(args)) = cli.command else {
            panic!("expected agent-dns-lab subcommand");
        };
        assert_eq!(args.dns_remote, "127.0.0.1:53");
        assert_eq!(args.name, "rustle-smoke.example.com");
        assert_eq!(args.queries, 4);
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            args.agent_command.as_deref(),
            Some("/tmp/rustle quic-agent")
        );
        assert!(args.agent_path.is_none());
        assert_eq!(args.agent_sessions, 1);
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn top_level_help_hides_development_subcommands() {
        let help = Cli::command().render_long_help().to_string();

        assert!(help.contains("CIDR"));
        assert!(help.contains("--remote"));
        assert!(help.contains("--password-file"));
        assert!(help.contains("--dns"));
        assert!(help.contains("--dns-remote"));
        assert!(!help.contains("--tun-ip"));
        assert!(!help.contains("--tun-prefix"));
        assert!(!help.contains("--mtu"));
        assert!(!help.contains("--name"));
        assert!(!help.contains("--udp-idle-timeout-ms"));
        assert!(!help.contains("--ssh-sessions"));
        assert!(!help.contains("--agent-sessions"));
        assert!(!help.contains("--bridge-transport"));
        assert!(!help.contains("--agent-command"));
        assert!(!help.contains("--agent-path"));
        assert!(!help.contains("direct-tcpip"));
        assert!(!help.contains("tun-capture"));
        assert!(!help.contains("bridge-lab"));
        assert!(!help.contains("agent-lab"));
        assert!(!help.contains("agent-udp-lab"));
        assert!(!help.contains("agent"));
    }

    #[test]
    fn tunnel_subcommand_accepts_multiple_targets_before_later_flags() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "--mtu",
            "1200",
            "--udp-idle-timeout-ms",
            "250",
        ])
        .expect("tunnel CLI with multiple targets");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(
            args.targets,
            vec![
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                "172.16.0.0/12".parse::<Ipv4Net>().unwrap()
            ]
        );
        assert_eq!(args.mtu, 1200);
        assert_eq!(args.udp_idle_timeout_ms, 250);
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
    }

    #[test]
    fn tunnel_subcommand_rejects_zero_udp_idle_timeout() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--udp-idle-timeout-ms",
            "0",
        ])
        .expect("tunnel CLI with zero UDP idle timeout");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        let err = validate_tunnel_args(&args).expect_err("zero UDP timeout must be rejected");
        assert!(err.to_string().contains("udp-idle-timeout-ms"));
    }

    #[test]
    fn tunnel_subcommand_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
        ])
        .expect("tunnel CLI with hidden agent transport");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
    }

    #[test]
    fn tunnel_subcommand_accepts_hidden_agent_path_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--agent-path",
            "/opt/rustle dir/rustle",
        ])
        .expect("tunnel CLI with hidden agent path");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert!(args.agent_command.is_none());
        assert_eq!(args.agent_path.as_deref(), Some("/opt/rustle dir/rustle"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote_by_default() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        validate_tunnel_args(&args).expect("agent can use hostname DNS");
    }

    #[test]
    fn explicit_auto_tunnel_validates_direct_fallback_session_count() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "auto",
            "--ssh-sessions",
            "0",
        ])
        .expect("tunnel CLI with zero SSH sessions");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Auto);
        let err = validate_tunnel_args(&args)
            .expect_err("explicit auto fallback needs valid ssh sessions");
        assert!(err.to_string().contains("--ssh-sessions"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("agent supports hostname DNS remote through OpenTcpHost");
    }

    #[test]
    fn quic_native_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "quic-native",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with native QUIC hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("native QUIC supports hostname DNS remote through TCP host open");
    }

    #[test]
    fn tun_capture_accepts_hidden_packet_limit_for_smokes() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tun-capture",
            "--target",
            "10.0.0.5/32",
            "--exit-after-packets",
            "1",
        ])
        .expect("tun-capture smoke packet limit");

        let Some(CommandKind::TunCapture(args)) = cli.command else {
            panic!("expected tun-capture subcommand");
        };
        assert_eq!(
            args.targets,
            vec!["10.0.0.5/32".parse::<Ipv4Net>().unwrap()]
        );
        assert_eq!(args.exit_after_packets, Some(1));
    }

    #[test]
    fn ssh_endpoint_parses_host_and_port_for_known_hosts() {
        assert_eq!(
            parse_ssh_endpoint("example.com").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 22,
                addr: "example.com:22".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("example.com:2222").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 2222,
                addr: "example.com:2222".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("[2001:db8::1]:2222").unwrap(),
            SshEndpoint {
                host: "2001:db8::1".to_owned(),
                port: 2222,
                addr: "[2001:db8::1]:2222".to_owned(),
            }
        );
    }

    #[test]
    fn known_hosts_patterns_support_wildcards_ports_and_negation() {
        assert!(patterns_match(
            &["*.example.com".to_owned()],
            &["api.example.com".to_owned()]
        ));
        assert!(patterns_match(
            &["[*.example.com]:2222".to_owned()],
            &["[api.example.com]:2222".to_owned()]
        ));
        assert!(!patterns_match(
            &["*.example.com".to_owned(), "!bad.example.com".to_owned()],
            &["bad.example.com".to_owned()]
        ));
    }

    #[test]
    fn known_hosts_hashed_name_matches_hmac_sha1_candidate() {
        let salt = b"01234567890123456789";
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&key, b"example.com");
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(tag.as_ref());

        assert!(known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["example.com".to_owned()]
        ));
        assert!(!known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["other.example.com".to_owned()]
        ));
    }

    #[test]
    fn host_key_verifier_accepts_matching_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_mismatched_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("mismatch must fail");
        assert!(err.to_string().contains("mismatch"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accepts_bracketed_non_default_port() {
        let path = write_temp_known_hosts(&format!("[test.example.com]:2222 {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            2222,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_revoked_key() {
        let path =
            write_temp_known_hosts(&format!("@revoked test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("revoked key must fail");
        assert!(err.to_string().contains("revoked"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_records_missing_host_key() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = env::temp_dir().join(format!(
            "rustle-known-hosts-accept-new-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let path = temp.path.join(".ssh").join("known_hosts");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was created");
        assert_eq!(recorded, format!("test.example.com {TEST_ED25519_KEY}\n"));

        let strict = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        assert!(strict.verify(&key).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .expect("known_hosts parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("known_hosts metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn host_key_verifier_accept_new_preserves_existing_line_without_newline() {
        let path = write_temp_known_hosts(&format!("other.example.com {OTHER_ED25519_KEY}"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was updated");
        assert_eq!(
            recorded,
            format!("other.example.com {OTHER_ED25519_KEY}\ntest.example.com {TEST_ED25519_KEY}\n")
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_rejects_changed_known_host() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("accept-new must reject changed keys");
        assert!(err.to_string().contains("mismatch"));
        let recorded = std::fs::read_to_string(&path).expect("known_hosts still readable");
        assert!(!recorded.contains(OTHER_ED25519_KEY));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_unknown_host_error_mentions_accept_new() {
        let path = write_temp_known_hosts("");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("unknown host must fail in strict mode");
        let message = err.to_string();
        assert!(message.contains("--accept-new-host-key"));
        assert!(message.contains("--insecure-accept-host-key"));
        assert!(message.contains("SHA256:"));
        std::fs::remove_file(path).ok();
    }

    fn write_temp_known_hosts(contents: &str) -> PathBuf {
        static NEXT_KNOWN_HOSTS_FILE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT_KNOWN_HOSTS_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustle-known-hosts-{}-{}-{}.tmp",
            std::process::id(),
            sequence,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn remote_backlog_is_bounded_per_flow() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        let mut backlogs = RemoteBacklogs::new(8);

        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"world")),
            RemoteBacklogPush::FlowLimit
        );
        assert_eq!(backlogs.active_flow_count(), 1);
        assert_eq!(backlogs.total_bytes(), 5);
        assert_eq!(
            backlogs.flows.get(&id).map(|backlog| backlog.bytes),
            Some(5)
        );

        backlogs.close_after_flush(id);
        assert_eq!(
            backlogs
                .flows
                .get(&id)
                .map(|backlog| backlog.close_after_flush),
            Some(true)
        );

        backlogs.remove_flow(flow);
        assert!(!backlogs.flows.contains_key(&id));
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_is_bounded_globally() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::TotalLimit
        );
        assert_eq!(backlogs.total_bytes(), 5);

        backlogs.remove_flow(first);
        assert_eq!(backlogs.total_bytes(), 0);
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::Accepted
        );
    }

    #[test]
    fn remote_backlog_pauses_bridge_events_at_high_watermark() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"!")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(backlogs.total_bytes(), 6);
        assert!(backlogs.should_pause_bridge_events());

        backlogs.remove_flow(first);
        assert!(!backlogs.should_pause_bridge_events());
    }

    #[test]
    fn remote_backlogs_flush_all_into_reuses_scratch_vectors() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let stale = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(192, 0, 2, 1),
                1,
                Ipv4Addr::new(192, 0, 2, 2),
                2,
            ),
            99,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"remote bytes")),
            RemoteBacklogPush::Accepted
        );

        let mut flow_keys = Vec::with_capacity(8);
        flow_keys.push(stale);
        let flow_keys_capacity = flow_keys.capacity();
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale.key);
        let closed_flows_capacity = closed_flows.capacity();

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("flush backlogs");

        assert!(flow_keys.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(flow_keys.capacity(), flow_keys_capacity);
        assert_eq!(closed_flows.capacity(), closed_flows_capacity);
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn bridge_lab_response_completion_uses_http_content_length() {
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let incomplete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";

        assert!(bridge_lab_response_complete(complete));
        assert!(!bridge_lab_response_complete(incomplete));
        assert!(!bridge_lab_response_complete(b"raw bytes"));
    }

    #[test]
    fn bridge_lab_cleanup_aborts_incomplete_client_socket() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 8080;
        let client_port = 50_000;
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut client = BridgeLabClient {
            flow: tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port),
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: true,
            request_sent_at: Some(StdInstant::now()),
            response_complete_at: None,
            saw_bridge_close: false,
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec(),
        };

        assert!(!bridge_lab_client_complete(&client));
        assert!(client
            .sockets
            .get_mut::<tcp::Socket>(client.handle)
            .is_active());

        assert!(abort_bridge_lab_client_socket(&mut client));
        assert!(!client
            .sockets
            .get_mut::<tcp::Socket>(client.handle)
            .is_active());
        assert!(!abort_bridge_lab_client_socket(&mut client));
    }

    #[test]
    fn remote_backlog_per_flow_has_agent_window_frame_headroom() {
        let backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        assert_eq!(
            backlogs.max_bytes_per_flow(),
            tcp_core::TCP_SEND_BUFFER_BYTES * REMOTE_BACKLOG_TCP_SEND_WINDOWS_PER_FLOW
        );
        assert!(backlogs.max_bytes_per_flow() > agent_window::AGENT_STREAM_MAX_WINDOW_BYTES);
        assert!(backlogs.max_bytes_per_flow() < REMOTE_BACKLOG_BYTES_TOTAL);
    }

    #[test]
    fn bridge_lab_latency_percentiles_use_nearest_rank() {
        let mut latencies = vec![900_u128, 100, 300, 500];

        assert_eq!(
            bridge_lab_latency_percentiles(&mut latencies),
            BridgeLabLatencySummary {
                p50_us: 300,
                p95_us: 900,
                max_us: 900,
            }
        );
    }

    #[test]
    fn bridge_lab_synthetic_client_models_proxy_response_window() {
        let (_iface, _device, sockets, handle) = synthetic_lab_client(
            Ipv4Addr::new(10, 255, 255, 2),
            DEFAULT_TUN_IP,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
            49152,
        )
        .expect("synthetic client");
        let socket = sockets.get::<tcp::Socket>(handle);

        assert_eq!(socket.recv_capacity(), tcp_core::TCP_SEND_BUFFER_BYTES);
        assert_eq!(socket.send_capacity(), tcp_core::TCP_RECV_BUFFER_BYTES);
        assert_eq!(socket.ack_delay(), None);
        assert!(!socket.nagle_enabled());
    }

    #[test]
    fn agent_bridge_admission_budget_exceeds_direct_tcpip_channel_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(direct.active, MAX_DIRECT_ACTIVE_CHANNELS);
        assert_eq!(direct.opening, MAX_DIRECT_OPENING_CHANNELS);
        assert_eq!(agent.active, tcp_core::DEFAULT_MAX_ACTIVE_FLOWS);
        assert!(agent.active > direct.active);
        assert!(agent.opening > direct.opening);
    }

    #[test]
    fn bridge_admission_decision_uses_transport_specific_opening_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS - 1, direct),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, direct),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, agent),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_AGENT_OPENING_STREAMS, agent),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(MAX_AGENT_ACTIVE_STREAMS, 0, agent),
            BridgeAdmissionDecision::DeferActive
        );
    }

    #[test]
    fn stale_bridge_event_for_removed_flow_is_not_fatal() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(
                Ipv4Addr::new(192, 168, 1, 10),
                32,
            )],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed {
                id: tcp_core::FlowId::new(flow, 1),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale bridge event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
    }

    #[test]
    fn stale_remote_data_storm_after_flow_removal_is_bounded() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager
            .remove_flow(flow)
            .expect("remove flow before stale storm");

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        let closed_capacity = closed_flows.capacity();
        let payload = Bytes::from(vec![0x5a; 16 * 1024]);
        let mut stale_events = 0_u64;
        let mut overflows = 0_u64;

        for tick in 0..2048 {
            let stats = handle_bridge_event_into(
                ssh_bridge::BridgeEvent::RemoteData {
                    id,
                    bytes: payload.clone(),
                },
                &mut manager,
                &mut backlogs,
                SmolInstant::from_millis(tick),
                &mut closed_flows,
            )
            .expect("stale remote-data event should not fail");
            stale_events = stale_events.saturating_add(stats.stale_bridge_events);
            overflows = overflows.saturating_add(stats.remote_backlog_overflows);

            assert!(closed_flows.is_empty());
            assert_eq!(closed_flows.capacity(), closed_capacity);
            assert_eq!(backlogs.active_flow_count(), 0);
            assert_eq!(backlogs.total_bytes(), 0);
        }

        assert_eq!(stale_events, 2048);
        assert_eq!(overflows, 0);
    }

    #[test]
    fn high_fanout_stale_remote_data_after_removal_is_bounded() {
        const FLOWS: usize = 32;
        const STALE_ROUNDS: usize = 64;

        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let mut ids = Vec::with_capacity(FLOWS);

        for index in 0..FLOWS {
            let client_port = 49152 + index as u16;
            ids.push(establish_lab_flow(
                &mut manager,
                client_ip,
                destination_ip,
                destination_port,
                client_port,
            ));
        }

        for id in &ids {
            manager
                .remove_flow(id.key)
                .expect("remove flow before high-fanout stale storm");
        }
        assert_eq!(manager.active_flow_count(), 0);

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(FLOWS);
        let closed_capacity = closed_flows.capacity();
        let payload = Bytes::from(vec![0x5a; 1024]);
        let mut stale_events = 0_u64;
        let mut overflows = 0_u64;

        for round in 0..STALE_ROUNDS {
            for id in &ids {
                let stats = handle_bridge_event_into(
                    ssh_bridge::BridgeEvent::RemoteData {
                        id: *id,
                        bytes: payload.clone(),
                    },
                    &mut manager,
                    &mut backlogs,
                    SmolInstant::from_millis(round as i64),
                    &mut closed_flows,
                )
                .expect("high-fanout stale remote-data event should not fail");

                stale_events = stale_events.saturating_add(stats.stale_bridge_events);
                overflows = overflows.saturating_add(stats.remote_backlog_overflows);
                assert!(closed_flows.is_empty());
                assert_eq!(closed_flows.capacity(), closed_capacity);
                assert_eq!(backlogs.active_flow_count(), 0);
                assert_eq!(backlogs.total_bytes(), 0);
            }
        }

        assert_eq!(stale_events, (FLOWS * STALE_ROUNDS) as u64);
        assert_eq!(overflows, 0);
    }

    #[test]
    fn stale_remote_data_events_are_counted_without_per_chunk_log() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 7);

        assert!(!should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"stale")
            }
        ));
        assert!(should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::Closed { id }
        ));
    }

    #[test]
    fn stale_bridge_event_for_reused_tuple_does_not_touch_new_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");

        let old_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager.remove_flow(flow).expect("remove old flow");
        let new_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(old_id.key, new_id.key);
        assert_ne!(old_id.generation, new_id.generation);

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(new_id, b"new-flow-data".to_vec()),
            RemoteBacklogPush::Accepted
        );
        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id: old_id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale generation event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
        assert!(manager.contains_flow_id(new_id));
        assert_eq!(backlogs.total_bytes(), b"new-flow-data".len() as u64);
    }

    #[test]
    fn remote_backlog_for_removed_flow_is_dropped_without_failing() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"stale remote bytes")),
            RemoteBacklogPush::Accepted
        );
        manager.remove_flow(flow).expect("remove flow before flush");

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("stale queued backlog should not fail");

        assert!(flow_ids.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_for_old_generation_does_not_touch_reused_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let old_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(old_id, Bytes::from_static(b"old-generation bytes")),
            RemoteBacklogPush::Accepted
        );
        manager.remove_flow(flow).expect("remove old flow");
        let new_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(old_id.key, new_id.key);
        assert_ne!(old_id.generation, new_id.generation);

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("old queued backlog should be dropped");

        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
        assert!(manager.contains_flow_id(new_id));
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("new flow snapshot");
        assert_eq!(snapshot.generation, new_id.generation);
        assert_eq!(snapshot.remote_to_local_bytes, 0);
    }

    #[test]
    fn remote_close_defers_flow_close_for_late_remote_data() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let close_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
        )
        .expect("remote close event");
        assert_eq!(close_outcome.closed_flows, vec![flow]);
        assert_eq!(close_outcome.stale_bridge_events, 0);
        assert!(manager.contains_flow_id(id));
        assert_eq!(backlogs.active_flow_count(), 1);

        let late_bytes = Bytes::from_static(b"late remote bytes after close marker");
        let expected_len = late_bytes.len() as u64;
        let data_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: late_bytes,
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(2),
        )
        .expect("late remote data event");
        assert!(data_outcome.closed_flows.is_empty());
        assert_eq!(data_outcome.stale_bridge_events, 0);
        assert_eq!(backlogs.total_bytes(), 0);

        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(snapshot.remote_to_local_bytes, expected_len);
        assert_eq!(snapshot.state, tcp_core::FlowState::TcpEstablished);

        let mut flow_keys = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(3),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("first deferred flush");
        assert!(manager.contains_flow_id(id));
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::TcpEstablished
        );

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(4),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("second deferred flush");
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::HalfClosedRemote
        );
        assert_eq!(backlogs.active_flow_count(), 0);
    }

    #[test]
    fn bridge_event_handler_into_reuses_closed_flow_scratch_vector() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let stale = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(id.key, flow);
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale);
        let capacity = closed_flows.capacity();

        let stats = handle_bridge_event_into(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"remote bytes"),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
            &mut closed_flows,
        )
        .expect("remote data event");

        assert_eq!(stats, BridgeEventStats::default());
        assert!(closed_flows.is_empty());
        assert_eq!(closed_flows.capacity(), capacity);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    fn establish_lab_flow(
        manager: &mut tcp_core::FlowManager,
        client_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        client_port: u16,
    ) -> tcp_core::FlowId {
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                return manager.flow_id(flow).expect("flow id");
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        panic!("synthetic flow did not reach TcpEstablished");
    }

    #[test]
    fn bridge_lab_router_recycles_client_packet_buffers_for_full_send_window() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        let payload = vec![0x42; tcp_core::TCP_SEND_BUFFER_BYTES];
        let sent = manager
            .send_flow_bytes_at(flow, &payload, now)
            .expect("enqueue full send window");
        assert_eq!(sent, payload.len());

        pump_lab_manager_to_clients(now, &mut manager, &mut clients)
            .expect("full send window should route without exhausting packet buffers");
        assert_eq!(clients[0].response.len(), payload.len());
        assert_eq!(clients[0].response, payload);
    }

    #[tokio::test]
    async fn missing_bridge_during_local_drain_resets_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET / HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 1);
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Reset
        }));
    }

    #[tokio::test]
    async fn dns_over_agent_round_trips_tcp_dns_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\x12\x34query");

            let response = b"\x12\x34answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

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
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response =
            query_dns_over_agent(transport.clone(), &remote, b"\x12\x34query", DEFAULT_TUN_IP)
                .await
                .expect("query DNS over agent");
        assert_eq!(response.as_ref(), b"\x12\x34answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    #[tokio::test]
    async fn dns_over_agent_prefers_udp_for_ipv4_remote() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP DNS socket");
        let destination = socket.local_addr().expect("UDP DNS socket address");
        let dns_server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("recv UDP DNS query");
            assert_eq!(&buf[..len], b"\x12\x34udp-query");
            socket
                .send_to(b"\x12\x34udp-answer", peer)
                .await
                .expect("send UDP DNS response");
        });

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
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response = query_dns_over_agent_udp(
            transport.clone(),
            &remote,
            b"\x12\x34udp-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over agent UDP");
        assert_eq!(response.as_ref(), b"\x12\x34udp-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS UDP server join");
    }

    #[tokio::test]
    async fn dns_over_quic_native_uses_udp_for_ipv4_remote() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP DNS socket");
        let destination = socket.local_addr().expect("UDP DNS socket address");
        let dns_server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("recv native QUIC UDP DNS query");
            assert_eq!(&buf[..len], b"\x12\x34native-query");
            socket
                .send_to(b"\x12\x34native-answer", peer)
                .await
                .expect("send native QUIC UDP DNS response");
        });
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;

        let response = query_dns_over_transport(
            DnsTransport::QuicNative(bridge.clone()),
            &remote,
            b"\x12\x34native-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over native QUIC UDP");
        assert_eq!(response.as_ref(), b"\x12\x34native-answer");

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        dns_server.await.expect("DNS UDP server join");
    }

    #[tokio::test]
    async fn dns_over_agent_accepts_hostname_remote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\xab\xcdname-query");

            let response = b"\xab\xcdname-answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

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
                .expect("connect agent transport");
        let remote = Destination {
            host: "localhost".to_owned(),
            port: destination.port(),
        };

        let response = query_dns_over_agent(
            transport.clone(),
            &remote,
            b"\xab\xcdname-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over agent hostname");
        assert_eq!(response.as_ref(), b"\xab\xcdname-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    #[tokio::test]
    async fn dns_over_quic_native_accepts_hostname_remote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .expect("accept native QUIC TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read native QUIC TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read native QUIC TCP DNS query");
            assert_eq!(query, b"\xab\xcdnative-name-query");

            let response = b"\xab\xcdnative-name-answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write native QUIC TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write native QUIC TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });
        let remote = Destination {
            host: "localhost".to_owned(),
            port: destination.port(),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;

        let response = query_dns_over_transport(
            DnsTransport::QuicNative(bridge.clone()),
            &remote,
            b"\xab\xcdnative-name-query",
            DEFAULT_TUN_IP,
        )
        .await
        .expect("query DNS over native QUIC hostname");
        assert_eq!(response.as_ref(), b"\xab\xcdnative-name-answer");

        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        dns_server.await.expect("DNS server join");
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

    #[tokio::test]
    async fn udp_over_agent_round_trips_datagram() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
            assert_eq!(&buf[..len], b"ping");
            socket
                .send_to(b"pong", peer)
                .await
                .expect("write UDP response");
        });

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
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };

        let response = query_udp_over_agent(
            transport.clone(),
            &dns::UdpPacket {
                src_ip: Ipv4Addr::new(10, 255, 255, 1),
                dst_ip: *destination.ip(),
                src_port: 49152,
                dst_port: destination.port(),
                payload: Bytes::from_static(b"ping"),
            },
        )
        .await
        .expect("query UDP over agent");
        assert_eq!(response, b"pong");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_reuses_agent_stream_for_multiple_datagrams() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });

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
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: *destination.ip(),
            dst_port: destination.port(),
        };

        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let association = tokio::spawn(run_udp_association_transport(
            transport.clone(),
            key,
            from_local,
            events,
            UDP_ASSOCIATION_IDLE_TIMEOUT,
        ));

        to_remote
            .send(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        to_remote
            .send(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            tokio::select! {
                event = response_rx.recv() => {
                    let event = event.expect("association response channel closed");
                    let event_key = event.key;
                    let payload = event.payload;
                    assert_eq!(event_key, key);
                    responses.push(payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"echo:one"),
                Bytes::from_static(b"echo:two")
            ]
        );

        drop(to_remote);
        tokio::time::timeout(std::time::Duration::from_secs(1), association)
            .await
            .expect("association exits")
            .expect("association join")
            .expect("association run");
        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_reuses_quic_native_stream_for_multiple_datagrams() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"native-echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: *destination.ip(),
            dst_port: destination.port(),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let association = tokio::spawn(run_udp_association(
            UdpAssociationTransport::QuicNative(bridge.clone()),
            key,
            from_local,
            events,
            UDP_ASSOCIATION_IDLE_TIMEOUT,
        ));

        to_remote
            .send(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        to_remote
            .send(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            tokio::select! {
                event = response_rx.recv() => {
                    let event = event.expect("association response channel closed");
                    assert_eq!(event.key, key);
                    responses.push(event.payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("native QUIC UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for native QUIC UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"native-echo:one"),
                Bytes::from_static(b"native-echo:two")
            ]
        );

        drop(to_remote);
        tokio::time::timeout(std::time::Duration::from_secs(1), association)
            .await
            .expect("association exits")
            .expect("association join")
            .expect("association run");
        bridge.close_for_test("test complete");
        bridge_task.await.expect("native bridge task");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_idle_timeout_emits_close_for_accounting() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(127, 0, 0, 1),
            dst_port: 5353,
        };
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = DnsInflight::new(1);
        assert!(association_limit.try_admit());

        spawn_udp_association_with_idle_timeout(
            UdpAssociationTransport::Agent(bridge.clone()),
            key,
            from_local,
            events,
            std::time::Duration::from_millis(10),
        );

        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("idle association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
        assert!(response_rx.try_recv().is_err());

        associations.remove(&closed.key);
        association_limit.complete();
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert!(associations.is_empty());

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn deferred_bridge_admission_leaves_local_bytes_buffered() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /deferred HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(stats.bridge_backpressure_events, 1);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
        }));
    }

    #[tokio::test]
    async fn saturated_bridge_queue_leaves_local_bytes_buffered() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            request_sent_at: None,
            response_complete_at: None,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
                .expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /slow HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(now, packets, &mut clients, &mut manager)
            .expect("route request packets");

        let (event_tx, _event_rx) = mpsc::channel(1);
        let id = manager.flow_id(flow).expect("flow id");
        let bridge =
            ssh_bridge::spawn_bridge_task(id, event_tx, |_id, local_rx, _event_tx| async {
                let _local_rx = local_rx;
                std::future::pending::<()>().await;
            });
        for index in 0..ssh_bridge::FLOW_CHANNEL_DEPTH {
            assert!(
                bridge
                    .try_send_local_data(vec![index as u8])
                    .expect("pre-fill bridge queue"),
                "bridge queue should accept pre-fill item {index}"
            );
        }
        assert_eq!(bridge.local_queue_capacity(), 0);

        let mut bridges = HashMap::from([(flow, bridge)]);
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain should not block or fail");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Relaying
        }));
    }

    #[test]
    fn ssh_target_parses_user_at_host_like_sshuttle() {
        assert_eq!(
            parse_ssh_target("alice@example.com:2222", None).unwrap(),
            SshTarget {
                user: "alice".to_owned(),
                addr: "example.com:2222".to_owned(),
                host: "example.com".to_owned(),
                port: 2222,
            }
        );
    }

    #[test]
    fn ssh_target_user_flag_overrides_remote_user() {
        assert_eq!(
            parse_ssh_target("alice@example.com", Some("bob")).unwrap(),
            SshTarget {
                user: "bob".to_owned(),
                addr: "example.com:22".to_owned(),
                host: "example.com".to_owned(),
                port: 22,
            }
        );
    }

    #[test]
    fn ssh_config_alias_resolves_target_user_port_and_paths() {
        let config_path = write_temp_ssh_config(
            "Host contabo\n\
             HostName 203.0.113.10\n\
             User deploy\n\
             Port 2202\n\
             IdentityFile ~/.ssh/%n-%r-%p\n\
             UserKnownHostsFile ~/.ssh/known_hosts_%h_%p\n",
        );
        let mut args = test_ssh_args("contabo");
        args.ssh_user = None;
        args.ssh_config = Some(config_path.clone());

        let prepared = prepare_ssh_connection(&args).expect("prepare SSH alias");

        assert_eq!(
            prepared.target,
            SshTarget {
                user: "deploy".to_owned(),
                addr: "203.0.113.10:2202".to_owned(),
                host: "203.0.113.10".to_owned(),
                port: 2202,
            }
        );
        let home = home_dir().expect("test requires home directory");
        assert_eq!(
            prepared.identity_files,
            vec![home.join(".ssh").join("contabo-deploy-2202")]
        );
        assert_eq!(
            prepared.known_hosts,
            Some(home.join(".ssh").join("known_hosts_203.0.113.10_2202"))
        );

        std::fs::remove_file(config_path).expect("remove temp SSH config");
    }

    #[test]
    fn ssh_config_alias_respects_cli_user_and_explicit_port_overrides() {
        let config_path = write_temp_ssh_config(
            "Host contabo\n\
             HostName 203.0.113.10\n\
             User deploy\n\
             Port 2202\n",
        );
        let mut args = test_ssh_args("contabo:2222");
        args.ssh_user = Some("root".to_owned());
        args.ssh_config = Some(config_path.clone());

        let target = resolve_ssh_target(&args).expect("resolve SSH alias with overrides");

        assert_eq!(
            target,
            SshTarget {
                user: "root".to_owned(),
                addr: "203.0.113.10:2222".to_owned(),
                host: "203.0.113.10".to_owned(),
                port: 2222,
            }
        );

        std::fs::remove_file(config_path).expect("remove temp SSH config");
    }

    #[test]
    fn ssh_config_host_patterns_support_wildcards_and_negation() {
        let config = "Host * !blocked\n\
                      User fallback\n\
                      Port 2200\n\
                      Host prod-*\n\
                      User deploy\n\
                      IdentityFile ~/.ssh/%h\n\
                      Host blocked\n\
                      HostName 192.0.2.9\n";

        assert_eq!(
            parse_ssh_config_for_host(config, "prod-api").expect("parse wildcard config"),
            SshConfigMatch {
                hostname: None,
                user: Some("fallback".to_owned()),
                port: Some(2200),
                identity_files: vec!["~/.ssh/%h".to_owned()],
                user_known_hosts_file: None,
            }
        );
        assert_eq!(
            parse_ssh_config_for_host(config, "blocked").expect("parse negated config"),
            SshConfigMatch {
                hostname: Some("192.0.2.9".to_owned()),
                user: None,
                port: None,
                identity_files: Vec::new(),
                user_known_hosts_file: None,
            }
        );
    }

    fn write_temp_ssh_config(contents: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "rustle-ssh-config-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        std::fs::write(&path, contents).expect("write temp SSH config");
        path
    }
}
