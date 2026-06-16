#[cfg(test)]
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use bytes::BytesMut;
use clap::Parser;
#[cfg(test)]
use smoltcp::socket::tcp;
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
use cli::{Cli, CommandKind};
pub(crate) use cli::{SshArgs, TunCaptureArgs, TunnelArgs};
use command_runtime::{run_compact_tunnel, run_direct_tcpip};
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
#[cfg(test)]
use packet_engine::{
    plan_udp_datagram_actions, DnsInflight, TunnelStats, UdpAssociationTransportPlan,
    UdpIngressAction,
};
use supervisor::{run_tun_capture, run_tunnel};
#[cfg(test)]
use transport_model::{BridgeTransportKind, UDP_DATAGRAMS_PER_ASSOCIATION};
#[cfg(test)]
use transport_model::{
    Destination, DnsResponseEvent, UdpAssociation, UdpAssociationEvents, UdpFlowKey,
};

pub(crate) const DEFAULT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
pub(crate) const DEFAULT_TUN_PREFIX: u8 = 24;
pub(crate) const DEFAULT_MTU: u16 = 1300;
pub(crate) const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS: u64 = 60_000;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_bridge::AgentBridgeConnector;
    use crate::bridge_runtime::DnsTransport;
    #[cfg(unix)]
    use crate::supervisor::unix_shutdown_signals;
    use crate::supervisor::{
        parse_ipv4_metadata, validate_tun_args, validate_tunnel_args, virtual_dns_ip,
    };
    use anyhow::anyhow;
    use smoltcp::time::Instant as SmolInstant;
    use std::net::IpAddr;
    use std::sync::Arc;

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
}
