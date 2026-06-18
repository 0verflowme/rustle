use super::test_support::{
    agent_transport_closes_after_first_open, agent_transport_closes_after_opened,
    agent_transport_pair, detached_bridge_transport, wait_for_reconnect_snapshot,
    wait_for_transport_failure, QueuedAgentConnector,
};
use super::*;
use crate::agent_proto;
use crate::control_plane::connect_auto_agent_bridge_transports_from_connector;
use crate::defaults::DEFAULT_TUN_IP;
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::time::Duration;

fn tcp_open_for_primary_agent_lane(
    mut open: agent_proto::AgentOpenIpv4,
    lane_count: usize,
    primary: usize,
) -> agent_proto::AgentOpenIpv4 {
    for _ in 0..4096 {
        if agent_lane_candidates(
            AgentOpenRequest::TcpIpv4 {
                open,
                mode: AgentTcpOpenMode::Strict,
            }
            .lane_hash(),
            lane_count,
        )
        .0 == primary
        {
            return open;
        }
        open.originator_port = open.originator_port.wrapping_add(1);
    }
    panic!("could not find TCP open request for primary agent lane {primary}");
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

#[tokio::test]
async fn detached_agent_carrier_disconnect_is_noop() {
    AgentBridgeCarrier::Detached
        .disconnect("detached test done")
        .await
        .expect("detached carrier disconnect");
}

#[tokio::test]
async fn agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary() {
    let (first_transport, first_agent) = agent_transport_pair().await;
    let (second_transport, second_agent) = agent_transport_pair().await;
    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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

    bridge.set_lane_load_for_test(1, 5);
    assert_eq!(
        bridge.choose_lane_index_for_test(0, 1).await,
        0,
        "equal candidate load should keep primary lane affinity"
    );

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
async fn agent_lane_selection_keeps_single_candidate_even_when_unhealthy() {
    let (failed_transport, failed_agent) = agent_transport_pair().await;
    let (healthy_transport, healthy_agent) = agent_transport_pair().await;

    failed_agent.abort();
    let _ = failed_agent.await;
    wait_for_transport_failure(&failed_transport).await;

    let bridge = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![
            detached_bridge_transport(failed_transport),
            detached_bridge_transport(healthy_transport),
        ],
    );

    assert_eq!(
        bridge.choose_lane_index_for_test(0, 0).await,
        0,
        "primary==secondary is already a deterministic affinity decision"
    );

    drop(bridge);
    tokio::time::timeout(std::time::Duration::from_secs(1), healthy_agent)
        .await
        .expect("healthy agent exits")
        .expect("healthy agent join")
        .expect("healthy agent run");
}

#[tokio::test]
async fn agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy() {
    let (failed_primary_transport, failed_primary_agent) = agent_transport_pair().await;
    let (failed_secondary_transport, failed_secondary_agent) = agent_transport_pair().await;
    let (busy_transport, busy_agent) = agent_transport_pair().await;
    let (idle_transport, idle_agent) = agent_transport_pair().await;
    let (primary_replacement_transport, primary_replacement_agent) = agent_transport_pair().await;
    let (secondary_replacement_transport, secondary_replacement_agent) =
        agent_transport_pair().await;

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
    let (skipped_transport, skipped_agent) = agent_transport_pair().await;
    let (busy_transport, busy_agent) = agent_transport_pair().await;
    let (idle_transport, idle_agent) = agent_transport_pair().await;
    let (middle_transport, middle_agent) = agent_transport_pair().await;
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
async fn alternate_lane_selection_ties_keep_lowest_lane_index() {
    let (skipped_transport, skipped_agent) = agent_transport_pair().await;
    let (first_transport, first_agent) = agent_transport_pair().await;
    let (second_transport, second_agent) = agent_transport_pair().await;
    let bridge = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![
            detached_bridge_transport(skipped_transport),
            detached_bridge_transport(first_transport),
            detached_bridge_transport(second_transport),
        ],
    );

    bridge.set_lane_load_for_test(1, 3);
    bridge.set_lane_load_for_test(2, 3);
    assert_eq!(
        bridge.next_alternate_lane_index_for_test(0, 0),
        Some(1),
        "equal-load alternates should choose the lowest lane index deterministically"
    );

    drop(bridge);
    for agent in [skipped_agent, first_agent, second_agent] {
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }
}

#[tokio::test]
async fn best_available_lane_selection_skips_both_candidate_lanes_and_preserves_ties() {
    let (first_skipped_transport, first_skipped_agent) = agent_transport_pair().await;
    let (second_skipped_transport, second_skipped_agent) = agent_transport_pair().await;
    let (first_candidate_transport, first_candidate_agent) = agent_transport_pair().await;
    let (second_candidate_transport, second_candidate_agent) = agent_transport_pair().await;
    let bridge = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![
            detached_bridge_transport(first_skipped_transport),
            detached_bridge_transport(second_skipped_transport),
            detached_bridge_transport(first_candidate_transport),
            detached_bridge_transport(second_candidate_transport),
        ],
    );

    bridge.set_lane_load_for_test(0, 0);
    bridge.set_lane_load_for_test(1, 0);
    bridge.set_lane_load_for_test(2, 4);
    bridge.set_lane_load_for_test(3, 4);

    assert_eq!(
        bridge.best_available_lane_index_except_for_test(0, 1).await,
        Some(2),
        "fallback scan must skip both original candidates and keep lowest-index tie"
    );

    drop(bridge);
    for agent in [
        first_skipped_agent,
        second_skipped_agent,
        first_candidate_agent,
        second_candidate_agent,
    ] {
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }
}

#[tokio::test]
async fn agent_lane_lease_releases_reserved_load_on_drop() {
    let (transport, agent) = agent_transport_pair().await;
    let bridge = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![detached_bridge_transport(transport)],
    );
    let load = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    {
        let _lease = AgentLaneLease::new(bridge.clone(), 0, std::sync::Arc::clone(&load));
        assert_eq!(load.load(std::sync::atomic::Ordering::Acquire), 1);
    }
    assert_eq!(
        load.load(std::sync::atomic::Ordering::Acquire),
        0,
        "dropping an unopened lane lease must release reserved load"
    );

    drop(bridge);
    tokio::time::timeout(std::time::Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
}

#[test]
fn agent_open_request_lane_hash_preserves_transport_affinity_inputs() {
    let tcp_open = agent_proto::AgentOpenIpv4 {
        destination_ip: Ipv4Addr::new(192, 0, 2, 10),
        destination_port: 443,
        originator_ip: DEFAULT_TUN_IP,
        originator_port: 49152,
    };
    let host_open = agent_proto::AgentOpenHost {
        destination_host: "example.internal".to_owned(),
        destination_port: 443,
        originator_ip: DEFAULT_TUN_IP,
        originator_port: 49152,
    };

    assert_eq!(
        AgentOpenRequest::TcpIpv4 {
            open: tcp_open,
            mode: AgentTcpOpenMode::Strict,
        }
        .lane_hash(),
        agent_ipv4_lane_hash(&tcp_open, TCP_PROTOCOL_NUMBER)
    );
    assert_eq!(
        AgentOpenRequest::UdpIpv4(tcp_open).lane_hash(),
        agent_ipv4_lane_hash(&tcp_open, UDP_PROTOCOL_NUMBER)
    );
    assert_eq!(
        AgentOpenRequest::TcpHost(host_open.clone()).lane_hash(),
        agent_host_lane_hash(&host_open, TCP_PROTOCOL_NUMBER)
    );
}

#[tokio::test]
async fn background_lane_repair_requests_are_coalesced() {
    let (transport, agent) = agent_transport_pair().await;
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

    let (transport, agent) = agent_transport_pair().await;
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
    tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .expect("TCP server should observe agent stream close")
        .expect("TCP server join");

    drop(bridge);
    tokio::time::timeout(std::time::Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
}

#[tokio::test]
async fn agent_bridge_stream_metrics_and_try_recv_forward_frames() {
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
        assert_eq!(request, b"metrics");
        socket.write_all(b"ok").await.expect("write response");
        socket.shutdown().await.expect("shutdown TCP stream");
    });

    let (transport, agent) = agent_transport_pair().await;
    let bridge = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![detached_bridge_transport(transport)],
    );
    let destination = match destination {
        std::net::SocketAddr::V4(addr) => addr,
        std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
    };

    let mut stream = bridge
        .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        })
        .await
        .expect("open tracked agent stream");
    let metrics = stream
        .send_data_with_metrics(Bytes::from_static(b"metrics"))
        .await
        .expect("send request with metrics");
    assert_eq!(metrics.frames, 1);
    stream.send_eof().await.expect("send EOF");

    let response = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut response = Vec::new();
        loop {
            if let Some(frame) = stream.try_recv().await {
                match frame.kind {
                    agent_proto::AgentFrameKind::Data => {
                        response.extend_from_slice(&frame.payload);
                    }
                    agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => {
                        break response;
                    }
                    agent_proto::AgentFrameKind::Reset => {
                        panic!("stream reset: {}", String::from_utf8_lossy(&frame.payload));
                    }
                    _ => {}
                }
            } else {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    })
    .await
    .expect("try_recv should observe response frames");
    assert_eq!(response, b"ok");

    drop(stream);
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
        agent_transport_closes_after_opened().await;
    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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
async fn fast_start_missing_lane_warmup_can_be_deferred() {
    let (first_transport, first_agent) = agent_transport_pair().await;
    let (second_transport, second_agent) = agent_transport_pair().await;
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
async fn agent_bridge_repairs_missing_startup_lane_in_background() {
    let (first_transport, first_agent) = agent_transport_pair().await;
    let (second_transport, second_agent) = agent_transport_pair().await;
    let (third_transport, third_agent) = agent_transport_pair().await;
    let (fourth_transport, fourth_agent) = agent_transport_pair().await;
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
    let (first_transport, first_agent) = agent_transport_pair().await;
    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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

    let (failed_transport, failed_agent) = agent_transport_pair().await;
    failed_agent.abort();
    let _ = failed_agent.await;
    wait_for_transport_failure(&failed_transport).await;

    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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

    let (failed_transport, failed_agent) = agent_transport_pair().await;
    failed_agent.abort();
    let _ = failed_agent.await;
    wait_for_transport_failure(&failed_transport).await;

    let (healthy_transport, healthy_agent) = agent_transport_pair().await;
    let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
    let bridge = ReconnectingAgentBridge::new(
        connector,
        vec![
            AgentBridgeTransport::detached_for_test(failed_transport, "rustle agent".to_owned()),
            AgentBridgeTransport::detached_for_test(healthy_transport, "rustle agent".to_owned()),
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

    let (failed_primary_transport, failed_primary_agent) = agent_transport_pair().await;
    failed_primary_agent.abort();
    let _ = failed_primary_agent.await;
    wait_for_transport_failure(&failed_primary_transport).await;

    let (failed_alternate_transport, failed_alternate_agent) = agent_transport_pair().await;
    failed_alternate_agent.abort();
    let _ = failed_alternate_agent.await;
    wait_for_transport_failure(&failed_alternate_transport).await;

    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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
async fn reconnecting_agent_skips_failed_alternate_and_uses_next_lane() {
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
        assert_eq!(request, b"skip-failed-alt");
        socket
            .write_all(b"next-alt:pong")
            .await
            .expect("write response");
        socket.shutdown().await.expect("shutdown TCP stream");
    });

    let (dying_primary_transport, dying_primary_agent) =
        agent_transport_closes_after_first_open().await;

    let (failed_first_alternate_transport, failed_first_alternate_agent) =
        agent_transport_pair().await;
    failed_first_alternate_agent.abort();
    let _ = failed_first_alternate_agent.await;
    wait_for_transport_failure(&failed_first_alternate_transport).await;

    let (healthy_second_alternate_transport, healthy_second_alternate_agent) =
        agent_transport_pair().await;
    let connector =
        QueuedAgentConnector::new_with_primary_failures("rustle agent", Vec::new(), Vec::new(), 2);
    let bridge = ReconnectingAgentBridge::new(
        connector,
        vec![
            AgentBridgeTransport::detached_for_test(
                dying_primary_transport,
                "rustle agent".to_owned(),
            ),
            AgentBridgeTransport::detached_for_test(
                failed_first_alternate_transport,
                "rustle agent".to_owned(),
            ),
            AgentBridgeTransport::detached_for_test(
                healthy_second_alternate_transport,
                "rustle agent".to_owned(),
            ),
        ],
    );
    bridge.set_lane_load_for_test(1, 0);
    bridge.set_lane_load_for_test(2, 4);

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
    let open = tcp_open_for_primary_agent_lane(open, 3, 0);

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        bridge.open_tcp_ipv4(open),
    )
    .await
    .expect("alternate scan should not stall on failed lower-load lane")
    .expect("open stream on second alternate lane");
    stream
        .send_data(Bytes::from_static(b"skip-failed-alt"))
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
                    "second alternate lane stream reset: {}",
                    String::from_utf8_lossy(&frame.payload)
                );
            }
            other => panic!("unexpected agent frame {other:?}"),
        }
    }
    assert!(saw_eof);
    assert_eq!(response, b"next-alt:pong");
    assert_eq!(
        bridge.reconnect_snapshot(),
        AgentReconnectSnapshot {
            attempts: 2,
            successes: 0,
            failures: 2,
        }
    );

    drop(stream);
    drop(bridge);
    dying_primary_agent
        .await
        .expect("dying primary fake agent join");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        healthy_second_alternate_agent,
    )
    .await
    .expect("healthy second alternate agent exits")
    .expect("healthy second alternate agent join")
    .expect("healthy second alternate agent run");
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

    let (failed_primary_transport, failed_primary_agent) = agent_transport_pair().await;
    failed_primary_agent.abort();
    let _ = failed_primary_agent.await;
    wait_for_transport_failure(&failed_primary_transport).await;

    let (dying_alternate_transport, dying_alternate_agent) =
        agent_transport_closes_after_first_open().await;

    let (replacement_transport, replacement_agent) = agent_transport_pair().await;
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

    let (failed_transport, failed_agent) = agent_transport_pair().await;
    failed_agent.abort();
    let _ = failed_agent.await;
    wait_for_transport_failure(&failed_transport).await;

    let (healthy_transport, healthy_agent) = agent_transport_pair().await;
    let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
    let bridge = ReconnectingAgentBridge::new(
        connector,
        vec![
            AgentBridgeTransport::detached_for_test(failed_transport, "rustle agent".to_owned()),
            AgentBridgeTransport::detached_for_test(healthy_transport, "rustle agent".to_owned()),
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
