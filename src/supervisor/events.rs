use std::time::Instant as StdInstant;

use anyhow::Result;

use crate::flow_bridge::{self, BridgeEvent};
use crate::packet_engine::TunnelEngine;

const BRIDGE_EVENT_BATCH_LIMIT: usize = 32;

pub(super) fn handle_bridge_event_batch(
    engine: &mut TunnelEngine,
    first: BridgeEvent,
    event_rx: &mut tokio::sync::mpsc::Receiver<BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<usize> {
    let started_at = StdInstant::now();
    let mut handled = 0_usize;
    let mut paused_by_backlog = false;
    let mut next = Some(first);
    while handled < BRIDGE_EVENT_BATCH_LIMIT {
        let event = if let Some(event) = next.take() {
            event
        } else {
            match event_rx.try_recv() {
                Ok(event) => event,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        };
        bridge_event_accounting.record_dequeued(&event);
        engine.handle_bridge_event(event)?;
        handled += 1;
        if engine.should_pause_bridge_events() {
            paused_by_backlog = true;
            break;
        }
    }
    engine.record_bridge_event_batch(handled, started_at.elapsed(), paused_by_backlog);
    Ok(handled)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::defaults::{DEFAULT_MTU, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};
    use crate::tcp_core;

    fn test_engine() -> TunnelEngine {
        TunnelEngine::new(
            tcp_core::FlowManager::new(
                DEFAULT_TUN_IP,
                DEFAULT_TUN_PREFIX,
                &[tcp_core::Ipv4NetParts::new(
                    Ipv4Addr::new(198, 18, 0, 0),
                    15,
                )],
                usize::from(DEFAULT_MTU),
            )
            .expect("flow manager"),
        )
    }

    fn test_flow_id() -> tcp_core::FlowId {
        tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 2),
                49152,
                Ipv4Addr::new(198, 18, 77, 77),
                80,
            ),
            1,
        )
    }

    #[test]
    fn bridge_event_batch_is_bounded() {
        let mut engine = test_engine();
        let id = test_flow_id();
        let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(BRIDGE_EVENT_BATCH_LIMIT + 1);
        for _ in 0..BRIDGE_EVENT_BATCH_LIMIT {
            tx.try_send(BridgeEvent::Closed { id })
                .expect("queue bridge event");
        }

        let handled = handle_bridge_event_batch(
            &mut engine,
            BridgeEvent::Closed { id },
            &mut rx,
            &bridge_event_accounting,
        )
        .expect("handle bridge event batch");

        assert_eq!(handled, BRIDGE_EVENT_BATCH_LIMIT);
        assert_eq!(
            rx.try_recv().expect("one queued event should remain"),
            BridgeEvent::Closed { id }
        );
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn bridge_event_batch_records_stats() {
        let mut engine = test_engine();
        let id = test_flow_id();
        let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        tx.try_send(BridgeEvent::Closed { id })
            .expect("queue bridge event");

        let handled = handle_bridge_event_batch(
            &mut engine,
            BridgeEvent::Closed { id },
            &mut rx,
            &bridge_event_accounting,
        )
        .expect("handle bridge event batch");

        let stats = engine.stats_for_test();
        assert_eq!(handled, 2);
        assert_eq!(stats.bridge_event_batches, 1);
        assert_eq!(stats.bridge_event_batch_events, 2);
        assert_eq!(stats.bridge_event_batch_max, 2);
        assert_eq!(stats.ssh_closed, 2);
        assert_eq!(stats.stale_bridge_events, 2);
    }

    #[test]
    fn bridge_event_batch_handles_receiver_disconnect_after_first_event() {
        let mut engine = test_engine();
        let id = test_flow_id();
        let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        drop(tx);

        let handled = handle_bridge_event_batch(
            &mut engine,
            BridgeEvent::Closed { id },
            &mut rx,
            &bridge_event_accounting,
        )
        .expect("handle bridge event batch");

        let stats = engine.stats_for_test();
        assert_eq!(handled, 1);
        assert_eq!(stats.bridge_event_batches, 1);
        assert_eq!(stats.bridge_event_batch_events, 1);
        assert_eq!(stats.ssh_closed, 1);
    }

    #[tokio::test]
    async fn bridge_event_batch_releases_accounted_remote_data_on_dequeue() {
        let mut engine = test_engine();
        let id = test_flow_id();
        let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let first = BridgeEvent::RemoteData {
            id,
            bytes: bytes::Bytes::from_static(b"first"),
        };
        let second = BridgeEvent::RemoteData {
            id,
            bytes: bytes::Bytes::from_static(b"second"),
        };

        assert!(
            flow_bridge::send_bridge_event_accounted(&tx, &bridge_event_accounting, first).await
        );
        assert!(
            flow_bridge::send_bridge_event_accounted(&tx, &bridge_event_accounting, second).await
        );
        assert_eq!(bridge_event_accounting.snapshot().remote_bytes, 11);
        assert_eq!(bridge_event_accounting.snapshot().remote_bytes_max, 11);
        let first = rx
            .recv()
            .await
            .expect("first bridge event should be queued");

        let handled =
            handle_bridge_event_batch(&mut engine, first, &mut rx, &bridge_event_accounting)
                .expect("handle bridge event batch");

        assert_eq!(handled, 2);
        assert_eq!(bridge_event_accounting.snapshot().remote_bytes, 0);
        assert_eq!(bridge_event_accounting.snapshot().remote_bytes_max, 11);
        assert_eq!(engine.stats_for_test().remote_to_local_bytes, 11);
    }
}
