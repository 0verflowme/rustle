use std::sync::Arc;

use anyhow::Result;

use crate::data_plane::{spawn_tcp_bridge_on_data_plane, DataPlane};
use crate::packet_engine::{TcpBridgeStart, TunnelEngine};
use crate::ssh_bridge;

pub(super) fn execute_bridge_starts(
    engine: &mut TunnelEngine,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<ssh_bridge::BridgeEvent>,
    bridge_event_accounting: &ssh_bridge::BridgeEventAccounting,
) -> Result<()> {
    for start in starts.drain(..) {
        let bridge = spawn_tcp_bridge_on_data_plane(
            Arc::clone(data_plane),
            start.id,
            start.ready_wait_ms,
            event_tx.clone(),
            bridge_event_accounting.clone(),
        );
        engine.register_tcp_bridge(start, bridge)?;
    }
    Ok(())
}
