use std::sync::Arc;

use anyhow::{Context, Result};

use crate::data_plane::{spawn_tcp_bridge_on_data_plane, DataPlane};
use crate::flow_bridge;
use crate::packet_engine::{TcpBridgeHandles, TcpBridgeStart, TunnelEngine};
use crate::tun_io::TunWriter;

use super::tun;

pub(super) struct BridgeEventSink<'a> {
    event_tx: &'a tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
    accounting: &'a flow_bridge::BridgeEventAccounting,
}

impl<'a> BridgeEventSink<'a> {
    pub(super) fn new(
        event_tx: &'a tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
        accounting: &'a flow_bridge::BridgeEventAccounting,
    ) -> Self {
        Self {
            event_tx,
            accounting,
        }
    }
}

pub(super) async fn execute_ingress_packet(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    packet: &[u8],
    tcp_bridges: &mut TcpBridgeHandles,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    bridge_events: BridgeEventSink<'_>,
) -> Result<()> {
    engine
        .ingest_tcp_packet(packet)
        .context("failed to feed packet into userspace TCP engine")?;
    tun::write_engine_packets(tun, engine).await?;
    plan_and_start_bridges(engine, tcp_bridges, starts, data_plane, bridge_events)?;
    engine.drain_local_bytes_to_bridges(tcp_bridges)?;
    flush_remote_backlogs_to_tun(engine, tcp_bridges, tun).await?;
    engine.expire_and_prune(tcp_bridges)
}

pub(super) async fn execute_bridge_event_cycle(
    engine: &mut TunnelEngine,
    tcp_bridges: &mut TcpBridgeHandles,
    tun: &TunWriter<'_>,
) -> Result<()> {
    engine.poll_tcp();
    flush_remote_backlogs_to_tun(engine, tcp_bridges, tun).await?;
    engine.expire_and_prune(tcp_bridges)
}

pub(super) async fn execute_tick_cycle(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    tcp_bridges: &mut TcpBridgeHandles,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    bridge_events: BridgeEventSink<'_>,
) -> Result<()> {
    engine.poll_tcp();
    flush_remote_backlogs_to_tun(engine, tcp_bridges, tun).await?;
    plan_and_start_bridges(engine, tcp_bridges, starts, data_plane, bridge_events)?;
    engine.drain_local_bytes_to_bridges(tcp_bridges)?;
    engine.expire_and_prune(tcp_bridges)
}

fn plan_and_start_bridges(
    engine: &mut TunnelEngine,
    tcp_bridges: &mut TcpBridgeHandles,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    bridge_events: BridgeEventSink<'_>,
) -> Result<()> {
    engine.plan_bridge_starts(tcp_bridges, data_plane.admission_limits(), starts)?;
    execute_bridge_starts(engine, tcp_bridges, starts, data_plane, bridge_events)
}

async fn flush_remote_backlogs_to_tun(
    engine: &mut TunnelEngine,
    tcp_bridges: &mut TcpBridgeHandles,
    tun: &TunWriter<'_>,
) -> Result<()> {
    tun::write_engine_packets(tun, engine).await?;
    engine.flush_remote_backlogs(tcp_bridges)?;
    tun::write_engine_packets(tun, engine).await
}

fn execute_bridge_starts(
    engine: &mut TunnelEngine,
    tcp_bridges: &mut TcpBridgeHandles,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    bridge_events: BridgeEventSink<'_>,
) -> Result<()> {
    for start in starts.drain(..) {
        let bridge = spawn_tcp_bridge_on_data_plane(
            Arc::clone(data_plane),
            start.id,
            start.ready_wait_ms,
            bridge_events.event_tx.clone(),
            bridge_events.accounting.clone(),
        );
        engine.register_tcp_bridge(tcp_bridges, start, bridge)?;
    }
    Ok(())
}
