use std::sync::Arc;

use anyhow::{Context, Result};

use crate::data_plane::{spawn_tcp_bridge_on_data_plane, DataPlane};
use crate::flow_bridge;
use crate::packet_engine::{TcpBridgeStart, TunnelEngine};
use crate::tun_io::TunWriter;

use super::tun;

pub(super) async fn execute_ingress_packet(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    packet: &[u8],
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<()> {
    engine
        .ingest_tcp_packet(packet)
        .context("failed to feed packet into userspace TCP engine")?;
    tun::write_engine_packets(tun, engine).await?;
    plan_and_start_bridges(
        engine,
        starts,
        data_plane,
        event_tx,
        bridge_event_accounting,
    )?;
    engine.drain_local_bytes_to_bridges()?;
    flush_remote_backlogs_to_tun(engine, tun).await?;
    engine.expire_and_prune()
}

pub(super) async fn execute_bridge_event_cycle(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
) -> Result<()> {
    engine.poll_tcp();
    flush_remote_backlogs_to_tun(engine, tun).await?;
    engine.expire_and_prune()
}

pub(super) async fn execute_tick_cycle(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<()> {
    engine.poll_tcp();
    flush_remote_backlogs_to_tun(engine, tun).await?;
    plan_and_start_bridges(
        engine,
        starts,
        data_plane,
        event_tx,
        bridge_event_accounting,
    )?;
    engine.drain_local_bytes_to_bridges()?;
    engine.expire_and_prune()
}

fn plan_and_start_bridges(
    engine: &mut TunnelEngine,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<()> {
    engine.plan_bridge_starts(data_plane.admission_limits(), starts)?;
    execute_bridge_starts(
        engine,
        starts,
        data_plane,
        event_tx,
        bridge_event_accounting,
    )
}

async fn flush_remote_backlogs_to_tun(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
) -> Result<()> {
    tun::write_engine_packets(tun, engine).await?;
    engine.flush_remote_backlogs()?;
    tun::write_engine_packets(tun, engine).await
}

fn execute_bridge_starts(
    engine: &mut TunnelEngine,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &tokio::sync::mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
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
