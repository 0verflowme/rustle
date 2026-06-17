use std::sync::Arc;

use anyhow::Result;

use crate::data_plane::{spawn_udp_association, DataPlane};
use crate::packet_engine::{TunnelEngine, UdpAssociationStart, UdpIngressAction};
use crate::transport_model::{UdpClosedEvent, UdpResponseEvent};
use crate::tun_io::TunWriter;

pub(super) fn execute_ingress_actions(
    engine: &mut TunnelEngine,
    data_plane: &Arc<dyn DataPlane>,
    actions: &mut Vec<UdpIngressAction>,
) {
    for action in actions.drain(..) {
        if let Some(start) = engine.apply_udp_ingress_action(action) {
            execute_association_start(data_plane, start);
        }
    }
}

fn execute_association_start(data_plane: &Arc<dyn DataPlane>, start: UdpAssociationStart) {
    eprintln!(
        "udp: opening association {}:{} -> {}:{} over {}",
        start.key.src_ip,
        start.key.src_port,
        start.key.dst_ip,
        start.key.dst_port,
        start.transport_label,
    );
    spawn_udp_association(
        data_plane.open_udp_ipv4(start.key.into_open_request()),
        start.key,
        start.from_local,
        start.events,
        start.idle_timeout,
    );
}

pub(super) async fn execute_response_event(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    event: UdpResponseEvent,
) -> Result<()> {
    let tun_write = tun.write_udp_response(event.key, event.payload).await?;
    engine.record_udp_delivery(tun_write);
    Ok(())
}

pub(super) fn execute_close_event(engine: &mut TunnelEngine, event: UdpClosedEvent) {
    engine.close_udp_association(event.key);
    if let Some(error) = event.error {
        eprintln!(
            "udp: association {}:{} -> {}:{} closed with error: {error}",
            event.key.src_ip, event.key.src_port, event.key.dst_ip, event.key.dst_port,
        );
        engine.record_udp_close_error();
    }
}
