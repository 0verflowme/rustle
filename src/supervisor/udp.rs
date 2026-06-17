use std::sync::Arc;

use crate::data_plane::{spawn_udp_association, DataPlane};
use crate::packet_engine::{TunnelEngine, UdpAssociationStart, UdpIngressAction};

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
