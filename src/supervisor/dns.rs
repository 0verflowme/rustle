use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::data_plane::{spawn_dns_query_on_data_plane, DataPlane};
use crate::defaults::DEFAULT_TUN_IP;
use crate::packet_engine::{parse_dns_request_for_tunnel, TunnelEngine};
use crate::transport_model::{Destination, DnsResponseEvent};
use crate::tun_io::TunWriter;

pub(super) async fn execute_ingress_packet(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    data_plane: &Arc<dyn DataPlane>,
    remote: &Destination,
    event_tx: &mpsc::Sender<DnsResponseEvent>,
    packet: &[u8],
) -> Result<bool> {
    let Some(request) = parse_dns_request_for_tunnel(packet) else {
        return Ok(false);
    };

    engine.record_dns_forwarded();
    eprintln!(
        "dns: forwarding UDP query {}:{} -> {}:{} over {} to {}:{}",
        request.src_ip,
        request.src_port,
        request.dst_ip,
        request.dst_port,
        data_plane.label(),
        remote.host,
        remote.port
    );
    if engine.try_admit_dns() {
        spawn_dns_query_on_data_plane(
            Arc::clone(data_plane),
            remote.clone(),
            request,
            event_tx.clone(),
            DEFAULT_TUN_IP,
        );
    } else {
        eprintln!(
            "dns: dropping query because {} DNS queries are already in flight",
            engine.dns_admission_limit()
        );
        engine.record_dns_drop();
        let tun_write = tun
            .write_dns_event(DnsResponseEvent {
                request,
                result: Err("DNS in-flight limit reached".to_owned()),
            })
            .await?;
        engine.record_tun_write(tun_write);
    }

    Ok(true)
}

pub(super) async fn execute_response_event(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    event: DnsResponseEvent,
) -> Result<()> {
    engine.complete_dns();
    let remote_ok = event.result.is_ok();
    let tun_write = tun.write_dns_event(event).await?;
    engine.record_dns_delivery(remote_ok, tun_write);
    Ok(())
}
