use anyhow::Result;

use crate::packet_engine::TunnelEngine;
use crate::tun_io::TunWriter;

pub(super) async fn write_engine_packets(
    tun: &TunWriter<'_>,
    engine: &mut TunnelEngine,
) -> Result<()> {
    let tun_write = tun.write_packets(engine.outbound_packets_mut()).await?;
    engine.record_tun_write(tun_write);
    Ok(())
}
