use std::net::Ipv4Addr;
use std::time::Instant as StdInstant;

use anyhow::{bail, Context, Result};

use crate::packet_engine::{smol_now, tun_ipv4_packet, PACKET_BUF_SIZE};
use crate::routing::{add_target_routes, expand_target_routes, target_route_parts};
use crate::supervisor::lifecycle::{open_tun, shutdown_signal, ShutdownSignal, TunConfig};
use crate::tun_io::TunWriter;
use crate::{platform, tcp_core, TunCaptureArgs};

pub(crate) async fn run_tun_capture(args: TunCaptureArgs) -> Result<()> {
    validate_tun_args(&args)?;
    let shutdown = shutdown_signal().await?;
    let target_routes = expand_target_routes(&args.targets)?;
    let tun = open_tun(&TunConfig::new(
        args.tun_ip,
        args.tun_prefix,
        args.mtu,
        args.name,
    ))?;

    let routes = add_target_routes(&target_routes, &tun.if_name, tun.if_index, args.tun_ip)?;
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = capture_packets(tun.dev, flow_manager, args.exit_after_packets, shutdown).await;
    drop(routes);
    result
}

pub(crate) async fn capture_packets(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    exit_after_packets: Option<u64>,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let tun = TunWriter::new(&dev);
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let started_at = StdInstant::now();
    let mut captured_packets = 0_u64;
    loop {
        tokio::select! {
            signal = shutdown.recv() => {
                eprintln!("signal: {} received", signal?);
                return Ok(());
            }
            result = tun.recv(&mut buf) => {
                let len = result?;
                captured_packets = captured_packets.saturating_add(1);
                let Some(packet) = tun_ipv4_packet(&buf[..len]) else {
                    eprintln!("packet: len={len} non_ipv4");
                    continue;
                };
                match parse_ipv4_metadata(packet) {
                    Ok(packet) => {
                        eprintln!(
                            "packet: len={} total_len={} proto={} src={} dst={}",
                            len,
                            packet.total_len,
                            packet.protocol,
                            packet.src,
                            packet.dst
                        );
                        match tcp_core::parse_ipv4_tcp_segment(&buf[..len]) {
                            Ok(Some(segment)) => {
                                eprintln!(
                                    "tcp: {}:{} -> {}:{} syn={} ack={} fin={} rst={} opening_syn={} payload_len={}",
                                    segment.flow.src_ip,
                                    segment.flow.src_port,
                                    segment.flow.dst_ip,
                                    segment.flow.dst_port,
                                    segment.flags.syn,
                                    segment.flags.ack,
                                    segment.flags.fin,
                                    segment.flags.rst,
                                    segment.flags.is_opening_syn(),
                                    segment.payload_len
                                );
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!("tcp: parse_error={err}");
                            }
                        }

                        flow_manager
                            .ingest_packet_into(
                                smol_now(started_at),
                                &buf[..len],
                                &mut outbound_packets,
                            )
                            .context("failed to feed packet into userspace TCP engine")?;
                        let _ = tun.write_packets(&mut outbound_packets).await?;
                        for snapshot in flow_manager.snapshots() {
                            eprintln!(
                                "flow: {:?} state={:?} buffered_rx={}",
                                snapshot.key,
                                snapshot.state,
                                snapshot.buffered_rx
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("packet: len={len} parse_error={err}");
                    }
                }
                if exit_after_packets
                    .is_some_and(|limit| captured_packets >= limit)
                {
                    eprintln!("capture: exit-after-packets reached ({captured_packets})");
                    return Ok(());
                }
            }
        }
    }
}

pub(crate) fn validate_tun_args(args: &TunCaptureArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
    platform::preflight_route_management().context("route preflight failed")?;
    if args.tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if args.mtu < 576 {
        bail!("mtu must be at least the IPv4 minimum of 576 bytes");
    }
    if args.mtu as usize > PACKET_BUF_SIZE {
        bail!("mtu must not exceed packet buffer size {PACKET_BUF_SIZE}");
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Ipv4PacketMetadata {
    pub(crate) total_len: u16,
    pub(crate) protocol: u8,
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
}

pub(crate) fn parse_ipv4_metadata(packet: &[u8]) -> Result<Ipv4PacketMetadata> {
    if packet.len() < 20 {
        bail!("short IPv4 packet");
    }

    let version = packet[0] >> 4;
    if version != 4 {
        bail!("not IPv4 version {version}");
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 {
        bail!("invalid IPv4 header length {header_len}");
    }
    if packet.len() < header_len {
        bail!("truncated IPv4 header");
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if usize::from(total_len) > packet.len() {
        bail!("truncated IPv4 payload");
    }

    Ok(Ipv4PacketMetadata {
        total_len,
        protocol: packet[9],
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::defaults::{DEFAULT_MTU, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX};

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
}
