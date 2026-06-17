use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::data_plane::{spawn_dns_query_on_data_plane, DataPlane};
use crate::defaults::DEFAULT_TUN_IP;
use crate::packet_engine::{
    parse_dns_request_for_tunnel, parse_udp_request_for_agent_tunnel, tun_ipv4_packet,
    TunnelEngine, UdpAssociationTransportPlan, MAX_ACTIVE_UDP_ASSOCIATIONS,
    MAX_IN_FLIGHT_DNS_QUERIES, PACKET_BUF_SIZE,
};
use crate::transport_model::{Destination, DnsResponseEvent, UdpAssociationEvents};
use crate::tun_io::TunWriter;
use crate::tunnel_lifecycle::ShutdownSignal;
use crate::{ssh_bridge, tcp_core};

mod events;
mod prepare;
#[cfg(test)]
mod prepare_tests;
mod tcp;
mod tun;
mod udp;

pub(crate) use prepare::run_tunnel;

const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct TunnelSupervisor {
    dev: tun_rs::AsyncDevice,
    engine: TunnelEngine,
    data_plane: Arc<dyn DataPlane>,
    dns_remote: Destination,
    udp_association_idle_timeout: Duration,
    shutdown: ShutdownSignal,
}

impl TunnelSupervisor {
    pub(crate) fn new(
        dev: tun_rs::AsyncDevice,
        flow_manager: tcp_core::FlowManager,
        data_plane: Arc<dyn DataPlane>,
        dns_remote: Destination,
        udp_association_idle_timeout: Duration,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            dev,
            engine: TunnelEngine::new(flow_manager),
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            shutdown,
        }
    }
}

impl TunnelSupervisor {
    pub(crate) async fn run(&mut self) -> Result<()> {
        let Self {
            dev,
            engine,
            data_plane,
            dns_remote,
            udp_association_idle_timeout,
            shutdown,
        } = self;

        let tun = TunWriter::new(dev);
        let data_plane = Arc::clone(data_plane);
        let dns_remote = dns_remote.clone();
        let udp_association_idle_timeout = *udp_association_idle_timeout;
        let mut buf = vec![0_u8; PACKET_BUF_SIZE];
        let mut tcp_bridge_starts = Vec::new();
        let mut udp_actions = Vec::new();
        let bridge_event_accounting = ssh_bridge::BridgeEventAccounting::new();
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1024);
        let (dns_tx, mut dns_rx) = tokio::sync::mpsc::channel(DNS_EVENT_CHANNEL_DEPTH);
        let (udp_response_tx, mut udp_response_rx) =
            tokio::sync::mpsc::channel(UDP_RESPONSE_EVENT_CHANNEL_DEPTH);
        let (udp_close_tx, mut udp_close_rx) =
            tokio::sync::mpsc::channel(UDP_CLOSE_EVENT_CHANNEL_DEPTH);
        let udp_events = UdpAssociationEvents {
            response_tx: udp_response_tx,
            close_tx: udp_close_tx,
        };
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let mut stats_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + STATS_LOG_INTERVAL,
            STATS_LOG_INTERVAL,
        );
        stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                signal = shutdown.recv() => {
                    eprintln!("signal: {} received", signal?);
                    eprintln!(
                        "stats: final {}",
                        engine.status_line(
                            data_plane.snapshot().await,
                            bridge_event_accounting.snapshot(),
                        )
                    );
                    return Ok(());
                }
                result = tun.recv(&mut buf) => {
                    let len = result?;
                    engine.record_tun_rx(len);
                    let Some(packet) = tun_ipv4_packet(&buf[..len]) else {
                        continue;
                    };
                    if let Some(request) = parse_dns_request_for_tunnel(packet) {
                        engine.record_dns_forwarded();
                        eprintln!(
                            "dns: forwarding UDP query {}:{} -> {}:{} over {} to {}:{}",
                            request.src_ip,
                            request.src_port,
                            request.dst_ip,
                            request.dst_port,
                            data_plane.label(),
                            dns_remote.host,
                            dns_remote.port
                        );
                        if engine.try_admit_dns() {
                            spawn_dns_query_on_data_plane(
                                Arc::clone(&data_plane),
                                dns_remote.clone(),
                                request,
                                dns_tx.clone(),
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
                        continue;
                    }
                    if let Some(request) = parse_udp_request_for_agent_tunnel(packet) {
                        let udp_transport = data_plane.caps().udp_associations.then(|| {
                            let label = data_plane
                                .udp_label()
                                .expect("UDP-capable data plane must provide a UDP label");
                            UdpAssociationTransportPlan::new(label)
                        });
                        engine.plan_udp_datagram(
                            udp_transport,
                            request,
                            udp_events.clone(),
                            udp_association_idle_timeout,
                            &mut udp_actions,
                        );
                        udp::execute_ingress_actions(engine, &data_plane, &mut udp_actions);
                        continue;
                    }

                    engine
                        .ingest_tcp_packet(packet)
                        .context("failed to feed packet into userspace TCP engine")?;
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.plan_bridge_starts(
                        data_plane.admission_limits(),
                        &mut tcp_bridge_starts,
                    )?;
                    tcp::execute_bridge_starts(
                        engine,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        &event_tx,
                        &bridge_event_accounting,
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.flush_remote_backlogs()?;
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.expire_and_prune()?;
                }
                event = dns_rx.recv() => {
                    if let Some(event) = event {
                        engine.complete_dns();
                        let remote_ok = event.result.is_ok();
                        let tun_write = tun.write_dns_event(event).await?;
                        engine.record_dns_delivery(remote_ok, tun_write);
                    }
                }
                event = udp_response_rx.recv() => {
                    if let Some(event) = event {
                        let tun_write = tun.write_udp_response(event.key, event.payload).await?;
                        engine.record_udp_delivery(tun_write);
                    }
                }
                event = udp_close_rx.recv() => {
                    if let Some(event) = event {
                        engine.close_udp_association(event.key);
                        if let Some(error) = event.error {
                            eprintln!(
                                "udp: association {}:{} -> {}:{} closed with error: {error}",
                                event.key.src_ip,
                                event.key.src_port,
                                event.key.dst_ip,
                                event.key.dst_port,
                            );
                            engine.record_udp_close_error();
                        }
                    }
                }
                event = event_rx.recv(), if !engine.should_pause_bridge_events() => {
                    let Some(event) = event else {
                        bail!("SSH bridge event channel closed");
                    };
                    events::handle_bridge_event_batch(
                        engine,
                        event,
                        &mut event_rx,
                        &bridge_event_accounting,
                    )?;
                    engine.poll_tcp();
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.expire_and_prune()?;
                }
                _ = stats_tick.tick() => {
                    eprintln!(
                        "stats: {}",
                        engine.status_line(
                            data_plane.snapshot().await,
                            bridge_event_accounting.snapshot(),
                        )
                    );
                }
                _ = tick.tick() => {
                    engine.poll_tcp();
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.flush_remote_backlogs()?;
                    tun::write_engine_packets(&tun, engine).await?;
                    engine.plan_bridge_starts(
                        data_plane.admission_limits(),
                        &mut tcp_bridge_starts,
                    )?;
                    tcp::execute_bridge_starts(
                        engine,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        &event_tx,
                        &bridge_event_accounting,
                    )?;
                    engine.drain_local_bytes_to_bridges()?;
                    engine.expire_and_prune()?;
                }
            }
        }
    }
}
