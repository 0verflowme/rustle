use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::data_plane::DataPlane;
use crate::packet_engine::{
    parse_udp_request_for_agent_tunnel, tun_ipv4_packet, TcpBridgeHandles, TunnelEngine,
    UdpAssociationTransportPlan, MAX_ACTIVE_UDP_ASSOCIATIONS, MAX_IN_FLIGHT_DNS_QUERIES,
    PACKET_BUF_SIZE,
};
use crate::transport_model::{Destination, UdpAssociationEvents};
use crate::tun_io::TunWriter;
use crate::{flow_bridge, tcp_core};

mod dns;
mod events;
pub(crate) mod lifecycle;
mod prepare;
#[cfg(test)]
mod prepare_tests;
mod tcp;
mod tun;
mod udp;

pub(crate) use prepare::run_tunnel;

use lifecycle::ShutdownSignal;

const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct TunnelSupervisor {
    dev: tun_rs::AsyncDevice,
    engine: TunnelEngine,
    tcp_bridges: TcpBridgeHandles,
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
            tcp_bridges: TcpBridgeHandles::default(),
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
            tcp_bridges,
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
        let bridge_event_accounting = flow_bridge::BridgeEventAccounting::new();
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
                            tcp_bridges.len(),
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
                    if dns::execute_ingress_packet(
                        engine,
                        &tun,
                        &data_plane,
                        &dns_remote,
                        &dns_tx,
                        packet,
                    )
                    .await?
                    {
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

                    tcp::execute_ingress_packet(
                        engine,
                        &tun,
                        packet,
                        tcp_bridges,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        tcp::BridgeEventSink::new(&event_tx, &bridge_event_accounting),
                    )
                    .await?;
                }
                event = dns_rx.recv() => {
                    if let Some(event) = event {
                        dns::execute_response_event(engine, &tun, event).await?;
                    }
                }
                event = udp_response_rx.recv() => {
                    if let Some(event) = event {
                        udp::execute_response_event(engine, &tun, event).await?;
                    }
                }
                event = udp_close_rx.recv() => {
                    if let Some(event) = event {
                        udp::execute_close_event(engine, event);
                    }
                }
                event = event_rx.recv(), if !engine.should_pause_bridge_events() => {
                    let Some(event) = event else {
                        bail!("bridge event channel closed");
                    };
                    events::handle_bridge_event_batch(
                        engine,
                        event,
                        &mut event_rx,
                        tcp_bridges,
                        &bridge_event_accounting,
                    )?;
                    tcp::execute_bridge_event_cycle(engine, tcp_bridges, &tun).await?;
                }
                _ = stats_tick.tick() => {
                    eprintln!(
                        "stats: {}",
                        engine.status_line(
                            tcp_bridges.len(),
                            data_plane.snapshot().await,
                            bridge_event_accounting.snapshot(),
                        )
                    );
                }
                _ = tick.tick() => {
                    tcp::execute_tick_cycle(
                        engine,
                        &tun,
                        tcp_bridges,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        tcp::BridgeEventSink::new(&event_tx, &bridge_event_accounting),
                    ).await?;
                }
            }
        }
    }
}
