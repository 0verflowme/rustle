use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::mpsc;

use crate::data_plane::DataPlane;
use crate::packet_engine::{
    parse_udp_request_for_agent_tunnel, tun_ipv4_packet, TcpBridgeHandles, TcpBridgeStart,
    TunnelEngine, UdpAssociationTransportPlan, UdpIngressAction, MAX_ACTIVE_UDP_ASSOCIATIONS,
    MAX_IN_FLIGHT_DNS_QUERIES, PACKET_BUF_SIZE,
};
use crate::transport_model::{
    Destination, DnsResponseEvent, UdpAssociationEvents, UdpClosedEvent, UdpResponseEvent,
};
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
        let (event_tx, mut event_rx) = mpsc::channel(1024);
        let (dns_tx, mut dns_rx) = mpsc::channel(DNS_EVENT_CHANNEL_DEPTH);
        let (udp_response_tx, mut udp_response_rx) =
            mpsc::channel(UDP_RESPONSE_EVENT_CHANNEL_DEPTH);
        let (udp_close_tx, mut udp_close_rx) = mpsc::channel(UDP_CLOSE_EVENT_CHANNEL_DEPTH);
        let udp_events = UdpAssociationEvents {
            response_tx: udp_response_tx,
            close_tx: udp_close_tx,
        };
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let mut stats_tick = stats_interval();
        loop {
            tokio::select! {
                signal = shutdown.recv() => {
                    log_final_stats(
                        signal,
                        engine,
                        tcp_bridges,
                        &data_plane,
                        &bridge_event_accounting,
                    ).await?;
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
                    if execute_udp_ingress_packet(
                        engine,
                        &data_plane,
                        packet,
                        &udp_events,
                        udp_association_idle_timeout,
                        &mut udp_actions,
                    ) {
                        continue;
                    }

                    execute_tcp_ingress_packet(
                        engine,
                        &tun,
                        packet,
                        TcpBridgeRuntime {
                            tcp_bridges,
                            starts: &mut tcp_bridge_starts,
                            data_plane: &data_plane,
                            event_tx: &event_tx,
                            bridge_event_accounting: &bridge_event_accounting,
                        },
                    )
                    .await?;
                }
                event = dns_rx.recv() => {
                    execute_dns_response_event(engine, &tun, event).await?;
                }
                event = udp_response_rx.recv() => {
                    execute_udp_response_event(engine, &tun, event).await?;
                }
                event = udp_close_rx.recv() => {
                    execute_udp_close_event(engine, event);
                }
                event = event_rx.recv(), if !engine.should_pause_bridge_events() => {
                    execute_bridge_event(
                        engine,
                        event,
                        &mut event_rx,
                        tcp_bridges,
                        &bridge_event_accounting,
                        &tun,
                    ).await?;
                }
                _ = stats_tick.tick() => {
                    log_stats(engine, tcp_bridges, &data_plane, &bridge_event_accounting).await;
                }
                _ = tick.tick() => {
                    execute_tick(
                        engine,
                        &tun,
                        tcp_bridges,
                        &mut tcp_bridge_starts,
                        &data_plane,
                        &event_tx,
                        &bridge_event_accounting,
                    ).await?;
                }
            }
        }
    }
}

fn stats_interval() -> tokio::time::Interval {
    let mut stats_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + STATS_LOG_INTERVAL,
        STATS_LOG_INTERVAL,
    );
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    stats_tick
}

async fn log_final_stats(
    signal: Result<&'static str>,
    engine: &TunnelEngine,
    tcp_bridges: &TcpBridgeHandles,
    data_plane: &Arc<dyn DataPlane>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<()> {
    eprintln!("signal: {} received", signal?);
    eprintln!(
        "stats: final {}",
        status_line(engine, tcp_bridges, data_plane, bridge_event_accounting).await
    );
    Ok(())
}

async fn log_stats(
    engine: &TunnelEngine,
    tcp_bridges: &TcpBridgeHandles,
    data_plane: &Arc<dyn DataPlane>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) {
    eprintln!(
        "stats: {}",
        status_line(engine, tcp_bridges, data_plane, bridge_event_accounting).await
    );
}

async fn status_line(
    engine: &TunnelEngine,
    tcp_bridges: &TcpBridgeHandles,
    data_plane: &Arc<dyn DataPlane>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> String {
    engine.status_line(
        tcp_bridges.len(),
        data_plane.snapshot().await,
        bridge_event_accounting.snapshot(),
    )
}

fn execute_udp_ingress_packet(
    engine: &mut TunnelEngine,
    data_plane: &Arc<dyn DataPlane>,
    packet: &[u8],
    udp_events: &UdpAssociationEvents,
    udp_association_idle_timeout: Duration,
    udp_actions: &mut Vec<UdpIngressAction>,
) -> bool {
    let Some(request) = parse_udp_request_for_agent_tunnel(packet) else {
        return false;
    };

    engine.plan_udp_datagram(
        udp_transport(data_plane),
        request,
        udp_events.clone(),
        udp_association_idle_timeout,
        udp_actions,
    );
    udp::execute_ingress_actions(engine, data_plane, udp_actions);
    true
}

fn udp_transport(data_plane: &Arc<dyn DataPlane>) -> Option<UdpAssociationTransportPlan> {
    if !data_plane.caps().udp_associations {
        return None;
    }
    data_plane.udp_label().map(UdpAssociationTransportPlan::new)
}

struct TcpBridgeRuntime<'a> {
    tcp_bridges: &'a mut TcpBridgeHandles,
    starts: &'a mut Vec<TcpBridgeStart>,
    data_plane: &'a Arc<dyn DataPlane>,
    event_tx: &'a mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &'a flow_bridge::BridgeEventAccounting,
}

async fn execute_tcp_ingress_packet(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    packet: &[u8],
    runtime: TcpBridgeRuntime<'_>,
) -> Result<()> {
    tcp::execute_ingress_packet(
        engine,
        tun,
        packet,
        runtime.tcp_bridges,
        runtime.starts,
        runtime.data_plane,
        tcp::BridgeEventSink::new(runtime.event_tx, runtime.bridge_event_accounting),
    )
    .await
}

async fn execute_dns_response_event(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    event: Option<DnsResponseEvent>,
) -> Result<()> {
    if let Some(event) = event {
        dns::execute_response_event(engine, tun, event).await?;
    }
    Ok(())
}

async fn execute_udp_response_event(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    event: Option<UdpResponseEvent>,
) -> Result<()> {
    if let Some(event) = event {
        udp::execute_response_event(engine, tun, event).await?;
    }
    Ok(())
}

fn execute_udp_close_event(engine: &mut TunnelEngine, event: Option<UdpClosedEvent>) {
    if let Some(event) = event {
        udp::execute_close_event(engine, event);
    }
}

async fn execute_bridge_event(
    engine: &mut TunnelEngine,
    event: Option<flow_bridge::BridgeEvent>,
    event_rx: &mut mpsc::Receiver<flow_bridge::BridgeEvent>,
    tcp_bridges: &mut TcpBridgeHandles,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
    tun: &TunWriter<'_>,
) -> Result<()> {
    let Some(event) = event else {
        bail!("bridge event channel closed");
    };
    events::handle_bridge_event_batch(
        engine,
        event,
        event_rx,
        tcp_bridges,
        bridge_event_accounting,
    )?;
    tcp::execute_bridge_event_cycle(engine, tcp_bridges, tun).await
}

async fn execute_tick(
    engine: &mut TunnelEngine,
    tun: &TunWriter<'_>,
    tcp_bridges: &mut TcpBridgeHandles,
    starts: &mut Vec<TcpBridgeStart>,
    data_plane: &Arc<dyn DataPlane>,
    event_tx: &mpsc::Sender<flow_bridge::BridgeEvent>,
    bridge_event_accounting: &flow_bridge::BridgeEventAccounting,
) -> Result<()> {
    tcp::execute_tick_cycle(
        engine,
        tun,
        tcp_bridges,
        starts,
        data_plane,
        tcp::BridgeEventSink::new(event_tx, bridge_event_accounting),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::{DataPlaneSnapshotFuture, OpenTcpFuture, OpenUdpFuture};
    use crate::transport_model::{
        BridgeAdmissionLimits, DataPlaneCaps, DataPlaneIpv4Open, DataPlaneRuntimeSnapshot,
        DataPlaneTcpOpen, DataPlaneTcpOpenMode,
    };

    struct FakeDataPlane {
        udp_associations: bool,
        udp_label: Option<&'static str>,
    }

    impl DataPlane for FakeDataPlane {
        fn label(&self) -> &'static str {
            "fake"
        }

        fn udp_label(&self) -> Option<&'static str> {
            self.udp_label
        }

        fn caps(&self) -> DataPlaneCaps {
            DataPlaneCaps {
                udp_associations: self.udp_associations,
            }
        }

        fn admission_limits(&self) -> BridgeAdmissionLimits {
            BridgeAdmissionLimits::agent()
        }

        fn snapshot(&self) -> DataPlaneSnapshotFuture<'_> {
            Box::pin(async { DataPlaneRuntimeSnapshot::default() })
        }

        fn open_tcp(
            &self,
            _open: DataPlaneTcpOpen,
            _mode: DataPlaneTcpOpenMode,
        ) -> OpenTcpFuture<'static> {
            Box::pin(async { panic!("fake data plane open_tcp should not be called") })
        }

        fn open_udp_ipv4(&self, _open: DataPlaneIpv4Open) -> OpenUdpFuture<'static> {
            Box::pin(async { panic!("fake data plane open_udp_ipv4 should not be called") })
        }
    }

    #[test]
    fn udp_transport_returns_expected_label_for_udp_capable_data_plane() {
        let data_plane: Arc<dyn DataPlane> = Arc::new(FakeDataPlane {
            udp_associations: true,
            udp_label: Some("fake-udp"),
        });

        let transport =
            udp_transport(&data_plane).expect("UDP-capable data plane should plan UDP transport");

        assert_eq!("fake-udp", transport.label);
    }

    #[test]
    fn udp_transport_returns_none_for_non_udp_data_plane() {
        let data_plane: Arc<dyn DataPlane> = Arc::new(FakeDataPlane {
            udp_associations: false,
            udp_label: Some("ignored-udp"),
        });

        assert!(udp_transport(&data_plane).is_none());
    }
}
