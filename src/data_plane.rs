use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::transport_model::{
    BridgeAdmissionLimits, DataPlaneCaps, DataPlaneIpv4Open, DataPlaneRuntimeSnapshot,
    DataPlaneTcpOpen, DataPlaneTcpOpenMode, UdpAssociationEvents, UdpFlowKey,
};
use crate::{ssh_bridge, tcp_core};

mod adapters;
#[cfg(test)]
mod contract_tests;
mod dns;
mod stream;
mod tcp;
#[cfg(test)]
mod test_support;
mod udp;

pub(crate) use adapters::{DirectTcpipDataPlane, FramedAgentDataPlane, QuicNativeDataPlane};
pub(crate) use dns::{query_dns_on_data_plane, spawn_dns_query_on_data_plane};
use stream::AgentIoStream;
use tcp::spawn_data_plane_tcp_bridge_with_open;

pub(crate) type DataPlaneSnapshotFuture<'a> =
    Pin<Box<dyn Future<Output = DataPlaneRuntimeSnapshot> + Send + 'a>>;
pub(crate) type OpenTcpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentIoStream>> + Send + 'a>>;
pub(crate) type OpenUdpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentIoStream>> + Send + 'a>>;

pub(crate) trait DataPlane: Send + Sync {
    fn label(&self) -> &'static str;
    fn udp_label(&self) -> Option<&'static str>;
    fn caps(&self) -> DataPlaneCaps;
    fn admission_limits(&self) -> BridgeAdmissionLimits;
    fn snapshot(&self) -> DataPlaneSnapshotFuture<'_>;
    fn open_tcp(
        &self,
        open: DataPlaneTcpOpen,
        mode: DataPlaneTcpOpenMode,
    ) -> OpenTcpFuture<'static>;
    fn open_udp_ipv4(&self, open: DataPlaneIpv4Open) -> OpenUdpFuture<'static>;
}

pub(crate) fn spawn_tcp_bridge_on_data_plane(
    data_plane: Arc<dyn DataPlane>,
    id: tcp_core::FlowId,
    ready_wait_ms: u64,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    event_accounting: ssh_bridge::BridgeEventAccounting,
) -> ssh_bridge::FlowBridge {
    let flow = id.key;
    let label = data_plane.udp_label().unwrap_or_else(|| data_plane.label());
    if data_plane.caps().udp_associations {
        eprintln!(
            "{label}: opening stream {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
    } else {
        eprintln!(
            "ssh: opening direct-tcpip {}:{} for local {}:{} generation={}",
            flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
        );
    }
    let open = DataPlaneIpv4Open {
        destination_ip: flow.dst_ip,
        destination_port: flow.dst_port,
        originator_ip: flow.src_ip,
        originator_port: flow.src_port,
        flow_generation: Some(id.generation),
    };
    spawn_data_plane_tcp_bridge_with_open(
        id,
        event_tx,
        event_accounting,
        ready_wait_ms,
        label,
        data_plane.open_tcp(
            DataPlaneTcpOpen::Ipv4(open),
            DataPlaneTcpOpenMode::Optimistic,
        ),
    )
}

pub(crate) fn spawn_udp_association(
    open_stream: OpenUdpFuture<'static>,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) {
    udp::spawn_udp_association_with_idle_timeout(
        open_stream,
        key,
        from_local,
        events,
        idle_timeout,
    );
}
