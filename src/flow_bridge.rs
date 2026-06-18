use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::tcp_core::FlowId;

pub const FLOW_CHANNEL_DEPTH: usize = 64;
pub const FLOW_CHANNEL_BYTES: usize = 128 * 1024;
pub const DIRECT_TCPIP_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
pub const AGENT_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
pub const BRIDGE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
pub const BRIDGE_EVENT_SEND_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub struct FlowBridge {
    pub id: FlowId,
    local_tx: mpsc::Sender<QueuedLocalData>,
    task: tokio::task::JoinHandle<()>,
    queued_local_bytes: Arc<AtomicUsize>,
    max_local_queue_bytes: usize,
}

impl FlowBridge {
    pub fn local_queue_capacity(&self) -> usize {
        self.local_tx.capacity()
    }

    pub fn local_queue_remaining_bytes(&self) -> usize {
        self.max_local_queue_bytes
            .saturating_sub(self.local_queue_bytes())
    }

    pub fn local_queue_bytes(&self) -> usize {
        self.queued_local_bytes.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn try_send_local_data(&self, bytes: impl Into<Bytes>) -> Result<bool> {
        self.try_send_local_data_with_metrics(bytes, None)
    }

    pub fn try_send_local_data_with_metrics(
        &self,
        bytes: impl Into<Bytes>,
        tcp_recv_queue_wait_us: Option<u64>,
    ) -> Result<bool> {
        let bytes = bytes.into();
        let queued = match QueuedLocalData::try_new(
            bytes,
            Arc::clone(&self.queued_local_bytes),
            self.max_local_queue_bytes,
            tcp_recv_queue_wait_us,
        ) {
            Some(queued) => queued,
            None => return Ok(false),
        };

        match self.local_tx.try_send(queued) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(_)) => Ok(false),
            Err(TrySendError::Closed(_)) => {
                anyhow::bail!("bridge local channel is closed")
            }
        }
    }
}

impl Drop for FlowBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeFailurePhase {
    Open,
    Write,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    Opened {
        id: FlowId,
        open_ms: u64,
    },
    RemoteData {
        id: FlowId,
        bytes: Bytes,
    },
    RemoteEof {
        id: FlowId,
    },
    Closed {
        id: FlowId,
    },
    Failed {
        id: FlowId,
        phase: BridgeFailurePhase,
        message: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct BridgeEventAccounting {
    queued_remote_bytes: Arc<AtomicUsize>,
    max_queued_remote_bytes: Arc<AtomicUsize>,
}

impl BridgeEventAccounting {
    pub(crate) fn new() -> Self {
        Self {
            queued_remote_bytes: Arc::new(AtomicUsize::new(0)),
            max_queued_remote_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn snapshot(&self) -> BridgeEventQueueSnapshot {
        BridgeEventQueueSnapshot {
            remote_bytes: usize_to_u64(self.queued_remote_bytes.load(Ordering::Acquire)),
            remote_bytes_max: usize_to_u64(self.max_queued_remote_bytes.load(Ordering::Acquire)),
        }
    }

    pub(crate) fn record_dequeued(&self, event: &BridgeEvent) {
        self.record_dequeued_remote_bytes(remote_data_len(event));
    }

    fn record_queued_remote_bytes(&self, len: usize) {
        if len == 0 {
            return;
        }
        let queued = self
            .queued_remote_bytes
            .fetch_add(len, Ordering::AcqRel)
            .saturating_add(len);
        update_max(&self.max_queued_remote_bytes, queued);
    }

    fn record_dequeued_remote_bytes(&self, len: usize) {
        if len == 0 {
            return;
        }
        let _ =
            self.queued_remote_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(len))
                });
    }
}

impl Default for BridgeEventAccounting {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BridgeEventQueueSnapshot {
    pub(crate) remote_bytes: u64,
    pub(crate) remote_bytes_max: u64,
}

fn remote_data_len(event: &BridgeEvent) -> usize {
    match event {
        BridgeEvent::RemoteData { bytes, .. } => bytes.len(),
        _ => 0,
    }
}

fn update_max(max: &AtomicUsize, value: usize) {
    let mut current = max.load(Ordering::Acquire);
    while value > current {
        match max.compare_exchange_weak(current, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgeEventSendError {
    Closed,
    Timeout,
}

pub async fn send_bridge_event(event_tx: &mpsc::Sender<BridgeEvent>, event: BridgeEvent) -> bool {
    send_bridge_event_with_timeout(event_tx, event, BRIDGE_EVENT_SEND_TIMEOUT)
        .await
        .is_ok()
}

pub(crate) async fn send_bridge_event_accounted(
    event_tx: &mpsc::Sender<BridgeEvent>,
    accounting: &BridgeEventAccounting,
    event: BridgeEvent,
) -> bool {
    send_bridge_event_accounted_with_timeout(event_tx, accounting, event, BRIDGE_EVENT_SEND_TIMEOUT)
        .await
        .is_ok()
}

async fn send_bridge_event_with_timeout(
    event_tx: &mpsc::Sender<BridgeEvent>,
    event: BridgeEvent,
    timeout: Duration,
) -> std::result::Result<(), BridgeEventSendError> {
    match tokio::time::timeout(timeout, event_tx.send(event)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(BridgeEventSendError::Closed),
        Err(_) => Err(BridgeEventSendError::Timeout),
    }
}

async fn send_bridge_event_accounted_with_timeout(
    event_tx: &mpsc::Sender<BridgeEvent>,
    accounting: &BridgeEventAccounting,
    event: BridgeEvent,
    timeout: Duration,
) -> std::result::Result<(), BridgeEventSendError> {
    let remote_data_len = remote_data_len(&event);
    accounting.record_queued_remote_bytes(remote_data_len);
    let result = send_bridge_event_with_timeout(event_tx, event, timeout).await;
    if result.is_err() {
        accounting.record_dequeued_remote_bytes(remote_data_len);
    }
    result
}

#[derive(Debug)]
pub struct LocalDataReceiver {
    rx: mpsc::Receiver<QueuedLocalData>,
}

#[derive(Debug)]
pub struct ReceivedLocalData {
    pub bytes: Bytes,
    pub queue_wait_us: u128,
    pub tcp_recv_queue_wait_us: Option<u64>,
}

impl LocalDataReceiver {
    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv_with_metrics().await.map(|local| local.bytes)
    }

    pub async fn recv_with_metrics(&mut self) -> Option<ReceivedLocalData> {
        let mut queued = self.rx.recv().await?;
        let queue_wait_us = queued.enqueued_at.elapsed().as_micros();
        let tcp_recv_queue_wait_us = queued.tcp_recv_queue_wait_us;
        let bytes = queued.bytes.take()?;
        Some(ReceivedLocalData {
            bytes,
            queue_wait_us,
            tcp_recv_queue_wait_us,
        })
    }
}

#[derive(Debug)]
struct QueuedLocalData {
    bytes: Option<Bytes>,
    len: usize,
    enqueued_at: Instant,
    tcp_recv_queue_wait_us: Option<u64>,
    queued_bytes: Arc<AtomicUsize>,
}

impl QueuedLocalData {
    fn try_new(
        bytes: Bytes,
        queued_bytes: Arc<AtomicUsize>,
        max_queue_bytes: usize,
        tcp_recv_queue_wait_us: Option<u64>,
    ) -> Option<Self> {
        let len = bytes.len();
        let mut current = queued_bytes.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(len)?;
            if next > max_queue_bytes {
                return None;
            }
            match queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(Self {
                        bytes: Some(bytes),
                        len,
                        enqueued_at: Instant::now(),
                        tcp_recv_queue_wait_us,
                        queued_bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for QueuedLocalData {
    fn drop(&mut self) {
        self.queued_bytes.fetch_sub(self.len, Ordering::AcqRel);
    }
}

pub fn spawn_bridge_task<F, Fut>(
    id: FlowId,
    event_tx: mpsc::Sender<BridgeEvent>,
    run: F,
) -> FlowBridge
where
    F: FnOnce(FlowId, LocalDataReceiver, mpsc::Sender<BridgeEvent>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (local_tx, local_rx) = mpsc::channel(FLOW_CHANNEL_DEPTH);
    let queued_local_bytes = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run(id, LocalDataReceiver { rx: local_rx }, event_tx));
    FlowBridge {
        id,
        local_tx,
        task,
        queued_local_bytes,
        max_local_queue_bytes: FLOW_CHANNEL_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use smoltcp::iface::{Config, Interface, Route, SocketSet};
    use smoltcp::socket::tcp;
    use smoltcp::time::{Duration, Instant};
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::tcp_core::{FlowManager, FlowState, Ipv4NetParts, PacketQueueDevice};

    struct AbortReport(Option<oneshot::Sender<()>>);

    impl Drop for AbortReport {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    #[tokio::test]
    async fn fake_bridge_round_trips_flow_manager_stream_bytes() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let flow = crate::tcp_core::FlowKey::tcp(
            client_ip,
            client_port,
            Ipv4Addr::new(172, 16, 0, 9),
            destination_port,
        );

        let mut manager = FlowManager::new(
            tun_ip,
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        let (mut client_iface, mut client_device, mut client_sockets, client_handle) =
            synthetic_client(
                client_ip,
                tun_ip,
                destination,
                destination_port,
                client_port,
            );

        let (event_tx, mut event_rx) = mpsc::channel(128);
        let mut bridges = HashMap::<crate::tcp_core::FlowKey, FlowBridge>::new();
        let request = b"through bridge".to_vec();
        let response = b"remote:through bridge".to_vec();
        let mut client_sent = false;
        let mut client_received = Vec::new();
        let mut now = Instant::from_millis(0);

        for _ in 0..512 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);
            pump_manager_to_client(now, &mut manager, &mut client_device);

            for ready_id in manager.ready_to_bridge_flow_ids() {
                let ready_flow = ready_id.key;
                if bridges.contains_key(&ready_flow) {
                    continue;
                }

                manager
                    .mark_flow_state(ready_flow, FlowState::BridgeOpening)
                    .expect("mark bridge opening");
                let bridge = spawn_fake_remote(ready_id, event_tx.clone());
                bridges.insert(ready_flow, bridge);
            }

            {
                let client = client_sockets.get_mut::<tcp::Socket>(client_handle);
                if !client_sent && client.can_send() {
                    client.send_slice(&request).expect("client send");
                    client_sent = true;
                }
                if client.can_recv() {
                    let mut buf = [0_u8; 128];
                    let len = client.recv_slice(&mut buf).expect("client recv");
                    client_received.extend_from_slice(&buf[..len]);
                }
            }

            pump_client_to_manager(now, &mut client_device, &mut manager);

            for (flow, bytes) in manager.drain_flow_bytes(4096).expect("drain flow bytes") {
                if let Some(bridge) = bridges.get(&flow) {
                    assert!(
                        bridge
                            .try_send_local_data(bytes)
                            .expect("send local bytes to bridge"),
                        "test bridge queue should have capacity"
                    );
                }
            }

            while let Ok(event) = event_rx.try_recv() {
                match event {
                    BridgeEvent::Opened { id, .. } => manager
                        .mark_flow_state(id.key, FlowState::Relaying)
                        .expect("mark relaying"),
                    BridgeEvent::RemoteData { id, bytes } => {
                        manager
                            .send_flow_bytes(id.key, &bytes)
                            .expect("send remote bytes into flow");
                    }
                    BridgeEvent::RemoteEof { id }
                    | BridgeEvent::Closed { id }
                    | BridgeEvent::Failed { id, .. } => {
                        manager
                            .mark_flow_state(id.key, FlowState::Closed)
                            .expect("mark flow closed");
                    }
                }
            }

            pump_manager_to_client(now, &mut manager, &mut client_device);
            if client_received == response {
                break;
            }

            now += Duration::from_millis(1);
            tokio::task::yield_now().await;
        }

        assert!(client_sent, "client never sent request");
        assert_eq!(client_received, response);
        assert_eq!(
            manager
                .snapshots()
                .into_iter()
                .find(|snapshot| snapshot.key == flow)
                .map(|snapshot| snapshot.state),
            Some(FlowState::Relaying)
        );
    }

    #[tokio::test]
    async fn flow_bridge_rejects_local_bytes_over_byte_budget() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let bridge = spawn_bridge_task(id, event_tx, |_id, _local_rx, _event_tx| async move {
            std::future::pending::<()>().await;
        });

        assert!(!bridge
            .try_send_local_data(vec![0; FLOW_CHANNEL_BYTES + 1])
            .expect("oversized local bytes should be rejected cleanly"));
        assert_eq!(bridge.local_queue_bytes(), 0);
        assert_eq!(bridge.local_queue_remaining_bytes(), FLOW_CHANNEL_BYTES);
    }

    #[tokio::test]
    async fn flow_bridge_drop_aborts_owned_bridge_task() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (abort_tx, abort_rx) = oneshot::channel();
        let bridge = spawn_bridge_task(id, event_tx, move |_id, _local_rx, _event_tx| async move {
            let _report = AbortReport(Some(abort_tx));
            started_tx.send(()).expect("report bridge task start");
            std::future::pending::<()>().await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
            .await
            .expect("bridge task should start")
            .expect("start report should be delivered");
        drop(bridge);

        tokio::time::timeout(std::time::Duration::from_secs(1), abort_rx)
            .await
            .expect("bridge task should be aborted when handle is dropped")
            .expect("abort report should be delivered");
    }

    #[tokio::test]
    async fn flow_bridge_releases_local_byte_budget_after_recv() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (release_tx, release_rx) = oneshot::channel();
        let bridge = spawn_bridge_task(
            id,
            event_tx,
            move |_id, mut local_rx, _event_tx| async move {
                let _ = release_rx.await;
                let _ = local_rx.recv().await;
                std::future::pending::<()>().await;
            },
        );

        assert!(bridge
            .try_send_local_data(vec![1; 4096])
            .expect("queue local bytes"));
        assert_eq!(bridge.local_queue_bytes(), 4096);
        release_tx.send(()).expect("release receiver");

        for _ in 0..100 {
            if bridge.local_queue_bytes() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("bridge did not release queued byte accounting after recv");
    }

    #[tokio::test]
    async fn flow_bridge_carries_tcp_recv_queue_wait_metric() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (received_tx, received_rx) = oneshot::channel();
        let bridge = spawn_bridge_task(
            id,
            event_tx,
            move |_id, mut local_rx, _event_tx| async move {
                let received = local_rx
                    .recv_with_metrics()
                    .await
                    .expect("queued local data");
                received_tx.send(received).expect("report local data");
                std::future::pending::<()>().await;
            },
        );

        assert!(bridge
            .try_send_local_data_with_metrics(Bytes::from_static(b"request"), Some(12_345))
            .expect("queue local bytes"));

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), received_rx)
            .await
            .expect("local data should be received")
            .expect("local data report should succeed");
        assert_eq!(received.bytes, Bytes::from_static(b"request"));
        assert_eq!(received.tcp_recv_queue_wait_us, Some(12_345));
    }

    #[tokio::test]
    async fn bridge_event_send_times_out_when_supervisor_queue_is_full() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let (event_tx, mut event_rx) = mpsc::channel(1);
        event_tx
            .try_send(BridgeEvent::Opened { id, open_ms: 0 })
            .expect("prefill event queue");

        let result = send_bridge_event_with_timeout(
            &event_tx,
            BridgeEvent::Closed { id },
            std::time::Duration::from_millis(25),
        )
        .await;

        assert_eq!(result, Err(BridgeEventSendError::Timeout));
        assert_eq!(
            event_rx.try_recv().expect("prefilled event"),
            BridgeEvent::Opened { id, open_ms: 0 }
        );
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn accounted_bridge_event_tracks_remote_data_until_dequeue() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let accounting = BridgeEventAccounting::new();
        let (event_tx, mut event_rx) = mpsc::channel(1);

        assert!(
            send_bridge_event_accounted(
                &event_tx,
                &accounting,
                BridgeEvent::RemoteData {
                    id,
                    bytes: Bytes::from_static(b"remote payload"),
                },
            )
            .await
        );

        assert_eq!(accounting.snapshot().remote_bytes, 14);
        assert_eq!(accounting.snapshot().remote_bytes_max, 14);
        let event = event_rx.recv().await.expect("accounted event");
        accounting.record_dequeued(&event);
        assert_eq!(accounting.snapshot().remote_bytes, 0);
        assert_eq!(accounting.snapshot().remote_bytes_max, 14);
    }

    #[tokio::test]
    async fn accounted_bridge_event_releases_remote_data_on_send_timeout() {
        let flow = crate::tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let id = FlowId::new(flow, 1);
        let accounting = BridgeEventAccounting::new();
        let (event_tx, mut event_rx) = mpsc::channel(1);
        event_tx
            .try_send(BridgeEvent::Opened { id, open_ms: 0 })
            .expect("prefill event queue");

        let result = send_bridge_event_accounted_with_timeout(
            &event_tx,
            &accounting,
            BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"blocked remote payload"),
            },
            std::time::Duration::from_millis(25),
        )
        .await;

        assert_eq!(result, Err(BridgeEventSendError::Timeout));
        assert_eq!(accounting.snapshot().remote_bytes, 0);
        assert_eq!(accounting.snapshot().remote_bytes_max, 22);
        assert_eq!(
            event_rx.try_recv().expect("prefilled event"),
            BridgeEvent::Opened { id, open_ms: 0 }
        );
        assert!(event_rx.try_recv().is_err());
    }

    fn spawn_fake_remote(id: FlowId, event_tx: mpsc::Sender<BridgeEvent>) -> FlowBridge {
        spawn_bridge_task(id, event_tx, |id, mut local_rx, event_tx| async move {
            let _ = send_bridge_event(&event_tx, BridgeEvent::Opened { id, open_ms: 0 }).await;
            while let Some(bytes) = local_rx.recv().await {
                let mut response = b"remote:".to_vec();
                response.extend_from_slice(&bytes);
                if !send_bridge_event(
                    &event_tx,
                    BridgeEvent::RemoteData {
                        id,
                        bytes: response.into(),
                    },
                )
                .await
                {
                    break;
                }
            }
        })
    }

    fn synthetic_client(
        client_ip: Ipv4Addr,
        gateway: Ipv4Addr,
        destination: IpAddress,
        destination_port: u16,
        client_port: u16,
    ) -> (
        Interface,
        PacketQueueDevice,
        SocketSet<'static>,
        smoltcp::iface::SocketHandle,
    ) {
        let mut device = PacketQueueDevice::new(1300);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x4252_4944_4745;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(client_ip), 24))
                .unwrap();
        });
        iface.routes_mut().update(|routes| {
            routes
                .push(Route {
                    cidr: IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(172, 16, 0, 0), 16)),
                    via_router: IpAddress::from(gateway),
                    preferred_until: None,
                    expires_at: None,
                })
                .unwrap();
        });

        let mut sockets = SocketSet::new(vec![]);
        let client_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        ));
        sockets
            .get_mut::<tcp::Socket>(client_handle)
            .connect(
                iface.context(),
                (destination, destination_port),
                client_port,
            )
            .expect("client connect");

        (iface, device, sockets, client_handle)
    }

    fn pump_client_to_manager(
        now: Instant,
        client_device: &mut PacketQueueDevice,
        manager: &mut FlowManager,
    ) {
        for packet in client_device.drain_tx() {
            let response_packets = manager
                .ingest_packet(now, packet.as_ref())
                .expect("manager ingest");
            for response in response_packets {
                client_device
                    .inject(response.as_ref())
                    .expect("inject response");
            }
        }
    }

    fn pump_manager_to_client(
        now: Instant,
        manager: &mut FlowManager,
        client_device: &mut PacketQueueDevice,
    ) {
        for packet in manager.poll(now) {
            client_device
                .inject(packet.as_ref())
                .expect("inject packet");
        }
    }
}
