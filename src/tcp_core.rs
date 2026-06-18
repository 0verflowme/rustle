use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::rc::Rc;

use anyhow::{bail, Context as AnyhowContext, Result};
use bytes::{Bytes, BytesMut};
use smoltcp::iface::{Config, Interface, Route, SocketHandle, SocketSet};
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, PacketMeta, RxToken, TxToken,
};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol as SmolIpProtocol, Ipv4Cidr, Ipv4Packet,
    TcpPacket,
};

pub const TCP_RECV_BUFFER_BYTES: usize = 64 * 1024;
pub const TCP_SEND_BUFFER_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_ACTIVE_FLOWS: usize = 1024;
pub const DEFAULT_FLOW_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_BRIDGE_OPEN_TIMEOUT: Duration = DEFAULT_FLOW_IDLE_TIMEOUT;
pub const PACKET_QUEUE_CAPACITY: usize = 256;
const PACKET_QUEUE_TX_RESERVE: usize = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: IpProtocol,
}

impl FlowKey {
    pub fn tcp(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol: IpProtocol::Tcp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId {
    pub key: FlowKey,
    pub generation: u64,
}

impl FlowId {
    pub fn new(key: FlowKey, generation: u64) -> Self {
        Self { key, generation }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpProtocol {
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowState {
    NewSyn,
    TcpHandshaking,
    TcpEstablished,
    BridgeOpening,
    Relaying,
    HalfClosedLocal,
    HalfClosedRemote,
    Reset,
    Closed,
}

pub fn new_flow_socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_RECV_BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER_BYTES]),
    );
    socket.set_ack_delay(None);
    socket.set_nagle_enabled(false);
    socket
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    pub fn is_opening_syn(self) -> bool {
        self.syn && !self.ack && !self.rst
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment {
    pub flow: FlowKey,
    pub flags: TcpFlags,
    pub payload_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketParseError {
    MalformedIpv4,
    MalformedTcp,
}

impl std::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedIpv4 => f.write_str("malformed IPv4 packet"),
            Self::MalformedTcp => f.write_str("malformed TCP packet"),
        }
    }
}

impl std::error::Error for PacketParseError {}

pub fn parse_ipv4_tcp_segment(packet: &[u8]) -> Result<Option<TcpSegment>, PacketParseError> {
    let ipv4 = Ipv4Packet::new_checked(packet).map_err(|_| PacketParseError::MalformedIpv4)?;
    if ipv4.next_header() != SmolIpProtocol::Tcp {
        return Ok(None);
    }

    let tcp = TcpPacket::new_checked(ipv4.payload()).map_err(|_| PacketParseError::MalformedTcp)?;
    let tcp_header_len = usize::from(tcp.header_len());
    Ok(Some(TcpSegment {
        flow: FlowKey::tcp(
            ipv4.src_addr(),
            tcp.src_port(),
            ipv4.dst_addr(),
            tcp.dst_port(),
        ),
        flags: TcpFlags {
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
        },
        payload_len: ipv4.payload().len().saturating_sub(tcp_header_len),
    }))
}

#[derive(Debug)]
pub struct FlowSnapshot {
    pub key: FlowKey,
    pub generation: u64,
    pub state: FlowState,
    pub buffered_rx: usize,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub local_to_remote_bytes: u64,
    pub remote_to_local_bytes: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlowBytes {
    pub bytes: Bytes,
    pub tcp_recv_queue_wait_us: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowPolicy {
    pub max_active_flows: usize,
    pub opening_timeout: Duration,
    pub bridge_open_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for FlowPolicy {
    fn default() -> Self {
        Self {
            max_active_flows: DEFAULT_MAX_ACTIVE_FLOWS,
            opening_timeout: DEFAULT_FLOW_OPEN_TIMEOUT,
            bridge_open_timeout: DEFAULT_BRIDGE_OPEN_TIMEOUT,
            idle_timeout: DEFAULT_FLOW_IDLE_TIMEOUT,
        }
    }
}

#[derive(Debug)]
struct FlowEntry {
    generation: u64,
    handle: SocketHandle,
    state: FlowState,
    created_at: Instant,
    state_since: Instant,
    last_activity: Instant,
    local_to_remote_bytes: u64,
    remote_to_local_bytes: u64,
    local_payload_buffered_since: Option<Instant>,
}

pub struct FlowManager {
    iface: Interface,
    device: PacketQueueDevice,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowKey, FlowEntry>,
    next_flow_generation: u64,
    policy: FlowPolicy,
}

impl FlowManager {
    pub fn new(
        tun_ip: Ipv4Addr,
        tun_prefix: u8,
        route_cidrs: &[Ipv4NetParts],
        mtu: usize,
    ) -> Result<Self> {
        Self::with_policy(tun_ip, tun_prefix, route_cidrs, mtu, FlowPolicy::default())
    }

    pub fn with_policy(
        tun_ip: Ipv4Addr,
        tun_prefix: u8,
        route_cidrs: &[Ipv4NetParts],
        mtu: usize,
        policy: FlowPolicy,
    ) -> Result<Self> {
        if route_cidrs.is_empty() {
            bail!("at least one target route is required");
        }
        if policy.max_active_flows == 0 {
            bail!("max_active_flows must be greater than zero");
        }
        if policy.opening_timeout == Duration::ZERO {
            bail!("opening_timeout must be greater than zero");
        }
        if policy.bridge_open_timeout == Duration::ZERO {
            bail!("bridge_open_timeout must be greater than zero");
        }
        if policy.idle_timeout == Duration::ZERO {
            bail!("idle_timeout must be greater than zero");
        }

        let mut device = PacketQueueDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5255_5354_4c45;

        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        let mut ip_addr_inserted = true;
        iface.update_ip_addrs(|ip_addrs| {
            ip_addr_inserted = ip_addrs
                .push(IpCidr::new(IpAddress::from(tun_ip), tun_prefix))
                .is_ok();
        });
        if !ip_addr_inserted {
            bail!("failed to add TUN IP address to smoltcp interface");
        }
        let mut route_error = None;
        iface.routes_mut().update(|routes| {
            for route_cidr in route_cidrs {
                if routes
                    .push(Route {
                        cidr: IpCidr::Ipv4(Ipv4Cidr::new(
                            route_cidr.network,
                            route_cidr.prefix_len,
                        )),
                        via_router: IpAddress::from(tun_ip),
                        preferred_until: None,
                        expires_at: None,
                    })
                    .is_err()
                {
                    route_error = Some(route_cidrs.len());
                    break;
                }
            }
        });
        if let Some(route_count) = route_error {
            bail!(
                "too many target routes for smoltcp route table: {route_count} requested, maximum is {}",
                smoltcp::config::IFACE_MAX_ROUTE_COUNT
            );
        }
        iface.set_any_ip(true);

        Ok(Self {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            next_flow_generation: 1,
            policy,
        })
    }

    pub fn ingest_packet(&mut self, now: Instant, packet: &[u8]) -> Result<Vec<PacketBuf>> {
        let mut outbound = Vec::new();
        self.ingest_packet_into(now, packet, &mut outbound)?;
        Ok(outbound)
    }

    pub fn ingest_packet_into(
        &mut self,
        now: Instant,
        packet: &[u8],
        outbound: &mut Vec<PacketBuf>,
    ) -> Result<()> {
        self.track_packet_flow(now, packet)?;
        self.device.inject(packet)?;
        self.poll_into(now, outbound);
        Ok(())
    }

    pub fn poll(&mut self, now: Instant) -> Vec<PacketBuf> {
        let mut outbound = Vec::new();
        self.poll_into(now, &mut outbound);
        outbound
    }

    pub fn poll_into(&mut self, now: Instant, outbound: &mut Vec<PacketBuf>) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.refresh_flow_states(now);
        self.refresh_local_payload_buffer_markers(now);
        self.device.drain_tx_into(outbound);
    }

    pub fn recv_flow_bytes(&mut self, flow: FlowKey, max_len: usize) -> Result<Bytes> {
        Ok(self.recv_flow_bytes_inner(flow, max_len, None)?.bytes)
    }

    pub fn recv_flow_bytes_with_metrics(
        &mut self,
        flow: FlowKey,
        max_len: usize,
        now: Instant,
    ) -> Result<FlowBytes> {
        self.recv_flow_bytes_inner(flow, max_len, Some(now))
    }

    fn recv_flow_bytes_inner(
        &mut self,
        flow: FlowKey,
        max_len: usize,
        now: Option<Instant>,
    ) -> Result<FlowBytes> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        let handle = entry.handle;
        let buffered_since = entry.local_payload_buffered_since;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if max_len == 0 || !socket.can_recv() {
            return Ok(FlowBytes {
                bytes: Bytes::new(),
                tcp_recv_queue_wait_us: None,
            });
        }

        let bytes = socket
            .recv(|data| {
                let len = data.len().min(max_len);
                (len, Bytes::copy_from_slice(&data[..len]))
            })
            .context("failed to receive flow bytes")?;
        let remaining = socket.recv_queue();
        let tcp_recv_queue_wait_us = if bytes.is_empty() {
            None
        } else {
            now.and_then(|now| {
                buffered_since.map(|since| {
                    let elapsed = now - since;
                    elapsed.total_micros()
                })
            })
        };
        if !bytes.is_empty() {
            if let Some(entry) = self.flows.get_mut(&flow) {
                entry.local_to_remote_bytes = entry
                    .local_to_remote_bytes
                    .saturating_add(bytes.len() as u64);
                if remaining == 0 {
                    entry.local_payload_buffered_since = None;
                } else if entry.local_payload_buffered_since.is_none() {
                    entry.local_payload_buffered_since = now;
                }
            }
        }
        Ok(FlowBytes {
            bytes,
            tcp_recv_queue_wait_us,
        })
    }

    pub fn send_flow_bytes(&mut self, flow: FlowKey, bytes: &[u8]) -> Result<usize> {
        self.send_flow_bytes_inner(flow, bytes, None)
    }

    pub fn send_flow_bytes_at(
        &mut self,
        flow: FlowKey,
        bytes: &[u8],
        now: Instant,
    ) -> Result<usize> {
        self.send_flow_bytes_inner(flow, bytes, Some(now))
    }

    fn send_flow_bytes_inner(
        &mut self,
        flow: FlowKey,
        bytes: &[u8],
        now: Option<Instant>,
    ) -> Result<usize> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        let handle = entry.handle;
        let len = self
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(bytes)
            .context("failed to enqueue flow bytes")?;
        if len > 0 {
            self.touch_remote_to_local(flow, len, now);
        }
        Ok(len)
    }

    pub fn try_send_flow_bytes(&mut self, flow: FlowKey, bytes: &[u8]) -> Result<Option<usize>> {
        self.try_send_flow_bytes_inner(flow, bytes, None)
    }

    pub fn try_send_flow_bytes_at(
        &mut self,
        flow: FlowKey,
        bytes: &[u8],
        now: Instant,
    ) -> Result<Option<usize>> {
        self.try_send_flow_bytes_inner(flow, bytes, Some(now))
    }

    fn try_send_flow_bytes_inner(
        &mut self,
        flow: FlowKey,
        bytes: &[u8],
        now: Option<Instant>,
    ) -> Result<Option<usize>> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        let handle = entry.handle;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.may_send() {
            return Ok(None);
        }

        match socket.send_slice(bytes) {
            Ok(len) => {
                if len > 0 {
                    self.touch_remote_to_local(flow, len, now);
                }
                Ok(Some(len))
            }
            Err(tcp::SendError::InvalidState) => Ok(None),
        }
    }

    pub fn snapshots(&self) -> Vec<FlowSnapshot> {
        let mut snapshots = Vec::with_capacity(self.flows.len());
        for (&key, entry) in &self.flows {
            let socket = self.sockets.get::<tcp::Socket>(entry.handle);
            snapshots.push(FlowSnapshot {
                key,
                generation: entry.generation,
                state: entry.state,
                buffered_rx: socket.recv_queue(),
                created_at: entry.created_at,
                last_activity: entry.last_activity,
                local_to_remote_bytes: entry.local_to_remote_bytes,
                remote_to_local_bytes: entry.remote_to_local_bytes,
            });
        }
        snapshots
    }

    pub fn opening_flow_count(&self) -> usize {
        self.flows
            .values()
            .filter(|entry| entry.state == FlowState::BridgeOpening)
            .count()
    }

    pub fn opening_flow_keys_into(&self, out: &mut Vec<FlowKey>) {
        out.clear();
        out.reserve(self.flows.len());
        out.extend(
            self.flows.iter().filter_map(|(&key, entry)| {
                (entry.state == FlowState::BridgeOpening).then_some(key)
            }),
        );
    }

    pub fn flow_keys(&self) -> Vec<FlowKey> {
        let mut keys = Vec::with_capacity(self.flows.len());
        self.flow_keys_into(&mut keys);
        keys
    }

    pub fn flow_keys_into(&self, out: &mut Vec<FlowKey>) {
        out.clear();
        out.reserve(self.flows.len());
        out.extend(self.flows.keys().copied());
    }

    pub fn recv_queue_len(&self, flow: FlowKey) -> Result<usize> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        Ok(self.sockets.get::<tcp::Socket>(entry.handle).recv_queue())
    }

    pub fn ready_to_bridge_flows(&self) -> Vec<FlowKey> {
        let mut flows = Vec::with_capacity(self.flows.len());
        flows.extend(
            self.flows.iter().filter_map(|(&key, entry)| {
                (entry.state == FlowState::TcpEstablished).then_some(key)
            }),
        );
        flows
    }

    pub fn ready_to_bridge_flow_ids(&self) -> Vec<FlowId> {
        let mut ids = Vec::with_capacity(self.flows.len());
        self.ready_to_bridge_flow_ids_into(&mut ids);
        ids
    }

    pub fn ready_to_bridge_flow_ids_into(&self, out: &mut Vec<FlowId>) {
        out.clear();
        out.reserve(self.flows.len());
        out.extend(self.flows.iter().filter_map(|(&key, entry)| {
            (entry.state == FlowState::TcpEstablished).then_some(FlowId::new(key, entry.generation))
        }));
    }

    pub fn contains_flow(&self, flow: FlowKey) -> bool {
        self.flows.contains_key(&flow)
    }

    pub fn contains_flow_id(&self, id: FlowId) -> bool {
        self.flows
            .get(&id.key)
            .is_some_and(|entry| entry.generation == id.generation)
    }

    pub fn flow_id(&self, flow: FlowKey) -> Result<FlowId> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        Ok(FlowId::new(flow, entry.generation))
    }

    pub fn flow_state(&self, flow: FlowKey) -> Result<FlowState> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        Ok(entry.state)
    }

    pub fn flow_state_elapsed_ms(&self, flow: FlowKey, now: Instant) -> Result<u64> {
        let Some(entry) = self.flows.get(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        Ok((now - entry.state_since).total_millis())
    }

    pub fn mark_flow_state(&mut self, flow: FlowKey, state: FlowState) -> Result<()> {
        let Some(entry) = self.flows.get_mut(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        if entry.state != state {
            entry.state = state;
            entry.state_since = entry.last_activity;
        }
        Ok(())
    }

    pub fn mark_flow_state_at(
        &mut self,
        flow: FlowKey,
        state: FlowState,
        now: Instant,
    ) -> Result<()> {
        let Some(entry) = self.flows.get_mut(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        if entry.state != state {
            entry.state = state;
            entry.state_since = now;
        }
        Ok(())
    }

    pub fn close_flow(&mut self, flow: FlowKey, state: FlowState) -> Result<()> {
        let Some(entry) = self.flows.get_mut(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        self.sockets.get_mut::<tcp::Socket>(entry.handle).close();
        entry.state = state;
        entry.state_since = entry.last_activity;
        Ok(())
    }

    pub fn abort_flow(&mut self, flow: FlowKey) -> Result<()> {
        let Some(entry) = self.flows.get_mut(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        self.sockets.get_mut::<tcp::Socket>(entry.handle).abort();
        entry.state = FlowState::Reset;
        entry.state_since = entry.last_activity;
        Ok(())
    }

    pub fn removable_flows(&self) -> Vec<FlowKey> {
        let mut flows = Vec::with_capacity(self.flows.len());
        self.removable_flows_into(&mut flows);
        flows
    }

    pub fn removable_flows_into(&self, out: &mut Vec<FlowKey>) {
        out.clear();
        out.reserve(self.flows.len());
        out.extend(self.flows.iter().filter_map(|(&key, entry)| {
            let socket = self.sockets.get::<tcp::Socket>(entry.handle);
            let terminal = matches!(entry.state, FlowState::Closed | FlowState::Reset);
            (terminal && !socket.is_open()).then_some(key)
        }));
    }

    pub fn remove_flow(&mut self, flow: FlowKey) -> Result<()> {
        let Some(entry) = self.flows.remove(&flow) else {
            bail!("flow {flow:?} does not exist");
        };
        self.sockets.remove(entry.handle);
        Ok(())
    }

    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn policy(&self) -> FlowPolicy {
        self.policy
    }

    pub fn expire_stale_flows(&mut self, now: Instant) -> Vec<FlowKey> {
        let mut expired = Vec::with_capacity(self.flows.len());
        self.expire_stale_flows_into(now, &mut expired);
        expired
    }

    pub fn expire_stale_flows_into(&mut self, now: Instant, out: &mut Vec<FlowKey>) {
        out.clear();
        out.reserve(self.flows.len());
        out.extend(self.flows.iter().filter_map(|(&flow, entry)| {
            let opening_expired = match entry.state {
                FlowState::NewSyn | FlowState::TcpHandshaking => {
                    now - entry.state_since >= self.policy.opening_timeout
                }
                FlowState::BridgeOpening => {
                    now - entry.state_since >= self.policy.bridge_open_timeout
                }
                _ => false,
            };
            let idle_expired = matches!(
                entry.state,
                FlowState::TcpEstablished
                    | FlowState::Relaying
                    | FlowState::HalfClosedLocal
                    | FlowState::HalfClosedRemote
            ) && now - entry.last_activity >= self.policy.idle_timeout;
            (opening_expired || idle_expired).then_some(flow)
        }));

        for flow in out.iter() {
            if let Some(entry) = self.flows.get_mut(flow) {
                self.sockets.get_mut::<tcp::Socket>(entry.handle).abort();
                entry.state = FlowState::Reset;
                entry.state_since = now;
                entry.last_activity = now;
            }
        }
    }

    pub fn drain_flow_bytes(&mut self, max_len_per_flow: usize) -> Result<Vec<(FlowKey, Bytes)>> {
        let flows: Vec<_> = self.flows.keys().copied().collect();
        let mut chunks = Vec::new();
        for flow in flows {
            let bytes = self.recv_flow_bytes(flow, max_len_per_flow)?;
            if !bytes.is_empty() {
                chunks.push((flow, bytes));
            }
        }
        Ok(chunks)
    }

    fn track_packet_flow(&mut self, now: Instant, packet: &[u8]) -> Result<()> {
        let Some(segment) =
            parse_ipv4_tcp_segment(packet).context("failed to inspect TCP packet")?
        else {
            return Ok(());
        };

        if let Some(entry) = self.flows.get_mut(&segment.flow) {
            entry.last_activity = now;
            return Ok(());
        }

        if !segment.flags.is_opening_syn() {
            return Ok(());
        }

        if self.flows.len() >= self.policy.max_active_flows {
            return Ok(());
        }

        let generation = self.next_flow_generation;
        self.next_flow_generation = self
            .next_flow_generation
            .checked_add(1)
            .context("flow generation counter exhausted")?;

        let mut socket = new_flow_socket();
        socket.set_timeout(Some(self.policy.idle_timeout));
        socket
            .listen((IpAddress::from(segment.flow.dst_ip), segment.flow.dst_port))
            .context("failed to listen for dynamic intercepted flow")?;
        let handle = self.sockets.add(socket);
        self.flows.insert(
            segment.flow,
            FlowEntry {
                generation,
                handle,
                state: FlowState::TcpHandshaking,
                created_at: now,
                state_since: now,
                last_activity: now,
                local_to_remote_bytes: 0,
                remote_to_local_bytes: 0,
                local_payload_buffered_since: None,
            },
        );
        Ok(())
    }

    fn refresh_flow_states(&mut self, now: Instant) {
        for entry in self.flows.values_mut() {
            let socket = self.sockets.get::<tcp::Socket>(entry.handle);
            if socket.may_send() && socket.may_recv() {
                if matches!(entry.state, FlowState::TcpHandshaking | FlowState::NewSyn) {
                    entry.state = FlowState::TcpEstablished;
                    entry.state_since = now;
                }
            } else if !socket.is_open() {
                entry.state = FlowState::Closed;
                entry.state_since = now;
                entry.last_activity = now;
            }
        }
    }

    fn touch_remote_to_local(&mut self, flow: FlowKey, len: usize, now: Option<Instant>) {
        if let Some(entry) = self.flows.get_mut(&flow) {
            if let Some(now) = now {
                entry.last_activity = now;
            }
            entry.remote_to_local_bytes = entry.remote_to_local_bytes.saturating_add(len as u64);
        }
    }

    fn refresh_local_payload_buffer_markers(&mut self, now: Instant) {
        for entry in self.flows.values_mut() {
            let recv_queue = self.sockets.get::<tcp::Socket>(entry.handle).recv_queue();
            if recv_queue == 0 {
                entry.local_payload_buffered_since = None;
            } else if entry.local_payload_buffered_since.is_none() {
                entry.local_payload_buffered_since = Some(now);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4NetParts {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4NetParts {
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len,
        }
    }
}

#[derive(Clone)]
pub struct PacketQueueDevice {
    inner: Rc<RefCell<PacketQueues>>,
    mtu: usize,
}

#[derive(Default)]
struct PacketQueues {
    rx: VecDeque<BytesMut>,
    tx: VecDeque<BytesMut>,
    free: VecDeque<BytesMut>,
}

impl PacketQueues {
    fn with_capacity(mtu: usize, capacity: usize) -> Self {
        let mut free = VecDeque::with_capacity(capacity);
        for _ in 0..capacity {
            free.push_back(BytesMut::with_capacity(mtu));
        }
        Self {
            rx: VecDeque::with_capacity(capacity),
            tx: VecDeque::with_capacity(capacity),
            free,
        }
    }

    fn take_buffer(&mut self) -> Option<BytesMut> {
        self.free.pop_front()
    }

    fn recycle(&mut self, mut packet: BytesMut) {
        packet.clear();
        self.free.push_back(packet);
    }
}

impl PacketQueueDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            inner: Rc::new(RefCell::new(PacketQueues::with_capacity(
                mtu,
                PACKET_QUEUE_CAPACITY,
            ))),
            mtu,
        }
    }

    pub fn inject(&mut self, packet: impl AsRef<[u8]>) -> Result<()> {
        let packet = packet.as_ref();
        if packet.len() > self.mtu {
            bail!(
                "packet length {} exceeds device MTU {}",
                packet.len(),
                self.mtu
            );
        }
        let mut queues = self.inner.borrow_mut();
        if queues.free.len() <= PACKET_QUEUE_TX_RESERVE {
            bail!("packet buffer pool exhausted");
        }
        let Some(mut buffer) = queues.take_buffer() else {
            bail!("packet buffer pool exhausted");
        };
        buffer.extend_from_slice(packet);
        queues.rx.push_back(buffer);
        Ok(())
    }

    pub fn drain_tx(&mut self) -> Vec<PacketBuf> {
        let mut packets = Vec::new();
        self.drain_tx_into(&mut packets);
        packets
    }

    pub fn drain_tx_into(&mut self, packets: &mut Vec<PacketBuf>) {
        packets.clear();
        let mut queues = self.inner.borrow_mut();
        packets.reserve(queues.tx.len());
        while let Some(packet) = queues.tx.pop_front() {
            packets.push(PacketBuf {
                packet: Some(packet),
                inner: self.inner.clone(),
            });
        }
    }
}

impl Device for PacketQueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut queues = self.inner.borrow_mut();
        if queues.rx.is_empty() || queues.free.is_empty() {
            return None;
        }
        let packet = queues.rx.pop_front()?;
        let tx_packet = queues.take_buffer()?;
        drop(queues);

        Some((
            QueueRxToken {
                packet: Some(packet),
                inner: self.inner.clone(),
            },
            QueueTxToken {
                inner: self.inner.clone(),
                packet: Some(tx_packet),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let packet = self.inner.borrow_mut().take_buffer()?;
        Some(QueueTxToken {
            inner: self.inner.clone(),
            packet: Some(packet),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = None;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

pub struct QueueRxToken {
    packet: Option<BytesMut>,
    inner: Rc<RefCell<PacketQueues>>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let Some(packet) = self.packet.take() else {
            debug_assert!(false, "RX token must hold packet");
            return f(&[]);
        };
        let result = f(&packet);
        self.inner.borrow_mut().recycle(packet);
        result
    }
}

impl Drop for QueueRxToken {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.inner.borrow_mut().recycle(packet);
        }
    }
}

pub struct QueueTxToken {
    inner: Rc<RefCell<PacketQueues>>,
    packet: Option<BytesMut>,
}

impl TxToken for QueueTxToken {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = match self.packet.take() {
            Some(packet) => packet,
            None => {
                debug_assert!(false, "TX token must hold packet");
                BytesMut::with_capacity(len)
            }
        };
        debug_assert!(len <= packet.capacity());
        packet.resize(len, 0);
        let result = f(&mut packet);
        self.inner.borrow_mut().tx.push_back(packet);
        result
    }

    fn set_meta(&mut self, _meta: PacketMeta) {}
}

impl Drop for QueueTxToken {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.inner.borrow_mut().recycle(packet);
        }
    }
}

pub struct PacketBuf {
    packet: Option<BytesMut>,
    inner: Rc<RefCell<PacketQueues>>,
}

impl PacketBuf {
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

impl AsRef<[u8]> for PacketBuf {
    fn as_ref(&self) -> &[u8] {
        let Some(packet) = self.packet.as_ref() else {
            debug_assert!(false, "packet buffer must hold bytes");
            return &[];
        };
        packet.as_ref()
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.inner.borrow_mut().recycle(packet);
        }
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::iface::{Config, Interface, Route, SocketSet};
    use smoltcp::phy::{Device, Loopback, Medium, RxToken, TxToken};
    use smoltcp::socket::tcp;
    use smoltcp::time::{Duration, Instant};
    use smoltcp::wire::{
        HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr, Ipv4Packet, TcpOption, TcpPacket,
    };

    use super::*;

    #[test]
    fn flow_key_preserves_original_destination() {
        let flow = FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 1),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );

        assert_eq!(flow.dst_ip, Ipv4Addr::new(172, 16, 0, 9));
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.protocol, IpProtocol::Tcp);
    }

    #[test]
    fn new_flow_socket_uses_proxy_response_window_and_latency_settings() {
        let socket = new_flow_socket();

        assert_eq!(socket.recv_capacity(), TCP_RECV_BUFFER_BYTES);
        assert_eq!(socket.send_capacity(), TCP_SEND_BUFFER_BYTES);
        assert_eq!(socket.ack_delay(), None);
        assert!(!socket.nagle_enabled());
    }

    #[test]
    fn parse_ipv4_tcp_segment_extracts_opening_syn_flow() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let segment = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment");

        assert_eq!(
            segment.flow,
            FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 1),
                49152,
                Ipv4Addr::new(172, 16, 0, 9),
                443,
            )
        );
        assert!(segment.flags.is_opening_syn());
        assert_eq!(segment.payload_len, 0);
    }

    #[test]
    fn parse_ipv4_tcp_segment_distinguishes_ack_from_opening_syn() {
        let packet = ipv4_tcp_packet(0x10, 5);
        let segment = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment");

        assert!(!segment.flags.is_opening_syn());
        assert!(segment.flags.ack);
        assert_eq!(segment.payload_len, 5);
    }

    #[test]
    fn tcp_flags_opening_syn_requires_syn_without_ack_or_rst() {
        for (flags, expected) in [
            (
                TcpFlags {
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                },
                true,
            ),
            (
                TcpFlags {
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                },
                false,
            ),
            (
                TcpFlags {
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: true,
                },
                false,
            ),
            (
                TcpFlags {
                    syn: false,
                    ack: false,
                    fin: false,
                    rst: false,
                },
                false,
            ),
        ] {
            assert_eq!(flags.is_opening_syn(), expected, "{flags:?}");
        }
    }

    #[test]
    fn parse_ipv4_tcp_segment_ignores_non_tcp_ipv4() {
        let mut packet = [0_u8; 28];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 255, 255, 1]);
        packet[16..20].copy_from_slice(&[172, 16, 0, 9]);

        assert_eq!(parse_ipv4_tcp_segment(&packet).expect("valid IPv4"), None);
    }

    #[test]
    fn parse_ipv4_tcp_segment_fuzzes_random_inputs_without_panics() {
        let mut seed = 0x5443_505f_6675_7a7a_u64;

        for case in 0..4096 {
            let len = case % 257;
            let mut packet = vec![0_u8; len];
            for byte in &mut packet {
                *byte = next_fuzz_byte(&mut seed);
            }

            let parsed = std::panic::catch_unwind(|| parse_ipv4_tcp_segment(&packet));
            assert!(parsed.is_ok(), "TCP parser panicked for len={len}");
        }
    }

    #[test]
    fn parse_ipv4_tcp_segment_fuzzes_structured_length_edges_without_panics() {
        let mut seed = 0x5443_505f_6c65_6e73_u64;

        for version_ihl in [0x40_u8, 0x45, 0x46, 0x4f, 0x55] {
            for total_len in [0_u16, 19, 20, 39, 40, 60, u16::MAX] {
                for tcp_data_offset in [0_u8, 4, 5, 6, 15] {
                    let actual_len = usize::from(total_len).clamp(0, 96);
                    let mut packet = vec![0_u8; actual_len.max(60)];
                    packet[0] = version_ihl;
                    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
                    packet[8] = 64;
                    packet[9] = 6;
                    packet[12..16].copy_from_slice(&[10, 255, 255, 2]);
                    packet[16..20].copy_from_slice(&[192, 0, 2, 10]);

                    let ipv4_header_len = usize::from(version_ihl & 0x0f) * 4;
                    if packet.len() >= ipv4_header_len.saturating_add(20) && ipv4_header_len >= 20 {
                        let tcp = &mut packet[ipv4_header_len..];
                        tcp[0..2].copy_from_slice(&49152_u16.to_be_bytes());
                        tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
                        tcp[12] = tcp_data_offset << 4;
                        tcp[13] = next_fuzz_byte(&mut seed);
                        tcp[14..16].copy_from_slice(&4096_u16.to_be_bytes());
                    }

                    packet.truncate(actual_len);
                    let parsed = std::panic::catch_unwind(|| parse_ipv4_tcp_segment(&packet));
                    assert!(
                        parsed.is_ok(),
                        "TCP parser panicked for ihl={version_ihl:#x} total_len={total_len} data_offset={tcp_data_offset}"
                    );
                }
            }
        }
    }

    #[test]
    fn flow_manager_assigns_new_generation_when_tuple_is_reused() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");

        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("first SYN");
        let first_id = manager.flow_id(flow).expect("first flow id");
        manager.remove_flow(flow).expect("remove first flow");

        manager
            .ingest_packet(Instant::from_millis(1), &packet)
            .expect("reused SYN");
        let second_id = manager.flow_id(flow).expect("second flow id");

        assert_eq!(first_id.key, second_id.key);
        assert!(second_id.generation > first_id.generation);
    }

    #[test]
    fn flow_manager_flow_keys_into_reuses_output_vector() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("SYN");

        let mut keys = Vec::with_capacity(8);
        keys.push(FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        ));
        let capacity = keys.capacity();

        manager.flow_keys_into(&mut keys);

        assert_eq!(keys, vec![flow]);
        assert_eq!(keys.capacity(), capacity);
    }

    #[test]
    fn flow_manager_ready_flow_ids_into_reuses_output_vector() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("SYN");
        manager
            .mark_flow_state(flow, FlowState::TcpEstablished)
            .expect("mark established");
        let id = manager.flow_id(flow).expect("flow id");

        let mut ids = Vec::with_capacity(8);
        ids.push(FlowId::new(flow, id.generation.saturating_add(1)));
        let capacity = ids.capacity();

        manager.ready_to_bridge_flow_ids_into(&mut ids);

        assert_eq!(ids, vec![id]);
        assert_eq!(ids.capacity(), capacity);
    }

    #[test]
    fn flow_manager_ready_flows_include_only_established_flows() {
        let first = ipv4_tcp_packet(0x02, 0);
        let first_flow = parse_ipv4_tcp_segment(&first)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut second = ipv4_tcp_packet(0x02, 0);
        second[20..22].copy_from_slice(&49153_u16.to_be_bytes());
        let second_flow = parse_ipv4_tcp_segment(&second)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let missing_flow = FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        );
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");

        manager
            .ingest_packet(Instant::from_millis(0), &first)
            .expect("first SYN");
        manager
            .ingest_packet(Instant::from_millis(0), &second)
            .expect("second SYN");
        manager
            .mark_flow_state(first_flow, FlowState::TcpEstablished)
            .expect("mark first established");

        assert!(manager.contains_flow(first_flow));
        assert!(manager.contains_flow(second_flow));
        assert!(!manager.contains_flow(missing_flow));
        let flow_keys = manager.flow_keys();
        assert_eq!(flow_keys.len(), 2);
        assert!(flow_keys.contains(&first_flow));
        assert!(flow_keys.contains(&second_flow));

        let ready = manager.ready_to_bridge_flows();
        assert_eq!(ready.len(), 1);
        assert!(ready.contains(&first_flow));
        assert!(!ready.contains(&second_flow));
    }

    #[test]
    fn flow_manager_returns_configured_policy() {
        let policy = FlowPolicy {
            max_active_flows: 3,
            opening_timeout: Duration::from_millis(7),
            bridge_open_timeout: Duration::from_millis(11),
            idle_timeout: Duration::from_millis(13),
        };
        let manager = FlowManager::with_policy(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
            policy,
        )
        .expect("flow manager");

        assert_eq!(manager.policy(), policy);
    }

    #[test]
    fn flow_manager_reports_current_state_age() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        manager
            .ingest_packet(Instant::from_millis(5), &packet)
            .expect("SYN");

        assert_eq!(
            manager
                .flow_state_elapsed_ms(flow, Instant::from_millis(9))
                .expect("handshake age"),
            4
        );
        manager
            .mark_flow_state_at(flow, FlowState::TcpEstablished, Instant::from_millis(20))
            .expect("mark established");
        assert_eq!(
            manager
                .flow_state_elapsed_ms(flow, Instant::from_millis(27))
                .expect("ready age"),
            7
        );
    }

    #[test]
    fn flow_manager_counts_opening_flows_without_snapshot_allocation() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("SYN");

        assert_eq!(manager.opening_flow_count(), 0);
        manager
            .mark_flow_state(flow, FlowState::BridgeOpening)
            .expect("mark opening");
        assert_eq!(manager.opening_flow_count(), 1);
    }

    #[test]
    fn bridge_opening_timeout_starts_when_flow_enters_bridge_opening() {
        let mut manager = FlowManager::with_policy(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
            FlowPolicy {
                max_active_flows: 16,
                opening_timeout: Duration::from_millis(5),
                bridge_open_timeout: Duration::from_millis(5),
                idle_timeout: Duration::from_secs(300),
            },
        )
        .expect("flow manager");
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 1),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );

        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("opening SYN");
        manager
            .mark_flow_state_at(flow, FlowState::TcpEstablished, Instant::from_millis(1))
            .expect("mark established");
        assert!(
            manager
                .expire_stale_flows(Instant::from_millis(100))
                .is_empty(),
            "established flow waiting for bridge admission should use idle timeout"
        );

        manager
            .mark_flow_state_at(flow, FlowState::BridgeOpening, Instant::from_millis(100))
            .expect("mark opening");
        assert!(manager
            .expire_stale_flows(Instant::from_millis(104))
            .is_empty());
        assert_eq!(
            manager.expire_stale_flows(Instant::from_millis(106)),
            vec![flow]
        );
    }

    #[test]
    fn flow_manager_cleanup_enumeration_into_reuses_output_vectors() {
        let mut manager = FlowManager::with_policy(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
            FlowPolicy {
                max_active_flows: 16,
                opening_timeout: Duration::from_millis(5),
                idle_timeout: Duration::from_secs(300),
                ..FlowPolicy::default()
            },
        )
        .expect("flow manager");
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 1),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );
        let stale = FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        );

        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("opening SYN");

        let mut expired = Vec::with_capacity(8);
        expired.push(stale);
        let expired_capacity = expired.capacity();
        manager.expire_stale_flows_into(Instant::from_millis(4), &mut expired);
        assert!(expired.is_empty());
        assert_eq!(expired.capacity(), expired_capacity);

        manager.expire_stale_flows_into(Instant::from_millis(6), &mut expired);
        assert_eq!(expired, vec![flow]);
        assert_eq!(expired.capacity(), expired_capacity);

        manager.poll(Instant::from_millis(6));
        let mut removable = Vec::with_capacity(8);
        removable.push(stale);
        let removable_capacity = removable.capacity();
        manager.removable_flows_into(&mut removable);

        assert_eq!(removable, vec![flow]);
        assert_eq!(removable.capacity(), removable_capacity);
    }

    #[test]
    fn flow_manager_does_not_remove_terminal_state_while_socket_is_open() {
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = parse_ipv4_tcp_segment(&packet)
            .expect("valid packet")
            .expect("TCP segment")
            .flow;
        let mut manager = FlowManager::new(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
        )
        .expect("flow manager");
        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("opening SYN");

        manager
            .mark_flow_state(flow, FlowState::Reset)
            .expect("mark terminal without closing socket");
        assert!(manager.removable_flows().is_empty());

        manager.abort_flow(flow).expect("abort flow socket");
        manager.poll(Instant::from_millis(1));
        assert_eq!(manager.removable_flows(), vec![flow]);
    }

    #[test]
    fn smoltcp_anyip_accepts_tcp_for_routed_arbitrary_destination() {
        let mut device = Loopback::new(Medium::Ip);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5255_5354_4c45;

        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(10, 255, 255, 1), 24))
                .unwrap();
        });
        iface.routes_mut().update(|routes| {
            routes
                .push(Route {
                    cidr: IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(172, 16, 0, 0), 16)),
                    via_router: IpAddress::v4(10, 255, 255, 1),
                    preferred_until: None,
                    expires_at: None,
                })
                .unwrap();
        });
        iface.set_any_ip(true);

        let server_socket = new_flow_socket();
        let client_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );

        let mut sockets = SocketSet::new(vec![]);
        let server_handle = sockets.add(server_socket);
        let client_handle = sockets.add(client_socket);

        let arbitrary_destination = IpAddress::v4(172, 16, 0, 9);
        let server_port = 443;
        let client_port = 49152;
        let request = b"hello over anyip";
        let response = b"accepted by smoltcp";

        {
            let server = sockets.get_mut::<tcp::Socket>(server_handle);
            server
                .listen((arbitrary_destination, server_port))
                .expect("server listen on arbitrary AnyIP destination");
        }
        {
            let client = sockets.get_mut::<tcp::Socket>(client_handle);
            client
                .connect(
                    iface.context(),
                    (arbitrary_destination, server_port),
                    client_port,
                )
                .expect("client connect to routed arbitrary destination");
        }

        let mut now = Instant::from_millis(0);
        let mut client_sent = false;
        let mut server_received = Vec::new();
        let mut server_replied = false;
        let mut client_received = Vec::new();
        let mut observed_server_local = None;
        let mut observed_server_remote = None;

        for _ in 0..256 {
            iface.poll(now, &mut device, &mut sockets);

            {
                let server = sockets.get_mut::<tcp::Socket>(server_handle);
                if server.local_endpoint().is_some() {
                    observed_server_local = server.local_endpoint();
                    observed_server_remote = server.remote_endpoint();
                }

                if server.can_recv() {
                    let mut buf = [0_u8; 64];
                    let len = server.recv_slice(&mut buf).expect("server recv");
                    server_received.extend_from_slice(&buf[..len]);
                }

                if !server_replied && !server_received.is_empty() && server.can_send() {
                    server
                        .send_slice(response)
                        .expect("server send response over accepted AnyIP flow");
                    server_replied = true;
                }
            }

            {
                let client = sockets.get_mut::<tcp::Socket>(client_handle);
                if !client_sent && client.can_send() {
                    client
                        .send_slice(request)
                        .expect("client send request through synthetic flow");
                    client_sent = true;
                }

                if client.can_recv() {
                    let mut buf = [0_u8; 64];
                    let len = client.recv_slice(&mut buf).expect("client recv");
                    client_received.extend_from_slice(&buf[..len]);
                }
            }

            if server_received == request && client_received == response {
                break;
            }

            match iface.poll_delay(now, &sockets) {
                Some(Duration::ZERO) => {}
                Some(delay) => now += delay,
                None => now += Duration::from_millis(1),
            }
        }

        assert!(client_sent, "client never reached TCP can_send");
        assert_eq!(server_received, request);
        assert_eq!(client_received, response);
        assert_eq!(
            observed_server_local,
            Some((arbitrary_destination, server_port).into())
        );
        assert_eq!(
            observed_server_remote,
            Some((IpAddress::v4(10, 255, 255, 1), client_port).into())
        );
    }

    #[test]
    fn flow_manager_allocates_socket_from_syn_and_moves_stream_bytes() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(10, 42, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let flow = FlowKey::tcp(
            client_ip,
            client_port,
            Ipv4Addr::new(10, 42, 0, 9),
            destination_port,
        );

        let mut manager = FlowManager::new(
            tun_ip,
            24,
            &[
                Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16),
                Ipv4NetParts::new(Ipv4Addr::new(10, 42, 0, 0), 16),
            ],
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

        let request = b"GET / HTTP/1.1\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut now = Instant::from_millis(0);
        let mut client_sent = false;
        let mut manager_received = Vec::new();
        let mut manager_replied = false;
        let mut client_received = Vec::new();
        let mut observed_recv_queue_wait = false;

        for _ in 0..512 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);
            pump_manager_to_client(now, &mut manager, &mut client_device);

            {
                let client = client_sockets.get_mut::<tcp::Socket>(client_handle);
                if !client_sent && client.can_send() {
                    client.send_slice(request).expect("client send request");
                    client_sent = true;
                }

                if client.can_recv() {
                    let mut buf = [0_u8; 128];
                    let len = client.recv_slice(&mut buf).expect("client recv response");
                    client_received.extend_from_slice(&buf[..len]);
                }
            }

            pump_client_to_manager(now, &mut client_device, &mut manager);

            let flow_bytes = manager
                .recv_flow_bytes_with_metrics(flow, 128, now + Duration::from_millis(5))
                .expect("manager receive flow bytes");
            let chunk = flow_bytes.bytes;
            if !chunk.is_empty() {
                assert_eq!(flow_bytes.tcp_recv_queue_wait_us, Some(5_000));
                observed_recv_queue_wait = true;
                assert_eq!(chunk.len(), request.len());
                manager_received.extend_from_slice(&chunk);
            }

            if !manager_replied && manager_received == request {
                manager
                    .send_flow_bytes(flow, response)
                    .expect("manager enqueue response");
                manager_replied = true;
            }

            pump_manager_to_client(now, &mut manager, &mut client_device);

            if manager_received == request && client_received == response {
                break;
            }

            now += Duration::from_millis(1);
        }

        assert!(client_sent, "client never became writable");
        assert!(observed_recv_queue_wait);
        assert_eq!(manager_received, request);
        assert_eq!(client_received, response);

        let snapshots = manager.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].key, flow);
        assert!(matches!(
            snapshots[0].state,
            FlowState::TcpEstablished | FlowState::Relaying
        ));
        assert_eq!(snapshots[0].local_to_remote_bytes, request.len() as u64);
        assert_eq!(snapshots[0].remote_to_local_bytes, response.len() as u64);
    }

    #[test]
    fn recv_flow_bytes_preserves_buffer_wait_marker_after_partial_read() {
        let (
            mut manager,
            mut client_iface,
            mut client_device,
            mut client_sockets,
            client_handle,
            flow,
            mut now,
        ) = established_flow_with_client();
        let request = b"abcdef";

        {
            let client = client_sockets.get_mut::<tcp::Socket>(client_handle);
            client.send_slice(request).expect("client send request");
        }
        for _ in 0..64 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);
            if manager.recv_queue_len(flow).expect("recv queue") == request.len() {
                break;
            }
            now += Duration::from_millis(1);
        }
        assert_eq!(
            manager.recv_queue_len(flow).expect("recv queue"),
            request.len()
        );

        let first = manager
            .recv_flow_bytes_with_metrics(flow, 2, now + Duration::from_millis(5))
            .expect("first partial recv");
        assert_eq!(first.bytes.as_ref(), b"ab");
        assert_eq!(first.tcp_recv_queue_wait_us, Some(5_000));
        assert_eq!(manager.recv_queue_len(flow).expect("remaining queue"), 4);

        let second = manager
            .recv_flow_bytes_with_metrics(flow, 4, now + Duration::from_millis(8))
            .expect("second partial recv");
        assert_eq!(second.bytes.as_ref(), b"cdef");
        assert_eq!(second.tcp_recv_queue_wait_us, Some(8_000));
        assert_eq!(manager.recv_queue_len(flow).expect("drained queue"), 0);
    }

    #[test]
    fn zero_length_remote_send_does_not_update_flow_activity() {
        let (
            mut manager,
            _client_iface,
            _client_device,
            _client_sockets,
            _client_handle,
            flow,
            now,
        ) = established_flow_with_client();
        let before = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");

        assert_eq!(
            manager
                .send_flow_bytes_at(flow, b"", now + Duration::from_millis(10))
                .expect("empty send"),
            0
        );
        let after_empty_send = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(after_empty_send.remote_to_local_bytes, 0);
        assert_eq!(after_empty_send.last_activity, before.last_activity);

        assert_eq!(
            manager
                .try_send_flow_bytes(flow, b"ok")
                .expect("try send bytes"),
            Some(2)
        );
        let after_try_send = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(after_try_send.remote_to_local_bytes, 2);
        assert_eq!(after_try_send.last_activity, before.last_activity);

        assert_eq!(
            manager
                .try_send_flow_bytes_at(flow, b"", now + Duration::from_millis(12))
                .expect("empty try send"),
            Some(0)
        );
        let after_empty_try_send = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(after_empty_try_send.remote_to_local_bytes, 2);
        assert_eq!(after_empty_try_send.last_activity, before.last_activity);
    }

    #[test]
    fn flow_manager_advertises_mtu_derived_mss_in_syn_ack() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let mtu = 1300;
        let mut manager = FlowManager::new(
            tun_ip,
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            mtu,
        )
        .expect("flow manager");
        let (mut client_iface, mut client_device, mut client_sockets, _) = synthetic_client(
            client_ip,
            tun_ip,
            destination,
            destination_port,
            client_port,
        );

        let now = Instant::from_millis(0);
        client_iface.poll(now, &mut client_device, &mut client_sockets);
        let mut packets = Vec::new();
        for packet in client_device.drain_tx() {
            packets.extend(
                manager
                    .ingest_packet(now, packet.as_ref())
                    .expect("opening SYN"),
            );
        }

        let syn_ack = packets
            .iter()
            .find(|packet| {
                parse_ipv4_tcp_segment(packet.as_ref())
                    .expect("valid SYN/ACK packet")
                    .is_some_and(|segment| segment.flags.syn && segment.flags.ack)
            })
            .expect("SYN/ACK packet");
        let advertised_mss = tcp_mss_option(syn_ack.as_ref()).expect("SYN/ACK must advertise MSS");

        assert_eq!(advertised_mss, (mtu - 20 - 20) as u16);
        assert!(advertised_mss <= 1260);
    }

    #[test]
    fn flow_manager_emits_remote_payload_packets_within_mtu() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let mtu = 1300;
        let flow = FlowKey::tcp(
            client_ip,
            client_port,
            Ipv4Addr::new(172, 16, 0, 9),
            destination_port,
        );
        let mut manager = FlowManager::new(
            tun_ip,
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            mtu,
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

        let request = b"GET / HTTP/1.1\r\n\r\n";
        let response = vec![0x5a; mtu * 8 + 313];
        let mut now = Instant::from_millis(0);
        let mut client_sent = false;
        let mut manager_received = Vec::new();
        let mut manager_replied = false;
        let mut client_received = Vec::new();
        let mut observed_large_response_packet = false;

        for _ in 0..2048 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);

            for packet in manager.poll(now) {
                assert!(
                    packet.len() <= mtu,
                    "FlowManager emitted packet length {} above MTU {mtu}",
                    packet.len()
                );
                if packet.len() > mtu / 2 {
                    observed_large_response_packet = true;
                }
                client_device
                    .inject(packet.as_ref())
                    .expect("inject manager packet into client");
            }

            {
                let client = client_sockets.get_mut::<tcp::Socket>(client_handle);
                if !client_sent && client.can_send() {
                    client.send_slice(request).expect("client send request");
                    client_sent = true;
                }

                while client.can_recv() {
                    let mut buf = [0_u8; 2048];
                    let len = client.recv_slice(&mut buf).expect("client recv response");
                    client_received.extend_from_slice(&buf[..len]);
                }
            }

            pump_client_to_manager(now, &mut client_device, &mut manager);

            let chunk = manager
                .recv_flow_bytes(flow, 4096)
                .expect("manager receive flow bytes");
            if !chunk.is_empty() {
                manager_received.extend_from_slice(&chunk);
            }

            if !manager_replied && manager_received == request {
                let accepted = manager
                    .send_flow_bytes(flow, &response)
                    .expect("manager enqueue large response");
                assert_eq!(accepted, response.len());
                manager_replied = true;
            }

            for packet in manager.poll(now) {
                assert!(
                    packet.len() <= mtu,
                    "FlowManager emitted packet length {} above MTU {mtu}",
                    packet.len()
                );
                if packet.len() > mtu / 2 {
                    observed_large_response_packet = true;
                }
                client_device
                    .inject(packet.as_ref())
                    .expect("inject manager packet into client");
            }

            if client_received == response {
                break;
            }

            now += Duration::from_millis(1);
        }

        assert!(client_sent, "client never became writable");
        assert_eq!(manager_received, request);
        assert_eq!(client_received, response);
        assert!(
            observed_large_response_packet,
            "test did not observe response-sized packets"
        );
    }

    #[test]
    fn packet_queue_device_bounds_rx_without_starving_tx_token() {
        let mut device = PacketQueueDevice::new(64);
        let packet = [0_u8; 8];

        for _ in 0..(PACKET_QUEUE_CAPACITY - PACKET_QUEUE_TX_RESERVE) {
            device.inject(packet).expect("inject within bounded pool");
        }

        let err = device
            .inject(packet)
            .expect_err("pool must reject unbounded RX growth");
        assert!(err.to_string().contains("packet buffer pool exhausted"));

        let (rx, tx) = device
            .receive(Instant::from_millis(0))
            .expect("reserved TX buffer must let RX progress");
        rx.consume(|bytes| assert_eq!(bytes, packet));
        drop(tx);

        device
            .inject(packet)
            .expect("recycled RX/TX buffers should accept another packet");
    }

    #[test]
    fn packet_queue_device_receive_without_tx_buffer_preserves_rx_packet() {
        let mut device = PacketQueueDevice::new(64);
        device.inject([0xaa]).expect("inject first packet");
        for index in 1..(PACKET_QUEUE_CAPACITY - PACKET_QUEUE_TX_RESERVE) {
            device
                .inject([index as u8])
                .expect("fill RX while preserving TX reserve");
        }
        let held_tx = device
            .transmit(Instant::from_millis(0))
            .expect("hold final free buffer");

        assert!(device.receive(Instant::from_millis(0)).is_none());
        drop(held_tx);

        let (rx, tx) = device
            .receive(Instant::from_millis(0))
            .expect("RX packet should still be queued after TX buffer returns");
        rx.consume(|bytes| assert_eq!(bytes, &[0xaa]));
        drop(tx);
    }

    #[test]
    fn packet_queue_device_recycles_drained_tx_packet_buffers() {
        let mut device = PacketQueueDevice::new(64);
        {
            let tx = device
                .transmit(Instant::from_millis(0))
                .expect("available TX buffer");
            tx.consume(4, |bytes| bytes.copy_from_slice(b"rust"));
        }

        let packets = device.drain_tx();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].as_ref(), b"rust");
        drop(packets);

        for _ in 0..(PACKET_QUEUE_CAPACITY - PACKET_QUEUE_TX_RESERVE) {
            device.inject([1_u8]).expect("buffer recycled after drain");
        }
    }

    #[test]
    fn packet_queue_device_recycles_unconsumed_rx_token_on_drop() {
        let mut device = PacketQueueDevice::new(64);
        device.inject([9_u8]).expect("inject packet");
        let (rx, tx) = device
            .receive(Instant::from_millis(0))
            .expect("receive packet");

        drop(rx);
        drop(tx);

        for _ in 0..(PACKET_QUEUE_CAPACITY - PACKET_QUEUE_TX_RESERVE) {
            device
                .inject([1_u8])
                .expect("dropped RX token should recycle packet buffer");
        }
    }

    #[test]
    fn packet_buf_is_empty_reflects_drained_packet_length() {
        let mut device = PacketQueueDevice::new(64);
        {
            let tx = device
                .transmit(Instant::from_millis(0))
                .expect("available TX buffer");
            tx.consume(0, |_| {});
        }
        {
            let tx = device
                .transmit(Instant::from_millis(0))
                .expect("available TX buffer");
            tx.consume(4, |bytes| bytes.copy_from_slice(b"rust"));
        }

        let packets = device.drain_tx();

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].len(), 0);
        assert!(packets[0].is_empty());
        assert_eq!(packets[1].len(), 4);
        assert!(!packets[1].is_empty());
    }

    #[test]
    fn packet_queue_device_drain_tx_into_reuses_output_vector() {
        let mut device = PacketQueueDevice::new(64);
        let mut packets = Vec::with_capacity(8);
        let retained_capacity = packets.capacity();
        {
            let tx = device
                .transmit(Instant::from_millis(0))
                .expect("available TX buffer");
            tx.consume(4, |bytes| bytes.copy_from_slice(b"rust"));
        }

        device.drain_tx_into(&mut packets);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets.capacity(), retained_capacity);
        assert_eq!(packets[0].as_ref(), b"rust");

        device.drain_tx_into(&mut packets);
        assert!(packets.is_empty());
        assert_eq!(packets.capacity(), retained_capacity);

        for _ in 0..(PACKET_QUEUE_CAPACITY - PACKET_QUEUE_TX_RESERVE) {
            device
                .inject([1_u8])
                .expect("clearing output vector recycles drained packet");
        }
    }

    #[test]
    fn flow_manager_aborts_and_removes_terminal_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let flow = FlowKey::tcp(
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
        let (mut client_iface, mut client_device, mut client_sockets, _) = synthetic_client(
            client_ip,
            tun_ip,
            destination,
            destination_port,
            client_port,
        );

        let mut now = Instant::from_millis(0);
        for _ in 0..128 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);
            pump_manager_to_client(now, &mut manager, &mut client_device);

            if manager
                .snapshots()
                .iter()
                .any(|snapshot| snapshot.state == FlowState::TcpEstablished)
            {
                break;
            }
            now += Duration::from_millis(1);
        }

        manager.abort_flow(flow).expect("abort flow");
        assert_eq!(
            manager
                .try_send_flow_bytes(flow, b"late remote bytes")
                .expect("late send should not fail process"),
            None
        );
        manager.poll(now);
        assert_eq!(manager.removable_flows(), vec![flow]);
        manager.remove_flow(flow).expect("remove flow");
        assert!(manager.snapshots().is_empty());
    }

    #[test]
    fn flow_manager_rejects_new_syn_after_flow_limit() {
        let mut manager = FlowManager::with_policy(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
            FlowPolicy {
                max_active_flows: 1,
                opening_timeout: Duration::from_secs(15),
                idle_timeout: Duration::from_secs(300),
                ..FlowPolicy::default()
            },
        )
        .expect("flow manager");

        let first = ipv4_tcp_packet(0x02, 0);
        let mut second = ipv4_tcp_packet(0x02, 0);
        second[20..22].copy_from_slice(&49153_u16.to_be_bytes());

        manager
            .ingest_packet(Instant::from_millis(0), &first)
            .expect("first SYN");
        manager
            .ingest_packet(Instant::from_millis(0), &second)
            .expect("second SYN");

        assert_eq!(manager.active_flow_count(), 1);
        assert_eq!(
            manager.snapshots()[0].key,
            FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 1),
                49152,
                Ipv4Addr::new(172, 16, 0, 9),
                443,
            )
        );
    }

    #[test]
    fn flow_manager_expires_stale_opening_flow() {
        let mut manager = FlowManager::with_policy(
            Ipv4Addr::new(10, 255, 255, 1),
            24,
            &[Ipv4NetParts::new(Ipv4Addr::new(172, 16, 0, 0), 16)],
            1300,
            FlowPolicy {
                max_active_flows: 16,
                opening_timeout: Duration::from_millis(5),
                idle_timeout: Duration::from_secs(300),
                ..FlowPolicy::default()
            },
        )
        .expect("flow manager");
        let packet = ipv4_tcp_packet(0x02, 0);
        let flow = FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 1),
            49152,
            Ipv4Addr::new(172, 16, 0, 9),
            443,
        );

        manager
            .ingest_packet(Instant::from_millis(0), &packet)
            .expect("opening SYN");
        assert_eq!(manager.active_flow_count(), 1);

        assert!(manager
            .expire_stale_flows(Instant::from_millis(4))
            .is_empty());
        assert_eq!(
            manager.expire_stale_flows(Instant::from_millis(6)),
            vec![flow]
        );

        manager.poll(Instant::from_millis(6));
        assert_eq!(manager.removable_flows(), vec![flow]);
        manager.remove_flow(flow).expect("remove expired flow");
        assert_eq!(manager.active_flow_count(), 0);
    }

    #[test]
    fn packet_queue_devices_can_handshake_between_two_interfaces() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let server_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;

        let (mut client_iface, mut client_device, mut client_sockets, client_handle) =
            synthetic_client(
                client_ip,
                server_ip,
                destination,
                destination_port,
                client_port,
            );

        let mut server_device = PacketQueueDevice::new(1300);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5352_5652;
        let mut server_iface = Interface::new(config, &mut server_device, Instant::from_millis(0));
        server_iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(server_ip), 24))
                .unwrap();
        });
        server_iface.routes_mut().update(|routes| {
            routes
                .push(Route {
                    cidr: IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(172, 16, 0, 0), 16)),
                    via_router: IpAddress::from(server_ip),
                    preferred_until: None,
                    expires_at: None,
                })
                .unwrap();
        });
        server_iface.set_any_ip(true);

        let mut server_sockets = SocketSet::new(vec![]);
        let server_handle = server_sockets.add(new_flow_socket());
        server_sockets
            .get_mut::<tcp::Socket>(server_handle)
            .listen((destination, destination_port))
            .expect("server listen");

        let mut now = Instant::from_millis(0);
        let mut connected = false;
        for _ in 0..128 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            for packet in client_device.drain_tx() {
                server_device
                    .inject(packet.as_ref())
                    .expect("inject server");
            }

            server_iface.poll(now, &mut server_device, &mut server_sockets);
            for packet in server_device.drain_tx() {
                client_device
                    .inject(packet.as_ref())
                    .expect("inject client");
            }

            connected = client_sockets.get::<tcp::Socket>(client_handle).can_send();
            if connected {
                break;
            }
            now += Duration::from_millis(1);
        }

        assert!(connected, "two-interface custom device handshake failed");
    }

    fn established_flow_with_client() -> (
        FlowManager,
        Interface,
        PacketQueueDevice,
        SocketSet<'static>,
        smoltcp::iface::SocketHandle,
        FlowKey,
        Instant,
    ) {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let tun_ip = Ipv4Addr::new(10, 255, 255, 1);
        let destination = IpAddress::v4(172, 16, 0, 9);
        let destination_port = 443;
        let client_port = 49152;
        let flow = FlowKey::tcp(
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
        let mut now = Instant::from_millis(0);

        for _ in 0..256 {
            client_iface.poll(now, &mut client_device, &mut client_sockets);
            pump_client_to_manager(now, &mut client_device, &mut manager);
            pump_manager_to_client(now, &mut manager, &mut client_device);

            if manager
                .snapshots()
                .iter()
                .any(|snapshot| snapshot.key == flow && snapshot.state == FlowState::TcpEstablished)
            {
                return (
                    manager,
                    client_iface,
                    client_device,
                    client_sockets,
                    client_handle,
                    flow,
                    now,
                );
            }

            now += Duration::from_millis(1);
        }

        panic!("synthetic flow did not reach TcpEstablished");
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
        config.random_seed = 0x434c_4945_4e54;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(client_ip), 24))
                .unwrap();
        });
        iface.routes_mut().update(|routes| {
            let IpAddress::Ipv4(destination) = destination;
            routes
                .push(Route {
                    cidr: IpCidr::Ipv4(Ipv4Cidr::new(destination, 32)),
                    via_router: IpAddress::from(gateway),
                    preferred_until: None,
                    expires_at: None,
                })
                .unwrap();
        });

        let mut sockets = SocketSet::new(vec![]);
        let client_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 4096]),
            tcp::SocketBuffer::new(vec![0; 4096]),
        );
        let client_handle = sockets.add(client_socket);
        let client = sockets.get_mut::<tcp::Socket>(client_handle);
        client
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

    fn ipv4_tcp_packet(tcp_flags: u8, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + 20 + payload_len;
        let mut packet = vec![0_u8; total_len];

        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 255, 255, 1]);
        packet[16..20].copy_from_slice(&[172, 16, 0, 9]);

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&49152_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags;
        tcp[14..16].copy_from_slice(&4096_u16.to_be_bytes());
        for byte in &mut tcp[20..] {
            *byte = b'x';
        }

        packet
    }

    fn tcp_mss_option(packet: &[u8]) -> Option<u16> {
        let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
        let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
        let mut options = tcp.options();
        while !options.is_empty() {
            let (next, option) = TcpOption::parse(options).ok()?;
            match option {
                TcpOption::EndOfList => return None,
                TcpOption::MaxSegmentSize(mss) => return Some(mss),
                _ => options = next,
            }
        }
        None
    }

    fn next_fuzz_byte(seed: &mut u64) -> u8 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 32) as u8
    }
}
