use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;

use crate::{agent_proto, agent_transport};

mod affinity;
mod carrier;
mod lane;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
pub(crate) use affinity::agent_lane_backoff_duration;
pub(crate) use affinity::agent_lane_bit;
use affinity::{
    agent_host_lane_hash, agent_ipv4_lane_hash, agent_lane_candidates, TCP_PROTOCOL_NUMBER,
    UDP_PROTOCOL_NUMBER,
};
#[cfg(test)]
pub(crate) use affinity::{
    agent_host_lane_index, agent_lane_index, AGENT_LANE_BACKOFF_BASE, AGENT_LANE_BACKOFF_MAX,
};
#[cfg(test)]
pub(crate) use carrier::AgentBridgeCarrier;
pub(crate) use carrier::{
    AgentBridgeTransport, QuicNativeBridge, QuicNativeBridgeSnapshot, QuicNativeBridgeStream,
};
use lane::{AgentBridgeLane, AgentLaneSelectionStatus, AgentReconnectCounters};
pub(crate) use lane::{AgentBridgeSnapshot, AgentReconnectSnapshot};

const AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS: usize = 3;

pub(crate) type AgentBridgeConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentBridgeTransport>> + Send + 'a>>;
pub(crate) type AgentBridgeConnectManyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<AgentBridgeTransport>>> + Send + 'a>>;

pub(crate) trait AgentBridgeConnector: Send + Sync {
    fn primary_command(&self) -> &str;
    fn connect_initial(&self, desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_>;
    fn connect_primary(&self) -> AgentBridgeConnectFuture<'_>;
    fn connect_command<'a>(&'a self, agent_command: &'a str) -> AgentBridgeConnectFuture<'a>;
}

struct AgentLaneLease {
    bridge: ReconnectingAgentBridge,
    lane_index: usize,
    load: Option<Arc<AtomicUsize>>,
}

impl AgentLaneLease {
    fn new(bridge: ReconnectingAgentBridge, lane_index: usize, load: Arc<AtomicUsize>) -> Self {
        load.fetch_add(1, Ordering::AcqRel);
        Self {
            bridge,
            lane_index,
            load: Some(load),
        }
    }

    fn into_stream(mut self, inner: agent_transport::AgentStream) -> AgentBridgeStream {
        AgentBridgeStream {
            bridge: self.bridge.clone(),
            lane_index: self.lane_index,
            inner: Some(inner),
            load: self.load.take(),
        }
    }
}

impl Drop for AgentLaneLease {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

pub(crate) struct AgentBridgeStream {
    bridge: ReconnectingAgentBridge,
    lane_index: usize,
    inner: Option<agent_transport::AgentStream>,
    load: Option<Arc<AtomicUsize>>,
}

impl AgentBridgeStream {
    #[cfg(test)]
    pub(crate) async fn send_data(&self, bytes: impl Into<Bytes>) -> Result<()> {
        let result = self
            .inner
            .as_ref()
            .context("agent bridge stream is already closed")?
            .send_data(bytes)
            .await;
        if result.is_err() {
            self.schedule_repair_if_transport_failed().await;
        }
        result
    }

    pub(crate) async fn send_data_with_metrics(
        &self,
        bytes: impl Into<Bytes>,
    ) -> Result<agent_transport::AgentStreamSendMetrics> {
        let result = self
            .inner
            .as_ref()
            .context("agent bridge stream is already closed")?
            .send_data_with_metrics(bytes)
            .await;
        if result.is_err() {
            self.schedule_repair_if_transport_failed().await;
        }
        result
    }

    pub(crate) async fn send_eof(&self) -> Result<()> {
        let result = self
            .inner
            .as_ref()
            .context("agent bridge stream is already closed")?
            .send_eof()
            .await;
        if result.is_err() {
            self.schedule_repair_if_transport_failed().await;
        }
        result
    }

    pub(crate) async fn recv(&mut self) -> Option<agent_proto::AgentFrame> {
        let frame = self.inner.as_mut()?.recv().await;
        if matches!(
            frame.as_ref().map(|frame| frame.kind),
            None | Some(agent_proto::AgentFrameKind::Reset)
        ) {
            self.schedule_repair_if_transport_failed().await;
        }
        frame
    }

    pub(crate) async fn try_recv(&mut self) -> Option<agent_proto::AgentFrame> {
        let frame = self.inner.as_mut()?.try_recv().await;
        if matches!(
            frame.as_ref().map(|frame| frame.kind),
            Some(agent_proto::AgentFrameKind::Reset)
        ) {
            self.schedule_repair_if_transport_failed().await;
        }
        frame
    }

    pub(crate) async fn close(mut self) -> Result<()> {
        match self.inner.take() {
            Some(stream) => {
                let result = stream.close().await;
                if let Err(err) = &result {
                    self.bridge
                        .spawn_lane_repair(self.lane_index, err.to_string());
                }
                result
            }
            None => Ok(()),
        }
    }

    async fn schedule_repair_if_transport_failed(&self) {
        let Some(stream) = self.inner.as_ref() else {
            return;
        };
        if let Some(failure) = stream.transport_failure_message().await {
            self.bridge.spawn_lane_repair(self.lane_index, failure);
        }
    }
}

impl Drop for AgentBridgeStream {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ReconnectingAgentBridge {
    connector: Arc<dyn AgentBridgeConnector>,
    lanes: Arc<Vec<AgentBridgeLane>>,
    desired_lanes: usize,
    reconnects: Arc<AgentReconnectCounters>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentTcpOpenMode {
    Strict,
    Optimistic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AgentOpenRequest {
    TcpIpv4 {
        open: agent_proto::AgentOpenIpv4,
        mode: AgentTcpOpenMode,
    },
    TcpHost(agent_proto::AgentOpenHost),
    UdpIpv4(agent_proto::AgentOpenIpv4),
}

impl AgentOpenRequest {
    fn lane_hash(&self) -> u64 {
        match self {
            Self::TcpIpv4 { open, .. } => agent_ipv4_lane_hash(open, TCP_PROTOCOL_NUMBER),
            Self::TcpHost(open) => agent_host_lane_hash(open, TCP_PROTOCOL_NUMBER),
            Self::UdpIpv4(open) => agent_ipv4_lane_hash(open, UDP_PROTOCOL_NUMBER),
        }
    }

    async fn open(
        &self,
        transport: &agent_transport::AgentTransport,
    ) -> Result<agent_transport::AgentStream> {
        match self {
            Self::TcpIpv4 {
                open,
                mode: AgentTcpOpenMode::Strict,
            } => transport.open_tcp_ipv4(*open).await,
            Self::TcpIpv4 {
                open,
                mode: AgentTcpOpenMode::Optimistic,
            } => transport.open_tcp_ipv4_optimistic(*open).await,
            Self::TcpHost(open) => transport.open_tcp_host(open.clone()).await,
            Self::UdpIpv4(open) => transport.open_udp_ipv4(*open).await,
        }
    }

    fn repaired_lane_context(&self) -> &'static str {
        match self {
            Self::TcpIpv4 { .. } => "failed to open agent TCP stream on repaired lane",
            Self::TcpHost(_) => "failed to open agent hostname TCP stream on repaired lane",
            Self::UdpIpv4(_) => "failed to open agent UDP stream on repaired lane",
        }
    }

    fn alternate_lane_context(&self, lane_index: usize) -> String {
        match self {
            Self::TcpIpv4 { .. } => {
                format!("failed to open agent TCP stream on alternate lane {lane_index}")
            }
            Self::TcpHost(_) => {
                format!("failed to open agent hostname TCP stream on alternate lane {lane_index}")
            }
            Self::UdpIpv4(_) => {
                format!("failed to open agent UDP stream on alternate lane {lane_index}")
            }
        }
    }

    fn repaired_alternate_lane_context(&self, lane_index: usize) -> String {
        match self {
            Self::TcpIpv4 { .. } => {
                format!("failed to open agent TCP stream on repaired alternate lane {lane_index}")
            }
            Self::TcpHost(_) => {
                format!(
                    "failed to open agent hostname TCP stream on repaired alternate lane {lane_index}"
                )
            }
            Self::UdpIpv4(_) => {
                format!("failed to open agent UDP stream on repaired alternate lane {lane_index}")
            }
        }
    }

    fn no_alternate_succeeded_context(&self) -> &'static str {
        match self {
            Self::TcpIpv4 { .. } => {
                "failed to open agent TCP stream on preferred lane and no alternate agent lane succeeded"
            }
            Self::TcpHost(_) => {
                "failed to open agent hostname TCP stream on preferred lane and no alternate agent lane succeeded"
            }
            Self::UdpIpv4(_) => {
                "failed to open agent UDP stream on preferred lane and no alternate agent lane succeeded"
            }
        }
    }

    fn log_alternate_opened(&self, lane_index: usize, skipped_index: usize, repaired: bool) {
        let request = match self {
            Self::TcpIpv4 { .. } => "TCP stream",
            Self::TcpHost(_) => "hostname TCP stream",
            Self::UdpIpv4(_) => "UDP stream",
        };
        let repaired = if repaired { "repaired " } else { "" };
        eprintln!(
            "agent: opened {request} on {repaired}alternate lane {lane_index} after lane {skipped_index} failed"
        );
    }
}

impl ReconnectingAgentBridge {
    #[cfg(test)]
    pub(crate) fn new(
        connector: Arc<dyn AgentBridgeConnector>,
        initial: Vec<AgentBridgeTransport>,
    ) -> Self {
        let desired_lanes = initial.len();
        Self::new_with_desired_lanes(connector, initial, desired_lanes)
    }

    pub(crate) fn new_with_desired_lanes(
        connector: Arc<dyn AgentBridgeConnector>,
        initial: Vec<AgentBridgeTransport>,
        desired_lanes: usize,
    ) -> Self {
        Self::new_with_desired_lanes_and_missing_repair_delay(
            connector,
            initial,
            desired_lanes,
            None,
        )
    }

    pub(crate) fn new_with_desired_lanes_and_missing_repair_delay(
        connector: Arc<dyn AgentBridgeConnector>,
        initial: Vec<AgentBridgeTransport>,
        desired_lanes: usize,
        missing_repair_delay: Option<Duration>,
    ) -> Self {
        assert!(
            !initial.is_empty(),
            "agent bridge requires at least one transport"
        );
        let desired_lanes = desired_lanes.max(initial.len());
        let first_effective_command = initial[0].agent_command.clone();
        let initial_len = initial.len();
        let mut lanes = initial
            .into_iter()
            .enumerate()
            .map(|(index, transport)| {
                let agent_command = transport.agent_command.clone();
                AgentBridgeLane::new(index, agent_command, Some(transport))
            })
            .collect::<Vec<_>>();
        for index in initial_len..desired_lanes {
            lanes.push(AgentBridgeLane::new(
                index,
                first_effective_command.clone(),
                None,
            ));
        }
        let bridge = Self {
            connector,
            lanes: Arc::new(lanes),
            desired_lanes,
            reconnects: Arc::new(AgentReconnectCounters::default()),
        };
        for index in initial_len..desired_lanes {
            bridge.spawn_lane_repair_with_delay(
                index,
                "missing startup exec transport".to_owned(),
                missing_repair_delay,
            );
        }
        bridge
    }

    pub(crate) async fn open_tcp_ipv4(
        &self,
        open: agent_proto::AgentOpenIpv4,
    ) -> Result<AgentBridgeStream> {
        self.open_request(AgentOpenRequest::TcpIpv4 {
            open,
            mode: AgentTcpOpenMode::Strict,
        })
        .await
    }

    pub(crate) async fn open_tcp_ipv4_optimistic(
        &self,
        open: agent_proto::AgentOpenIpv4,
    ) -> Result<AgentBridgeStream> {
        self.open_request(AgentOpenRequest::TcpIpv4 {
            open,
            mode: AgentTcpOpenMode::Optimistic,
        })
        .await
    }

    pub(crate) async fn open_tcp_host(
        &self,
        open: agent_proto::AgentOpenHost,
    ) -> Result<AgentBridgeStream> {
        self.open_request(AgentOpenRequest::TcpHost(open)).await
    }

    pub(crate) async fn open_udp_ipv4(
        &self,
        open: agent_proto::AgentOpenIpv4,
    ) -> Result<AgentBridgeStream> {
        self.open_request(AgentOpenRequest::UdpIpv4(open)).await
    }

    async fn open_request(&self, request: AgentOpenRequest) -> Result<AgentBridgeStream> {
        let (primary, secondary) = agent_lane_candidates(request.lane_hash(), self.lanes.len());
        let lane_index = self.choose_lane_index(primary, secondary).await;
        let lane = &self.lanes[lane_index];
        if let Some(err) = lane.quarantined_error().await {
            return self
                .open_request_on_alternate_lane(request, lane_index, err)
                .await;
        }
        let lease = self.reserve_lane(lane);
        let transport = match lane.current_transport().await {
            Some(transport) => transport,
            None => match self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
            {
                Ok(replacement) => replacement,
                Err(reconnect_err) => {
                    drop(lease);
                    return self
                        .open_request_on_alternate_lane(request, lane_index, reconnect_err)
                        .await;
                }
            },
        };
        match request.open(&transport).await {
            Ok(stream) => {
                lane.mark_open_success().await;
                Ok(lease.into_stream(stream))
            }
            Err(err) => {
                let Some(failure) = transport.failure_message().await else {
                    return Err(err);
                };
                let replacement = match self.reconnect_failed_lane(lane, failure).await {
                    Ok(replacement) => replacement,
                    Err(reconnect_err) => {
                        drop(lease);
                        return self
                            .open_request_on_alternate_lane(request, lane_index, reconnect_err)
                            .await;
                    }
                };
                match request.open(&replacement).await {
                    Ok(stream) => {
                        lane.mark_open_success().await;
                        Ok(lease.into_stream(stream))
                    }
                    Err(err) => {
                        if replacement.failure_message().await.is_some() {
                            drop(lease);
                            self.open_request_on_alternate_lane(request, lane_index, err)
                                .await
                        } else {
                            Err(err).context(request.repaired_lane_context())
                        }
                    }
                }
            }
        }
    }

    async fn open_request_on_alternate_lane(
        &self,
        request: AgentOpenRequest,
        skipped_index: usize,
        original_err: anyhow::Error,
    ) -> Result<AgentBridgeStream> {
        let mut last_err = original_err;
        let mut tried_lanes = 0_u64;
        while let Some(lane) = self.next_alternate_lane_by_load(skipped_index, tried_lanes) {
            tried_lanes |= agent_lane_bit(lane.index);
            let transport = match self.alternate_transport_or_repair(lane).await {
                Ok(Some(transport)) => transport,
                Ok(None) => continue,
                Err(err) => {
                    last_err = err;
                    continue;
                }
            };
            let lease = self.reserve_lane(lane);
            match request.open(&transport).await {
                Ok(stream) => {
                    lane.mark_open_success().await;
                    request.log_alternate_opened(lane.index, skipped_index, false);
                    return Ok(lease.into_stream(stream));
                }
                Err(err) => {
                    let Some(failure) = transport.failure_message().await else {
                        return Err(err)
                            .with_context(|| request.alternate_lane_context(lane.index));
                    };
                    drop(lease);
                    let repaired = match self.reconnect_failed_lane(lane, failure).await {
                        Ok(repaired) => repaired,
                        Err(reconnect_err) => {
                            last_err = reconnect_err;
                            continue;
                        }
                    };
                    let lease = self.reserve_lane(lane);
                    match request.open(&repaired).await {
                        Ok(stream) => {
                            lane.mark_open_success().await;
                            request.log_alternate_opened(lane.index, skipped_index, true);
                            return Ok(lease.into_stream(stream));
                        }
                        Err(err) => {
                            if repaired.failure_message().await.is_some() {
                                drop(lease);
                                last_err = err;
                                continue;
                            }
                            return Err(err).with_context(|| {
                                request.repaired_alternate_lane_context(lane.index)
                            });
                        }
                    }
                }
            }
        }
        Err(last_err).context(request.no_alternate_succeeded_context())
    }

    fn next_alternate_lane_by_load(
        &self,
        skipped_index: usize,
        tried_lanes: u64,
    ) -> Option<&AgentBridgeLane> {
        let mut best = None;
        for lane in self.lanes.iter() {
            if lane.index == skipped_index || tried_lanes & agent_lane_bit(lane.index) != 0 {
                continue;
            }
            let candidate = (lane.load(), lane.index);
            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
        best.and_then(|(_, index)| self.lanes.get(index))
    }

    async fn alternate_transport_or_repair(
        &self,
        lane: &AgentBridgeLane,
    ) -> Result<Option<agent_transport::AgentTransport>> {
        if lane.quarantine_remaining().await.is_some() {
            return Ok(None);
        }

        let Some(transport) = lane.current_transport().await else {
            return self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
                .map(Some);
        };

        match transport.failure_message().await {
            Some(failure) => self.reconnect_failed_lane(lane, failure).await.map(Some),
            None => Ok(Some(transport)),
        }
    }

    fn reserve_lane(&self, lane: &AgentBridgeLane) -> AgentLaneLease {
        AgentLaneLease::new(self.clone(), lane.index, lane.load_handle())
    }

    async fn choose_lane_index(&self, primary: usize, secondary: usize) -> usize {
        if primary == secondary || self.lanes.len() == 1 {
            return primary;
        }

        let primary_lane = &self.lanes[primary];
        let primary_status = primary_lane.selection_status().await;

        let secondary_lane = &self.lanes[secondary];
        let secondary_status = secondary_lane.selection_status().await;
        match (primary_status, secondary_status) {
            (
                AgentLaneSelectionStatus::Available { load: primary_load },
                AgentLaneSelectionStatus::Available {
                    load: secondary_load,
                },
            ) if secondary_load < primary_load => secondary,
            (AgentLaneSelectionStatus::Available { .. }, secondary_status) => {
                self.spawn_lane_repair_for_status(secondary, &secondary_status);
                primary
            }
            (primary_status, AgentLaneSelectionStatus::Available { .. }) => {
                self.spawn_lane_repair_for_status(primary, &primary_status);
                secondary
            }
            (primary_status, secondary_status) => {
                if let Some(index) = self
                    .best_available_lane_index_except(primary, secondary)
                    .await
                {
                    self.spawn_lane_repair_for_status(primary, &primary_status);
                    self.spawn_lane_repair_for_status(secondary, &secondary_status);
                    index
                } else {
                    primary
                }
            }
        }
    }

    async fn best_available_lane_index_except(
        &self,
        first_skipped: usize,
        second_skipped: usize,
    ) -> Option<usize> {
        let mut best = None;
        for lane in self
            .lanes
            .iter()
            .filter(|lane| lane.index != first_skipped && lane.index != second_skipped)
        {
            if let AgentLaneSelectionStatus::Available { load } = lane.selection_status().await {
                let candidate = (load, lane.index);
                if best.is_none_or(|current| candidate < current) {
                    best = Some(candidate);
                }
            }
        }
        best.map(|(_, index)| index)
    }

    fn spawn_lane_repair_for_status(&self, lane_index: usize, status: &AgentLaneSelectionStatus) {
        match status {
            AgentLaneSelectionStatus::Failed { failure } => {
                self.spawn_lane_repair(lane_index, failure.clone());
            }
            AgentLaneSelectionStatus::Missing => {
                self.spawn_lane_repair(lane_index, "missing startup exec transport".to_owned());
            }
            AgentLaneSelectionStatus::Available { .. }
            | AgentLaneSelectionStatus::Repairing
            | AgentLaneSelectionStatus::Quarantined => {}
        }
    }

    pub(crate) fn spawn_lane_repair(&self, lane_index: usize, failure: String) {
        self.spawn_lane_repair_with_delay(lane_index, failure, None);
    }

    fn spawn_lane_repair_with_delay(
        &self,
        lane_index: usize,
        failure: String,
        delay: Option<Duration>,
    ) {
        let lane = &self.lanes[lane_index];
        if !lane.try_start_background_repair() {
            return;
        }

        let lanes = Arc::downgrade(&self.lanes);
        let reconnects = Arc::downgrade(&self.reconnects);
        let connector = Arc::clone(&self.connector);
        tokio::spawn(async move {
            if let Some(delay) = delay.filter(|delay| !delay.is_zero()) {
                tokio::time::sleep(delay).await;
            }

            let mut last_failure = failure;
            let mut attempts = 0_usize;

            loop {
                let Some(lanes_for_wait) = lanes.upgrade() else {
                    return;
                };
                let remaining = {
                    let lane = &lanes_for_wait[lane_index];
                    lane.quarantine_remaining().await
                };
                drop(lanes_for_wait);
                if let Some(remaining) = remaining {
                    tokio::time::sleep(remaining).await;
                    continue;
                }

                if attempts >= AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS {
                    let Some(lanes_for_finish) = lanes.upgrade() else {
                        return;
                    };
                    let lane = &lanes_for_finish[lane_index];
                    lane.finish_background_repair().await;
                    eprintln!(
                        "agent: background repair of lane {} stopped after {} failed attempt(s)",
                        lane.index, attempts
                    );
                    return;
                }
                attempts = attempts.saturating_add(1);

                let Some(lanes_for_repair) = lanes.upgrade() else {
                    return;
                };
                let Some(reconnects) = reconnects.upgrade() else {
                    return;
                };
                let lane = &lanes_for_repair[lane_index];
                match ReconnectingAgentBridge::reconnect_failed_lane_with(
                    &connector,
                    &reconnects,
                    lane,
                    last_failure.clone(),
                )
                .await
                {
                    Ok(_) => {
                        lane.finish_background_repair().await;
                        return;
                    }
                    Err(err) => {
                        last_failure = err.to_string();
                        eprintln!(
                            "agent: background repair attempt {}/{} of lane {} failed: {err:#}",
                            attempts, AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS, lane.index
                        );
                    }
                }
            }
        });
    }

    #[cfg(test)]
    pub(crate) async fn choose_lane_index_for_test(
        &self,
        primary: usize,
        secondary: usize,
    ) -> usize {
        self.choose_lane_index(primary, secondary).await
    }

    #[cfg(test)]
    pub(crate) fn lane_load_for_test(&self, lane_index: usize) -> usize {
        self.lanes[lane_index].load()
    }

    #[cfg(test)]
    pub(crate) fn set_lane_load_for_test(&self, lane_index: usize, load: usize) {
        self.lanes[lane_index].set_load(load);
    }

    #[cfg(test)]
    pub(crate) fn next_alternate_lane_index_for_test(
        &self,
        skipped_index: usize,
        tried_lanes: u64,
    ) -> Option<usize> {
        self.next_alternate_lane_by_load(skipped_index, tried_lanes)
            .map(|lane| lane.index)
    }

    #[cfg(test)]
    pub(crate) fn try_start_background_lane_repair_for_test(&self, lane_index: usize) -> bool {
        self.lanes[lane_index].try_start_background_repair()
    }

    #[cfg(test)]
    pub(crate) async fn finish_background_lane_repair_for_test(&self, lane_index: usize) {
        self.lanes[lane_index].finish_background_repair().await;
    }

    pub(crate) fn reconnect_snapshot(&self) -> AgentReconnectSnapshot {
        self.reconnects.snapshot()
    }

    pub(crate) async fn snapshot(&self) -> AgentBridgeSnapshot {
        let mut snapshot = AgentBridgeSnapshot {
            reconnects: self.reconnect_snapshot(),
            lanes_total: self.lanes.len(),
            lanes_desired: self.desired_lanes,
            ..AgentBridgeSnapshot::default()
        };

        for lane in self.lanes.iter() {
            let lane_load = lane.load();
            snapshot.active_streams = snapshot.active_streams.saturating_add(lane_load);
            snapshot.max_lane_load = snapshot.max_lane_load.max(lane_load);
            let (quarantine_ms, repairing) = lane.snapshot_health().await;
            if let Some(quarantine_ms) = quarantine_ms {
                snapshot.lanes_quarantined = snapshot.lanes_quarantined.saturating_add(1);
                snapshot.max_quarantine_ms = snapshot.max_quarantine_ms.max(quarantine_ms);
            }
            if repairing {
                snapshot.lanes_repairing = snapshot.lanes_repairing.saturating_add(1);
            }

            match lane.current_transport().await {
                Some(transport) => {
                    let writer = transport.writer_snapshot();
                    snapshot.writer_queued_frames = snapshot
                        .writer_queued_frames
                        .saturating_add(writer.queued_frames);
                    snapshot.writer_queued_bytes = snapshot
                        .writer_queued_bytes
                        .saturating_add(writer.queued_bytes);
                    snapshot.writer_queued_frames_max = snapshot
                        .writer_queued_frames_max
                        .max(writer.queued_frames_max);
                    snapshot.writer_queued_bytes_max = snapshot
                        .writer_queued_bytes_max
                        .max(writer.queued_bytes_max);
                    snapshot.writer_bursts = snapshot.writer_bursts.saturating_add(writer.bursts);
                    snapshot.writer_burst_frames = snapshot
                        .writer_burst_frames
                        .saturating_add(writer.burst_frames);
                    snapshot.writer_burst_bytes = snapshot
                        .writer_burst_bytes
                        .saturating_add(writer.burst_bytes);
                    snapshot.writer_burst_frames_max = snapshot
                        .writer_burst_frames_max
                        .max(writer.burst_frames_max);
                    snapshot.writer_burst_bytes_max =
                        snapshot.writer_burst_bytes_max.max(writer.burst_bytes_max);
                    snapshot.writer_enqueue_to_write_us = snapshot
                        .writer_enqueue_to_write_us
                        .saturating_add(writer.enqueue_to_write_us);
                    snapshot.writer_enqueue_to_write_max_us = snapshot
                        .writer_enqueue_to_write_max_us
                        .max(writer.enqueue_to_write_max_us);
                    snapshot.writer_enqueue_to_write_samples = snapshot
                        .writer_enqueue_to_write_samples
                        .saturating_add(writer.enqueue_to_write_samples);
                    snapshot.writer_write_us =
                        snapshot.writer_write_us.saturating_add(writer.write_us);
                    snapshot.writer_write_max_us =
                        snapshot.writer_write_max_us.max(writer.write_max_us);
                    snapshot.writer_flush_us =
                        snapshot.writer_flush_us.saturating_add(writer.flush_us);
                    snapshot.writer_flush_max_us =
                        snapshot.writer_flush_max_us.max(writer.flush_max_us);

                    if transport.failure_message().await.is_some() {
                        snapshot.lanes_failed = snapshot.lanes_failed.saturating_add(1);
                    } else if quarantine_ms.is_none() {
                        snapshot.lanes_available = snapshot.lanes_available.saturating_add(1);
                    }
                }
                None => {
                    snapshot.lanes_missing = snapshot.lanes_missing.saturating_add(1);
                }
            }
        }

        snapshot
    }

    async fn reconnect_failed_lane(
        &self,
        lane: &AgentBridgeLane,
        failure: String,
    ) -> Result<agent_transport::AgentTransport> {
        Self::reconnect_failed_lane_with(&self.connector, &self.reconnects, lane, failure).await
    }

    async fn reconnect_failed_lane_with(
        connector: &Arc<dyn AgentBridgeConnector>,
        reconnects: &AgentReconnectCounters,
        lane: &AgentBridgeLane,
        failure: String,
    ) -> Result<agent_transport::AgentTransport> {
        if let Some(err) = lane.quarantined_error().await {
            return Err(err);
        }
        let mut inner = lane.inner.lock().await;
        let reconnect_command = match inner.as_ref() {
            Some(transport) => {
                if transport.transport.failure_message().await.is_none() {
                    return Ok(transport.transport.clone());
                }
                transport.agent_command.clone()
            }
            None => lane.agent_command.lock().await.clone(),
        };

        if inner.is_some() {
            eprintln!(
                "agent: reconnecting after transport failure on lane {}: {failure}",
                lane.index
            );
        } else {
            eprintln!(
                "agent: connecting missing exec transport on lane {}: {failure}",
                lane.index
            );
        }
        reconnects.record_attempt();
        let replacement = match Self::reconnect_agent_lane_transport_with(
            connector,
            lane.index,
            &reconnect_command,
            &failure,
        )
        .await
        {
            Ok(replacement) => replacement,
            Err(err) => {
                reconnects.record_failure();
                let backoff = lane.mark_reconnect_failure().await;
                eprintln!(
                    "agent: quarantined lane {} for {}ms after reconnect failure",
                    lane.index,
                    backoff.as_millis()
                );
                return Err(err);
            }
        };
        let replacement_command = replacement.agent_command.clone();
        let transport = replacement.transport.clone();
        *inner = Some(replacement);
        *lane.agent_command.lock().await = replacement_command;
        lane.mark_open_success().await;
        reconnects.record_success();
        Ok(transport)
    }

    async fn reconnect_agent_lane_transport_with(
        connector: &Arc<dyn AgentBridgeConnector>,
        lane_index: usize,
        reconnect_command: &str,
        failure: &str,
    ) -> Result<AgentBridgeTransport> {
        if reconnect_command == connector.primary_command() {
            return connector.connect_primary().await.with_context(|| {
                format!("failed to reconnect Rustle agent after transport failure: {failure}")
            });
        }

        match connector.connect_command(reconnect_command).await {
            Ok(replacement) => Ok(replacement),
            Err(reconnect_err) => {
                eprintln!(
                    "agent: lane {lane_index} effective reconnect command failed ({reconnect_err:#}); trying primary/bootstrap"
                );
                connector.connect_primary().await.with_context(|| {
                    format!(
                        "failed to reconnect Rustle agent after lane command failure ({reconnect_err:#}) and transport failure: {failure}"
                    )
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
