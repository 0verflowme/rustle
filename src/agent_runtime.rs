use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

use crate::agent_io::{
    AgentFrameBurstWriter, AgentFrameReader, AgentFrameWriteItem, AgentFrameWriteQueue,
    AgentFrameWriteReceiver, AGENT_FRAME_WRITE_BURST, AGENT_FRAME_WRITE_BURST_BYTES,
};
use crate::agent_proto::{
    AgentEofTiming, AgentFrame, AgentFrameKind, AgentHello, AgentOpenHost, AgentOpenIpv4,
    AgentOpenedTiming, AGENT_MAX_FRAME_PAYLOAD, CAP_FLOW_CONTROL,
};
use crate::agent_window::{AgentCreditWindow, AGENT_STREAM_MAX_WINDOW_BYTES};

const AGENT_OUTBOUND_FRAMES: usize = 512;
const AGENT_LOCAL_INPUT_FRAMES_PER_STREAM: usize = 128;
const AGENT_STREAM_COMPLETIONS: usize = 1024;
const AGENT_TCP_READ_CHUNK: usize = AGENT_MAX_FRAME_PAYLOAD;
const AGENT_UDP_READ_CHUNK: usize = 64 * 1024;
const AGENT_FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const AGENT_OUTPUT_PRODUCER_YIELD_FRAMES: usize = 8;

const _: () = assert!(
    AGENT_STREAM_MAX_WINDOW_BYTES <= AGENT_LOCAL_INPUT_FRAMES_PER_STREAM * AGENT_MAX_FRAME_PAYLOAD
);

#[derive(Clone, Copy, Debug)]
pub struct AgentRuntimeConfig {
    pub mtu: u16,
    tcp_connect_timeout: Duration,
}

impl AgentRuntimeConfig {
    pub fn new(mtu: u16) -> Self {
        Self {
            mtu,
            tcp_connect_timeout: AGENT_TCP_CONNECT_TIMEOUT,
        }
    }
}

enum AgentTcpInput {
    Data(Bytes),
    Eof,
}

enum AgentUdpInput {
    Data(Bytes),
}

struct AgentTcpHandle {
    to_remote: mpsc::Sender<AgentTcpInput>,
    output_credit: Arc<Semaphore>,
    task: JoinHandle<()>,
}

impl AgentTcpHandle {
    fn abort(self) {
        self.output_credit.close();
        self.task.abort();
    }

    fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

struct AgentUdpHandle {
    to_remote: mpsc::Sender<AgentUdpInput>,
    output_credit: Arc<Semaphore>,
    task: JoinHandle<()>,
}

impl AgentUdpHandle {
    fn abort(self) {
        self.output_credit.close();
        self.task.abort();
    }

    fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

enum AgentStreamHandle {
    Tcp(AgentTcpHandle),
    Udp(AgentUdpHandle),
}

#[derive(Clone)]
struct AgentTcpStreamOptions {
    connect_timeout: Duration,
    max_frame_payload: usize,
    done_tx: mpsc::Sender<u64>,
}

#[derive(Debug, Default)]
struct AgentTcpOutputTiming {
    remote_read_wait_us: u128,
    remote_read_wait_max_us: u128,
    remote_read_events: u64,
    output_credit_wait_us: u128,
    output_credit_wait_max_us: u128,
    output_send_wait_us: u128,
    output_send_wait_max_us: u128,
    output_frames: u64,
    remote_bytes: u64,
}

impl AgentTcpOutputTiming {
    fn record_remote_read_wait(&mut self, started_at: Instant) {
        let elapsed = started_at.elapsed().as_micros();
        self.remote_read_wait_us = self.remote_read_wait_us.saturating_add(elapsed);
        self.remote_read_wait_max_us = self.remote_read_wait_max_us.max(elapsed);
        self.remote_read_events = self.remote_read_events.saturating_add(1);
    }

    fn record_output_credit_wait(&mut self, started_at: Instant) {
        let elapsed = started_at.elapsed().as_micros();
        self.output_credit_wait_us = self.output_credit_wait_us.saturating_add(elapsed);
        self.output_credit_wait_max_us = self.output_credit_wait_max_us.max(elapsed);
    }

    fn record_output_send_wait(&mut self, started_at: Instant) {
        let elapsed = started_at.elapsed().as_micros();
        self.output_send_wait_us = self.output_send_wait_us.saturating_add(elapsed);
        self.output_send_wait_max_us = self.output_send_wait_max_us.max(elapsed);
    }

    fn record_output_frame(&mut self, bytes: usize) {
        self.output_frames = self.output_frames.saturating_add(1);
        self.remote_bytes = self.remote_bytes.saturating_add(bytes as u64);
    }

    fn encode(&self) -> Bytes {
        AgentEofTiming {
            remote_read_wait_us: micros_u128_to_u64(self.remote_read_wait_us),
            remote_read_wait_max_us: micros_u128_to_u64(self.remote_read_wait_max_us),
            remote_read_events: self.remote_read_events,
            output_credit_wait_us: micros_u128_to_u64(self.output_credit_wait_us),
            output_credit_wait_max_us: micros_u128_to_u64(self.output_credit_wait_max_us),
            output_send_wait_us: micros_u128_to_u64(self.output_send_wait_us),
            output_send_wait_max_us: micros_u128_to_u64(self.output_send_wait_max_us),
            output_frames: self.output_frames,
            remote_bytes: self.remote_bytes,
        }
        .encode()
    }
}

#[derive(Debug, Default)]
struct OutputProducerYieldBudget {
    frames_since_yield: usize,
}

impl OutputProducerYieldBudget {
    fn record_data_frame(&mut self) -> bool {
        self.frames_since_yield = self.frames_since_yield.saturating_add(1);
        if self.frames_since_yield < AGENT_OUTPUT_PRODUCER_YIELD_FRAMES {
            return false;
        }
        self.frames_since_yield = 0;
        true
    }
}

impl AgentStreamHandle {
    fn abort(self) {
        match self {
            Self::Tcp(handle) => handle.abort(),
            Self::Udp(handle) => handle.abort(),
        }
    }

    fn is_finished(&self) -> bool {
        match self {
            Self::Tcp(handle) => handle.is_finished(),
            Self::Udp(handle) => handle.is_finished(),
        }
    }
}

pub async fn run_stdio(config: AgentRuntimeConfig) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run(stdin, stdout, config).await
}

pub async fn run<R, W>(reader: R, writer: W, config: AgentRuntimeConfig) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, out_rx) = AgentFrameWriteQueue::channel(AGENT_OUTBOUND_FRAMES);
    let writer_task = tokio::spawn(write_agent_frames(writer, out_rx));
    let result = read_agent_frames(reader, config, out_tx.clone()).await;

    drop(out_tx);
    if result.is_err() {
        writer_task.abort();
        let _ = writer_task.await;
        return result;
    }

    match writer_task.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.context("agent writer failed after reader completed")),
        Err(err) => return Err(err.into()),
    }

    result
}

async fn write_agent_frames<W>(mut writer: W, mut out_rx: AgentFrameWriteReceiver) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut burst_writer = AgentFrameBurstWriter::new();
    let mut burst_items = Vec::with_capacity(AGENT_FRAME_WRITE_BURST);
    while let Some(first) = out_rx.recv().await {
        burst_items.clear();
        let mut burst_bytes = first.encoded_len();
        burst_items.push(first);
        for _ in 1..AGENT_FRAME_WRITE_BURST {
            if let Some(item) = out_rx.try_recv_priority() {
                burst_bytes = burst_bytes.saturating_add(item.encoded_len());
                burst_items.push(item);
                continue;
            }
            if burst_bytes >= AGENT_FRAME_WRITE_BURST_BYTES {
                break;
            }
            if let Some(item) = out_rx.try_recv_data() {
                burst_bytes = burst_bytes.saturating_add(item.encoded_len());
                burst_items.push(item);
            } else {
                break;
            }
        }
        burst_writer.write_items(&mut writer, &burst_items).await?;
    }
    writer
        .shutdown()
        .await
        .context("failed to shut down agent writer")
}

async fn read_agent_frames<R>(
    mut reader: R,
    config: AgentRuntimeConfig,
    out_tx: AgentFrameWriteQueue,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut frame_reader = AgentFrameReader::new();
    let mut streams = HashMap::<u64, AgentStreamHandle>::new();
    let (done_tx, mut done_rx) = mpsc::channel(AGENT_STREAM_COMPLETIONS);
    let mut peer_max_frame_payload = AGENT_MAX_FRAME_PAYLOAD;

    loop {
        drain_completed_streams(&mut done_rx, &mut streams);
        while let Some(frame) = frame_reader
            .try_next_frame()
            .context("failed to decode agent frame")?
        {
            drain_completed_streams(&mut done_rx, &mut streams);
            handle_agent_frame(
                frame,
                config,
                &out_tx,
                &done_tx,
                &mut streams,
                &mut peer_max_frame_payload,
            )
            .await?;
        }
        drain_completed_streams(&mut done_rx, &mut streams);

        tokio::select! {
            read = frame_reader.read_more(&mut reader, "failed to read agent input") => {
                if read? == 0 {
                    break;
                }
            }
            maybe_stream_id = done_rx.recv(), if !streams.is_empty() => {
                if let Some(stream_id) = maybe_stream_id {
                    streams.remove(&stream_id);
                }
            }
        }
    }

    for (_, handle) in streams {
        handle.abort();
    }
    Ok(())
}

fn drain_completed_streams(
    done_rx: &mut mpsc::Receiver<u64>,
    streams: &mut HashMap<u64, AgentStreamHandle>,
) {
    while let Ok(stream_id) = done_rx.try_recv() {
        streams.remove(&stream_id);
    }
}

fn remove_finished_stream_id(streams: &mut HashMap<u64, AgentStreamHandle>, stream_id: u64) {
    let should_remove = streams
        .get(&stream_id)
        .is_some_and(AgentStreamHandle::is_finished);
    if should_remove {
        streams.remove(&stream_id);
    }
}

async fn handle_agent_frame(
    frame: AgentFrame,
    config: AgentRuntimeConfig,
    out_tx: &AgentFrameWriteQueue,
    done_tx: &mpsc::Sender<u64>,
    streams: &mut HashMap<u64, AgentStreamHandle>,
    peer_max_frame_payload: &mut usize,
) -> Result<()> {
    match frame.kind {
        AgentFrameKind::Hello => {
            handle_hello_frame(frame, config, out_tx, peer_max_frame_payload).await?;
        }
        AgentFrameKind::OpenTcp => {
            handle_open_tcp_frame(
                frame,
                config,
                out_tx,
                done_tx,
                streams,
                *peer_max_frame_payload,
            )
            .await?;
        }
        AgentFrameKind::OpenTcpHost => {
            handle_open_tcp_host_frame(
                frame,
                config,
                out_tx,
                done_tx,
                streams,
                *peer_max_frame_payload,
            )
            .await?;
        }
        AgentFrameKind::OpenUdp => {
            handle_open_udp_frame(frame, out_tx, done_tx, streams).await?;
        }
        AgentFrameKind::Data => handle_data_frame(frame, out_tx, streams).await?,
        AgentFrameKind::Eof => handle_eof_frame(frame, out_tx, streams).await?,
        AgentFrameKind::Close | AgentFrameKind::Reset => {
            if let Some(stream) = streams.remove(&frame.stream_id) {
                stream.abort();
            }
        }
        AgentFrameKind::Window => {
            handle_window_frame(frame, streams);
        }
        AgentFrameKind::Opened => {
            send_reset(
                out_tx,
                frame.stream_id,
                "unsupported agent frame for remote agent",
            )
            .await?;
        }
        AgentFrameKind::Ping => handle_ping_frame(frame, out_tx).await?,
        AgentFrameKind::Pong => validate_pong_frame(frame)?,
    }
    Ok(())
}

async fn handle_hello_frame(
    frame: AgentFrame,
    config: AgentRuntimeConfig,
    out_tx: &AgentFrameWriteQueue,
    peer_max_frame_payload: &mut usize,
) -> Result<()> {
    let peer = AgentHello::decode(&frame.payload)?;
    if peer.protocol_version != crate::agent_proto::AGENT_PROTOCOL_VERSION {
        bail!(
            "unsupported agent protocol version {}",
            peer.protocol_version
        );
    }
    if peer.capabilities & CAP_FLOW_CONTROL == 0 {
        bail!("agent controller does not advertise flow-control support");
    }
    if peer.max_frame_payload == 0 {
        bail!("agent controller advertised zero max frame payload");
    }
    *peer_max_frame_payload = (peer.max_frame_payload as usize).min(AGENT_MAX_FRAME_PAYLOAD);
    send_agent_frame(
        out_tx,
        AgentFrame::new(
            AgentFrameKind::Hello,
            0,
            AgentHello::current(config.mtu).encode(),
        )?,
    )
    .await
}

async fn handle_open_tcp_frame(
    frame: AgentFrame,
    config: AgentRuntimeConfig,
    out_tx: &AgentFrameWriteQueue,
    done_tx: &mpsc::Sender<u64>,
    streams: &mut HashMap<u64, AgentStreamHandle>,
    peer_max_frame_payload: usize,
) -> Result<()> {
    if !prepare_new_stream_id(
        streams,
        out_tx,
        frame.stream_id,
        "agent TCP stream id must be non-zero",
    )
    .await?
    {
        return Ok(());
    }

    let open = AgentOpenIpv4::decode(&frame.payload)?;
    let (to_remote, from_local) = mpsc::channel(AGENT_LOCAL_INPUT_FRAMES_PER_STREAM);
    let output_credit = Arc::new(Semaphore::new(0));
    let options = tcp_stream_options(config, peer_max_frame_payload, done_tx);
    let task = tokio::spawn(run_tcp_stream(
        frame.stream_id,
        open,
        from_local,
        out_tx.clone(),
        Arc::clone(&output_credit),
        options,
    ));
    streams.insert(
        frame.stream_id,
        AgentStreamHandle::Tcp(AgentTcpHandle {
            to_remote,
            output_credit,
            task,
        }),
    );
    Ok(())
}

async fn handle_open_tcp_host_frame(
    frame: AgentFrame,
    config: AgentRuntimeConfig,
    out_tx: &AgentFrameWriteQueue,
    done_tx: &mpsc::Sender<u64>,
    streams: &mut HashMap<u64, AgentStreamHandle>,
    peer_max_frame_payload: usize,
) -> Result<()> {
    if !prepare_new_stream_id(
        streams,
        out_tx,
        frame.stream_id,
        "agent hostname TCP stream id must be non-zero",
    )
    .await?
    {
        return Ok(());
    }

    let open = AgentOpenHost::decode(&frame.payload)?;
    let (to_remote, from_local) = mpsc::channel(AGENT_LOCAL_INPUT_FRAMES_PER_STREAM);
    let output_credit = Arc::new(Semaphore::new(0));
    let options = tcp_stream_options(config, peer_max_frame_payload, done_tx);
    let task = tokio::spawn(run_tcp_host_stream(
        frame.stream_id,
        open,
        from_local,
        out_tx.clone(),
        Arc::clone(&output_credit),
        options,
    ));
    streams.insert(
        frame.stream_id,
        AgentStreamHandle::Tcp(AgentTcpHandle {
            to_remote,
            output_credit,
            task,
        }),
    );
    Ok(())
}

async fn handle_open_udp_frame(
    frame: AgentFrame,
    out_tx: &AgentFrameWriteQueue,
    done_tx: &mpsc::Sender<u64>,
    streams: &mut HashMap<u64, AgentStreamHandle>,
) -> Result<()> {
    if !prepare_new_stream_id(
        streams,
        out_tx,
        frame.stream_id,
        "agent UDP stream id must be non-zero",
    )
    .await?
    {
        return Ok(());
    }

    let open = AgentOpenIpv4::decode(&frame.payload)?;
    let (to_remote, from_local) = mpsc::channel(AGENT_LOCAL_INPUT_FRAMES_PER_STREAM);
    let output_credit = Arc::new(Semaphore::new(0));
    let task = tokio::spawn(run_udp_stream(
        frame.stream_id,
        open,
        from_local,
        out_tx.clone(),
        Arc::clone(&output_credit),
        done_tx.clone(),
    ));
    streams.insert(
        frame.stream_id,
        AgentStreamHandle::Udp(AgentUdpHandle {
            to_remote,
            output_credit,
            task,
        }),
    );
    Ok(())
}

async fn prepare_new_stream_id(
    streams: &mut HashMap<u64, AgentStreamHandle>,
    out_tx: &AgentFrameWriteQueue,
    stream_id: u64,
    zero_stream_error: &str,
) -> Result<bool> {
    if stream_id == 0 {
        bail!("{zero_stream_error}");
    }
    remove_finished_stream_id(streams, stream_id);
    if streams.contains_key(&stream_id) {
        send_reset(out_tx, stream_id, "stream id already exists").await?;
        return Ok(false);
    }
    Ok(true)
}

fn tcp_stream_options(
    config: AgentRuntimeConfig,
    peer_max_frame_payload: usize,
    done_tx: &mpsc::Sender<u64>,
) -> AgentTcpStreamOptions {
    AgentTcpStreamOptions {
        connect_timeout: config.tcp_connect_timeout,
        max_frame_payload: peer_max_frame_payload,
        done_tx: done_tx.clone(),
    }
}

async fn handle_data_frame(
    frame: AgentFrame,
    out_tx: &AgentFrameWriteQueue,
    streams: &mut HashMap<u64, AgentStreamHandle>,
) -> Result<()> {
    let stream_id = frame.stream_id;
    let Some(stream) = streams.get(&stream_id) else {
        send_reset(out_tx, frame.stream_id, "unknown stream id").await?;
        return Ok(());
    };
    let reset_reason = queue_stream_data(stream, frame.payload);
    reset_stream_with_reason(streams, out_tx, stream_id, reset_reason).await
}

async fn handle_eof_frame(
    frame: AgentFrame,
    out_tx: &AgentFrameWriteQueue,
    streams: &mut HashMap<u64, AgentStreamHandle>,
) -> Result<()> {
    let stream_id = frame.stream_id;
    let reset_reason = if let Some(AgentStreamHandle::Tcp(stream)) = streams.get(&stream_id) {
        queue_tcp_eof(stream)
    } else {
        None
    };
    reset_stream_with_reason(streams, out_tx, stream_id, reset_reason).await
}

fn queue_stream_data(stream: &AgentStreamHandle, payload: Bytes) -> Option<&'static str> {
    match stream {
        AgentStreamHandle::Tcp(stream) => {
            match stream.to_remote.try_send(AgentTcpInput::Data(payload)) {
                Ok(()) => None,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    Some("remote TCP stream input queue is full")
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Some("remote TCP stream task is closed")
                }
            }
        }
        AgentStreamHandle::Udp(stream) => {
            match stream.to_remote.try_send(AgentUdpInput::Data(payload)) {
                Ok(()) => None,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    Some("remote UDP stream input queue is full")
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Some("remote UDP stream task is closed")
                }
            }
        }
    }
}

fn queue_tcp_eof(stream: &AgentTcpHandle) -> Option<&'static str> {
    match stream.to_remote.try_send(AgentTcpInput::Eof) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Full(_)) => Some("remote TCP stream input queue is full"),
        Err(mpsc::error::TrySendError::Closed(_)) => Some("remote TCP stream task is closed"),
    }
}

async fn reset_stream_with_reason(
    streams: &mut HashMap<u64, AgentStreamHandle>,
    out_tx: &AgentFrameWriteQueue,
    stream_id: u64,
    reset_reason: Option<&str>,
) -> Result<()> {
    if let Some(reason) = reset_reason {
        if let Some(stream) = streams.remove(&stream_id) {
            stream.abort();
        }
        send_reset(out_tx, stream_id, reason).await?;
    }
    Ok(())
}

fn handle_window_frame(frame: AgentFrame, streams: &HashMap<u64, AgentStreamHandle>) {
    if frame.credit == 0 {
        return;
    }
    if let Some(stream) = streams.get(&frame.stream_id) {
        match stream {
            AgentStreamHandle::Tcp(stream) => {
                stream.output_credit.add_permits(frame.credit as usize);
            }
            AgentStreamHandle::Udp(stream) => {
                stream.output_credit.add_permits(frame.credit as usize);
            }
        }
    }
}

async fn handle_ping_frame(frame: AgentFrame, out_tx: &AgentFrameWriteQueue) -> Result<()> {
    if frame.stream_id != 0 {
        bail!("agent heartbeat ping must use stream id 0");
    }
    send_agent_frame(
        out_tx,
        AgentFrame::new(AgentFrameKind::Pong, 0, frame.payload)?,
    )
    .await
}

fn validate_pong_frame(frame: AgentFrame) -> Result<()> {
    if frame.stream_id != 0 {
        bail!("agent heartbeat pong must use stream id 0");
    }
    Ok(())
}

async fn run_tcp_stream(
    stream_id: u64,
    open: AgentOpenIpv4,
    from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    options: AgentTcpStreamOptions,
) {
    run_tcp_stream_inner(
        stream_id,
        open,
        from_local,
        out_tx,
        output_credit,
        options.clone(),
    )
    .await;
    let _ = options.done_tx.try_send(stream_id);
}

async fn run_tcp_host_stream(
    stream_id: u64,
    open: AgentOpenHost,
    from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    options: AgentTcpStreamOptions,
) {
    run_tcp_host_stream_inner(
        stream_id,
        open,
        from_local,
        out_tx,
        output_credit,
        options.clone(),
    )
    .await;
    let _ = options.done_tx.try_send(stream_id);
}

async fn run_tcp_stream_inner(
    stream_id: u64,
    open: AgentOpenIpv4,
    from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    options: AgentTcpStreamOptions,
) {
    let destination = SocketAddrV4::new(open.destination_ip, open.destination_port);
    let connect_started_at = Instant::now();
    let stream =
        tcp_connect_with_timeout(TcpStream::connect(destination), options.connect_timeout).await;
    let connect_elapsed = connect_started_at.elapsed();
    run_tcp_connected_stream(
        stream_id,
        stream,
        Some(connect_elapsed),
        from_local,
        out_tx,
        output_credit,
        options.max_frame_payload,
    )
    .await;
}

async fn run_tcp_host_stream_inner(
    stream_id: u64,
    open: AgentOpenHost,
    from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    options: AgentTcpStreamOptions,
) {
    let connect_started_at = Instant::now();
    let stream = tcp_connect_with_timeout(
        TcpStream::connect((open.destination_host.as_str(), open.destination_port)),
        options.connect_timeout,
    )
    .await;
    let connect_elapsed = connect_started_at.elapsed();
    run_tcp_connected_stream(
        stream_id,
        stream,
        Some(connect_elapsed),
        from_local,
        out_tx,
        output_credit,
        options.max_frame_payload,
    )
    .await;
}

async fn tcp_connect_with_timeout<F>(
    connect: F,
    timeout: Duration,
) -> std::result::Result<TcpStream, std::io::Error>
where
    F: Future<Output = std::result::Result<TcpStream, std::io::Error>>,
{
    match tokio::time::timeout(timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "timed out after {}ms connecting remote TCP stream",
                timeout.as_millis()
            ),
        )),
    }
}

async fn run_tcp_connected_stream(
    stream_id: u64,
    stream: Result<TcpStream, std::io::Error>,
    remote_connect_elapsed: Option<Duration>,
    from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    max_frame_payload: usize,
) {
    let Some(stream) = prepare_connected_tcp_stream(stream, stream_id, &out_tx).await else {
        return;
    };

    let (mut reader, writer) = stream.into_split();
    let write_out_tx = out_tx.clone();
    let writer_task = tokio::spawn(run_tcp_remote_writer(
        stream_id,
        writer,
        from_local,
        write_out_tx,
    ));

    if send_tcp_opened_frame(&out_tx, stream_id, remote_connect_elapsed)
        .await
        .is_err()
    {
        writer_task.abort();
        return;
    }

    run_tcp_output_loop(
        &mut reader,
        stream_id,
        &out_tx,
        output_credit,
        max_frame_payload,
    )
    .await;
    close_tcp_connected_stream(&out_tx, stream_id, writer_task).await;
}

async fn prepare_connected_tcp_stream(
    stream: Result<TcpStream, std::io::Error>,
    stream_id: u64,
    out_tx: &AgentFrameWriteQueue,
) -> Option<TcpStream> {
    match stream {
        Ok(stream) => {
            if let Err(err) = stream.set_nodelay(true) {
                let _ = send_reset(
                    out_tx,
                    stream_id,
                    &format!("failed to configure remote TCP stream: {err}"),
                )
                .await;
                return None;
            }
            Some(stream)
        }
        Err(err) => {
            let _ = send_reset(
                out_tx,
                stream_id,
                &format!("failed to connect remote TCP stream: {err}"),
            )
            .await;
            None
        }
    }
}

async fn run_tcp_remote_writer(
    stream_id: u64,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut from_local: mpsc::Receiver<AgentTcpInput>,
    out_tx: AgentFrameWriteQueue,
) {
    let mut receive_window = AgentCreditWindow::new();
    while let Some(input) = from_local.recv().await {
        match input {
            AgentTcpInput::Data(bytes) => {
                if write_tcp_remote_data(
                    stream_id,
                    &mut writer,
                    &out_tx,
                    &mut receive_window,
                    bytes,
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            AgentTcpInput::Eof => {
                shutdown_tcp_remote_writer(stream_id, &mut writer, &out_tx).await;
                return;
            }
        }
    }
}

async fn write_tcp_remote_data(
    stream_id: u64,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    out_tx: &AgentFrameWriteQueue,
    receive_window: &mut AgentCreditWindow,
    bytes: Bytes,
) -> Result<()> {
    let len = bytes.len();
    if let Err(err) = writer.write_all(&bytes).await {
        let _ = send_reset(
            out_tx,
            stream_id,
            &format!("failed to write remote TCP stream: {err}"),
        )
        .await;
        return Err(err.into());
    }
    record_receive_credit(out_tx, stream_id, receive_window, len).await
}

async fn shutdown_tcp_remote_writer(
    stream_id: u64,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    out_tx: &AgentFrameWriteQueue,
) {
    if let Err(err) = writer.shutdown().await {
        let _ = send_reset(
            out_tx,
            stream_id,
            &format!("failed to half-close remote TCP stream: {err}"),
        )
        .await;
    }
}

async fn send_tcp_opened_frame(
    out_tx: &AgentFrameWriteQueue,
    stream_id: u64,
    remote_connect_elapsed: Option<Duration>,
) -> Result<()> {
    let frame = AgentFrame::new(
        AgentFrameKind::Opened,
        stream_id,
        opened_timing_payload(remote_connect_elapsed),
    )
    .context("failed to build TCP opened frame")?
    .with_credit(AgentCreditWindow::initial_credit() as u32);
    send_agent_frame(out_tx, frame).await
}

async fn run_tcp_output_loop(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    stream_id: u64,
    out_tx: &AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    max_frame_payload: usize,
) {
    let read_chunk = max_frame_payload.clamp(1, AGENT_TCP_READ_CHUNK);
    let mut read_buf = vec![0_u8; read_chunk];
    let mut output_timing = AgentTcpOutputTiming::default();
    let mut output_yield_budget = OutputProducerYieldBudget::default();
    loop {
        let read_started_at = Instant::now();
        match reader.read(&mut read_buf).await {
            Ok(0) => {
                output_timing.record_remote_read_wait(read_started_at);
                match AgentFrame::new(AgentFrameKind::Eof, stream_id, output_timing.encode()) {
                    Ok(frame) => {
                        let _ = send_agent_frame(out_tx, frame).await;
                    }
                    Err(err) => {
                        let _ = send_reset(
                            out_tx,
                            stream_id,
                            &format!("failed to build TCP EOF frame: {err}"),
                        )
                        .await;
                    }
                }
                break;
            }
            Ok(len) => {
                output_timing.record_remote_read_wait(read_started_at);
                let bytes = Bytes::copy_from_slice(&read_buf[..len]);
                let credit_started_at = Instant::now();
                let permit = match output_credit.clone().acquire_many_owned(len as u32).await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                output_timing.record_output_credit_wait(credit_started_at);
                let send_started_at = Instant::now();
                let frame = match AgentFrame::new(AgentFrameKind::Data, stream_id, bytes) {
                    Ok(frame) => frame,
                    Err(err) => {
                        let _ = send_reset(
                            out_tx,
                            stream_id,
                            &format!("failed to build TCP data frame: {err}"),
                        )
                        .await;
                        break;
                    }
                };
                let send_result = send_agent_frame(out_tx, frame).await;
                output_timing.record_output_send_wait(send_started_at);
                if send_result.is_err() {
                    break;
                }
                output_timing.record_output_frame(len);
                permit.forget();
                yield_after_output_data_frame(&mut output_yield_budget).await;
            }
            Err(err) => {
                output_timing.record_remote_read_wait(read_started_at);
                let _ = send_reset(
                    out_tx,
                    stream_id,
                    &format!("failed to read remote TCP stream: {err}"),
                )
                .await;
                break;
            }
        }
    }
}

async fn close_tcp_connected_stream(
    out_tx: &AgentFrameWriteQueue,
    stream_id: u64,
    writer_task: JoinHandle<()>,
) {
    writer_task.abort();
    if let Ok(frame) = AgentFrame::new(AgentFrameKind::Close, stream_id, Bytes::new()) {
        let _ = send_agent_frame(out_tx, frame).await;
    }
}

fn opened_timing_payload(remote_connect_elapsed: Option<Duration>) -> Bytes {
    let Some(elapsed) = remote_connect_elapsed else {
        return Bytes::new();
    };
    AgentOpenedTiming {
        remote_connect_us: duration_micros_u64(elapsed),
    }
    .encode()
}

fn duration_micros_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn micros_u128_to_u64(micros: u128) -> u64 {
    u64::try_from(micros).unwrap_or(u64::MAX)
}

async fn run_udp_stream(
    stream_id: u64,
    open: AgentOpenIpv4,
    from_local: mpsc::Receiver<AgentUdpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
    done_tx: mpsc::Sender<u64>,
) {
    run_udp_stream_inner(stream_id, open, from_local, out_tx, output_credit).await;
    let _ = done_tx.try_send(stream_id);
}

async fn run_udp_stream_inner(
    stream_id: u64,
    open: AgentOpenIpv4,
    mut from_local: mpsc::Receiver<AgentUdpInput>,
    out_tx: AgentFrameWriteQueue,
    output_credit: Arc<Semaphore>,
) {
    let destination = SocketAddrV4::new(open.destination_ip, open.destination_port);
    let socket = match UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(err) => {
            let _ = send_reset(
                &out_tx,
                stream_id,
                &format!("failed to bind remote UDP socket: {err}"),
            )
            .await;
            return;
        }
    };

    if let Err(err) = socket.connect(destination).await {
        let _ = send_reset(
            &out_tx,
            stream_id,
            &format!("failed to connect remote UDP socket: {err}"),
        )
        .await;
        return;
    }

    let opened = match AgentFrame::new(AgentFrameKind::Opened, stream_id, Bytes::new()) {
        Ok(frame) => frame.with_credit(AgentCreditWindow::initial_credit() as u32),
        Err(err) => {
            let _ = send_reset(
                &out_tx,
                stream_id,
                &format!("failed to build UDP opened frame: {err}"),
            )
            .await;
            return;
        }
    };
    if send_agent_frame(&out_tx, opened).await.is_err() {
        return;
    }

    let socket = Arc::new(socket);
    let write_socket = Arc::clone(&socket);
    let write_out_tx = out_tx.clone();
    let writer_task = tokio::spawn(async move {
        let mut receive_window = AgentCreditWindow::new();
        while let Some(input) = from_local.recv().await {
            match input {
                AgentUdpInput::Data(bytes) => {
                    let len = bytes.len();
                    if let Err(err) = write_socket.send(&bytes).await {
                        let _ = send_reset(
                            &write_out_tx,
                            stream_id,
                            &format!("failed to write remote UDP socket: {err}"),
                        )
                        .await;
                        return;
                    }
                    if record_receive_credit(&write_out_tx, stream_id, &mut receive_window, len)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });

    let mut read_buf = vec![0_u8; AGENT_UDP_READ_CHUNK];
    let mut output_yield_budget = OutputProducerYieldBudget::default();
    loop {
        match socket.recv(&mut read_buf).await {
            Ok(len) => {
                let bytes = Bytes::copy_from_slice(&read_buf[..len]);
                let permit = match output_credit.clone().acquire_many_owned(len as u32).await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let frame = match AgentFrame::new(AgentFrameKind::Data, stream_id, bytes) {
                    Ok(frame) => frame,
                    Err(err) => {
                        let _ = send_reset(
                            &out_tx,
                            stream_id,
                            &format!("failed to build UDP data frame: {err}"),
                        )
                        .await;
                        break;
                    }
                };
                if send_agent_frame(&out_tx, frame).await.is_err() {
                    break;
                }
                permit.forget();
                yield_after_output_data_frame(&mut output_yield_budget).await;
            }
            Err(err) => {
                let _ = send_reset(
                    &out_tx,
                    stream_id,
                    &format!("failed to read remote UDP socket: {err}"),
                )
                .await;
                break;
            }
        }
    }

    writer_task.abort();
    if let Ok(frame) = AgentFrame::new(AgentFrameKind::Close, stream_id, Bytes::new()) {
        let _ = send_agent_frame(&out_tx, frame).await;
    }
}

async fn yield_after_output_data_frame(budget: &mut OutputProducerYieldBudget) {
    if budget.record_data_frame() {
        tokio::task::yield_now().await;
    }
}

async fn record_receive_credit(
    out_tx: &AgentFrameWriteQueue,
    stream_id: u64,
    receive_window: &mut AgentCreditWindow,
    bytes: usize,
) -> Result<()> {
    if let Some(credit) = receive_window.record_consumed(bytes) {
        send_window(out_tx, stream_id, credit).await?;
    }
    Ok(())
}

async fn send_reset(out_tx: &AgentFrameWriteQueue, stream_id: u64, reason: &str) -> Result<()> {
    let payload = Bytes::copy_from_slice(reason.as_bytes());
    send_agent_frame(
        out_tx,
        AgentFrame::new(AgentFrameKind::Reset, stream_id, payload)?,
    )
    .await
}

async fn send_window(out_tx: &AgentFrameWriteQueue, stream_id: u64, bytes: usize) -> Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    let credit = u32::try_from(bytes).context("agent window credit exceeds u32")?;
    send_agent_frame(
        out_tx,
        AgentFrame::new(AgentFrameKind::Window, stream_id, Bytes::new())?.with_credit(credit),
    )
    .await
}

async fn send_agent_frame(out_tx: &AgentFrameWriteQueue, frame: AgentFrame) -> Result<()> {
    send_agent_frame_with_timeout(out_tx, frame, AGENT_FRAME_SEND_TIMEOUT).await
}

async fn send_agent_frame_with_timeout(
    out_tx: &AgentFrameWriteQueue,
    frame: AgentFrame,
    timeout: Duration,
) -> Result<()> {
    let item = AgentFrameWriteItem::new(frame)?;
    match tokio::time::timeout(timeout, out_tx.reserve_owned(&item)).await {
        Ok(Ok(permit)) => {
            permit.send(item);
            Ok(())
        }
        Ok(Err(_)) => bail!("agent output channel closed"),
        Err(_) => bail!(
            "timed out after {}ms enqueueing agent output frame",
            timeout.as_millis()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    use bytes::BytesMut;
    use tokio::io::AsyncWrite;
    use tokio::io::{duplex, split};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::Notify;
    use tokio::time::timeout;

    use super::*;
    use crate::agent_io::{AGENT_FRAME_WRITE_BURST, AGENT_FRAME_WRITE_BURST_BYTES};
    use crate::agent_proto::{
        encode_frame, try_decode_frame, AgentHello, AgentOpenIpv4, AGENT_FRAME_HEADER_LEN,
    };
    use crate::agent_window::{
        AGENT_STREAM_INITIAL_WINDOW_BYTES as AGENT_STREAM_WINDOW_BYTES,
        AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES,
    };

    struct PendingWriter {
        entered_write: Arc<Notify>,
    }

    struct ShutdownFailWriter;

    #[derive(Clone, Default)]
    struct CountingWriter {
        writes: Arc<AtomicUsize>,
        flushes: Arc<AtomicUsize>,
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::AcqRel);
            self.bytes
                .lock()
                .expect("counting writer lock")
                .extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.entered_write.notify_waiters();
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ShutdownFailWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic shutdown failure",
            )))
        }
    }

    async fn queue_output_frame(out_tx: &AgentFrameWriteQueue, frame: AgentFrame) {
        send_agent_frame(out_tx, frame)
            .await
            .expect("queue agent output frame");
    }

    async fn recv_output_frame(out_rx: &mut AgentFrameWriteReceiver) -> AgentFrame {
        out_rx
            .recv()
            .await
            .expect("receive agent output frame")
            .frame
    }

    fn output_queue_is_empty(out_rx: &mut AgentFrameWriteReceiver) -> bool {
        out_rx.try_recv_priority().is_none() && out_rx.try_recv_data().is_none()
    }

    #[tokio::test]
    async fn agent_writer_flushes_once_per_queued_burst() {
        let writer = CountingWriter::default();
        let flushes = Arc::clone(&writer.flushes);
        let writes = Arc::clone(&writer.writes);
        let bytes = Arc::clone(&writer.bytes);
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(8);

        for stream_id in 1..=3 {
            queue_output_frame(
                &out_tx,
                AgentFrame::new(
                    AgentFrameKind::Data,
                    stream_id,
                    Bytes::copy_from_slice(&[stream_id as u8]),
                )
                .expect("data frame"),
            )
            .await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued burst");

        assert_eq!(writes.load(Ordering::Acquire), 1);
        assert_eq!(flushes.load(Ordering::Acquire), 1);
        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = 0;
        while try_decode_frame(&mut encoded)
            .expect("decode written frame")
            .is_some()
        {
            decoded += 1;
        }
        assert_eq!(decoded, 3);
        assert!(encoded.is_empty());
    }

    #[tokio::test]
    async fn agent_writer_clears_reused_buffers_between_bursts() {
        let writer = CountingWriter::default();
        let flushes = Arc::clone(&writer.flushes);
        let writes = Arc::clone(&writer.writes);
        let bytes = Arc::clone(&writer.bytes);
        let total_frames = AGENT_FRAME_WRITE_BURST + 1;
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(total_frames);

        for stream_id in 1..=total_frames {
            queue_output_frame(
                &out_tx,
                AgentFrame::new(
                    AgentFrameKind::Data,
                    stream_id as u64,
                    Bytes::copy_from_slice(&[stream_id as u8]),
                )
                .expect("data frame"),
            )
            .await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued bursts");

        assert_eq!(writes.load(Ordering::Acquire), 2);
        assert_eq!(flushes.load(Ordering::Acquire), 2);
        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = Vec::new();
        while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
            decoded.push(frame.stream_id);
        }
        assert_eq!(decoded.len(), total_frames);
        assert_eq!(decoded[0], 1);
        assert_eq!(
            decoded[AGENT_FRAME_WRITE_BURST - 1],
            AGENT_FRAME_WRITE_BURST as u64
        );
        assert_eq!(decoded[AGENT_FRAME_WRITE_BURST], total_frames as u64);
        assert!(encoded.is_empty());
    }

    #[tokio::test]
    async fn agent_writer_caps_large_data_burst_by_encoded_bytes() {
        let writer = CountingWriter::default();
        let flushes = Arc::clone(&writer.flushes);
        let writes = Arc::clone(&writer.writes);
        let frames_until_byte_cap =
            AGENT_FRAME_WRITE_BURST_BYTES / (AGENT_MAX_FRAME_PAYLOAD + AGENT_FRAME_HEADER_LEN) + 1;
        assert_eq!(frames_until_byte_cap, 4);
        assert!(frames_until_byte_cap < AGENT_FRAME_WRITE_BURST);
        let total_frames = frames_until_byte_cap + 1;
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(total_frames);

        for stream_id in 1..=total_frames {
            queue_output_frame(
                &out_tx,
                AgentFrame::new(
                    AgentFrameKind::Data,
                    stream_id as u64,
                    Bytes::from(vec![0x5a; AGENT_MAX_FRAME_PAYLOAD]),
                )
                .expect("data frame"),
            )
            .await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write byte-capped bursts");

        assert_eq!(writes.load(Ordering::Acquire), 2);
        assert_eq!(flushes.load(Ordering::Acquire), 2);
    }

    #[test]
    fn output_producer_yield_budget_yields_after_bounded_data_frames() {
        let mut budget = OutputProducerYieldBudget::default();

        for _ in 1..AGENT_OUTPUT_PRODUCER_YIELD_FRAMES {
            assert!(
                !budget.record_data_frame(),
                "producer should keep sending until the yield budget is exhausted"
            );
        }

        assert!(budget.record_data_frame(), "budget should yield on the cap");
        assert!(
            !budget.record_data_frame(),
            "budget should reset after forcing a yield"
        );
    }

    #[test]
    fn tcp_read_chunk_matches_agent_frame_payload() {
        assert_eq!(AGENT_TCP_READ_CHUNK, AGENT_MAX_FRAME_PAYLOAD);
    }

    #[tokio::test]
    async fn agent_writer_prioritizes_control_frames_inside_burst() {
        let writer = CountingWriter::default();
        let bytes = Arc::clone(&writer.bytes);
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(8);

        for frame in [
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                .expect("window frame")
                .with_credit(32),
            AgentFrame::new(AgentFrameKind::Pong, 0, Bytes::new()).expect("pong frame"),
            AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"two"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Opened, 4, Bytes::new()).expect("opened frame"),
        ] {
            queue_output_frame(&out_tx, frame).await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued burst");

        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = Vec::new();
        while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
            decoded.push((frame.kind, frame.stream_id));
        }
        assert_eq!(
            decoded,
            vec![
                (AgentFrameKind::Window, 1),
                (AgentFrameKind::Pong, 0),
                (AgentFrameKind::Opened, 4),
                (AgentFrameKind::Data, 1),
                (AgentFrameKind::Data, 3),
            ]
        );
    }

    #[tokio::test]
    async fn agent_writer_round_robins_non_priority_frames_inside_burst() {
        let writer = CountingWriter::default();
        let bytes = Arc::clone(&writer.bytes);
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(8);

        for frame in [
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one-a"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one-b"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"three-a"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"three-b"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Data, 5, Bytes::from_static(b"five-a"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).expect("eof frame"),
        ] {
            queue_output_frame(&out_tx, frame).await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued burst");

        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = Vec::new();
        while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
            decoded.push((frame.kind, frame.stream_id, frame.payload));
        }
        assert_eq!(
            decoded,
            vec![
                (AgentFrameKind::Data, 1, Bytes::from_static(b"one-a")),
                (AgentFrameKind::Data, 3, Bytes::from_static(b"three-a")),
                (AgentFrameKind::Data, 5, Bytes::from_static(b"five-a")),
                (AgentFrameKind::Data, 1, Bytes::from_static(b"one-b")),
                (AgentFrameKind::Data, 3, Bytes::from_static(b"three-b")),
                (AgentFrameKind::Eof, 1, Bytes::new()),
            ]
        );
    }

    #[tokio::test]
    async fn agent_writer_keeps_eof_after_preceding_data_inside_burst() {
        let writer = CountingWriter::default();
        let bytes = Arc::clone(&writer.bytes);
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(8);

        for frame in [
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"response"))
                .expect("data frame"),
            AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).expect("eof frame"),
            AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                .expect("window frame")
                .with_credit(32),
        ] {
            queue_output_frame(&out_tx, frame).await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued burst");

        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = Vec::new();
        while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
            decoded.push((frame.kind, frame.stream_id));
        }
        assert_eq!(
            decoded,
            vec![
                (AgentFrameKind::Window, 1),
                (AgentFrameKind::Data, 1),
                (AgentFrameKind::Eof, 1),
            ]
        );
    }

    #[tokio::test]
    async fn agent_writer_keeps_hello_before_heartbeat_frames() {
        let writer = CountingWriter::default();
        let bytes = Arc::clone(&writer.bytes);
        let (out_tx, out_rx) = AgentFrameWriteQueue::channel(8);

        for frame in [
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("hello frame"),
            AgentFrame::new(AgentFrameKind::Pong, 0, Bytes::new()).expect("pong frame"),
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"payload"))
                .expect("data frame"),
        ] {
            queue_output_frame(&out_tx, frame).await;
        }
        drop(out_tx);

        write_agent_frames(writer, out_rx)
            .await
            .expect("write queued burst");

        let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
        let mut decoded = Vec::new();
        while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
            decoded.push((frame.kind, frame.stream_id));
        }
        assert_eq!(
            decoded,
            vec![
                (AgentFrameKind::Hello, 0),
                (AgentFrameKind::Pong, 0),
                (AgentFrameKind::Data, 1),
            ]
        );
    }

    #[tokio::test]
    async fn runtime_receive_credit_batches_until_threshold() {
        let (out_tx, mut out_rx) = AgentFrameWriteQueue::channel(8);
        let mut receive_window = AgentCreditWindow::new();
        let chunk = AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES / 4;

        for _ in 0..3 {
            record_receive_credit(&out_tx, 7, &mut receive_window, chunk)
                .await
                .expect("record receive credit below threshold");
            assert!(
                output_queue_is_empty(&mut out_rx),
                "receive credit below threshold should stay batched"
            );
        }

        record_receive_credit(&out_tx, 7, &mut receive_window, chunk)
            .await
            .expect("record receive credit at threshold");

        let window = recv_output_frame(&mut out_rx).await;
        assert_eq!(window.kind, AgentFrameKind::Window);
        assert_eq!(window.stream_id, 7);
        assert_eq!(
            window.credit as usize,
            AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES
        );
        assert!(
            output_queue_is_empty(&mut out_rx),
            "batched receive credit should emit exactly one window"
        );
    }

    #[tokio::test]
    async fn runtime_receive_credit_grants_max_frame_immediately() {
        let (out_tx, mut out_rx) = AgentFrameWriteQueue::channel(8);
        let mut receive_window = AgentCreditWindow::new();

        record_receive_credit(
            &out_tx,
            9,
            &mut receive_window,
            AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES,
        )
        .await
        .expect("record max-frame receive credit");

        let window = recv_output_frame(&mut out_rx).await;
        assert_eq!(window.kind, AgentFrameKind::Window);
        assert_eq!(window.stream_id, 9);
        assert_eq!(
            window.credit as usize,
            AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES
        );
        assert!(
            output_queue_is_empty(&mut out_rx),
            "single max frame should emit exactly one window"
        );
    }

    #[tokio::test]
    async fn runtime_receive_credit_grows_after_sustained_window_consumption() {
        let (out_tx, mut out_rx) = AgentFrameWriteQueue::channel(8);
        let mut receive_window = AgentCreditWindow::new();

        record_receive_credit(&out_tx, 11, &mut receive_window, AGENT_STREAM_WINDOW_BYTES)
            .await
            .expect("record sustained receive credit");

        let window = recv_output_frame(&mut out_rx).await;
        assert_eq!(window.kind, AgentFrameKind::Window);
        assert_eq!(window.stream_id, 11);
        assert!(window.credit as usize > AGENT_STREAM_WINDOW_BYTES);
        assert!(receive_window.current_window() > AGENT_STREAM_WINDOW_BYTES);
    }

    #[tokio::test]
    async fn agent_replies_to_heartbeat_ping() {
        let (client_io, agent_io) = duplex(256 * 1024);
        let (agent_reader, agent_writer) = split(agent_io);
        let agent = tokio::spawn(run(
            agent_reader,
            agent_writer,
            AgentRuntimeConfig::new(1300),
        ));

        let (mut client_reader, mut client_writer) = split(client_io);
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;

        let mut inbound = BytesMut::new();
        let hello = read_test_frame(&mut client_reader, &mut inbound, "hello").await;
        assert_eq!(hello.kind, AgentFrameKind::Hello);

        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::from_static(b"beat")).unwrap(),
        )
        .await;
        let pong = read_test_frame(&mut client_reader, &mut inbound, "heartbeat pong").await;
        assert_eq!(pong.kind, AgentFrameKind::Pong);
        assert_eq!(pong.stream_id, 0);
        assert_eq!(&pong.payload[..], b"beat");

        drop(client_writer);
        drop(client_reader);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client EOF")
            .expect("agent task join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn agent_output_send_times_out_when_queue_is_full() {
        let (out_tx, _out_rx) = AgentFrameWriteQueue::channel(1);
        queue_output_frame(
            &out_tx,
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).unwrap(),
        )
        .await;

        let err = send_agent_frame_with_timeout(
            &out_tx,
            AgentFrame::new(AgentFrameKind::Pong, 0, Bytes::new()).unwrap(),
            Duration::from_millis(25),
        )
        .await
        .expect_err("send should time out while queue is full");
        assert!(
            err.to_string().contains("enqueueing agent output frame"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn agent_resets_tcp_stream_when_input_queue_is_full() {
        let (out_tx, mut out_rx) = AgentFrameWriteQueue::channel(4);
        let (done_tx, _done_rx) = mpsc::channel(4);
        let mut streams = HashMap::new();
        let (to_remote, _from_local) = mpsc::channel(1);
        to_remote
            .try_send(AgentTcpInput::Data(Bytes::from_static(b"queued")))
            .expect("prefill remote input queue");
        let output_credit = Arc::new(Semaphore::new(0));
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        streams.insert(
            7,
            AgentStreamHandle::Tcp(AgentTcpHandle {
                to_remote,
                output_credit,
                task,
            }),
        );
        let mut peer_max_frame_payload = AGENT_MAX_FRAME_PAYLOAD;

        handle_agent_frame(
            AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from_static(b"blocked")).unwrap(),
            AgentRuntimeConfig::new(1300),
            &out_tx,
            &done_tx,
            &mut streams,
            &mut peer_max_frame_payload,
        )
        .await
        .expect("full stream input queue should reset stream");

        assert!(streams.is_empty());
        let reset = timeout(Duration::from_secs(1), recv_output_frame(&mut out_rx))
            .await
            .expect("timed out waiting for reset");
        assert_eq!(reset.kind, AgentFrameKind::Reset);
        assert_eq!(reset.stream_id, 7);
        assert!(
            String::from_utf8_lossy(&reset.payload).contains("input queue is full"),
            "unexpected reset: {reset:?}"
        );
    }

    #[tokio::test]
    async fn stream_task_does_not_wait_for_full_completion_queue() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind listener");
        let destination = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept connection");
        });

        let (from_local, remote_rx) = mpsc::channel(1);
        drop(from_local);
        let (out_tx, _out_rx) = AgentFrameWriteQueue::channel(8);
        let output_credit = Arc::new(Semaphore::new(AGENT_STREAM_WINDOW_BYTES));
        let (done_tx, _done_rx) = mpsc::channel(1);
        done_tx.try_send(999).expect("prefill completion queue");

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
        };
        timeout(
            Duration::from_secs(1),
            run_tcp_stream(
                7,
                AgentOpenIpv4 {
                    destination_ip: *destination.ip(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                },
                remote_rx,
                out_tx,
                output_credit,
                AgentTcpStreamOptions {
                    connect_timeout: AGENT_TCP_CONNECT_TIMEOUT,
                    max_frame_payload: AGENT_TCP_READ_CHUNK,
                    done_tx,
                },
            ),
        )
        .await
        .expect("stream task should not wait on full completion queue");
        server.await.expect("server join");
    }

    #[tokio::test]
    async fn tcp_connect_with_timeout_returns_timed_out_error() {
        let err = tcp_connect_with_timeout(
            std::future::pending::<std::result::Result<TcpStream, std::io::Error>>(),
            Duration::from_millis(1),
        )
        .await
        .expect_err("pending TCP connect should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("timed out after 1ms"),
            "unexpected timeout error: {err}"
        );
    }

    #[tokio::test]
    async fn tcp_connect_timeout_is_reported_as_stream_reset() {
        let (_to_remote, from_local) = mpsc::channel(1);
        let (out_tx, mut out_rx) = AgentFrameWriteQueue::channel(4);
        run_tcp_connected_stream(
            9,
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out after 1ms connecting remote TCP stream",
            )),
            None,
            from_local,
            out_tx,
            Arc::new(Semaphore::new(0)),
            AGENT_TCP_READ_CHUNK,
        )
        .await;

        let frame = recv_output_frame(&mut out_rx).await;
        assert_eq!(frame.kind, AgentFrameKind::Reset);
        assert_eq!(frame.stream_id, 9);
        let reason = String::from_utf8_lossy(&frame.payload);
        assert!(
            reason.contains("failed to connect remote TCP stream"),
            "unexpected reset reason: {reason}"
        );
        assert!(
            reason.contains("timed out after 1ms"),
            "reset should preserve timeout context: {reason}"
        );
    }

    #[tokio::test]
    async fn tcp_writer_drains_queued_data_before_opened_enqueue_completes() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind listener");
        let destination = listener.local_addr().expect("listener address");
        let client_stream = TcpStream::connect(destination)
            .await
            .expect("connect remote TCP");
        let (mut server_socket, _) = listener.accept().await.expect("accept remote TCP");

        let (to_remote, from_local) = mpsc::channel(2);
        to_remote
            .try_send(AgentTcpInput::Data(Bytes::from_static(b"queued")))
            .expect("queue optimistic request bytes");
        to_remote
            .try_send(AgentTcpInput::Eof)
            .expect("queue optimistic EOF");

        let (out_tx, _out_rx) = AgentFrameWriteQueue::channel(1);
        queue_output_frame(
            &out_tx,
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).unwrap(),
        )
        .await;
        let task = tokio::spawn(run_tcp_connected_stream(
            7,
            Ok(client_stream),
            None,
            from_local,
            out_tx,
            Arc::new(Semaphore::new(AGENT_STREAM_WINDOW_BYTES)),
            AGENT_TCP_READ_CHUNK,
        ));

        let mut received = [0_u8; 6];
        timeout(
            Duration::from_secs(1),
            server_socket.read_exact(&mut received),
        )
        .await
        .expect("queued request bytes should reach remote before opened enqueue completes")
        .expect("read queued request bytes");
        assert_eq!(&received, b"queued");

        task.abort();
    }

    #[tokio::test]
    async fn run_aborts_blocked_writer_after_reader_error() {
        let (mut client, agent_reader) = duplex(256 * 1024);
        let entered_write = Arc::new(Notify::new());
        let agent = tokio::spawn(run(
            agent_reader,
            PendingWriter {
                entered_write: Arc::clone(&entered_write),
            },
            AgentRuntimeConfig::new(1300),
        ));

        write_test_frame(
            &mut client,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;
        timeout(Duration::from_secs(1), entered_write.notified())
            .await
            .expect("writer should block on hello response");
        client
            .write_all(&[0xff; crate::agent_proto::AGENT_FRAME_HEADER_LEN])
            .await
            .expect("write invalid frame");

        let result = timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent should exit after reader error")
            .expect("agent join");
        assert!(result.is_err(), "invalid frame should fail agent run");
    }

    #[tokio::test]
    async fn run_reports_writer_error_after_reader_eof() {
        let (mut client, agent_reader) = duplex(256 * 1024);
        let agent = tokio::spawn(run(
            agent_reader,
            ShutdownFailWriter,
            AgentRuntimeConfig::new(1300),
        ));

        write_test_frame(
            &mut client,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;
        drop(client);

        let err = timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent should exit after reader EOF")
            .expect("agent join")
            .expect_err("writer shutdown failure should fail agent run");
        assert!(
            format!("{err:#}").contains("agent writer failed after reader completed"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn agent_opens_tcp_stream_and_relays_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind echo listener");
        let destination = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept remote TCP");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read remote request");
            socket.write_all(b"echo:").await.expect("write prefix");
            socket.write_all(&request).await.expect("write request");
            socket.shutdown().await.expect("shutdown echo socket");
        });

        let (client_io, agent_io) = duplex(256 * 1024);
        let (agent_reader, agent_writer) = split(agent_io);
        let agent = tokio::spawn(run(
            agent_reader,
            agent_writer,
            AgentRuntimeConfig::new(1300),
        ));

        let (mut client_reader, mut client_writer) = split(client_io);
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;

        let mut inbound = BytesMut::new();
        let hello = read_test_frame(&mut client_reader, &mut inbound, "hello").await;
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        assert_eq!(
            AgentHello::decode(&hello.payload).unwrap().protocol_version,
            crate::agent_proto::AGENT_PROTOCOL_VERSION
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
        };
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(
                AgentFrameKind::OpenTcp,
                1,
                AgentOpenIpv4 {
                    destination_ip: *destination.ip(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                }
                .encode(),
            )
            .unwrap(),
        )
        .await;

        let opened = read_test_frame(&mut client_reader, &mut inbound, "opened").await;
        assert_eq!(opened.kind, AgentFrameKind::Opened);
        assert_eq!(opened.stream_id, 1);
        assert!(opened.credit > 0);

        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                .unwrap()
                .with_credit(AGENT_STREAM_WINDOW_BYTES as u32),
        )
        .await;

        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"hello")).unwrap(),
        )
        .await;
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).unwrap(),
        )
        .await;

        let mut response = Vec::new();
        let mut saw_eof = false;
        let mut saw_close = false;
        for _ in 0..16 {
            let frame = read_test_frame(&mut client_reader, &mut inbound, "response").await;
            match frame.kind {
                AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                AgentFrameKind::Window => panic!("tiny TCP request should not emit a window"),
                AgentFrameKind::Eof => saw_eof = true,
                AgentFrameKind::Close => {
                    saw_close = true;
                    break;
                }
                other => panic!("unexpected frame from agent: {other:?}"),
            }
        }

        assert_eq!(response, b"echo:hello");
        assert!(saw_eof);
        assert!(saw_close);

        drop(client_writer);
        drop(client_reader);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client EOF")
            .expect("agent task join")
            .expect("agent run");
        server.await.expect("server task join");
    }

    #[tokio::test]
    async fn agent_tcp_output_honors_controller_frame_cap() {
        let peer_frame_cap = 1024_usize;
        let response_body = vec![0x5a; peer_frame_cap * 3 + 17];
        let expected_response_len = response_body.len();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP listener");
        let destination = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept remote TCP");
            socket
                .write_all(&response_body)
                .await
                .expect("write remote response");
            socket.shutdown().await.expect("shutdown remote TCP");
        });

        let (client_io, agent_io) = duplex(256 * 1024);
        let (agent_reader, agent_writer) = split(agent_io);
        let agent = tokio::spawn(run(
            agent_reader,
            agent_writer,
            AgentRuntimeConfig::new(1300),
        ));
        let (mut client_reader, mut client_writer) = split(client_io);

        let mut controller_hello = AgentHello::current(1300);
        controller_hello.max_frame_payload = peer_frame_cap as u32;
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Hello, 0, controller_hello.encode()).unwrap(),
        )
        .await;

        let mut inbound = BytesMut::new();
        let hello = read_test_frame(&mut client_reader, &mut inbound, "hello").await;
        assert_eq!(hello.kind, AgentFrameKind::Hello);

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
        };
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(
                AgentFrameKind::OpenTcp,
                1,
                AgentOpenIpv4 {
                    destination_ip: *destination.ip(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                }
                .encode(),
            )
            .unwrap(),
        )
        .await;

        let opened = read_test_frame(&mut client_reader, &mut inbound, "opened").await;
        assert_eq!(opened.kind, AgentFrameKind::Opened);
        assert_eq!(opened.stream_id, 1);
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                .unwrap()
                .with_credit(AGENT_STREAM_WINDOW_BYTES as u32),
        )
        .await;

        let mut response_len = 0_usize;
        let mut saw_eof = false;
        let mut saw_close = false;
        for _ in 0..16 {
            let frame = read_test_frame(&mut client_reader, &mut inbound, "capped response").await;
            match frame.kind {
                AgentFrameKind::Data => {
                    assert!(
                        frame.payload.len() <= peer_frame_cap,
                        "payload length {} exceeded controller cap {peer_frame_cap}",
                        frame.payload.len()
                    );
                    response_len += frame.payload.len();
                }
                AgentFrameKind::Eof => saw_eof = true,
                AgentFrameKind::Close => {
                    saw_close = true;
                    break;
                }
                other => panic!("unexpected frame from agent: {other:?}"),
            }
        }

        assert_eq!(response_len, expected_response_len);
        assert!(saw_eof);
        assert!(saw_close);

        drop(client_writer);
        drop(client_reader);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client EOF")
            .expect("agent task join")
            .expect("agent run");
        server.await.expect("server task join");
    }

    #[tokio::test]
    async fn agent_removes_completed_tcp_stream_without_peer_close() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind echo listener");
        let destination = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("accept remote TCP");
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    socket
                        .read_to_end(&mut request)
                        .await
                        .expect("read remote request");
                    socket.write_all(b"done:").await.expect("write prefix");
                    socket.write_all(&request).await.expect("write request");
                    socket.shutdown().await.expect("shutdown echo socket");
                });
            }
        });

        let (client_io, agent_io) = duplex(256 * 1024);
        let (agent_reader, agent_writer) = split(agent_io);
        let agent = tokio::spawn(run(
            agent_reader,
            agent_writer,
            AgentRuntimeConfig::new(1300),
        ));

        let (mut client_reader, mut client_writer) = split(client_io);
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;

        let mut inbound = BytesMut::new();
        let hello = read_test_frame(&mut client_reader, &mut inbound, "hello").await;
        assert_eq!(hello.kind, AgentFrameKind::Hello);

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
        };
        for attempt in 0..2 {
            write_test_frame(
                &mut client_writer,
                AgentFrame::new(
                    AgentFrameKind::OpenTcp,
                    1,
                    AgentOpenIpv4 {
                        destination_ip: *destination.ip(),
                        destination_port: destination.port(),
                        originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                        originator_port: 49152 + attempt,
                    }
                    .encode(),
                )
                .unwrap(),
            )
            .await;

            let opened = read_test_frame(&mut client_reader, &mut inbound, "opened").await;
            assert_eq!(opened.kind, AgentFrameKind::Opened);
            assert_eq!(opened.stream_id, 1);

            write_test_frame(
                &mut client_writer,
                AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                    .unwrap()
                    .with_credit(AGENT_STREAM_WINDOW_BYTES as u32),
            )
            .await;
            write_test_frame(
                &mut client_writer,
                AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"again")).unwrap(),
            )
            .await;
            write_test_frame(
                &mut client_writer,
                AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).unwrap(),
            )
            .await;

            let mut response = Vec::new();
            let mut saw_close = false;
            for _ in 0..16 {
                let frame = read_test_frame(&mut client_reader, &mut inbound, "response").await;
                match frame.kind {
                    AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                    AgentFrameKind::Window => panic!("tiny TCP request should not emit a window"),
                    AgentFrameKind::Eof => {}
                    AgentFrameKind::Close => {
                        saw_close = true;
                        break;
                    }
                    other => panic!("unexpected frame from agent: {other:?}"),
                }
            }
            assert_eq!(response, b"done:again");
            assert!(saw_close);
        }

        drop(client_writer);
        drop(client_reader);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client EOF")
            .expect("agent task join")
            .expect("agent run");
        server.await.expect("server task join");
    }

    #[tokio::test]
    async fn agent_opens_udp_stream_and_relays_datagram() {
        let socket = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP echo socket");
        let destination = socket.local_addr().expect("UDP socket address");
        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP request");
            assert_eq!(&buf[..len], b"ping");
            socket
                .send_to(b"pong", peer)
                .await
                .expect("write UDP response");
        });

        let (client_io, agent_io) = duplex(256 * 1024);
        let (agent_reader, agent_writer) = split(agent_io);
        let agent = tokio::spawn(run(
            agent_reader,
            agent_writer,
            AgentRuntimeConfig::new(1300),
        ));

        let (mut client_reader, mut client_writer) = split(client_io);
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode()).unwrap(),
        )
        .await;

        let mut inbound = BytesMut::new();
        let hello = read_test_frame(&mut client_reader, &mut inbound, "hello").await;
        assert_eq!(hello.kind, AgentFrameKind::Hello);

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("UDP socket should be IPv4"),
        };
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(
                AgentFrameKind::OpenUdp,
                1,
                AgentOpenIpv4 {
                    destination_ip: *destination.ip(),
                    destination_port: destination.port(),
                    originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                    originator_port: 49152,
                }
                .encode(),
            )
            .unwrap(),
        )
        .await;

        let opened = read_test_frame(&mut client_reader, &mut inbound, "opened").await;
        assert_eq!(opened.kind, AgentFrameKind::Opened);
        assert_eq!(opened.stream_id, 1);
        assert!(opened.credit > 0);

        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
                .unwrap()
                .with_credit(AGENT_STREAM_WINDOW_BYTES as u32),
        )
        .await;
        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"ping")).unwrap(),
        )
        .await;

        let frame = read_test_frame(&mut client_reader, &mut inbound, "UDP response").await;
        match frame.kind {
            AgentFrameKind::Data => assert_eq!(&frame.payload[..], b"pong"),
            AgentFrameKind::Window => panic!("tiny UDP datagram should not emit a window"),
            other => panic!("unexpected UDP frame from agent: {other:?}"),
        }

        write_test_frame(
            &mut client_writer,
            AgentFrame::new(AgentFrameKind::Close, 1, Bytes::new()).unwrap(),
        )
        .await;

        drop(client_writer);
        drop(client_reader);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client EOF")
            .expect("agent task join")
            .expect("agent run");
        server.await.expect("server task join");
    }

    async fn write_test_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: AgentFrame) {
        let encoded = encode_frame(&frame).expect("encode frame");
        writer.write_all(&encoded).await.expect("write frame");
        writer.flush().await.expect("flush frame");
    }

    async fn read_test_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
        inbound: &mut BytesMut,
        context: &'static str,
    ) -> AgentFrame {
        timeout(Duration::from_secs(1), async {
            loop {
                if let Some(frame) = try_decode_frame(inbound).expect("decode frame") {
                    return frame;
                }

                let mut buf = [0_u8; 8192];
                let read = reader.read(&mut buf).await.expect("read frame bytes");
                assert_ne!(read, 0, "agent stream closed before next frame");
                inbound.extend_from_slice(&buf[..read]);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out reading {context} frame"))
    }
}
