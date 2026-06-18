use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use super::failure::{truncate_reset_message, AGENT_STREAM_RESET_BYTES};
use super::*;
use crate::agent_io::{AgentFrameReader, AGENT_FRAME_WRITE_BURST, AGENT_FRAME_WRITE_BURST_BYTES};
use crate::agent_proto::{
    try_decode_frame, AgentFrame, AgentFrameKind, AgentOpenHost, AgentOpenIpv4,
    AGENT_FRAME_HEADER_LEN, AGENT_MAX_FRAME_PAYLOAD, AGENT_PROTOCOL_VERSION, CAP_TCP_CONNECT_HOST,
};
use crate::agent_runtime::{run, AgentRuntimeConfig};
use crate::agent_window::{
    AgentCreditWindow, AGENT_STREAM_INITIAL_WINDOW_BYTES as AGENT_STREAM_WINDOW_BYTES,
    AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES,
};

async fn read_agent_frame<R>(reader: &mut R, inbound: &mut bytes::BytesMut) -> Result<AgentFrame>
where
    R: AsyncRead + Unpin,
{
    let mut frame_reader = AgentFrameReader::from_input(std::mem::take(inbound));
    let frame = frame_reader
        .read_frame(
            reader,
            "failed to read agent frame",
            "agent stream closed before next frame",
        )
        .await?;
    *inbound = frame_reader.into_input();
    Ok(frame)
}

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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::AcqRel);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn test_agent_stream(
    stream_id: u64,
    outbound: mpsc::Sender<AgentFrameWriteItem>,
    inbound: mpsc::Receiver<AgentFrame>,
) -> AgentStream {
    AgentStream {
        stream_id,
        outbound,
        inbound,
        streams: Arc::new(Mutex::new(HashMap::new())),
        failure: Arc::new(Mutex::new(None)),
        writer_metrics: Arc::new(AgentWriterMetrics::default()),
        send_credit: Arc::new(Semaphore::new(0)),
        max_frame_payload: AGENT_MAX_FRAME_PAYLOAD,
        receive_window: AgentCreditWindow::new(),
        initial_receive_credit_granted: true,
    }
}

fn queued_writer_item(
    writer_metrics: &AgentWriterMetrics,
    frame: AgentFrame,
) -> AgentFrameWriteItem {
    let item = AgentFrameWriteItem::new(frame).expect("queued writer frame");
    writer_metrics.record_enqueued(item.encoded_len());
    item
}

async fn queue_writer_frame(
    outbound: &mpsc::Sender<AgentFrameWriteItem>,
    writer_metrics: &AgentWriterMetrics,
    frame: AgentFrame,
) {
    outbound
        .send(queued_writer_item(writer_metrics, frame))
        .await
        .expect("queue frame");
}

#[tokio::test]
async fn transport_writer_flushes_once_per_queued_burst() {
    let writer = CountingWriter::default();
    let flushes = Arc::clone(&writer.flushes);
    let writes = Arc::clone(&writer.writes);
    let bytes = Arc::clone(&writer.bytes);
    let (outbound, outbound_rx) = mpsc::channel(8);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for stream_id in 1..=3 {
        queue_writer_frame(
            &outbound,
            &writer_metrics,
            AgentFrame::new(
                AgentFrameKind::Data,
                stream_id,
                Bytes::copy_from_slice(&[stream_id as u8]),
            )
            .expect("data frame"),
        )
        .await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        Arc::clone(&streams),
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

    assert_eq!(writes.load(Ordering::Acquire), 1);
    assert_eq!(flushes.load(Ordering::Acquire), 1);
    assert!(failure.lock().await.is_none());
    let snapshot = writer_metrics.snapshot();
    assert_eq!(snapshot.queued_frames, 0);
    assert_eq!(snapshot.queued_bytes, 0);
    assert_eq!(snapshot.queued_frames_max, 3);
    assert!(snapshot.queued_bytes_max > 0);
    assert_eq!(snapshot.bursts, 1);
    assert_eq!(snapshot.burst_frames, 3);
    assert_eq!(snapshot.burst_bytes, snapshot.queued_bytes_max as u64);
    assert_eq!(snapshot.burst_frames_max, 3);
    assert_eq!(snapshot.burst_bytes_max, snapshot.queued_bytes_max as u64);
    assert_eq!(snapshot.enqueue_to_write_samples, 3);
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
async fn transport_writer_clears_reused_buffers_between_bursts() {
    let writer = CountingWriter::default();
    let flushes = Arc::clone(&writer.flushes);
    let writes = Arc::clone(&writer.writes);
    let bytes = Arc::clone(&writer.bytes);
    let total_frames = AGENT_FRAME_WRITE_BURST + 1;
    let (outbound, outbound_rx) = mpsc::channel(total_frames);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for stream_id in 1..=total_frames {
        queue_writer_frame(
            &outbound,
            &writer_metrics,
            AgentFrame::new(
                AgentFrameKind::Data,
                stream_id as u64,
                Bytes::copy_from_slice(&[stream_id as u8]),
            )
            .expect("data frame"),
        )
        .await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        Arc::clone(&streams),
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

    assert_eq!(writes.load(Ordering::Acquire), 2);
    assert_eq!(flushes.load(Ordering::Acquire), 2);
    assert!(failure.lock().await.is_none());
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
async fn transport_writer_caps_large_data_burst_by_encoded_bytes() {
    let writer = CountingWriter::default();
    let flushes = Arc::clone(&writer.flushes);
    let writes = Arc::clone(&writer.writes);
    let frames_until_byte_cap =
        AGENT_FRAME_WRITE_BURST_BYTES / (AGENT_MAX_FRAME_PAYLOAD + AGENT_FRAME_HEADER_LEN) + 1;
    assert_eq!(frames_until_byte_cap, 4);
    assert!(frames_until_byte_cap < AGENT_FRAME_WRITE_BURST);
    let total_frames = frames_until_byte_cap + 1;
    let (outbound, outbound_rx) = mpsc::channel(total_frames);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for stream_id in 1..=total_frames {
        queue_writer_frame(
            &outbound,
            &writer_metrics,
            AgentFrame::new(
                AgentFrameKind::Data,
                stream_id as u64,
                Bytes::from(vec![0x5a; AGENT_MAX_FRAME_PAYLOAD]),
            )
            .expect("data frame"),
        )
        .await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        streams,
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

    assert_eq!(writes.load(Ordering::Acquire), 2);
    assert_eq!(flushes.load(Ordering::Acquire), 2);
    assert!(failure.lock().await.is_none());
}

#[tokio::test]
async fn transport_writer_prioritizes_control_frames_inside_burst() {
    let writer = CountingWriter::default();
    let bytes = Arc::clone(&writer.bytes);
    let (outbound, outbound_rx) = mpsc::channel(8);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for frame in [
        AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one")).expect("data frame"),
        AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
            .expect("window frame")
            .with_credit(32),
        AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"two")).expect("data frame"),
        AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).expect("ping frame"),
        AgentFrame::new(AgentFrameKind::Opened, 4, Bytes::new()).expect("opened frame"),
        AgentFrame::new(AgentFrameKind::Pong, 0, Bytes::new()).expect("pong frame"),
    ] {
        queue_writer_frame(&outbound, &writer_metrics, frame).await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        streams,
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

    let mut encoded = BytesMut::from(bytes.lock().expect("counting writer lock").as_slice());
    let mut decoded = Vec::new();
    while let Some(frame) = try_decode_frame(&mut encoded).expect("decode written frame") {
        decoded.push((frame.kind, frame.stream_id));
    }
    assert_eq!(
        decoded,
        vec![
            (AgentFrameKind::Window, 1),
            (AgentFrameKind::Ping, 0),
            (AgentFrameKind::Opened, 4),
            (AgentFrameKind::Pong, 0),
            (AgentFrameKind::Data, 1),
            (AgentFrameKind::Data, 3),
        ]
    );
    assert!(failure.lock().await.is_none());
}

#[tokio::test]
async fn transport_writer_round_robins_non_priority_frames_inside_burst() {
    let writer = CountingWriter::default();
    let bytes = Arc::clone(&writer.bytes);
    let (outbound, outbound_rx) = mpsc::channel(8);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for frame in [
        AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one-a")).expect("data frame"),
        AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"one-b")).expect("data frame"),
        AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"three-a"))
            .expect("data frame"),
        AgentFrame::new(AgentFrameKind::Data, 3, Bytes::from_static(b"three-b"))
            .expect("data frame"),
        AgentFrame::new(AgentFrameKind::Data, 5, Bytes::from_static(b"five-a"))
            .expect("data frame"),
        AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).expect("eof frame"),
    ] {
        queue_writer_frame(&outbound, &writer_metrics, frame).await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        streams,
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

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
    assert!(failure.lock().await.is_none());
}

#[tokio::test]
async fn transport_writer_keeps_eof_after_preceding_data_inside_burst() {
    let writer = CountingWriter::default();
    let bytes = Arc::clone(&writer.bytes);
    let (outbound, outbound_rx) = mpsc::channel(8);
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let failure = Arc::new(Mutex::new(None));
    let writer_metrics = Arc::new(AgentWriterMetrics::default());

    for frame in [
        AgentFrame::new(AgentFrameKind::Data, 1, Bytes::from_static(b"request"))
            .expect("data frame"),
        AgentFrame::new(AgentFrameKind::Eof, 1, Bytes::new()).expect("eof frame"),
        AgentFrame::new(AgentFrameKind::Window, 1, Bytes::new())
            .expect("window frame")
            .with_credit(32),
    ] {
        queue_writer_frame(&outbound, &writer_metrics, frame).await;
    }
    drop(outbound);

    write_agent_frames(
        writer,
        outbound_rx,
        streams,
        Arc::clone(&failure),
        Arc::clone(&writer_metrics),
    )
    .await;

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
    assert!(failure.lock().await.is_none());
}

#[tokio::test]
async fn inbound_stream_frame_refreshes_heartbeat_activity() {
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let heartbeat = Arc::new(Mutex::new(AgentHeartbeat {
        last_peer_activity: Instant::now() - Duration::from_secs(60),
        sent: 1,
        received_pongs: 0,
    }));
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    let send_credit = Arc::new(Semaphore::new(0));
    streams.lock().await.insert(
        7,
        StreamEntry {
            inbound: inbound_tx,
            send_credit,
            optimistic_open_credit: 0,
        },
    );

    let before = Instant::now();
    dispatch_agent_frame(
        &streams,
        Some(&heartbeat),
        AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from_static(b"alive")).expect("data frame"),
    )
    .await;

    let heartbeat = heartbeat.lock().await;
    assert!(
        heartbeat.last_peer_activity >= before,
        "valid inbound stream traffic should count as transport activity"
    );
    assert_eq!(
        heartbeat.received_pongs, 0,
        "stream traffic should not be counted as heartbeat pong replies"
    );
    drop(heartbeat);

    let frame = inbound_rx.recv().await.expect("dispatched stream frame");
    assert_eq!(frame.kind, AgentFrameKind::Data);
    assert_eq!(&frame.payload[..], b"alive");
}

#[tokio::test]
async fn pong_refreshes_heartbeat_activity_and_count() {
    let streams = Arc::new(Mutex::new(HashMap::new()));
    let heartbeat = Arc::new(Mutex::new(AgentHeartbeat {
        last_peer_activity: Instant::now() - Duration::from_secs(60),
        sent: 1,
        received_pongs: 0,
    }));

    let before = Instant::now();
    dispatch_agent_frame(
        &streams,
        Some(&heartbeat),
        AgentFrame::new(AgentFrameKind::Pong, 0, Bytes::new()).expect("pong frame"),
    )
    .await;

    let heartbeat = heartbeat.lock().await;
    assert!(
        heartbeat.last_peer_activity >= before,
        "pong should count as transport activity"
    );
    assert_eq!(heartbeat.received_pongs, 1);
}

#[tokio::test]
async fn transport_multiplexes_multiple_tcp_streams() {
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
                    .expect("read request");
                socket.write_all(b"mux:").await.expect("write prefix");
                socket.write_all(&request).await.expect("write response");
                socket.shutdown().await.expect("shutdown response");
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

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    assert_eq!(
        transport.peer_hello().protocol_version,
        AGENT_PROTOCOL_VERSION
    );

    let destination = match destination {
        std::net::SocketAddr::V4(addr) => addr,
        std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
    };
    let open = AgentOpenIpv4 {
        destination_ip: *destination.ip(),
        destination_port: destination.port(),
        originator_ip: Ipv4Addr::new(10, 255, 255, 1),
        originator_port: 49152,
    };
    let mut first = transport.open_tcp_ipv4(open).await.expect("open first");
    let mut second = transport
        .open_tcp_ipv4(AgentOpenIpv4 {
            originator_port: 49153,
            ..open
        })
        .await
        .expect("open second");
    assert_ne!(first.stream_id(), second.stream_id());

    first
        .send_data(Bytes::from_static(b"one"))
        .await
        .expect("send first");
    second
        .send_data(Bytes::from_static(b"two"))
        .await
        .expect("send second");
    first.send_eof().await.expect("eof first");
    second.send_eof().await.expect("eof second");

    assert_eq!(collect_stream_response(&mut first).await, b"mux:one");
    assert_eq!(collect_stream_response(&mut second).await, b"mux:two");

    let _ = first.close().await;
    let _ = second.close().await;
    drop(transport);
    timeout(Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
    server.await.expect("server join");
}

#[tokio::test]
async fn transport_opens_tcp_host_stream_and_relays_bytes() {
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
            .expect("read request");
        socket.write_all(b"host:").await.expect("write prefix");
        socket.write_all(&request).await.expect("write response");
        socket.shutdown().await.expect("shutdown response");
    });

    let (client_io, agent_io) = duplex(256 * 1024);
    let (agent_reader, agent_writer) = split(agent_io);
    let agent = tokio::spawn(run(
        agent_reader,
        agent_writer,
        AgentRuntimeConfig::new(1300),
    ));

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    assert_ne!(
        transport.peer_hello().capabilities & CAP_TCP_CONNECT_HOST,
        0
    );

    let mut stream = transport
        .open_tcp_host(AgentOpenHost {
            destination_host: "localhost".to_owned(),
            destination_port: destination.port(),
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
        })
        .await
        .expect("open hostname TCP stream");
    stream
        .send_data(Bytes::from_static(b"dns"))
        .await
        .expect("send request");
    stream.send_eof().await.expect("send EOF");

    assert_eq!(collect_stream_response(&mut stream).await, b"host:dns");

    let _ = stream.close().await;
    drop(transport);
    timeout(Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
    server.await.expect("server join");
}

#[tokio::test]
async fn transport_rejects_tcp_host_when_peer_lacks_capability() {
    let (outbound, _outbound_rx) = mpsc::channel(1);
    let mut peer = AgentHello::current(1300);
    peer.capabilities &= !CAP_TCP_CONNECT_HOST;
    let transport = AgentTransport {
        outbound,
        streams: Arc::new(Mutex::new(HashMap::new())),
        failure: Arc::new(Mutex::new(None)),
        writer_metrics: Arc::new(AgentWriterMetrics::default()),
        peer,
        next_stream_id: Arc::new(AtomicU64::new(1)),
        _heartbeat_guard: None,
    };

    let err = transport
        .open_tcp_host(AgentOpenHost {
            destination_host: "localhost".to_owned(),
            destination_port: 53,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 0,
        })
        .await
        .expect_err("host open requires peer capability");

    assert!(err.to_string().contains("hostname TCP connect"));
}

#[tokio::test]
async fn transport_flow_control_moves_large_responses_across_streams() {
    const STREAMS: usize = 4;
    const RESPONSE_BYTES: usize = AGENT_STREAM_WINDOW_BYTES + 96 * 1024;

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind large response listener");
    let destination = listener.local_addr().expect("listener address");
    let response = std::sync::Arc::new(vec![0x5a; RESPONSE_BYTES]);
    let server = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..STREAMS {
            let body = std::sync::Arc::clone(&response);
            let (mut socket, _) = listener.accept().await.expect("accept remote TCP");
            tasks.push(tokio::spawn(async move {
                let mut request = Vec::new();
                socket
                    .read_to_end(&mut request)
                    .await
                    .expect("read request");
                assert!(!request.is_empty());
                socket.write_all(&body).await.expect("write response");
                socket.shutdown().await.expect("shutdown response");
            }));
        }
        for task in tasks {
            task.await.expect("large response task join");
        }
    });

    let (client_io, agent_io) = duplex(1024 * 1024);
    let (agent_reader, agent_writer) = split(agent_io);
    let agent = tokio::spawn(run(
        agent_reader,
        agent_writer,
        AgentRuntimeConfig::new(1300),
    ));

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let destination = match destination {
        std::net::SocketAddr::V4(addr) => addr,
        std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
    };

    let mut streams = Vec::new();
    for index in 0..STREAMS {
        let stream = transport
            .open_tcp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152 + index as u16,
            })
            .await
            .expect("open stream");
        stream
            .send_data(Bytes::copy_from_slice(format!("stream-{index}").as_bytes()))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");
        streams.push(stream);
    }

    for stream in &mut streams {
        let body = collect_stream_response(stream).await;
        assert_eq!(body.len(), RESPONSE_BYTES);
        assert!(body.iter().all(|byte| *byte == 0x5a));
    }

    for stream in streams {
        let _ = stream.close().await;
    }
    drop(transport);
    timeout(Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
    server.await.expect("server join");
}

#[tokio::test]
async fn transport_opens_udp_stream_and_relays_datagram() {
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

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let destination = match destination {
        std::net::SocketAddr::V4(addr) => addr,
        std::net::SocketAddr::V6(_) => panic!("UDP socket should be IPv4"),
    };
    let mut stream = transport
        .open_udp_ipv4(AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
        })
        .await
        .expect("open UDP stream");

    stream
        .send_data(Bytes::from_static(b"ping"))
        .await
        .expect("send UDP datagram");

    let response = timeout(Duration::from_secs(1), async {
        loop {
            let frame = stream.recv().await.expect("stream closed before UDP reply");
            match frame.kind {
                AgentFrameKind::Data => return frame.payload,
                AgentFrameKind::Reset => {
                    panic!(
                        "UDP stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    )
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for UDP reply");
    assert_eq!(&response[..], b"pong");

    let _ = stream.close().await;
    drop(transport);
    timeout(Duration::from_secs(1), agent)
        .await
        .expect("agent exits")
        .expect("agent join")
        .expect("agent run");
    server.await.expect("server join");
}

#[tokio::test]
async fn stream_send_data_waits_for_window_credit() {
    let (client_io, agent_io) = duplex(256 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");

        let open = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read open frame");
        assert_eq!(open.kind, AgentFrameKind::OpenTcp);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Opened, open.stream_id, Bytes::new())
                .expect("opened")
                .with_credit(0),
        )
        .await
        .expect("write opened");

        let receive_window = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read initial receive window");
        assert_eq!(receive_window.kind, AgentFrameKind::Window);
        assert_eq!(receive_window.stream_id, open.stream_id);
        assert_eq!(receive_window.credit as usize, AGENT_STREAM_WINDOW_BYTES);

        assert!(
            timeout(
                Duration::from_millis(50),
                read_agent_frame(&mut agent_reader, &mut inbound)
            )
            .await
            .is_err(),
            "data should not be sent without stream credit"
        );

        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Window, open.stream_id, Bytes::new())
                .expect("window")
                .with_credit(5),
        )
        .await
        .expect("write send window");

        let data = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read credited data");
        assert_eq!(data.kind, AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"hello");
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let stream = transport
        .open_tcp_ipv4(AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(127, 0, 0, 1),
            destination_port: 8080,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
        })
        .await
        .expect("open stream");

    assert!(
        timeout(
            Duration::from_millis(50),
            stream.send_data(Bytes::from_static(b"hello"))
        )
        .await
        .is_err(),
        "send should wait for window credit"
    );
    stream
        .send_data(Bytes::from_static(b"hello"))
        .await
        .expect("send after window credit");

    drop(stream);
    drop(transport);
    fake_agent.await.expect("fake agent join");
}

#[tokio::test]
async fn optimistic_open_sends_first_data_before_opened() {
    let (client_io, agent_io) = duplex(256 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");

        let open = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read open frame");
        assert_eq!(open.kind, AgentFrameKind::OpenTcp);

        let receive_window = timeout(
            Duration::from_secs(1),
            read_agent_frame(&mut agent_reader, &mut inbound),
        )
        .await
        .expect("receive window before opened")
        .expect("read optimistic receive window");
        assert_eq!(receive_window.kind, AgentFrameKind::Window);
        assert_eq!(receive_window.stream_id, open.stream_id);
        assert_eq!(receive_window.credit as usize, AGENT_STREAM_WINDOW_BYTES);

        let data = timeout(
            Duration::from_secs(1),
            read_agent_frame(&mut agent_reader, &mut inbound),
        )
        .await
        .expect("data before opened")
        .expect("read optimistic data");
        assert_eq!(data.kind, AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"hello");

        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Opened, open.stream_id, Bytes::new())
                .expect("opened")
                .with_credit(5),
        )
        .await
        .expect("write opened");

        assert!(
            timeout(
                Duration::from_millis(50),
                read_agent_frame(&mut agent_reader, &mut inbound)
            )
            .await
            .is_err(),
            "opened should not trigger a duplicate receive window"
        );
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let mut stream = timeout(
        Duration::from_millis(100),
        transport.open_tcp_ipv4_optimistic(AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(127, 0, 0, 1),
            destination_port: 8080,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
        }),
    )
    .await
    .expect("optimistic open should return before opened")
    .expect("open optimistic stream");

    stream
        .send_data(Bytes::from_static(b"hello"))
        .await
        .expect("send before opened");
    let opened = timeout(Duration::from_secs(1), stream.recv())
        .await
        .expect("receive opened")
        .expect("opened frame");
    assert_eq!(opened.kind, AgentFrameKind::Opened);

    fake_agent.await.expect("fake agent join");
    drop(transport);
}

#[tokio::test]
async fn stream_recv_batches_receive_credit_until_threshold() {
    let (outbound, mut outbound_rx) = mpsc::channel(8);
    let (inbound_tx, inbound) = mpsc::channel(8);
    let mut stream = test_agent_stream(7, outbound, inbound);
    let chunk = AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES / 4;

    for _ in 0..3 {
        inbound_tx
            .send(
                AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from(vec![0x5a; chunk]))
                    .expect("data frame"),
            )
            .await
            .expect("queue data frame");
        let frame = stream.recv().await.expect("receive data frame");
        assert_eq!(frame.kind, AgentFrameKind::Data);
        assert!(
            outbound_rx.try_recv().is_err(),
            "receive credit below threshold should stay batched"
        );
    }

    inbound_tx
        .send(
            AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from(vec![0x5a; chunk]))
                .expect("data frame"),
        )
        .await
        .expect("queue threshold data frame");
    let frame = stream.recv().await.expect("receive threshold data frame");
    assert_eq!(frame.kind, AgentFrameKind::Data);

    let window = outbound_rx
        .recv()
        .await
        .expect("receive batched window")
        .frame;
    assert_eq!(window.kind, AgentFrameKind::Window);
    assert_eq!(window.stream_id, 7);
    assert_eq!(
        window.credit as usize,
        AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES
    );
    assert!(
        outbound_rx.try_recv().is_err(),
        "batched credit should emit exactly one window"
    );
}

#[tokio::test]
async fn stream_recv_batches_max_frame_receive_credit_until_threshold() {
    let (outbound, mut outbound_rx) = mpsc::channel(8);
    let (inbound_tx, inbound) = mpsc::channel(8);
    let mut stream = test_agent_stream(9, outbound, inbound);
    let max_frame = AGENT_MAX_FRAME_PAYLOAD;
    let frames_to_threshold = AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES / max_frame;

    for index in 0..frames_to_threshold {
        inbound_tx
            .send(
                AgentFrame::new(AgentFrameKind::Data, 9, Bytes::from(vec![0xa5; max_frame]))
                    .expect("max data frame"),
            )
            .await
            .expect("queue max data frame");
        let frame = stream.recv().await.expect("receive max data frame");
        assert_eq!(frame.kind, AgentFrameKind::Data);
        if index + 1 < frames_to_threshold {
            assert!(
                outbound_rx.try_recv().is_err(),
                "max frames below threshold should stay batched"
            );
        }
    }

    let window = outbound_rx
        .recv()
        .await
        .expect("receive immediate window")
        .frame;
    assert_eq!(window.kind, AgentFrameKind::Window);
    assert_eq!(window.stream_id, 9);
    assert_eq!(
        window.credit as usize,
        AGENT_STREAM_RECEIVE_CREDIT_BATCH_BYTES
    );
    assert!(
        outbound_rx.try_recv().is_err(),
        "single max frame should emit exactly one window"
    );
}

#[tokio::test]
async fn stream_recv_grows_receive_window_after_sustained_consumption() {
    let (outbound, mut outbound_rx) = mpsc::channel(8);
    let (inbound_tx, inbound) = mpsc::channel(8);
    let mut stream = test_agent_stream(11, outbound, inbound);
    let frames_to_window = AGENT_STREAM_WINDOW_BYTES / AGENT_MAX_FRAME_PAYLOAD;
    let mut largest_credit = 0_usize;

    for _ in 0..frames_to_window {
        inbound_tx
            .send(
                AgentFrame::new(
                    AgentFrameKind::Data,
                    11,
                    Bytes::from(vec![0x5a; AGENT_MAX_FRAME_PAYLOAD]),
                )
                .expect("data frame"),
            )
            .await
            .expect("queue max-frame data");
        let frame = stream.recv().await.expect("receive max-frame data");
        assert_eq!(frame.kind, AgentFrameKind::Data);
        while let Ok(window) = outbound_rx.try_recv() {
            let window = window.frame;
            assert_eq!(window.kind, AgentFrameKind::Window);
            assert_eq!(window.stream_id, 11);
            largest_credit = largest_credit.max(window.credit as usize);
        }
    }

    assert!(largest_credit > AGENT_STREAM_WINDOW_BYTES);
    assert!(stream.receive_window.current_window() > AGENT_STREAM_WINDOW_BYTES);
}

#[tokio::test]
async fn stream_send_data_segments_payloads_above_frame_limit() {
    let (client_io, agent_io) = duplex(512 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);
    let payload = Bytes::from(vec![0x5a; AGENT_MAX_FRAME_PAYLOAD * 2 + 17]);
    let expected = payload.clone();

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");

        let open = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read open frame");
        assert_eq!(open.kind, AgentFrameKind::OpenTcp);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Opened, open.stream_id, Bytes::new())
                .expect("opened")
                .with_credit(expected.len() as u32),
        )
        .await
        .expect("write opened");

        let receive_window = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read initial receive window");
        assert_eq!(receive_window.kind, AgentFrameKind::Window);

        let mut received = Vec::new();
        let mut data_frames = 0_usize;
        while received.len() < expected.len() {
            let data = read_agent_frame(&mut agent_reader, &mut inbound)
                .await
                .expect("read segmented data frame");
            assert_eq!(data.kind, AgentFrameKind::Data);
            assert_eq!(data.stream_id, open.stream_id);
            assert!(
                data.payload.len() <= AGENT_MAX_FRAME_PAYLOAD,
                "agent data frame exceeded max payload: {}",
                data.payload.len()
            );
            data_frames += 1;
            received.extend_from_slice(&data.payload);
        }

        assert_eq!(received, expected);
        assert_eq!(data_frames, 3);
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let stream = transport
        .open_tcp_ipv4(AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(127, 0, 0, 1),
            destination_port: 8080,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 49152,
        })
        .await
        .expect("open stream");

    stream
        .send_data(payload)
        .await
        .expect("send segmented payload");

    drop(stream);
    drop(transport);
    fake_agent.await.expect("fake agent join");
}

#[tokio::test]
async fn transport_rejects_new_streams_after_agent_disconnect() {
    let (client_io, agent_io) = duplex(256 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    fake_agent.await.expect("fake agent join");

    let open = AgentOpenIpv4 {
        destination_ip: Ipv4Addr::new(127, 0, 0, 1),
        destination_port: 8080,
        originator_ip: Ipv4Addr::new(10, 255, 255, 1),
        originator_port: 49152,
    };
    let first = timeout(Duration::from_secs(1), transport.open_tcp_ipv4(open))
        .await
        .expect("first open should observe agent disconnect");
    assert!(
        first.is_err(),
        "first open after disconnect should not succeed"
    );

    let second = timeout(
        Duration::from_millis(50),
        transport.open_tcp_ipv4(AgentOpenIpv4 {
            originator_port: 49153,
            ..open
        }),
    )
    .await
    .expect("sticky transport failure should reject without waiting")
    .expect_err("second open after disconnect should fail");
    assert!(
        second.to_string().contains("agent transport closed"),
        "unexpected error: {second:#}"
    );
}

#[tokio::test]
async fn active_stream_resets_and_later_opens_fail_after_agent_disconnect() {
    let (client_io, agent_io) = duplex(256 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");

        let open = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read open frame");
        assert_eq!(open.kind, AgentFrameKind::OpenTcp);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Opened, open.stream_id, Bytes::new())
                .expect("opened")
                .with_credit(AGENT_STREAM_WINDOW_BYTES as u32),
        )
        .await
        .expect("write opened");

        let window = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read initial receive window");
        assert_eq!(window.kind, AgentFrameKind::Window);
        assert_eq!(window.stream_id, open.stream_id);
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");
    let open = AgentOpenIpv4 {
        destination_ip: Ipv4Addr::new(127, 0, 0, 1),
        destination_port: 8080,
        originator_ip: Ipv4Addr::new(10, 255, 255, 1),
        originator_port: 49152,
    };
    let mut stream = transport.open_tcp_ipv4(open).await.expect("open stream");
    fake_agent.await.expect("fake agent join");

    let reset = timeout(Duration::from_secs(1), stream.recv())
        .await
        .expect("active stream should be reset after agent disconnect")
        .expect("stream should receive reset frame");
    assert_eq!(reset.kind, AgentFrameKind::Reset);
    let reset_message = String::from_utf8_lossy(&reset.payload);
    assert!(
        reset_message.contains("agent stream closed"),
        "unexpected reset message: {reset_message}"
    );
    assert!(
        transport.failure_message().await.is_some(),
        "transport failure should be sticky"
    );

    let later = timeout(
        Duration::from_millis(50),
        transport.open_tcp_ipv4(AgentOpenIpv4 {
            originator_port: 49153,
            ..open
        }),
    )
    .await
    .expect("sticky transport failure should reject without waiting")
    .expect_err("open after active disconnect should fail");
    assert!(
        later.to_string().contains("agent transport closed"),
        "unexpected later open error: {later:#}"
    );
}

#[tokio::test]
async fn open_timeout_unregisters_pending_stream() {
    let (client_io, agent_io) = duplex(256 * 1024);
    let (mut agent_reader, mut agent_writer) = split(agent_io);

    let fake_agent = tokio::spawn(async move {
        let mut inbound = BytesMut::new();
        let hello = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read client hello");
        assert_eq!(hello.kind, AgentFrameKind::Hello);
        write_agent_frame(
            &mut agent_writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(1300).encode())
                .expect("agent hello"),
        )
        .await
        .expect("write agent hello");

        let open = read_agent_frame(&mut agent_reader, &mut inbound)
            .await
            .expect("read open frame");
        assert_eq!(open.kind, AgentFrameKind::OpenTcp);
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let (client_reader, client_writer) = split(client_io);
    let transport = AgentTransport::connect(client_reader, client_writer, 1300)
        .await
        .expect("connect transport");

    let err = transport
        .open_ipv4_with_timeout(
            AgentFrameKind::OpenTcp,
            AgentOpenIpv4 {
                destination_ip: Ipv4Addr::new(127, 0, 0, 1),
                destination_port: 8080,
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            },
            Duration::from_millis(25),
        )
        .await
        .expect_err("open should time out");
    assert!(
        err.to_string().contains("timed out"),
        "unexpected error: {err:#}"
    );
    assert!(
        transport.streams.lock().await.is_empty(),
        "timed-out open should not leave a stale stream registration"
    );

    drop(transport);
    fake_agent.await.expect("fake agent join");
}

#[tokio::test]
async fn open_timeout_when_outbound_queue_is_full() {
    let (outbound, _outbound_rx) = mpsc::channel(1);
    let writer_metrics = Arc::new(AgentWriterMetrics::default());
    outbound
        .try_send(queued_writer_item(
            &writer_metrics,
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).unwrap(),
        ))
        .expect("prefill outbound queue");
    let streams = std::sync::Arc::new(Mutex::new(HashMap::new()));
    let failure = std::sync::Arc::new(Mutex::new(None));
    let transport = AgentTransport {
        outbound,
        streams: std::sync::Arc::clone(&streams),
        failure: std::sync::Arc::clone(&failure),
        writer_metrics,
        peer: AgentHello::current(1300),
        next_stream_id: std::sync::Arc::new(AtomicU64::new(1)),
        _heartbeat_guard: None,
    };

    let err = transport
        .open_ipv4_with_timeout(
            AgentFrameKind::OpenTcp,
            AgentOpenIpv4 {
                destination_ip: Ipv4Addr::new(127, 0, 0, 1),
                destination_port: 8080,
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            },
            Duration::from_millis(25),
        )
        .await
        .expect_err("open should time out waiting for outbound capacity");
    assert!(
        err.to_string().contains("outbound capacity"),
        "unexpected error: {err:#}"
    );
    assert!(
        streams.lock().await.is_empty(),
        "open timeout before enqueue should not register a stream"
    );
    let failure = failure.lock().await.clone().expect("transport failure");
    assert!(failure.contains("outbound capacity"));
}

#[tokio::test]
async fn stream_send_timeout_marks_transport_failed_without_blocking_reset() {
    let (outbound, _outbound_rx) = mpsc::channel(1);
    let writer_metrics = Arc::new(AgentWriterMetrics::default());
    outbound
        .try_send(queued_writer_item(
            &writer_metrics,
            AgentFrame::new(AgentFrameKind::Ping, 0, Bytes::new()).unwrap(),
        ))
        .expect("prefill outbound queue");
    let streams = std::sync::Arc::new(Mutex::new(HashMap::new()));
    let failure = std::sync::Arc::new(Mutex::new(None));
    let blocked_credit = std::sync::Arc::new(Semaphore::new(0));
    let (blocked_tx, _blocked_rx) = mpsc::channel(1);
    blocked_tx
        .try_send(AgentFrame::new(AgentFrameKind::Data, 99, Bytes::new()).unwrap())
        .expect("prefill inbound stream queue");
    streams.lock().await.insert(
        99,
        StreamEntry {
            inbound: blocked_tx,
            send_credit: std::sync::Arc::clone(&blocked_credit),
            optimistic_open_credit: 0,
        },
    );

    let (_inbound_tx, inbound) = mpsc::channel(1);
    let stream = AgentStream {
        stream_id: 7,
        outbound,
        inbound,
        streams: std::sync::Arc::clone(&streams),
        failure: std::sync::Arc::clone(&failure),
        writer_metrics,
        send_credit: std::sync::Arc::new(Semaphore::new(0)),
        max_frame_payload: AGENT_MAX_FRAME_PAYLOAD,
        receive_window: AgentCreditWindow::new(),
        initial_receive_credit_granted: true,
    };
    let err = stream
        .send_frame_with_timeout(
            AgentFrame::new(AgentFrameKind::Window, 7, Bytes::new()).unwrap(),
            Duration::from_millis(25),
        )
        .await
        .expect_err("send should time out waiting for outbound capacity");
    assert!(
        err.to_string().contains("enqueueing agent stream frame"),
        "unexpected error: {err:#}"
    );
    assert!(streams.lock().await.is_empty());
    assert!(blocked_credit.is_closed());
    let failure = failure.lock().await.clone().expect("transport failure");
    assert!(failure.contains("enqueueing agent stream frame"));
}

#[tokio::test]
async fn dispatch_drops_stream_when_inbound_queue_is_full() {
    let streams = std::sync::Arc::new(Mutex::new(HashMap::new()));
    let send_credit = std::sync::Arc::new(Semaphore::new(0));
    let (inbound, _inbound_rx) = mpsc::channel(1);
    inbound
        .try_send(AgentFrame::new(AgentFrameKind::Data, 5, Bytes::new()).unwrap())
        .expect("prefill inbound queue");
    streams.lock().await.insert(
        5,
        StreamEntry {
            inbound,
            send_credit: std::sync::Arc::clone(&send_credit),
            optimistic_open_credit: 0,
        },
    );

    dispatch_agent_frame(
        &streams,
        None,
        AgentFrame::new(AgentFrameKind::Data, 5, Bytes::from_static(b"blocked")).unwrap(),
    )
    .await;

    assert!(streams.lock().await.is_empty());
    assert!(send_credit.is_closed());
}

#[test]
fn reset_message_truncation_preserves_utf8_boundary() {
    let message = "é".repeat(AGENT_STREAM_RESET_BYTES);
    let truncated = truncate_reset_message(&message);

    assert!(truncated.len() <= AGENT_STREAM_RESET_BYTES);
    assert!(truncated.is_char_boundary(truncated.len()));
    assert!(message.starts_with(&truncated));
}

async fn collect_stream_response(stream: &mut AgentStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut saw_eof = false;
    for _ in 0..512 {
        let frame = timeout(Duration::from_secs(1), stream.recv())
            .await
            .expect("timed out waiting for stream frame")
            .expect("stream closed before response");
        match frame.kind {
            AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
            AgentFrameKind::Eof => saw_eof = true,
            AgentFrameKind::Close => break,
            AgentFrameKind::Reset => {
                panic!("stream reset: {}", String::from_utf8_lossy(&frame.payload))
            }
            other => panic!("unexpected stream frame: {other:?}"),
        }
    }
    assert!(saw_eof);
    response
}
