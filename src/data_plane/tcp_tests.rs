use bytes::{Bytes, BytesMut};
use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::tcp::spawn_agent_tcp_bridge;
use crate::agent_bridge::{
    test_support::{detached_bridge_transport, QueuedAgentConnector},
    ReconnectingAgentBridge,
};
use crate::defaults::DEFAULT_MTU;
use crate::{agent_proto, agent_transport, ssh_bridge, tcp_core};

async fn read_test_agent_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    inbound: &mut BytesMut,
) -> agent_proto::AgentFrame {
    loop {
        if let Some(frame) =
            agent_proto::try_decode_frame(inbound).expect("decode test agent frame")
        {
            return frame;
        }

        let mut buf = [0_u8; 8192];
        let read = reader.read(&mut buf).await.expect("read test agent frame");
        assert_ne!(read, 0, "test agent stream closed before next frame");
        inbound.extend_from_slice(&buf[..read]);
    }
}

async fn write_test_agent_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: agent_proto::AgentFrame,
) {
    let encoded = agent_proto::encode_frame(&frame).expect("encode test agent frame");
    writer
        .write_all(&encoded)
        .await
        .expect("write test agent frame");
    writer.flush().await.expect("flush test agent frame");
}

fn test_flow_id() -> tcp_core::FlowId {
    tcp_core::FlowId::new(
        tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 1),
            49152,
            Ipv4Addr::new(192, 0, 2, 10),
            443,
        ),
        1,
    )
}

#[tokio::test]
async fn agent_tcp_bridge_sends_local_data_before_agent_opened() {
    let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
    let (data_seen_tx, data_seen_rx) = tokio::sync::oneshot::channel();
    let (send_opened_tx, send_opened_rx) = tokio::sync::oneshot::channel();
    let fake_agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("test hello frame"),
        )
        .await;

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

        let window = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
        assert_eq!(window.stream_id, open.stream_id);

        let data = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"hello");
        data_seen_tx.send(()).expect("report optimistic data");

        send_opened_rx.await.expect("release opened frame");
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Opened,
                open.stream_id,
                Bytes::new(),
            )
            .expect("opened frame")
            .with_credit((1024 * 1024) as u32),
        )
        .await;
    });

    let (client_reader, client_writer) = tokio::io::split(client_io);
    let transport =
        agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
            .await
            .expect("connect fake agent transport");
    let agent = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![detached_bridge_transport(transport)],
    );
    let id = test_flow_id();
    let (event_tx, mut event_rx) = mpsc::channel(4);
    let bridge = spawn_agent_tcp_bridge(id, event_tx, agent);

    assert!(
        bridge
            .try_send_local_data(Bytes::from_static(b"hello"))
            .expect("queue local data"),
        "bridge should accept first local payload"
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), data_seen_rx)
        .await
        .expect("agent sees data before opened")
        .expect("data seen notification");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv())
            .await
            .is_err(),
        "bridge must not report opened before the agent sends Opened"
    );

    send_opened_tx.send(()).expect("release fake opened");
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
        .await
        .expect("opened event")
        .expect("bridge event");
    assert!(
        matches!(event, ssh_bridge::BridgeEvent::Opened { id: event_id, .. } if event_id == id)
    );

    drop(bridge);
    fake_agent.await.expect("fake agent join");
}

#[tokio::test]
async fn agent_tcp_bridge_retries_pre_open_close_and_replays_local_data() {
    let (first_client_io, first_agent_io) = tokio::io::duplex(256 * 1024);
    let (replacement_client_io, replacement_agent_io) = tokio::io::duplex(256 * 1024);
    let (first_data_seen_tx, first_data_seen_rx) = tokio::sync::oneshot::channel();
    let (replacement_data_seen_tx, replacement_data_seen_rx) = tokio::sync::oneshot::channel();
    let (replacement_finish_tx, replacement_finish_rx) = tokio::sync::oneshot::channel();

    let first_fake_agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(first_agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("test hello frame"),
        )
        .await;

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

        let window = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
        assert_eq!(window.stream_id, open.stream_id);

        let data = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"retry-me");
        first_data_seen_tx.send(()).expect("report first data");
    });

    let replacement_fake_agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(replacement_agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("replacement hello frame"),
        )
        .await;

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

        let window = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
        assert_eq!(window.stream_id, open.stream_id);

        let data = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"retry-me");
        replacement_data_seen_tx
            .send(())
            .expect("report replacement data");

        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Opened,
                open.stream_id,
                Bytes::new(),
            )
            .expect("replacement opened frame")
            .with_credit((1024 * 1024) as u32),
        )
        .await;
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Eof,
                open.stream_id,
                Bytes::new(),
            )
            .expect("replacement EOF frame"),
        )
        .await;
        let _ = replacement_finish_rx.await;
    });

    let (first_client_reader, first_client_writer) = tokio::io::split(first_client_io);
    let first_transport = agent_transport::AgentTransport::connect(
        first_client_reader,
        first_client_writer,
        DEFAULT_MTU,
    )
    .await
    .expect("connect first fake agent transport");
    let (replacement_client_reader, replacement_client_writer) =
        tokio::io::split(replacement_client_io);
    let replacement_transport = agent_transport::AgentTransport::connect(
        replacement_client_reader,
        replacement_client_writer,
        DEFAULT_MTU,
    )
    .await
    .expect("connect replacement fake agent transport");
    let connector = QueuedAgentConnector::new(
        "rustle agent",
        vec![detached_bridge_transport(replacement_transport)],
        Vec::new(),
    );
    let agent =
        ReconnectingAgentBridge::new(connector, vec![detached_bridge_transport(first_transport)]);
    let id = test_flow_id();
    let (event_tx, mut event_rx) = mpsc::channel(4);
    let bridge = spawn_agent_tcp_bridge(id, event_tx, agent);

    assert!(
        bridge
            .try_send_local_data(Bytes::from_static(b"retry-me"))
            .expect("queue local data"),
        "bridge should accept first local payload"
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), first_data_seen_rx)
        .await
        .expect("first agent sees optimistic data")
        .expect("first data seen notification");
    tokio::time::timeout(std::time::Duration::from_secs(1), replacement_data_seen_rx)
        .await
        .expect("replacement agent sees replayed data")
        .expect("replacement data seen notification");

    let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
        .await
        .expect("opened event after retry")
        .expect("bridge event");
    assert!(
        matches!(event, ssh_bridge::BridgeEvent::Opened { id: event_id, .. } if event_id == id),
        "expected opened event after retry, got {event:?}"
    );
    if let Ok(Some(ssh_bridge::BridgeEvent::Failed { message, .. })) =
        tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv()).await
    {
        panic!("bridge emitted failure after successful retry: {message}");
    }

    drop(bridge);
    replacement_finish_tx
        .send(())
        .expect("release replacement fake agent");
    first_fake_agent.await.expect("first fake agent join");
    replacement_fake_agent
        .await
        .expect("replacement fake agent join");
}

#[tokio::test]
async fn agent_tcp_bridge_gives_queued_local_data_a_turn_after_remote_event() {
    let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
    let (remote_written_tx, remote_written_rx) = tokio::sync::oneshot::channel();
    let (local_seen_tx, local_seen_rx) = tokio::sync::oneshot::channel();
    let fake_agent = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(agent_io);
        let mut inbound = BytesMut::new();

        let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("test hello frame"),
        )
        .await;

        let open = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(open.kind, agent_proto::AgentFrameKind::OpenTcp);

        let window = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(window.kind, agent_proto::AgentFrameKind::Window);
        assert_eq!(window.stream_id, open.stream_id);

        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Opened,
                open.stream_id,
                Bytes::new(),
            )
            .expect("opened frame")
            .with_credit((1024 * 1024) as u32),
        )
        .await;
        write_test_agent_frame(
            &mut writer,
            agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Data,
                open.stream_id,
                Bytes::from_static(b"remote-first"),
            )
            .expect("remote data frame"),
        )
        .await;
        remote_written_tx.send(()).expect("report remote frame");

        let data = read_test_agent_frame(&mut reader, &mut inbound).await;
        assert_eq!(data.kind, agent_proto::AgentFrameKind::Data);
        assert_eq!(data.stream_id, open.stream_id);
        assert_eq!(&data.payload[..], b"local-later");
        local_seen_tx.send(()).expect("report local data");
    });

    let (client_reader, client_writer) = tokio::io::split(client_io);
    let transport =
        agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
            .await
            .expect("connect fake agent transport");
    let agent = ReconnectingAgentBridge::new(
        QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
        vec![detached_bridge_transport(transport)],
    );
    let id = test_flow_id();
    let (event_tx, mut event_rx) = mpsc::channel(1);
    event_tx
        .send(ssh_bridge::BridgeEvent::Closed { id })
        .await
        .expect("prefill event queue");
    let bridge = spawn_agent_tcp_bridge(id, event_tx, agent);

    remote_written_rx
        .await
        .expect("fake agent should write remote data");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(
        bridge
            .try_send_local_data(Bytes::from_static(b"local-later"))
            .expect("queue local data"),
        "bridge should accept local payload"
    );

    let blocker = event_rx.recv().await.expect("prefilled event");
    assert!(matches!(
        blocker,
        ssh_bridge::BridgeEvent::Closed { id: event_id } if event_id == id
    ));
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
        .await
        .expect("opened event")
        .expect("bridge event");
    assert!(
        matches!(event, ssh_bridge::BridgeEvent::Opened { id: event_id, .. } if event_id == id)
    );

    tokio::time::timeout(std::time::Duration::from_secs(1), local_seen_rx)
        .await
        .expect("local data should not starve behind ready remote data")
        .expect("local data seen notification");
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
        .await
        .expect("remote data event")
        .expect("bridge event");
    match event {
        ssh_bridge::BridgeEvent::RemoteData {
            id: event_id,
            bytes,
        } => {
            assert_eq!(event_id, id);
            assert_eq!(&bytes[..], b"remote-first");
        }
        other => panic!("expected remote data after local send, got {other:?}"),
    }

    drop(bridge);
    fake_agent.await.expect("fake agent join");
}
