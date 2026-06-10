use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::agent_proto::{
    encode_frame, try_decode_frame, AgentFrame, AgentFrameKind, AgentHello, AgentOpenIpv4,
    AGENT_PROTOCOL_VERSION, CAP_FLOW_CONTROL,
};

const AGENT_CLIENT_RECEIVE_WINDOW_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub struct AgentClient<R, W> {
    reader: R,
    writer: W,
    inbound: BytesMut,
    peer: AgentHello,
    next_stream_id: u64,
}

impl<R, W> AgentClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub async fn connect(mut reader: R, mut writer: W, mtu: u16) -> Result<Self> {
        write_frame(
            &mut writer,
            &AgentFrame::new(AgentFrameKind::Hello, 0, AgentHello::current(mtu).encode())?,
        )
        .await?;

        let mut inbound = BytesMut::new();
        let frame = read_frame(&mut reader, &mut inbound).await?;
        if frame.kind != AgentFrameKind::Hello {
            bail!("agent expected hello response, got {:?}", frame.kind);
        }
        let peer = AgentHello::decode(&frame.payload)?;
        if peer.protocol_version != AGENT_PROTOCOL_VERSION {
            bail!(
                "unsupported agent protocol version {}",
                peer.protocol_version
            );
        }
        if peer.capabilities & CAP_FLOW_CONTROL == 0 {
            bail!("agent does not advertise flow-control support");
        }

        Ok(Self {
            reader,
            writer,
            inbound,
            peer,
            next_stream_id: 1,
        })
    }

    pub fn peer_hello(&self) -> AgentHello {
        self.peer
    }

    pub async fn open_tcp_ipv4(&mut self, open: AgentOpenIpv4) -> Result<u64> {
        let stream_id = self.allocate_stream_id()?;
        self.write_frame(&AgentFrame::new(
            AgentFrameKind::OpenTcp,
            stream_id,
            open.encode(),
        )?)
        .await?;

        let frame = self.read_frame().await?;
        if frame.stream_id != stream_id {
            bail!(
                "agent received frame for stream {} while opening stream {}",
                frame.stream_id,
                stream_id
            );
        }
        match frame.kind {
            AgentFrameKind::Opened => {
                self.send_window(stream_id, AGENT_CLIENT_RECEIVE_WINDOW_BYTES)
                    .await?;
                Ok(stream_id)
            }
            AgentFrameKind::Reset => {
                let message = String::from_utf8_lossy(&frame.payload);
                bail!("agent failed to open stream {stream_id}: {message}");
            }
            other => bail!("agent expected opened/reset for stream {stream_id}, got {other:?}"),
        }
    }

    pub async fn send_data(&mut self, stream_id: u64, bytes: impl Into<Bytes>) -> Result<()> {
        self.write_frame(&AgentFrame::new(AgentFrameKind::Data, stream_id, bytes)?)
            .await
    }

    pub async fn send_eof(&mut self, stream_id: u64) -> Result<()> {
        self.write_frame(&AgentFrame::new(
            AgentFrameKind::Eof,
            stream_id,
            Bytes::new(),
        )?)
        .await
    }

    pub async fn read_frame(&mut self) -> Result<AgentFrame> {
        let frame = read_frame(&mut self.reader, &mut self.inbound).await?;
        if frame.kind == AgentFrameKind::Data && frame.stream_id != 0 && !frame.payload.is_empty() {
            self.send_window(frame.stream_id, frame.payload.len())
                .await?;
        }
        Ok(frame)
    }

    async fn write_frame(&mut self, frame: &AgentFrame) -> Result<()> {
        write_frame(&mut self.writer, frame).await
    }

    async fn send_window(&mut self, stream_id: u64, bytes: usize) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let credit = u32::try_from(bytes).context("agent receive credit exceeds u32")?;
        self.write_frame(
            &AgentFrame::new(AgentFrameKind::Window, stream_id, Bytes::new())?.with_credit(credit),
        )
        .await
    }

    fn allocate_stream_id(&mut self) -> Result<u64> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self
            .next_stream_id
            .checked_add(2)
            .context("agent stream id counter exhausted")?;
        Ok(stream_id)
    }
}

async fn write_frame<W>(writer: &mut W, frame: &AgentFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame)?;
    writer
        .write_all(&encoded)
        .await
        .context("failed to write agent frame")?;
    writer.flush().await.context("failed to flush agent frame")
}

async fn read_frame<R>(reader: &mut R, inbound: &mut BytesMut) -> Result<AgentFrame>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(frame) = try_decode_frame(inbound)? {
            return Ok(frame);
        }

        let mut buf = [0_u8; 8192];
        let read = reader
            .read(&mut buf)
            .await
            .context("failed to read agent frame")?;
        if read == 0 {
            bail!("agent stream closed before next frame");
        }
        inbound.extend_from_slice(&buf[..read]);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::io::{duplex, split};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::agent_runtime::{run, AgentRuntimeConfig};

    #[tokio::test]
    async fn agent_client_round_trips_tcp_stream_through_runtime() {
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
            socket.write_all(b"agent:").await.expect("write prefix");
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

        let (client_reader, client_writer) = split(client_io);
        let mut client = AgentClient::connect(client_reader, client_writer, 1300)
            .await
            .expect("connect agent client");
        assert_eq!(client.peer_hello().protocol_version, AGENT_PROTOCOL_VERSION);

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("listener should be IPv4"),
        };
        let stream_id = client
            .open_tcp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open TCP stream");

        client
            .send_data(stream_id, Bytes::from_static(b"hello"))
            .await
            .expect("send data");
        client.send_eof(stream_id).await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        let mut saw_close = false;
        for _ in 0..16 {
            let frame = timeout(Duration::from_secs(1), client.read_frame())
                .await
                .expect("timed out reading response frame")
                .expect("read response frame");
            match frame.kind {
                AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                AgentFrameKind::Window => {}
                AgentFrameKind::Eof => saw_eof = true,
                AgentFrameKind::Close => {
                    saw_close = true;
                    break;
                }
                other => panic!("unexpected frame from agent: {other:?}"),
            }
        }

        assert_eq!(response, b"agent:hello");
        assert!(saw_eof);
        assert!(saw_close);

        drop(client);
        timeout(Duration::from_secs(1), agent)
            .await
            .expect("agent task should exit after client drop")
            .expect("agent task join")
            .expect("agent run");
        server.await.expect("server task join");
    }
}
