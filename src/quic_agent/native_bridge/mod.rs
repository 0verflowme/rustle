use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use quinn::{Connection, Endpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::agent_proto::{AgentOpenHost, AgentOpenIpv4};

use super::auth::{
    authenticate_quic_bridge_connection_on_client, authenticate_quic_bridge_connection_on_server,
    generate_quic_auth_token, open_quic_bi_stream_with_timeout, QUIC_AUTH_FAILED_CODE,
};
use super::bootstrap::{sha256_hex, QuicAgentBootstrap};
use super::config::{
    quic_client_config, quic_client_endpoint, quic_server_config, quic_server_endpoint,
    QUIC_AGENT_SERVER_NAME, QUIC_BRIDGE_MAX_CONCURRENT_BIDI_STREAMS,
};
mod wire;

pub use wire::QUIC_BRIDGE_TCP_CHUNK;
use wire::{
    decode_quic_bridge_open_header, encode_quic_bridge_host_open, encode_quic_bridge_ipv4_open,
    read_quic_bridge_datagram, read_quic_bridge_error, write_quic_bridge_datagram,
    write_quic_bridge_error, QuicBridgeIpv4Open, QuicBridgeOpenHeader, QuicBridgeProtocol,
    QUIC_BRIDGE_OPEN_HEADER_LEN, QUIC_BRIDGE_STATUS_ERR, QUIC_BRIDGE_STATUS_OK,
    QUIC_BRIDGE_UDP_CHUNK,
};

const QUIC_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(8);

pub struct QuicBridgeServer {
    endpoint: Endpoint,
    bootstrap: QuicAgentBootstrap,
}

#[derive(Clone)]
pub struct QuicBridgeClient {
    inner: Arc<QuicBridgeClientInner>,
}

struct QuicBridgeClientInner {
    _endpoint: Endpoint,
    connection: Connection,
}

pub struct QuicBridgeStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
    open_status: QuicBridgeOpenStatus,
}

struct QuicBridgeConnectDiagnostics<'a> {
    remote: SocketAddr,
    cert_sha256: &'a str,
    cert_der_len: usize,
    token_sha256_prefix: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicBridgeOpenStatus {
    Pending,
    Opened,
}

impl<'a> QuicBridgeConnectDiagnostics<'a> {
    fn new(remote: SocketAddr, bootstrap: &'a QuicAgentBootstrap) -> Self {
        let token_hash = sha256_hex(&bootstrap.auth_token);
        Self {
            remote,
            cert_sha256: &bootstrap.cert_sha256,
            cert_der_len: bootstrap.cert_der.len(),
            token_sha256_prefix: token_hash.chars().take(12).collect(),
        }
    }
}

impl std::fmt::Display for QuicBridgeConnectDiagnostics<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "native QUIC bridge remote={} cert_sha256={} cert_der_len={} auth_token_sha256_prefix={}",
            self.remote, self.cert_sha256, self.cert_der_len, self.token_sha256_prefix
        )
    }
}

impl QuicBridgeServer {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read QUIC bridge local address")
    }

    pub fn bootstrap(&self) -> &QuicAgentBootstrap {
        &self.bootstrap
    }

    pub async fn run(self) -> Result<()> {
        loop {
            let incoming = self.endpoint.accept().await.ok_or_else(|| {
                anyhow!("QUIC bridge endpoint closed before accepting a connection")
            })?;
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(err) => {
                    eprintln!("quic-bridge-agent: rejected connection before auth: {err:#}");
                    continue;
                }
            };
            if let Err(err) = authenticate_quic_bridge_connection_on_server(
                &connection,
                &self.bootstrap.auth_token,
            )
            .await
            {
                eprintln!("quic-bridge-agent: rejected unauthenticated connection: {err:#}");
                connection.close(QUIC_AUTH_FAILED_CODE.into(), b"invalid auth token");
                continue;
            }
            return run_bridge_on_connection(connection).await;
        }
    }
}

pub fn start_quic_bridge_server(bind: SocketAddr) -> Result<QuicBridgeServer> {
    let (server_config, cert_der) = quic_server_config(QUIC_BRIDGE_MAX_CONCURRENT_BIDI_STREAMS)?;
    let endpoint =
        quic_server_endpoint(server_config, bind).context("failed to bind QUIC bridge endpoint")?;
    let port = endpoint
        .local_addr()
        .context("failed to inspect QUIC bridge bind address")?
        .port();
    let cert_bytes = cert_der.as_ref().to_vec();
    let bootstrap = QuicAgentBootstrap {
        port,
        cert_sha256: sha256_hex(&cert_bytes),
        cert_der: cert_bytes,
        auth_token: generate_quic_auth_token()?,
    };
    Ok(QuicBridgeServer {
        endpoint,
        bootstrap,
    })
}

pub async fn connect_quic_bridge(
    remote: SocketAddr,
    bootstrap: &QuicAgentBootstrap,
) -> Result<QuicBridgeClient> {
    let diagnostics = QuicBridgeConnectDiagnostics::new(remote, bootstrap);
    let mut endpoint =
        quic_client_endpoint(remote).with_context(|| format!("{diagnostics} stage=client_bind"))?;
    endpoint.set_default_client_config(
        quic_client_config(bootstrap)
            .with_context(|| format!("{diagnostics} stage=client_config"))?,
    );
    let connection = endpoint
        .connect(remote, QUIC_AGENT_SERVER_NAME)
        .with_context(|| format!("{diagnostics} stage=connect_start"))?
        .await
        .with_context(|| format!("{diagnostics} stage=connect_establish"))?;
    authenticate_quic_bridge_connection_on_client(&connection, &bootstrap.auth_token)
        .await
        .with_context(|| format!("{diagnostics} stage=authenticate"))?;
    Ok(QuicBridgeClient {
        inner: Arc::new(QuicBridgeClientInner {
            _endpoint: endpoint,
            connection,
        }),
    })
}

impl QuicBridgeClient {
    #[cfg(test)]
    pub async fn open_tcp_ipv4(&self, open: AgentOpenIpv4) -> Result<QuicBridgeStream> {
        self.open_ipv4(QuicBridgeProtocol::Tcp, open).await
    }

    pub async fn open_tcp_ipv4_optimistic(&self, open: AgentOpenIpv4) -> Result<QuicBridgeStream> {
        self.open_ipv4_optimistic(QuicBridgeProtocol::Tcp, open)
            .await
    }

    pub async fn open_udp_ipv4(&self, open: AgentOpenIpv4) -> Result<QuicBridgeStream> {
        self.open_ipv4(QuicBridgeProtocol::Udp, open).await
    }

    pub async fn open_tcp_host(&self, open: AgentOpenHost) -> Result<QuicBridgeStream> {
        let host = open.destination_host.as_bytes();
        let header = encode_quic_bridge_host_open(&open)?;
        self.open_with_header_and_payload(header, host).await
    }

    async fn open_ipv4(
        &self,
        protocol: QuicBridgeProtocol,
        open: AgentOpenIpv4,
    ) -> Result<QuicBridgeStream> {
        let header = encode_quic_bridge_ipv4_open(QuicBridgeIpv4Open {
            protocol,
            flow: open,
        });
        self.open_with_header_and_payload(header, &[]).await
    }

    async fn open_ipv4_optimistic(
        &self,
        protocol: QuicBridgeProtocol,
        open: AgentOpenIpv4,
    ) -> Result<QuicBridgeStream> {
        let header = encode_quic_bridge_ipv4_open(QuicBridgeIpv4Open {
            protocol,
            flow: open,
        });
        self.open_with_header_and_payload_optimistic(header, &[])
            .await
    }

    async fn open_with_header_and_payload(
        &self,
        header: [u8; QUIC_BRIDGE_OPEN_HEADER_LEN],
        payload: &[u8],
    ) -> Result<QuicBridgeStream> {
        let mut stream = self
            .open_with_header_and_payload_optimistic(header, payload)
            .await?;
        stream.wait_opened().await?;
        Ok(stream)
    }

    async fn open_with_header_and_payload_optimistic(
        &self,
        header: [u8; QUIC_BRIDGE_OPEN_HEADER_LEN],
        payload: &[u8],
    ) -> Result<QuicBridgeStream> {
        let (mut send, recv) = open_quic_bi_stream_with_timeout(
            &self.inner.connection,
            QUIC_STREAM_OPEN_TIMEOUT,
            "native QUIC bridge stream",
        )
        .await?;
        write_quic_open_bytes_with_timeout(&mut send, &header, "native QUIC bridge open header")
            .await?;
        if !payload.is_empty() {
            write_quic_open_bytes_with_timeout(
                &mut send,
                payload,
                "native QUIC bridge open payload",
            )
            .await?;
        }
        Ok(QuicBridgeStream {
            recv,
            send,
            open_status: QuicBridgeOpenStatus::Pending,
        })
    }

    #[cfg(test)]
    pub fn close(&self, reason: &str) {
        self.inner.connection.close(0_u32.into(), reason.as_bytes());
    }
}

impl QuicBridgeStream {
    pub async fn wait_opened(&mut self) -> Result<()> {
        if self.open_status == QuicBridgeOpenStatus::Opened {
            return Ok(());
        }

        let mut status = [0_u8; 1];
        read_quic_open_exact_with_timeout(
            &mut self.recv,
            &mut status,
            "native QUIC bridge open status",
        )
        .await?;
        match status[0] {
            QUIC_BRIDGE_STATUS_OK => {
                self.open_status = QuicBridgeOpenStatus::Opened;
                Ok(())
            }
            QUIC_BRIDGE_STATUS_ERR => {
                let reason = tokio::time::timeout(
                    QUIC_STREAM_OPEN_TIMEOUT,
                    read_quic_bridge_error(&mut self.recv),
                )
                .await
                .context("timed out reading native QUIC bridge open error")??;
                bail!("native QUIC bridge failed to open stream: {reason}");
            }
            other => bail!("native QUIC bridge returned invalid open status {other}"),
        }
    }

    pub async fn send_data(&mut self, bytes: Bytes) -> Result<()> {
        self.send
            .write_chunk(bytes)
            .await
            .context("failed to write native QUIC bridge stream")
    }

    pub async fn send_eof(&mut self) -> Result<()> {
        self.send
            .shutdown()
            .await
            .context("failed to finish native QUIC bridge send stream")
    }

    #[cfg(test)]
    pub async fn recv_data(&mut self, buf: &mut [u8]) -> Result<Option<Bytes>> {
        self.wait_opened().await?;
        let Some(len) = self
            .recv
            .read(buf)
            .await
            .context("failed to read native QUIC bridge stream")?
        else {
            return Ok(None);
        };
        Ok(Some(Bytes::copy_from_slice(&buf[..len])))
    }

    pub async fn recv_chunk(&mut self, max_length: usize) -> Result<Option<Bytes>> {
        self.wait_opened().await?;
        let chunk = self
            .recv
            .read_chunk(max_length, true)
            .await
            .context("failed to read native QUIC bridge stream chunk")?;
        Ok(chunk.map(|chunk| chunk.bytes))
    }

    pub async fn send_datagram(&mut self, bytes: Bytes) -> Result<()> {
        write_quic_bridge_datagram(&mut self.send, bytes.as_ref()).await
    }

    pub async fn recv_datagram(&mut self) -> Result<Option<Bytes>> {
        self.wait_opened().await?;
        read_quic_bridge_datagram(&mut self.recv).await
    }
}

async fn run_bridge_on_connection(connection: Connection) -> Result<()> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(err) = run_bridge_stream(send, recv).await {
                        eprintln!("quic-bridge-agent: stream failed: {err:#}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::Reset) => break,
            Err(err) => return Err(err).context("failed to accept native QUIC bridge stream"),
        }
    }
    Ok(())
}

async fn run_bridge_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let mut header = [0_u8; QUIC_BRIDGE_OPEN_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .context("failed to read native QUIC bridge open header")?;
    let header = match decode_quic_bridge_open_header(&header) {
        Ok(open) => open,
        Err(err) => {
            let _ = write_quic_bridge_error(&mut send, &err.to_string()).await;
            return Err(err);
        }
    };
    match header {
        QuicBridgeOpenHeader::Ipv4(open) => match open.protocol {
            QuicBridgeProtocol::Tcp => {
                run_bridge_tcp_stream(
                    send,
                    recv,
                    SocketAddr::new(open.flow.destination_ip.into(), open.flow.destination_port),
                )
                .await
            }
            QuicBridgeProtocol::Udp => run_bridge_udp_stream(send, recv, open.flow).await,
            QuicBridgeProtocol::TcpHost => {
                let reason = "hostname protocol is not valid for IPv4 open headers";
                let _ = write_quic_bridge_error(&mut send, reason).await;
                bail!(reason);
            }
        },
        QuicBridgeOpenHeader::TcpHost(header) => {
            let mut host = vec![0_u8; header.host_len as usize];
            recv.read_exact(&mut host)
                .await
                .context("failed to read native QUIC bridge hostname open payload")?;
            let mut payload = BytesMut::with_capacity(8 + host.len());
            payload.put_u16(header.destination_port);
            payload.put_slice(&header.originator_ip.octets());
            payload.put_u16(header.originator_port);
            payload.extend_from_slice(&host);
            let open = match AgentOpenHost::decode(payload.as_ref()) {
                Ok(open) => open,
                Err(err) => {
                    let _ = write_quic_bridge_error(&mut send, &err.to_string()).await;
                    return Err(err);
                }
            };
            run_bridge_tcp_host_stream(send, recv, open).await
        }
    }
}

async fn run_bridge_tcp_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    destination: SocketAddr,
) -> Result<()> {
    let stream = match TcpStream::connect(destination).await {
        Ok(stream) => stream,
        Err(err) => {
            let reason = format!("failed to connect remote TCP stream {destination}: {err}");
            let _ = write_quic_bridge_error(&mut send, &reason).await;
            bail!(reason);
        }
    };
    relay_quic_bridge_tcp_stream(send, recv, stream).await
}

async fn relay_quic_bridge_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    stream: TcpStream,
) -> Result<()> {
    send.write_all(&[QUIC_BRIDGE_STATUS_OK])
        .await
        .context("failed to write native QUIC bridge open status")?;
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let local_to_remote = tokio::spawn(async move {
        let result = tokio::io::copy(&mut recv, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
        result
    });

    let mut buf = BytesMut::with_capacity(QUIC_BRIDGE_TCP_CHUNK);
    loop {
        if buf.capacity() < QUIC_BRIDGE_TCP_CHUNK {
            buf.reserve(QUIC_BRIDGE_TCP_CHUNK - buf.capacity());
        }
        let len = tcp_read
            .read_buf(&mut buf)
            .await
            .context("failed to read remote TCP stream")?;
        if len == 0 {
            break;
        }
        send.write_chunk(buf.split_to(len).freeze())
            .await
            .context("failed to write native QUIC bridge response")?;
    }
    let _ = send.shutdown().await;
    local_to_remote.abort();
    Ok(())
}

async fn run_bridge_tcp_host_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    open: AgentOpenHost,
) -> Result<()> {
    let destination = format!("{}:{}", open.destination_host, open.destination_port);
    let stream = match TcpStream::connect(&destination).await {
        Ok(stream) => stream,
        Err(err) => {
            let reason =
                format!("failed to connect remote hostname TCP stream {destination}: {err}");
            let _ = write_quic_bridge_error(&mut send, &reason).await;
            bail!(reason);
        }
    };
    relay_quic_bridge_tcp_stream(send, recv, stream).await
}

async fn run_bridge_udp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    open: AgentOpenIpv4,
) -> Result<()> {
    let destination = SocketAddr::new(open.destination_ip.into(), open.destination_port);
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(err) => {
            let reason = format!("failed to bind remote UDP socket: {err}");
            let _ = write_quic_bridge_error(&mut send, &reason).await;
            bail!(reason);
        }
    };
    if let Err(err) = socket.connect(destination).await {
        let reason = format!("failed to connect remote UDP socket {destination}: {err}");
        let _ = write_quic_bridge_error(&mut send, &reason).await;
        bail!(reason);
    }

    send.write_all(&[QUIC_BRIDGE_STATUS_OK])
        .await
        .context("failed to write native QUIC bridge open status")?;
    let mut read_buf = vec![0_u8; QUIC_BRIDGE_UDP_CHUNK];
    loop {
        tokio::select! {
            local = read_quic_bridge_datagram(&mut recv) => {
                match local? {
                    Some(datagram) => {
                        socket
                            .send(datagram.as_ref())
                            .await
                            .context("failed to write remote UDP socket")?;
                    }
                    None => break,
                }
            }
            remote = socket.recv(&mut read_buf) => {
                let len = remote.context("failed to read remote UDP socket")?;
                write_quic_bridge_datagram(&mut send, &read_buf[..len]).await?;
            }
        }
    }
    let _ = send.shutdown().await;
    Ok(())
}

async fn write_quic_open_bytes_with_timeout(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    tokio::time::timeout(QUIC_STREAM_OPEN_TIMEOUT, send.write_all(bytes))
        .await
        .with_context(|| {
            format!(
                "timed out writing {label} after {}ms",
                QUIC_STREAM_OPEN_TIMEOUT.as_millis()
            )
        })?
        .with_context(|| format!("failed to write {label}"))
}

async fn read_quic_open_exact_with_timeout(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
    label: &str,
) -> Result<()> {
    tokio::time::timeout(QUIC_STREAM_OPEN_TIMEOUT, recv.read_exact(buf))
        .await
        .with_context(|| {
            format!(
                "timed out reading {label} after {}ms",
                QUIC_STREAM_OPEN_TIMEOUT.as_millis()
            )
        })?
        .with_context(|| format!("failed to read {label}"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use super::*;

    fn tampered_bootstrap_token(bootstrap: &QuicAgentBootstrap) -> QuicAgentBootstrap {
        let mut tampered = bootstrap.clone();
        tampered.auth_token[0] ^= 0xff;
        tampered
    }

    #[test]
    fn quic_bridge_connect_diagnostics_include_fingerprint_without_raw_token() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
        let cert_der = vec![1_u8, 2, 3, 4];
        let auth_token = vec![0xab; super::super::auth::QUIC_AUTH_TOKEN_BYTES];
        let token_hash = sha256_hex(&auth_token);
        let bootstrap = QuicAgentBootstrap {
            port: remote.port(),
            cert_sha256: sha256_hex(&cert_der),
            cert_der,
            auth_token,
        };

        let diagnostics = QuicBridgeConnectDiagnostics::new(remote, &bootstrap).to_string();

        assert!(diagnostics.contains("native QUIC bridge remote=127.0.0.1:4433"));
        assert!(diagnostics.contains(&bootstrap.cert_sha256));
        assert!(diagnostics.contains("cert_der_len=4"));
        assert!(diagnostics.contains(&format!("auth_token_sha256_prefix={}", &token_hash[..12])));
        assert!(
            !diagnostics.contains("abababababab"),
            "diagnostics must not expose raw auth token bytes"
        );
    }

    #[tokio::test]
    async fn quic_bridge_auth_rejects_bad_token_and_accepts_next_connection() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP echo listener");
        let destination = listener.local_addr().expect("listener address");
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut request)
                .await
                .expect("read request");
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"auth:")
                .await
                .expect("write prefix");
            tokio::io::AsyncWriteExt::write_all(&mut socket, &request)
                .await
                .expect("write response");
        });

        let quic_server =
            start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });

        let bad_bootstrap = tampered_bootstrap_token(&bootstrap);
        let bad_token_hash = sha256_hex(&bad_bootstrap.auth_token);
        let bad = connect_quic_bridge(quic_addr, &bad_bootstrap).await;
        let bad_err = match bad {
            Ok(_) => panic!("bad token unexpectedly authenticated"),
            Err(err) => err,
        };
        let bad_detail = format!("{bad_err:#}");
        assert!(bad_detail.contains("stage=authenticate"));
        assert!(bad_detail.contains(&format!("remote={quic_addr}")));
        assert!(bad_detail.contains(&format!(
            "auth_token_sha256_prefix={}",
            &bad_token_hash[..12]
        )));
        assert!(bad_detail.contains("native QUIC bridge auth stage="));
        assert!(bad_detail.contains("elapsed_ms="));

        let client = connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("valid token authenticates after bad token");
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination should be IPv4");
        };
        let mut stream = client
            .open_tcp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC bridge stream after auth");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut buf = vec![0_u8; 1024];
        while let Some(chunk) = stream.recv_data(&mut buf).await.expect("read response") {
            response.extend_from_slice(chunk.as_ref());
        }

        assert_eq!(response, b"auth:ping");
        client.close("test complete");
        bridge_task.await.expect("bridge task");
        server_task.await.expect("TCP server task");
    }

    #[tokio::test]
    async fn quic_bridge_stream_round_trips_tcp_payload() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP echo listener");
        let destination = listener.local_addr().expect("listener address");
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut request)
                .await
                .expect("read request");
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"native:")
                .await
                .expect("write prefix");
            tokio::io::AsyncWriteExt::write_all(&mut socket, &request)
                .await
                .expect("write response");
        });

        let quic_server =
            start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });

        let client = connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("connect native QUIC bridge");
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination should be IPv4");
        };
        let mut stream = client
            .open_tcp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC bridge stream");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut buf = vec![0_u8; 1024];
        while let Some(chunk) = stream.recv_data(&mut buf).await.expect("read response") {
            response.extend_from_slice(chunk.as_ref());
        }

        assert_eq!(response, b"native:ping");
        client.close("test complete");
        bridge_task.await.expect("bridge task");
        server_task.await.expect("TCP server task");
    }

    #[tokio::test]
    async fn quic_bridge_optimistic_tcp_open_forwards_payload_before_client_reads_status() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP echo listener");
        let destination = listener.local_addr().expect("listener address");
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut request)
                .await
                .expect("read request");
            assert_eq!(&request, b"ping");
            seen_tx.send(()).expect("report request");
        });

        let quic_server =
            start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });

        let client = connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("connect native QUIC bridge");
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination should be IPv4");
        };
        let mut stream = client
            .open_tcp_ipv4_optimistic(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open optimistic native QUIC bridge stream");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request before reading open status");
        tokio::time::timeout(std::time::Duration::from_secs(1), seen_rx)
            .await
            .expect("remote server sees optimistic payload")
            .expect("request seen");
        stream.wait_opened().await.expect("read open status");
        stream.send_eof().await.expect("send EOF");

        client.close("test complete");
        bridge_task.await.expect("bridge task");
        server_task.await.expect("TCP server task");
    }

    #[tokio::test]
    async fn quic_bridge_stream_round_trips_tcp_hostname_payload() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP echo listener");
        let destination = listener.local_addr().expect("listener address");
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut socket, &mut request)
                .await
                .expect("read request");
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"host:")
                .await
                .expect("write prefix");
            tokio::io::AsyncWriteExt::write_all(&mut socket, &request)
                .await
                .expect("write response");
        });

        let quic_server =
            start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });

        let client = connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("connect native QUIC bridge");
        let mut stream = client
            .open_tcp_host(AgentOpenHost {
                destination_host: "localhost".to_owned(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC hostname bridge stream");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut buf = vec![0_u8; 1024];
        while let Some(chunk) = stream.recv_data(&mut buf).await.expect("read response") {
            response.extend_from_slice(chunk.as_ref());
        }

        assert_eq!(response, b"host:ping");
        client.close("test complete");
        bridge_task.await.expect("bridge task");
        server_task.await.expect("TCP server task");
    }

    #[tokio::test]
    async fn quic_bridge_stream_round_trips_udp_datagrams() {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP echo socket");
        let destination = socket.local_addr().expect("UDP socket address");
        let server_task = tokio::spawn(async move {
            let mut buf = [0_u8; 1024];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP request");
                let mut response = b"native-udp:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });

        let quic_server =
            start_quic_bridge_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start native QUIC bridge");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let bridge_task =
            tokio::spawn(async move { quic_server.run().await.expect("run native QUIC bridge") });

        let client = connect_quic_bridge(quic_addr, &bootstrap)
            .await
            .expect("connect native QUIC bridge");
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination should be IPv4");
        };
        let mut stream = client
            .open_udp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC UDP bridge stream");

        stream
            .send_datagram(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        stream
            .send_datagram(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        assert_eq!(
            stream
                .recv_datagram()
                .await
                .expect("read first response")
                .expect("first response"),
            Bytes::from_static(b"native-udp:one")
        );
        assert_eq!(
            stream
                .recv_datagram()
                .await
                .expect("read second response")
                .expect("second response"),
            Bytes::from_static(b"native-udp:two")
        );

        stream.send_eof().await.expect("close UDP stream");
        client.close("test complete");
        bridge_task.await.expect("bridge task");
        server_task.await.expect("UDP server task");
    }
}
