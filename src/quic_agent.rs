use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, MtuDiscoveryConfig, ServerConfig,
    TransportConfig,
};
use rcgen::generate_simple_self_signed;
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::agent_proto::{AgentOpenHost, AgentOpenIpv4};
use crate::agent_runtime::{self, AgentRuntimeConfig};
use crate::agent_transport::AgentTransport;

pub const QUIC_AGENT_SERVER_NAME: &str = "rustle-agent";
pub const QUIC_AGENT_BOOTSTRAP_MAGIC: &str = "RUSTLE_QUIC_AGENT_V1";
pub const QUIC_BRIDGE_BOOTSTRAP_MAGIC: &str = "RUSTLE_QUIC_BRIDGE_V1";
const QUIC_AGENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_AGENT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const QUIC_AGENT_MAX_CONCURRENT_BIDI_STREAMS: u16 = 1;
const QUIC_BRIDGE_MAX_CONCURRENT_BIDI_STREAMS: u16 = 1024;
const QUIC_AGENT_MAX_CONCURRENT_UNI_STREAMS: u16 = 0;
const QUIC_AGENT_STREAM_RECEIVE_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const QUIC_AGENT_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
const QUIC_AGENT_SEND_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES: u16 = 9000;
const QUIC_BRIDGE_OPEN_MAGIC: &[u8; 4] = b"RQB2";
const QUIC_BRIDGE_OPEN_HEADER_LEN: usize = 20;
const QUIC_BRIDGE_STATUS_OK: u8 = 0;
const QUIC_BRIDGE_STATUS_ERR: u8 = 1;
pub const QUIC_BRIDGE_TCP_CHUNK: usize = 256 * 1024;
const QUIC_BRIDGE_UDP_CHUNK: usize = u16::MAX as usize;
const QUIC_BRIDGE_PROTO_TCP: u8 = 6;
const QUIC_BRIDGE_PROTO_UDP: u8 = 17;
const QUIC_BRIDGE_PROTO_TCP_HOST: u8 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicBridgeProtocol {
    Tcp,
    Udp,
    TcpHost,
}

impl QuicBridgeProtocol {
    const fn code(self) -> u8 {
        match self {
            Self::Tcp => QUIC_BRIDGE_PROTO_TCP,
            Self::Udp => QUIC_BRIDGE_PROTO_UDP,
            Self::TcpHost => QUIC_BRIDGE_PROTO_TCP_HOST,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            QUIC_BRIDGE_PROTO_TCP => Ok(Self::Tcp),
            QUIC_BRIDGE_PROTO_UDP => Ok(Self::Udp),
            QUIC_BRIDGE_PROTO_TCP_HOST => Ok(Self::TcpHost),
            _ => bail!("unsupported native QUIC bridge protocol {code}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuicBridgeIpv4Open {
    protocol: QuicBridgeProtocol,
    flow: AgentOpenIpv4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuicBridgeHostOpenHeader {
    destination_port: u16,
    originator_ip: Ipv4Addr,
    originator_port: u16,
    host_len: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicBridgeOpenHeader {
    Ipv4(QuicBridgeIpv4Open),
    TcpHost(QuicBridgeHostOpenHeader),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicAgentBootstrap {
    pub port: u16,
    pub cert_sha256: String,
    pub cert_der: Vec<u8>,
}

impl QuicAgentBootstrap {
    pub fn encode_line(&self) -> String {
        self.encode_line_with_magic(QUIC_AGENT_BOOTSTRAP_MAGIC)
    }

    pub fn encode_bridge_line(&self) -> String {
        self.encode_line_with_magic(QUIC_BRIDGE_BOOTSTRAP_MAGIC)
    }

    fn encode_line_with_magic(&self, magic: &str) -> String {
        format!(
            "{magic} {} {} {}",
            self.port,
            self.cert_sha256,
            lower_hex(&self.cert_der)
        )
    }

    pub fn decode_line(line: &str) -> Result<Self> {
        Self::decode_line_with_magic(line, QUIC_AGENT_BOOTSTRAP_MAGIC)
    }

    pub fn decode_bridge_line(line: &str) -> Result<Self> {
        Self::decode_line_with_magic(line, QUIC_BRIDGE_BOOTSTRAP_MAGIC)
    }

    fn decode_line_with_magic(line: &str, expected_magic: &str) -> Result<Self> {
        let mut fields = line.split_whitespace();
        let Some(magic) = fields.next() else {
            bail!("empty QUIC agent bootstrap line");
        };
        if magic != expected_magic {
            bail!("unexpected QUIC bootstrap magic {magic:?}");
        }
        let port = fields
            .next()
            .context("missing QUIC agent UDP port")?
            .parse::<u16>()
            .context("invalid QUIC agent UDP port")?;
        let cert_sha256 = fields
            .next()
            .context("missing QUIC agent certificate SHA-256")?
            .to_ascii_lowercase();
        if !is_sha256_hex(&cert_sha256) {
            bail!("invalid QUIC agent certificate SHA-256 {cert_sha256:?}");
        }
        let cert_der = decode_hex(
            fields
                .next()
                .context("missing QUIC agent certificate DER")?,
        )
        .context("invalid QUIC agent certificate DER")?;
        if fields.next().is_some() {
            bail!("unexpected trailing fields in QUIC agent bootstrap line");
        }
        let actual_sha256 = sha256_hex(&cert_der);
        if actual_sha256 != cert_sha256 {
            bail!(
                "QUIC agent certificate SHA-256 mismatch: expected {cert_sha256}, got {actual_sha256}"
            );
        }
        Ok(Self {
            port,
            cert_sha256,
            cert_der,
        })
    }
}

pub struct QuicAgentServer {
    endpoint: Endpoint,
    bootstrap: QuicAgentBootstrap,
}

pub struct QuicBridgeServer {
    endpoint: Endpoint,
    bootstrap: QuicAgentBootstrap,
}

impl QuicAgentServer {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read QUIC agent local address")
    }

    pub fn bootstrap(&self) -> &QuicAgentBootstrap {
        &self.bootstrap
    }

    pub async fn run_one(self, config: AgentRuntimeConfig) -> Result<()> {
        let incoming =
            self.endpoint.accept().await.ok_or_else(|| {
                anyhow!("QUIC agent endpoint closed before accepting a connection")
            })?;
        let connection = incoming
            .await
            .context("failed to accept QUIC agent connection")?;
        run_agent_on_connection(connection, config).await
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
        let incoming =
            self.endpoint.accept().await.ok_or_else(|| {
                anyhow!("QUIC bridge endpoint closed before accepting a connection")
            })?;
        let connection = incoming
            .await
            .context("failed to accept QUIC bridge connection")?;
        run_bridge_on_connection(connection).await
    }
}

pub struct QuicAgentClient {
    session: QuicAgentSession,
    pub transport: AgentTransport,
}

pub struct QuicAgentSession {
    _endpoint: Endpoint,
    _connection: Connection,
}

impl QuicAgentClient {
    pub fn into_transport_and_session(self) -> (AgentTransport, QuicAgentSession) {
        (self.transport, self.session)
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicBridgeOpenStatus {
    Pending,
    Opened,
}

pub fn start_quic_agent_server(bind: SocketAddr) -> Result<QuicAgentServer> {
    let (server_config, cert_der) = quic_server_config(QUIC_AGENT_MAX_CONCURRENT_BIDI_STREAMS)?;
    let endpoint =
        quic_server_endpoint(server_config, bind).context("failed to bind QUIC endpoint")?;
    let port = endpoint
        .local_addr()
        .context("failed to inspect QUIC bind address")?
        .port();
    let cert_bytes = cert_der.as_ref().to_vec();
    let bootstrap = QuicAgentBootstrap {
        port,
        cert_sha256: sha256_hex(&cert_bytes),
        cert_der: cert_bytes,
    };
    Ok(QuicAgentServer {
        endpoint,
        bootstrap,
    })
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
    };
    Ok(QuicBridgeServer {
        endpoint,
        bootstrap,
    })
}

pub async fn connect_quic_agent(
    remote: SocketAddr,
    bootstrap: &QuicAgentBootstrap,
    mtu: u16,
) -> Result<QuicAgentClient> {
    let mut endpoint = quic_client_endpoint(remote).context("failed to bind QUIC client")?;
    endpoint.set_default_client_config(quic_client_config(bootstrap)?);
    let connection = endpoint
        .connect(remote, QUIC_AGENT_SERVER_NAME)
        .context("failed to start QUIC agent connection")?
        .await
        .context("failed to establish QUIC agent connection")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC agent stream")?;
    let transport = AgentTransport::connect(recv, send, mtu)
        .await
        .context("failed to negotiate Rustle agent protocol over QUIC")?;
    Ok(QuicAgentClient {
        session: QuicAgentSession {
            _endpoint: endpoint,
            _connection: connection,
        },
        transport,
    })
}

pub async fn connect_quic_bridge(
    remote: SocketAddr,
    bootstrap: &QuicAgentBootstrap,
) -> Result<QuicBridgeClient> {
    let mut endpoint = quic_client_endpoint(remote).context("failed to bind QUIC client")?;
    endpoint.set_default_client_config(quic_client_config(bootstrap)?);
    let connection = endpoint
        .connect(remote, QUIC_AGENT_SERVER_NAME)
        .context("failed to start QUIC bridge connection")?
        .await
        .context("failed to establish QUIC bridge connection")?;
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
        let (mut send, recv) = self
            .inner
            .connection
            .open_bi()
            .await
            .context("failed to open native QUIC bridge stream")?;
        send.write_all(&header)
            .await
            .context("failed to write native QUIC bridge open header")?;
        if !payload.is_empty() {
            send.write_all(payload)
                .await
                .context("failed to write native QUIC bridge open payload")?;
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
        self.recv
            .read_exact(&mut status)
            .await
            .context("failed to read native QUIC bridge open status")?;
        match status[0] {
            QUIC_BRIDGE_STATUS_OK => {
                self.open_status = QuicBridgeOpenStatus::Opened;
                Ok(())
            }
            QUIC_BRIDGE_STATUS_ERR => {
                let reason = read_quic_bridge_error(&mut self.recv).await?;
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

async fn run_agent_on_connection(connection: Connection, config: AgentRuntimeConfig) -> Result<()> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("failed to accept QUIC agent stream")?;
    let result = agent_runtime::run(recv, send, config).await;
    connection.close(0_u32.into(), b"rustle agent complete");
    result.context("QUIC agent runtime failed")
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
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
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

fn quic_server_config(
    max_concurrent_bidi_streams: u16,
) -> Result<(ServerConfig, CertificateDer<'static>)> {
    let cert = generate_simple_self_signed(vec![QUIC_AGENT_SERVER_NAME.to_owned()])
        .context("failed to generate QUIC agent certificate")?;
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key.into())
        .context("failed to build QUIC agent server TLS config")?;
    let transport = Arc::get_mut(&mut server_config.transport)
        .context("QUIC server transport config is unexpectedly shared")?;
    configure_quic_agent_transport(transport, max_concurrent_bidi_streams)?;
    Ok((server_config, cert_der))
}

fn quic_client_config(bootstrap: &QuicAgentBootstrap) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(bootstrap.cert_der.clone()))
        .context("failed to add pinned QUIC agent certificate")?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .context("failed to build QUIC agent client TLS config")?;
    let mut transport = TransportConfig::default();
    configure_quic_agent_transport(&mut transport, 0)?;
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn configure_quic_agent_transport(
    transport: &mut TransportConfig,
    max_concurrent_bidi_streams: u16,
) -> Result<()> {
    let mut mtu_discovery = MtuDiscoveryConfig::default();
    mtu_discovery.upper_bound(QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES);
    transport
        .max_concurrent_bidi_streams(max_concurrent_bidi_streams.into())
        .max_concurrent_uni_streams(QUIC_AGENT_MAX_CONCURRENT_UNI_STREAMS.into())
        .stream_receive_window(QUIC_AGENT_STREAM_RECEIVE_WINDOW_BYTES.into())
        .receive_window(QUIC_AGENT_CONNECTION_RECEIVE_WINDOW_BYTES.into())
        .send_window(QUIC_AGENT_SEND_WINDOW_BYTES)
        .mtu_discovery_config(Some(mtu_discovery))
        .keep_alive_interval(Some(QUIC_AGENT_KEEPALIVE_INTERVAL))
        .max_idle_timeout(Some(QUIC_AGENT_IDLE_TIMEOUT.try_into()?));
    Ok(())
}

fn quic_endpoint_config() -> Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES)
        .context("failed to configure QUIC endpoint UDP payload size")?;
    Ok(config)
}

fn quic_server_endpoint(server_config: ServerConfig, bind: SocketAddr) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(bind).context("failed to bind QUIC UDP socket")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no QUIC async runtime found"))?;
    Endpoint::new(
        quic_endpoint_config()?,
        Some(server_config),
        socket,
        runtime,
    )
    .context("failed to create QUIC server endpoint")
}

fn quic_client_endpoint(remote: SocketAddr) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(client_bind_addr_for(remote))
        .context("failed to bind QUIC client UDP socket")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no QUIC async runtime found"))?;
    Endpoint::new(quic_endpoint_config()?, None, socket, runtime)
        .context("failed to create QUIC client endpoint")
}

fn encode_quic_bridge_ipv4_open(open: QuicBridgeIpv4Open) -> [u8; QUIC_BRIDGE_OPEN_HEADER_LEN] {
    let mut header = [0_u8; QUIC_BRIDGE_OPEN_HEADER_LEN];
    header[..4].copy_from_slice(QUIC_BRIDGE_OPEN_MAGIC);
    header[4] = open.protocol.code();
    header[8..12].copy_from_slice(&open.flow.destination_ip.octets());
    header[12..14].copy_from_slice(&open.flow.destination_port.to_be_bytes());
    header[14..18].copy_from_slice(&open.flow.originator_ip.octets());
    header[18..20].copy_from_slice(&open.flow.originator_port.to_be_bytes());
    header
}

fn encode_quic_bridge_host_open(open: &AgentOpenHost) -> Result<[u8; QUIC_BRIDGE_OPEN_HEADER_LEN]> {
    open.encode()
        .context("invalid native QUIC hostname open payload")?;
    let host_len = u16::try_from(open.destination_host.len())
        .context("native QUIC hostname open destination is too long")?;
    let mut header = [0_u8; QUIC_BRIDGE_OPEN_HEADER_LEN];
    header[..4].copy_from_slice(QUIC_BRIDGE_OPEN_MAGIC);
    header[4] = QuicBridgeProtocol::TcpHost.code();
    header[8..10].copy_from_slice(&open.destination_port.to_be_bytes());
    header[10..14].copy_from_slice(&open.originator_ip.octets());
    header[14..16].copy_from_slice(&open.originator_port.to_be_bytes());
    header[16..18].copy_from_slice(&host_len.to_be_bytes());
    Ok(header)
}

fn decode_quic_bridge_open_header(
    header: &[u8; QUIC_BRIDGE_OPEN_HEADER_LEN],
) -> Result<QuicBridgeOpenHeader> {
    if &header[..4] != QUIC_BRIDGE_OPEN_MAGIC {
        bail!("invalid native QUIC bridge open magic");
    }
    if header[5..8] != [0, 0, 0] {
        bail!("native QUIC bridge open reserved bytes must be zero");
    }
    let protocol = QuicBridgeProtocol::from_code(header[4])?;
    match protocol {
        QuicBridgeProtocol::Tcp | QuicBridgeProtocol::Udp => {
            Ok(QuicBridgeOpenHeader::Ipv4(QuicBridgeIpv4Open {
                protocol,
                flow: AgentOpenIpv4 {
                    destination_ip: Ipv4Addr::new(header[8], header[9], header[10], header[11]),
                    destination_port: u16::from_be_bytes([header[12], header[13]]),
                    originator_ip: Ipv4Addr::new(header[14], header[15], header[16], header[17]),
                    originator_port: u16::from_be_bytes([header[18], header[19]]),
                },
            }))
        }
        QuicBridgeProtocol::TcpHost => {
            if header[18..20] != [0, 0] {
                bail!("native QUIC hostname open reserved bytes must be zero");
            }
            let host_len = u16::from_be_bytes([header[16], header[17]]);
            if host_len == 0 {
                bail!("native QUIC hostname open destination is empty");
            }
            Ok(QuicBridgeOpenHeader::TcpHost(QuicBridgeHostOpenHeader {
                destination_port: u16::from_be_bytes([header[8], header[9]]),
                originator_ip: Ipv4Addr::new(header[10], header[11], header[12], header[13]),
                originator_port: u16::from_be_bytes([header[14], header[15]]),
                host_len,
            }))
        }
    }
}

async fn write_quic_bridge_datagram(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > QUIC_BRIDGE_UDP_CHUNK {
        bail!(
            "native QUIC bridge UDP datagram exceeds {} byte limit",
            QUIC_BRIDGE_UDP_CHUNK
        );
    }
    send.write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .context("failed to write native QUIC bridge UDP datagram length")?;
    send.write_all(bytes)
        .await
        .context("failed to write native QUIC bridge UDP datagram body")
}

async fn read_quic_bridge_datagram(recv: &mut quinn::RecvStream) -> Result<Option<Bytes>> {
    let mut len = [0_u8; 2];
    if !read_quic_bridge_exact_or_eof(recv, &mut len).await? {
        return Ok(None);
    }
    let len = u16::from_be_bytes(len) as usize;
    let mut body = vec![0_u8; len];
    recv.read_exact(&mut body)
        .await
        .context("failed to read native QUIC bridge UDP datagram body")?;
    Ok(Some(Bytes::from(body)))
}

async fn read_quic_bridge_exact_or_eof(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
) -> Result<bool> {
    let mut offset = 0;
    while offset < buf.len() {
        match recv.read(&mut buf[offset..]).await {
            Ok(Some(0)) => bail!("native QUIC bridge UDP datagram read made no progress"),
            Ok(Some(len)) => offset += len,
            Ok(None) if offset == 0 => return Ok(false),
            Ok(None) => bail!("native QUIC bridge UDP datagram ended mid-frame"),
            Err(quinn::ReadError::ConnectionLost(_)) if offset == 0 => return Ok(false),
            Err(err) => {
                return Err(err).context("failed to read native QUIC bridge UDP datagram length")
            }
        }
    }
    Ok(true)
}

async fn write_quic_bridge_error(send: &mut quinn::SendStream, reason: &str) -> Result<()> {
    let reason = reason.as_bytes();
    let len = reason.len().min(u16::MAX as usize);
    send.write_all(&[QUIC_BRIDGE_STATUS_ERR])
        .await
        .context("failed to write native QUIC bridge error status")?;
    send.write_all(&(len as u16).to_be_bytes())
        .await
        .context("failed to write native QUIC bridge error length")?;
    send.write_all(&reason[..len])
        .await
        .context("failed to write native QUIC bridge error body")?;
    let _ = send.shutdown().await;
    Ok(())
}

async fn read_quic_bridge_error(recv: &mut quinn::RecvStream) -> Result<String> {
    let mut len = [0_u8; 2];
    recv.read_exact(&mut len)
        .await
        .context("failed to read native QUIC bridge error length")?;
    let len = u16::from_be_bytes(len) as usize;
    let mut reason = vec![0_u8; len];
    recv.read_exact(&mut reason)
        .await
        .context("failed to read native QUIC bridge error body")?;
    Ok(String::from_utf8_lossy(&reason).into_owned())
}

fn client_bind_addr_for(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex string has an odd length");
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("non-hex byte 0x{byte:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::agent_proto::AgentOpenIpv4;

    #[test]
    fn bootstrap_line_round_trips_and_verifies_hash() {
        let bootstrap = QuicAgentBootstrap {
            port: 4433,
            cert_der: vec![0, 1, 2, 0xfe, 0xff],
            cert_sha256: sha256_hex(&[0, 1, 2, 0xfe, 0xff]),
        };

        assert_eq!(
            QuicAgentBootstrap::decode_line(&bootstrap.encode_line()).unwrap(),
            bootstrap
        );
    }

    #[test]
    fn bootstrap_line_rejects_tampered_cert() {
        let bootstrap = QuicAgentBootstrap {
            port: 4433,
            cert_der: vec![1, 2, 3],
            cert_sha256: sha256_hex(&[1, 2, 3]),
        };
        let mut line = bootstrap.encode_line();
        line.push_str("00");

        assert!(QuicAgentBootstrap::decode_line(&line).is_err());
    }

    #[test]
    fn quic_agent_server_transport_is_tuned_for_single_agent_stream() {
        let mut transport = TransportConfig::default();
        configure_quic_agent_transport(&mut transport, QUIC_AGENT_MAX_CONCURRENT_BIDI_STREAMS)
            .expect("configure server QUIC transport");
        let debug = format!("{transport:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 1"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("stream_receive_window: 16777216"));
        assert!(debug.contains("receive_window: 67108864"));
        assert!(debug.contains("send_window: 67108864"));
        assert!(debug.contains("upper_bound: 9000"));
        assert!(debug.contains("max_idle_timeout: Some(30000)"));
        assert!(debug.contains("keep_alive_interval: Some(5s)"));
    }

    #[test]
    fn quic_agent_client_rejects_remote_initiated_streams_but_uses_same_windows() {
        let mut transport = TransportConfig::default();
        configure_quic_agent_transport(&mut transport, 0).expect("configure client QUIC transport");
        let debug = format!("{transport:?}");

        assert!(debug.contains("max_concurrent_bidi_streams: 0"));
        assert!(debug.contains("max_concurrent_uni_streams: 0"));
        assert!(debug.contains("stream_receive_window: 16777216"));
        assert!(debug.contains("receive_window: 67108864"));
        assert!(debug.contains("send_window: 67108864"));
        assert!(debug.contains("upper_bound: 9000"));
    }

    #[test]
    fn quic_endpoint_accepts_jumbo_payloads_for_mtu_discovery() {
        let config = quic_endpoint_config().expect("QUIC endpoint config");

        assert_eq!(
            config.get_max_udp_payload_size(),
            u64::from(QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES)
        );
    }

    #[test]
    fn quic_bridge_open_header_round_trips_ipv4_flow_and_protocol() {
        let flow = AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(192, 0, 2, 80),
            destination_port: 443,
            originator_ip: Ipv4Addr::new(10, 255, 255, 2),
            originator_port: 49152,
        };
        let open = QuicBridgeIpv4Open {
            protocol: QuicBridgeProtocol::Udp,
            flow,
        };

        assert_eq!(
            decode_quic_bridge_open_header(&encode_quic_bridge_ipv4_open(open)).unwrap(),
            QuicBridgeOpenHeader::Ipv4(open)
        );
    }

    #[test]
    fn quic_bridge_host_open_header_round_trips_metadata() {
        let open = AgentOpenHost {
            destination_host: "localhost".to_owned(),
            destination_port: 5353,
            originator_ip: Ipv4Addr::new(10, 255, 255, 2),
            originator_port: 49152,
        };

        assert_eq!(
            decode_quic_bridge_open_header(&encode_quic_bridge_host_open(&open).unwrap()).unwrap(),
            QuicBridgeOpenHeader::TcpHost(QuicBridgeHostOpenHeader {
                destination_port: 5353,
                originator_ip: Ipv4Addr::new(10, 255, 255, 2),
                originator_port: 49152,
                host_len: "localhost".len() as u16,
            })
        );
    }

    #[test]
    fn quic_bridge_open_header_rejects_wrong_magic() {
        let open = AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(192, 0, 2, 80),
            destination_port: 443,
            originator_ip: Ipv4Addr::new(10, 255, 255, 2),
            originator_port: 49152,
        };
        let mut header = encode_quic_bridge_ipv4_open(QuicBridgeIpv4Open {
            protocol: QuicBridgeProtocol::Tcp,
            flow: open,
        });
        header[0] = b'X';

        assert!(decode_quic_bridge_open_header(&header).is_err());
    }

    #[tokio::test]
    async fn quic_agent_transport_round_trips_tcp_stream() {
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
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"quic:")
                .await
                .expect("write prefix");
            tokio::io::AsyncWriteExt::write_all(&mut socket, &request)
                .await
                .expect("write response");
        });

        let quic_server =
            start_quic_agent_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start QUIC agent");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let agent_task = tokio::spawn(async move {
            quic_server
                .run_one(AgentRuntimeConfig::new(1300))
                .await
                .expect("run QUIC agent")
        });

        let client = connect_quic_agent(quic_addr, &bootstrap, 1300)
            .await
            .expect("connect QUIC agent");
        let SocketAddr::V4(destination) = destination else {
            panic!("test destination should be IPv4");
        };
        let mut stream = client
            .transport
            .open_tcp_ipv4(AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::new(10, 255, 255, 1),
                originator_port: 49152,
            })
            .await
            .expect("open remote TCP stream");
        stream
            .send_data(bytes::Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                crate::agent_proto::AgentFrameKind::Data => {
                    response.extend_from_slice(frame.payload.as_ref());
                }
                crate::agent_proto::AgentFrameKind::Eof
                | crate::agent_proto::AgentFrameKind::Close => break,
                crate::agent_proto::AgentFrameKind::Reset => {
                    panic!("stream reset: {}", String::from_utf8_lossy(&frame.payload));
                }
                _ => {}
            }
        }

        assert_eq!(response, b"quic:ping");
        stream.close().await.expect("close stream");
        drop(client);
        agent_task.await.expect("agent task");
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
