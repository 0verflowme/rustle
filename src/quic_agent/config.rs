use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use quinn::{
    ClientConfig, Endpoint, EndpointConfig, MtuDiscoveryConfig, ServerConfig, TransportConfig,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::bootstrap::QuicAgentBootstrap;

pub const QUIC_AGENT_SERVER_NAME: &str = "rustle-agent";
pub(super) const QUIC_AGENT_MAX_CONCURRENT_BIDI_STREAMS: u16 = 1;
pub(super) const QUIC_BRIDGE_MAX_CONCURRENT_BIDI_STREAMS: u16 = 1024;
const QUIC_AGENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_AGENT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const QUIC_AGENT_MAX_CONCURRENT_UNI_STREAMS: u16 = 0;
const QUIC_AGENT_STREAM_RECEIVE_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const QUIC_AGENT_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
const QUIC_AGENT_SEND_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES: u16 = 9000;

pub(super) fn quic_server_config(
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

pub(super) fn quic_client_config(bootstrap: &QuicAgentBootstrap) -> Result<ClientConfig> {
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

pub(super) fn quic_server_endpoint(
    server_config: ServerConfig,
    bind: SocketAddr,
) -> Result<Endpoint> {
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

pub(super) fn quic_client_endpoint(remote: SocketAddr) -> Result<Endpoint> {
    let socket = std::net::UdpSocket::bind(client_bind_addr_for(remote))
        .context("failed to bind QUIC client UDP socket")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no QUIC async runtime found"))?;
    Endpoint::new(quic_endpoint_config()?, None, socket, runtime)
        .context("failed to create QUIC client endpoint")
}

fn quic_endpoint_config() -> Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(QUIC_AGENT_MAX_UDP_PAYLOAD_BYTES)
        .context("failed to configure QUIC endpoint UDP payload size")?;
    Ok(config)
}

fn client_bind_addr_for(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
