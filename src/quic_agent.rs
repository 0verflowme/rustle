use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use quinn::{Connection, Endpoint};

mod auth;
mod bootstrap;
mod config;
mod native_bridge;

use auth::{
    generate_quic_auth_token, open_quic_bi_stream_with_timeout, quic_auth_stage_context,
    read_quic_auth_ok, verify_quic_auth_token, write_quic_auth_ok, write_quic_auth_token,
    QUIC_AUTH_FAILED_CODE, QUIC_AUTH_TIMEOUT,
};
use bootstrap::sha256_hex;
pub use bootstrap::QuicAgentBootstrap;
pub use config::QUIC_AGENT_SERVER_NAME;
use config::{
    quic_client_config, quic_client_endpoint, quic_server_config, quic_server_endpoint,
    QUIC_AGENT_MAX_CONCURRENT_BIDI_STREAMS,
};
pub use native_bridge::{
    connect_quic_bridge, start_quic_bridge_server, QuicBridgeClient, QuicBridgeStream,
    QUIC_BRIDGE_TCP_CHUNK,
};

pub struct QuicAgentServer {
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

    pub async fn accept_agent_stream(
        self,
    ) -> Result<(quinn::RecvStream, quinn::SendStream, QuicAgentSession)> {
        loop {
            let incoming = self.endpoint.accept().await.ok_or_else(|| {
                anyhow!("QUIC agent endpoint closed before accepting a connection")
            })?;
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(err) => {
                    eprintln!("quic-agent: rejected connection before auth: {err:#}");
                    continue;
                }
            };
            let (mut send, mut recv) =
                match tokio::time::timeout(QUIC_AUTH_TIMEOUT, connection.accept_bi()).await {
                    Ok(Ok(streams)) => streams,
                    Ok(Err(err)) => {
                        eprintln!("quic-agent: failed to accept auth stream: {err:#}");
                        connection.close(QUIC_AUTH_FAILED_CODE.into(), b"auth stream failed");
                        continue;
                    }
                    Err(_) => {
                        eprintln!("quic-agent: timed out waiting for auth stream");
                        connection.close(QUIC_AUTH_FAILED_CODE.into(), b"auth timeout");
                        continue;
                    }
                };
            if let Err(err) = verify_quic_auth_token(&mut recv, &self.bootstrap.auth_token).await {
                eprintln!("quic-agent: rejected unauthenticated connection: {err:#}");
                connection.close(QUIC_AUTH_FAILED_CODE.into(), b"invalid auth token");
                continue;
            }
            write_quic_auth_ok(&mut send)
                .await
                .context("failed to acknowledge QUIC agent auth")?;
            return Ok((
                recv,
                send,
                QuicAgentSession {
                    _endpoint: self.endpoint,
                    connection,
                },
            ));
        }
    }
}

pub struct QuicAgentSession {
    _endpoint: Endpoint,
    connection: Connection,
}

impl QuicAgentSession {
    pub(crate) fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
    }
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
        auth_token: generate_quic_auth_token()?,
    };
    Ok(QuicAgentServer {
        endpoint,
        bootstrap,
    })
}

pub async fn connect_quic_agent_stream(
    remote: SocketAddr,
    bootstrap: &QuicAgentBootstrap,
) -> Result<(quinn::RecvStream, quinn::SendStream, QuicAgentSession)> {
    let mut endpoint = quic_client_endpoint(remote).context("failed to bind QUIC client")?;
    endpoint.set_default_client_config(quic_client_config(bootstrap)?);
    let connection = endpoint
        .connect(remote, QUIC_AGENT_SERVER_NAME)
        .context("failed to start QUIC agent connection")?
        .await
        .context("failed to establish QUIC agent connection")?;
    let stage_started = Instant::now();
    let (mut send, mut recv) =
        open_quic_bi_stream_with_timeout(&connection, QUIC_AUTH_TIMEOUT, "QUIC agent auth stream")
            .await
            .with_context(|| {
                quic_auth_stage_context("QUIC agent auth", "open_stream", stage_started)
            })?;
    let stage_started = Instant::now();
    write_quic_auth_token(&mut send, &bootstrap.auth_token)
        .await
        .with_context(|| {
            quic_auth_stage_context("QUIC agent auth", "write_token", stage_started)
        })?;
    let stage_started = Instant::now();
    read_quic_auth_ok(&mut recv)
        .await
        .with_context(|| quic_auth_stage_context("QUIC agent auth", "read_ack", stage_started))?;
    Ok((
        recv,
        send,
        QuicAgentSession {
            _endpoint: endpoint,
            connection,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn tampered_bootstrap_token(bootstrap: &QuicAgentBootstrap) -> QuicAgentBootstrap {
        let mut tampered = bootstrap.clone();
        tampered.auth_token[0] ^= 0xff;
        tampered
    }

    #[tokio::test]
    async fn quic_agent_auth_rejects_bad_token_and_accepts_next_connection() {
        let quic_server =
            start_quic_agent_server(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .expect("start QUIC agent");
        let quic_addr = quic_server.local_addr().expect("QUIC local address");
        let bootstrap = quic_server.bootstrap().clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (_recv, _send, session) = quic_server
                .accept_agent_stream()
                .await
                .expect("accept authenticated QUIC agent stream");
            let _ = done_rx.await;
            session.close(0, b"test complete");
        });

        let bad_bootstrap = tampered_bootstrap_token(&bootstrap);
        let bad = connect_quic_agent_stream(quic_addr, &bad_bootstrap).await;
        let bad_err = match bad {
            Ok(_) => panic!("bad token unexpectedly authenticated"),
            Err(err) => err,
        };
        let bad_detail = format!("{bad_err:#}");
        assert!(bad_detail.contains("QUIC agent auth stage=read_ack"));
        assert!(bad_detail.contains("elapsed_ms="));

        let (_recv, _send, session) = connect_quic_agent_stream(quic_addr, &bootstrap)
            .await
            .expect("valid token authenticates after bad token");
        session.close(0, b"test complete");
        done_tx.send(()).expect("release server session");
        server_task.await.expect("server task");
    }
}
