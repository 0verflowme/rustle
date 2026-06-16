use anyhow::{Context, Result};
use std::net::SocketAddr;

use crate::agent_runtime::{self, AgentRuntimeConfig};
use crate::agent_transport::AgentTransport;
use crate::quic_agent::{self, QuicAgentBootstrap, QuicAgentServer, QuicAgentSession};

pub(crate) struct QuicAgentClient {
    session: QuicAgentSession,
    pub(crate) transport: AgentTransport,
}

impl QuicAgentClient {
    pub(crate) fn into_transport_and_session(self) -> (AgentTransport, QuicAgentSession) {
        (self.transport, self.session)
    }
}

pub(crate) async fn connect_quic_agent(
    remote: SocketAddr,
    bootstrap: &QuicAgentBootstrap,
    mtu: u16,
) -> Result<QuicAgentClient> {
    let (recv, send, session) = quic_agent::connect_quic_agent_stream(remote, bootstrap).await?;
    let transport = AgentTransport::connect(recv, send, mtu)
        .await
        .context("failed to negotiate Rustle agent protocol over QUIC")?;
    Ok(QuicAgentClient { session, transport })
}

pub(crate) async fn run_one(server: QuicAgentServer, config: AgentRuntimeConfig) -> Result<()> {
    let (recv, send, session) = server.accept_agent_stream().await?;
    let result = agent_runtime::run(recv, send, config).await;
    session.close(0, b"rustle agent complete");
    result.context("QUIC agent runtime failed")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use super::*;
    use crate::agent_proto::{AgentFrameKind, AgentOpenIpv4};
    use crate::quic_agent::start_quic_agent_server;

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
            run_one(quic_server, AgentRuntimeConfig::new(1300))
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
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                AgentFrameKind::Data => {
                    response.extend_from_slice(frame.payload.as_ref());
                }
                AgentFrameKind::Eof | AgentFrameKind::Close => break,
                AgentFrameKind::Reset => {
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
}
