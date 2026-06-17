use anyhow::{Context, Result};
use bytes::Bytes;

use crate::agent_proto;

use crate::agent_bridge::{AgentBridgeStream, QuicNativeBridgeStream};
#[cfg(test)]
use crate::agent_transport;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StreamSendMetrics {
    pub(crate) agent_credit_wait_us: u128,
    pub(crate) agent_outbound_wait_us: u128,
    pub(crate) agent_outbound_frames: u64,
}

impl From<crate::agent_transport::AgentStreamSendMetrics> for StreamSendMetrics {
    fn from(metrics: crate::agent_transport::AgentStreamSendMetrics) -> Self {
        Self {
            agent_credit_wait_us: metrics.credit_wait_us,
            agent_outbound_wait_us: metrics.outbound_wait_us,
            agent_outbound_frames: metrics.frames,
        }
    }
}

pub(crate) enum AgentIoStream {
    Bridge(AgentBridgeStream),
    QuicNativeTcp {
        stream: QuicNativeBridgeStream,
        opened_reported: bool,
    },
    QuicNativeUdp(QuicNativeBridgeStream),
    #[cfg(test)]
    Raw(agent_transport::AgentStream),
}

impl AgentIoStream {
    pub(crate) fn quic_native_tcp(stream: QuicNativeBridgeStream) -> Self {
        Self::quic_native_tcp_with_open_status(stream, false)
    }

    pub(crate) fn quic_native_tcp_opened(stream: QuicNativeBridgeStream) -> Self {
        Self::quic_native_tcp_with_open_status(stream, true)
    }

    fn quic_native_tcp_with_open_status(
        stream: QuicNativeBridgeStream,
        opened_reported: bool,
    ) -> Self {
        Self::QuicNativeTcp {
            stream,
            opened_reported,
        }
    }

    pub(crate) async fn send_data(&mut self, bytes: impl Into<Bytes>) -> Result<()> {
        self.send_data_with_metrics(bytes).await.map(|_| ())
    }

    pub(crate) async fn send_data_with_metrics(
        &mut self,
        bytes: impl Into<Bytes>,
    ) -> Result<StreamSendMetrics> {
        match self {
            Self::Bridge(stream) => stream.send_data_with_metrics(bytes).await.map(Into::into),
            Self::QuicNativeTcp { stream, .. } => {
                stream.send_data(bytes.into()).await?;
                Ok(StreamSendMetrics::default())
            }
            Self::QuicNativeUdp(stream) => {
                stream.send_datagram(bytes.into()).await?;
                Ok(StreamSendMetrics::default())
            }
            #[cfg(test)]
            Self::Raw(stream) => stream.send_data_with_metrics(bytes).await.map(Into::into),
        }
    }

    pub(crate) async fn send_eof(&mut self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_eof().await,
            Self::QuicNativeTcp { stream, .. } => stream.send_eof().await,
            Self::QuicNativeUdp(stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_eof().await,
        }
    }

    pub(crate) async fn recv(&mut self) -> Result<Option<agent_proto::AgentFrame>> {
        match self {
            Self::Bridge(stream) => Ok(stream.recv().await),
            Self::QuicNativeTcp {
                stream,
                opened_reported,
            } => {
                if !*opened_reported {
                    stream
                        .wait_opened()
                        .await
                        .context("failed to read native QUIC TCP open status")?;
                    *opened_reported = true;
                    return Ok(Some(
                        agent_proto::AgentFrame::new(
                            agent_proto::AgentFrameKind::Opened,
                            0,
                            Bytes::new(),
                        )
                        .context("failed to synthesize native QUIC TCP opened frame")?,
                    ));
                }
                let payload = stream
                    .recv_chunk(agent_proto::AGENT_MAX_FRAME_PAYLOAD)
                    .await
                    .context("failed to read native QUIC TCP data")?;
                Ok(payload.and_then(|payload| {
                    agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload).ok()
                }))
            }
            Self::QuicNativeUdp(stream) => match stream.recv_datagram().await {
                Ok(Some(payload)) => {
                    Ok(
                        agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload)
                            .ok(),
                    )
                }
                Ok(None) => Ok(None),
                Err(err) => Err(err).context("failed to read native QUIC UDP datagram"),
            },
            #[cfg(test)]
            Self::Raw(stream) => Ok(stream.recv().await),
        }
    }

    pub(crate) async fn close(self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.close().await,
            Self::QuicNativeTcp { mut stream, .. } => stream.send_eof().await,
            Self::QuicNativeUdp(mut stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.close().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::super::test_support::test_quic_native_bridge;
    use super::*;
    #[tokio::test]
    async fn quic_native_tcp_recv_error_propagates() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let tcp_server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.expect("accept TCP stream");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let stream = bridge
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: destination.ip().to_string(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::LOCALHOST,
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC TCP stream");
        let mut stream = AgentIoStream::quic_native_tcp(stream);

        let opened = stream
            .recv()
            .await
            .expect("read native TCP opened event")
            .expect("opened event");
        assert_eq!(opened.kind, agent_proto::AgentFrameKind::Opened);

        bridge.close_for_test("force receive error");
        let err = stream.recv().await.expect_err("native TCP read error");
        assert!(
            err.to_string()
                .contains("failed to read native QUIC TCP data"),
            "unexpected error: {err:#}"
        );

        tcp_server.abort();
        bridge_task.await.expect("native bridge task");
    }

    #[tokio::test]
    async fn quic_native_udp_recv_error_propagates() {
        let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (_len, _peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        let destination = match destination {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let (bridge, bridge_task) = test_quic_native_bridge().await;
        let stream = bridge
            .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: Ipv4Addr::LOCALHOST,
                originator_port: 49152,
            })
            .await
            .expect("open native QUIC UDP stream");
        let mut stream = AgentIoStream::QuicNativeUdp(stream);

        bridge.close_for_test("force receive error");
        let err = stream.recv().await.expect_err("native UDP read error");
        assert!(
            err.to_string()
                .contains("failed to read native QUIC UDP datagram"),
            "unexpected error: {err:#}"
        );

        udp_server.abort();
        bridge_task.await.expect("native bridge task");
    }
}
