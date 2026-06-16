use anyhow::Result;
use bytes::Bytes;

use crate::{agent_proto, quic_agent};

use crate::agent_bridge::AgentBridgeStream;
#[cfg(test)]
use crate::agent_transport;

pub(super) enum AgentIoStream {
    Bridge(AgentBridgeStream),
    QuicNativeTcp(quic_agent::QuicBridgeStream),
    QuicNativeUdp(quic_agent::QuicBridgeStream),
    #[cfg(test)]
    Raw(agent_transport::AgentStream),
}

impl AgentIoStream {
    pub(super) async fn send_data(&mut self, bytes: impl Into<Bytes>) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_data(bytes).await,
            Self::QuicNativeTcp(stream) => stream.send_data(bytes.into()).await,
            Self::QuicNativeUdp(stream) => stream.send_datagram(bytes.into()).await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_data(bytes).await,
        }
    }

    pub(super) async fn send_eof(&mut self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_eof().await,
            Self::QuicNativeTcp(stream) => stream.send_eof().await,
            Self::QuicNativeUdp(stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_eof().await,
        }
    }

    pub(super) async fn recv(&mut self) -> Option<agent_proto::AgentFrame> {
        match self {
            Self::Bridge(stream) => stream.recv().await,
            Self::QuicNativeTcp(stream) => {
                match stream
                    .recv_chunk(agent_proto::AGENT_MAX_FRAME_PAYLOAD)
                    .await
                {
                    Ok(Some(payload)) => {
                        agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload)
                            .ok()
                    }
                    Ok(None) => None,
                    Err(err) => {
                        eprintln!("quic-native: failed to read TCP data: {err:#}");
                        None
                    }
                }
            }
            Self::QuicNativeUdp(stream) => match stream.recv_datagram().await {
                Ok(Some(payload)) => {
                    agent_proto::AgentFrame::new(agent_proto::AgentFrameKind::Data, 0, payload).ok()
                }
                Ok(None) => None,
                Err(err) => {
                    eprintln!("quic-native: failed to read UDP datagram: {err:#}");
                    None
                }
            },
            #[cfg(test)]
            Self::Raw(stream) => stream.recv().await,
        }
    }

    pub(super) async fn close(self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.close().await,
            Self::QuicNativeTcp(mut stream) => stream.send_eof().await,
            Self::QuicNativeUdp(mut stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.close().await,
        }
    }
}
