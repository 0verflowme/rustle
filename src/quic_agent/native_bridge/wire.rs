use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use tokio::io::AsyncWriteExt;

use crate::agent_proto::{AgentOpenHost, AgentOpenIpv4};

const QUIC_BRIDGE_OPEN_MAGIC: &[u8; 4] = b"RQB2";
pub(super) const QUIC_BRIDGE_OPEN_HEADER_LEN: usize = 20;
pub(super) const QUIC_BRIDGE_STATUS_OK: u8 = 0;
pub(super) const QUIC_BRIDGE_STATUS_ERR: u8 = 1;
pub const QUIC_BRIDGE_TCP_CHUNK: usize = 256 * 1024;
pub(super) const QUIC_BRIDGE_UDP_CHUNK: usize = u16::MAX as usize;
const QUIC_BRIDGE_PROTO_TCP: u8 = 6;
const QUIC_BRIDGE_PROTO_UDP: u8 = 17;
const QUIC_BRIDGE_PROTO_TCP_HOST: u8 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuicBridgeProtocol {
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
pub(super) struct QuicBridgeIpv4Open {
    pub(super) protocol: QuicBridgeProtocol,
    pub(super) flow: AgentOpenIpv4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct QuicBridgeHostOpenHeader {
    pub(super) destination_port: u16,
    pub(super) originator_ip: Ipv4Addr,
    pub(super) originator_port: u16,
    pub(super) host_len: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QuicBridgeOpenHeader {
    Ipv4(QuicBridgeIpv4Open),
    TcpHost(QuicBridgeHostOpenHeader),
}

pub(super) fn encode_quic_bridge_ipv4_open(
    open: QuicBridgeIpv4Open,
) -> [u8; QUIC_BRIDGE_OPEN_HEADER_LEN] {
    let mut header = [0_u8; QUIC_BRIDGE_OPEN_HEADER_LEN];
    header[..4].copy_from_slice(QUIC_BRIDGE_OPEN_MAGIC);
    header[4] = open.protocol.code();
    header[8..12].copy_from_slice(&open.flow.destination_ip.octets());
    header[12..14].copy_from_slice(&open.flow.destination_port.to_be_bytes());
    header[14..18].copy_from_slice(&open.flow.originator_ip.octets());
    header[18..20].copy_from_slice(&open.flow.originator_port.to_be_bytes());
    header
}

pub(super) fn encode_quic_bridge_host_open(
    open: &AgentOpenHost,
) -> Result<[u8; QUIC_BRIDGE_OPEN_HEADER_LEN]> {
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

pub(super) fn decode_quic_bridge_open_header(
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

pub(super) async fn write_quic_bridge_datagram(
    send: &mut quinn::SendStream,
    bytes: &[u8],
) -> Result<()> {
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

pub(super) async fn read_quic_bridge_datagram(
    recv: &mut quinn::RecvStream,
) -> Result<Option<Bytes>> {
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
            Err(err) => {
                return Err(err).context("failed to read native QUIC bridge UDP datagram length")
            }
        }
    }
    Ok(true)
}

pub(super) async fn write_quic_bridge_error(
    send: &mut quinn::SendStream,
    reason: &str,
) -> Result<()> {
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

pub(super) async fn read_quic_bridge_error(recv: &mut quinn::RecvStream) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
