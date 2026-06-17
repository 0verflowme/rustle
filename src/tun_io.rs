use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;

use crate::packet_engine::{TunWriteStats, TunnelEngine};
use crate::transport_model::{DnsResponseEvent, UdpFlowKey};
use crate::{dns, tcp_core};

const TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct TunWriter<'a> {
    dev: &'a tun_rs::AsyncDevice,
}

impl<'a> TunWriter<'a> {
    pub(crate) fn new(dev: &'a tun_rs::AsyncDevice) -> Self {
        Self { dev }
    }

    pub(crate) async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev
            .recv(buf)
            .await
            .context("failed to read packet from TUN device")
    }

    pub(crate) async fn write_engine_packets(&self, engine: &mut TunnelEngine) -> Result<()> {
        let tun_write = self.write_packets(engine.outbound_packets_mut()).await?;
        engine.record_tun_write(tun_write);
        Ok(())
    }

    pub(crate) async fn write_dns_event(&self, event: DnsResponseEvent) -> Result<TunWriteStats> {
        let Some(packet) = dns_response_packet_for_event(event)? else {
            return Ok(TunWriteStats::default());
        };
        self.write_packet(&packet, "DNS response").await
    }

    pub(crate) async fn write_udp_response(
        &self,
        key: UdpFlowKey,
        payload: Bytes,
    ) -> Result<TunWriteStats> {
        let packet = udp_response_packet_for_key(key, &payload)?;
        self.write_packet(&packet, "UDP response").await
    }

    pub(crate) async fn write_packets(
        &self,
        packets: &mut Vec<tcp_core::PacketBuf>,
    ) -> Result<TunWriteStats> {
        let mut stats = TunWriteStats::default();
        for packet in packets.drain(..) {
            stats.combine(
                self.write_packet(packet.as_ref(), "userspace TCP packet")
                    .await?,
            );
        }
        Ok(stats)
    }

    async fn write_packet(
        &self,
        packet: &[u8],
        description: &'static str,
    ) -> Result<TunWriteStats> {
        let len = packet.len();
        let mut stats = TunWriteStats::default();
        match tokio::time::timeout(TUN_WRITE_TIMEOUT, self.dev.send(packet)).await {
            Ok(Ok(_)) => {
                stats.record_written(len);
            }
            Ok(Err(err)) => {
                return Err(err)
                    .with_context(|| format!("failed to write {description} to TUN device"));
            }
            Err(_) => {
                eprintln!(
                    "tun: dropping {len}-byte {description} after {}ms waiting for TUN write",
                    TUN_WRITE_TIMEOUT.as_millis()
                );
                stats.record_dropped(len);
            }
        }
        Ok(stats)
    }
}

fn dns_response_packet_for_event(event: DnsResponseEvent) -> Result<Option<Vec<u8>>> {
    let payload = match event.result {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("dns: remote query failed: {err}");
            let Some(payload) = dns::build_dns_servfail_response(event.request.payload.as_ref())
            else {
                return Ok(None);
            };
            Bytes::from(payload)
        }
    };

    dns::build_udp_dns_response(&event.request, &payload)
        .context("failed to synthesize DNS UDP response packet")
        .map(Some)
}

fn udp_response_packet_for_key(key: UdpFlowKey, payload: &[u8]) -> Result<Vec<u8>> {
    let request = key.response_template();
    dns::build_udp_response(&request, payload).context("failed to synthesize UDP response packet")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::transport_model::DnsResponseEvent;

    fn dns_query_payload() -> Bytes {
        Bytes::from_static(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ])
    }

    fn dns_request(payload: Bytes) -> dns::UdpDnsRequest {
        dns::UdpPacket {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            dst_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 53000,
            dst_port: dns::DNS_PORT,
            payload,
        }
    }

    #[test]
    fn dns_error_event_synthesizes_servfail_udp_packet() {
        let request = dns_request(dns_query_payload());
        let packet = dns_response_packet_for_event(DnsResponseEvent {
            request: request.clone(),
            result: Err("upstream failed".to_owned()),
        })
        .expect("packet synthesis")
        .expect("SERVFAIL packet");

        let response = dns::parse_ipv4_udp_packet(&packet)
            .expect("valid packet")
            .expect("UDP packet");

        assert_eq!(response.src_ip, request.dst_ip);
        assert_eq!(response.dst_ip, request.src_ip);
        assert_eq!(response.src_port, dns::DNS_PORT);
        assert_eq!(response.dst_port, request.src_port);
        assert_eq!(&response.payload[0..2], &request.payload[0..2]);
        assert_eq!(
            u16::from_be_bytes([response.payload[2], response.payload[3]]) & 0x800f,
            0x8002
        );
    }

    #[test]
    fn dns_error_event_with_invalid_query_writes_nothing() {
        let packet = dns_response_packet_for_event(DnsResponseEvent {
            request: dns_request(Bytes::from_static(b"short")),
            result: Err("upstream failed".to_owned()),
        })
        .expect("packet synthesis");

        assert!(packet.is_none());
    }

    #[test]
    fn udp_response_packet_uses_flow_key_response_template_once() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 53000,
            dst_ip: Ipv4Addr::new(192, 0, 2, 10),
            dst_port: 12345,
        };

        let packet = udp_response_packet_for_key(key, b"pong").expect("packet synthesis");
        let response = dns::parse_ipv4_udp_packet(&packet)
            .expect("valid packet")
            .expect("UDP packet");

        assert_eq!(response.src_ip, key.dst_ip);
        assert_eq!(response.dst_ip, key.src_ip);
        assert_eq!(response.src_port, key.dst_port);
        assert_eq!(response.dst_port, key.src_port);
        assert_eq!(response.payload.as_ref(), b"pong");
    }
}
