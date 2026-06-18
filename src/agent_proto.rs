use std::convert::TryFrom;
use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const AGENT_PROTOCOL_VERSION: u16 = 1;
pub const AGENT_MAX_FRAME_PAYLOAD: usize = 256 * 1024;
pub const AGENT_CARRIER_READ_BUFFER_BYTES: usize = 64 * 1024;
pub const AGENT_FRAME_HEADER_LEN: usize = 24;
pub const AGENT_MAGIC: [u8; 4] = *b"RLA1";

pub const CAP_TCP_CONNECT: u64 = 1 << 0;
pub const CAP_UDP_ASSOCIATE: u64 = 1 << 1;
pub const CAP_DNS_RELAY: u64 = 1 << 2;
pub const CAP_FLOW_CONTROL: u64 = 1 << 3;
pub const CAP_HEARTBEAT: u64 = 1 << 4;
pub const CAP_TCP_CONNECT_HOST: u64 = 1 << 5;
pub const AGENT_MAX_HOST_LEN: usize = 253;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AgentFrameKind {
    Hello = 1,
    OpenTcp = 2,
    OpenUdp = 3,
    Data = 4,
    Window = 5,
    Eof = 6,
    Close = 7,
    Reset = 8,
    Opened = 9,
    Ping = 10,
    Pong = 11,
    OpenTcpHost = 12,
}

impl TryFrom<u8> for AgentFrameKind {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::OpenTcp),
            3 => Ok(Self::OpenUdp),
            4 => Ok(Self::Data),
            5 => Ok(Self::Window),
            6 => Ok(Self::Eof),
            7 => Ok(Self::Close),
            8 => Ok(Self::Reset),
            9 => Ok(Self::Opened),
            10 => Ok(Self::Ping),
            11 => Ok(Self::Pong),
            12 => Ok(Self::OpenTcpHost),
            _ => bail!("unknown agent frame kind {value}"),
        }
    }
}

impl AgentFrameKind {
    pub(crate) fn is_priority_control(self) -> bool {
        matches!(
            self,
            Self::Hello
                | Self::OpenTcp
                | Self::OpenUdp
                | Self::Window
                | Self::Reset
                | Self::Opened
                | Self::Ping
                | Self::Pong
                | Self::OpenTcpHost
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentFrame {
    pub kind: AgentFrameKind,
    pub flags: u8,
    pub stream_id: u64,
    pub credit: u32,
    pub payload: Bytes,
}

impl AgentFrame {
    pub fn new(kind: AgentFrameKind, stream_id: u64, payload: impl Into<Bytes>) -> Result<Self> {
        let payload = payload.into();
        validate_payload_len(payload.len())?;
        Ok(Self {
            kind,
            flags: 0,
            stream_id,
            credit: 0,
            payload,
        })
    }

    pub fn with_credit(mut self, credit: u32) -> Self {
        self.credit = credit;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentOpenedTiming {
    pub remote_connect_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentEofTiming {
    pub remote_read_wait_us: u64,
    pub remote_read_wait_max_us: u64,
    pub remote_read_events: u64,
    pub output_credit_wait_us: u64,
    pub output_credit_wait_max_us: u64,
    pub output_send_wait_us: u64,
    pub output_send_wait_max_us: u64,
    pub output_frames: u64,
    pub remote_bytes: u64,
}

impl AgentOpenedTiming {
    const WIRE_LEN: usize = 8;

    pub fn encode(self) -> Bytes {
        let mut payload = BytesMut::with_capacity(Self::WIRE_LEN);
        payload.put_u64(self.remote_connect_us);
        payload.freeze()
    }

    pub fn decode_optional(mut payload: &[u8]) -> Result<Option<Self>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() != Self::WIRE_LEN {
            bail!(
                "agent opened timing payload must be {} bytes, got {}",
                Self::WIRE_LEN,
                payload.len()
            );
        }
        Ok(Some(Self {
            remote_connect_us: payload.get_u64(),
        }))
    }
}

impl AgentEofTiming {
    const WIRE_LEN: usize = 72;

    pub fn encode(self) -> Bytes {
        let mut payload = BytesMut::with_capacity(Self::WIRE_LEN);
        payload.put_u64(self.remote_read_wait_us);
        payload.put_u64(self.remote_read_wait_max_us);
        payload.put_u64(self.remote_read_events);
        payload.put_u64(self.output_credit_wait_us);
        payload.put_u64(self.output_credit_wait_max_us);
        payload.put_u64(self.output_send_wait_us);
        payload.put_u64(self.output_send_wait_max_us);
        payload.put_u64(self.output_frames);
        payload.put_u64(self.remote_bytes);
        payload.freeze()
    }

    pub fn decode_optional(mut payload: &[u8]) -> Result<Option<Self>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() != Self::WIRE_LEN {
            bail!(
                "agent EOF timing payload must be {} bytes, got {}",
                Self::WIRE_LEN,
                payload.len()
            );
        }
        Ok(Some(Self {
            remote_read_wait_us: payload.get_u64(),
            remote_read_wait_max_us: payload.get_u64(),
            remote_read_events: payload.get_u64(),
            output_credit_wait_us: payload.get_u64(),
            output_credit_wait_max_us: payload.get_u64(),
            output_send_wait_us: payload.get_u64(),
            output_send_wait_max_us: payload.get_u64(),
            output_frames: payload.get_u64(),
            remote_bytes: payload.get_u64(),
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentHello {
    pub protocol_version: u16,
    pub mtu: u16,
    pub max_frame_payload: u32,
    pub capabilities: u64,
}

impl AgentHello {
    pub fn current(mtu: u16) -> Self {
        Self {
            protocol_version: AGENT_PROTOCOL_VERSION,
            mtu,
            max_frame_payload: AGENT_MAX_FRAME_PAYLOAD as u32,
            capabilities: CAP_TCP_CONNECT
                | CAP_UDP_ASSOCIATE
                | CAP_DNS_RELAY
                | CAP_FLOW_CONTROL
                | CAP_HEARTBEAT
                | CAP_TCP_CONNECT_HOST,
        }
    }

    pub fn encode(self) -> Bytes {
        let mut payload = BytesMut::with_capacity(16);
        payload.put_u16(self.protocol_version);
        payload.put_u16(self.mtu);
        payload.put_u32(self.max_frame_payload);
        payload.put_u64(self.capabilities);
        payload.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self> {
        if payload.len() != 16 {
            bail!(
                "agent hello payload must be 16 bytes, got {}",
                payload.len()
            );
        }
        Ok(Self {
            protocol_version: payload.get_u16(),
            mtu: payload.get_u16(),
            max_frame_payload: payload.get_u32(),
            capabilities: payload.get_u64(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentOpenIpv4 {
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub originator_ip: Ipv4Addr,
    pub originator_port: u16,
}

impl AgentOpenIpv4 {
    pub fn encode(self) -> Bytes {
        let mut payload = BytesMut::with_capacity(12);
        payload.put_slice(&self.destination_ip.octets());
        payload.put_u16(self.destination_port);
        payload.put_slice(&self.originator_ip.octets());
        payload.put_u16(self.originator_port);
        payload.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self> {
        if payload.len() != 12 {
            bail!(
                "agent IPv4 open payload must be 12 bytes, got {}",
                payload.len()
            );
        }
        let destination_ip = Ipv4Addr::from(payload.get_u32());
        let destination_port = payload.get_u16();
        let originator_ip = Ipv4Addr::from(payload.get_u32());
        let originator_port = payload.get_u16();
        Ok(Self {
            destination_ip,
            destination_port,
            originator_ip,
            originator_port,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOpenHost {
    pub destination_host: String,
    pub destination_port: u16,
    pub originator_ip: Ipv4Addr,
    pub originator_port: u16,
}

impl AgentOpenHost {
    pub fn encode(&self) -> Result<Bytes> {
        validate_agent_host(&self.destination_host)?;
        let host = self.destination_host.as_bytes();
        let mut payload = BytesMut::with_capacity(8 + host.len());
        payload.put_u16(self.destination_port);
        payload.put_slice(&self.originator_ip.octets());
        payload.put_u16(self.originator_port);
        payload.put_slice(host);
        Ok(payload.freeze())
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self> {
        if payload.len() < 9 {
            bail!(
                "agent host open payload must be at least 9 bytes, got {}",
                payload.len()
            );
        }
        let destination_port = payload.get_u16();
        let originator_ip = Ipv4Addr::from(payload.get_u32());
        let originator_port = payload.get_u16();
        let destination_host = std::str::from_utf8(payload)
            .context("agent host open destination is not valid UTF-8")?
            .to_owned();
        validate_agent_host(&destination_host)?;
        Ok(Self {
            destination_host,
            destination_port,
            originator_ip,
            originator_port,
        })
    }
}

pub fn encode_frame(frame: &AgentFrame) -> Result<Bytes> {
    let mut encoded = BytesMut::with_capacity(encoded_frame_len(frame)?);
    encode_frame_into(frame, &mut encoded)?;
    Ok(encoded.freeze())
}

pub fn encoded_frame_len(frame: &AgentFrame) -> Result<usize> {
    validate_payload_len(frame.payload.len())?;
    AGENT_FRAME_HEADER_LEN
        .checked_add(frame.payload.len())
        .context("agent frame encoded length overflow")
}

pub fn encoded_frames_len<'a>(frames: impl IntoIterator<Item = &'a AgentFrame>) -> Result<usize> {
    frames.into_iter().try_fold(0_usize, |total, frame| {
        let len = encoded_frame_len(frame)?;
        total
            .checked_add(len)
            .context("agent frame burst encoded length overflow")
    })
}

pub fn encode_frame_into(frame: &AgentFrame, encoded: &mut BytesMut) -> Result<()> {
    validate_payload_len(frame.payload.len())?;
    let payload_len = frame.payload.len() as u32;
    encoded.reserve(AGENT_FRAME_HEADER_LEN + frame.payload.len());
    encoded.put_slice(&AGENT_MAGIC);
    encoded.put_u8(frame.kind as u8);
    encoded.put_u8(frame.flags);
    encoded.put_u16(0);
    encoded.put_u64(frame.stream_id);
    encoded.put_u32(frame.credit);
    encoded.put_u32(payload_len);
    encoded.put_slice(&frame.payload);
    Ok(())
}

pub fn try_decode_frame(buf: &mut BytesMut) -> Result<Option<AgentFrame>> {
    if buf.len() < AGENT_FRAME_HEADER_LEN {
        return Ok(None);
    }

    if buf[..4] != AGENT_MAGIC {
        bail!("invalid agent frame magic");
    }

    let kind = AgentFrameKind::try_from(buf[4])?;
    let flags = buf[5];
    let reserved = u16::from_be_bytes([buf[6], buf[7]]);
    if reserved != 0 {
        bail!("agent frame reserved header bits must be zero");
    }
    let stream_id = u64::from_be_bytes(
        buf[8..16]
            .try_into()
            .context("agent frame stream id header slice is invalid")?,
    );
    let credit = u32::from_be_bytes(
        buf[16..20]
            .try_into()
            .context("agent frame credit header slice is invalid")?,
    );
    let payload_len = u32::from_be_bytes(
        buf[20..24]
            .try_into()
            .context("agent frame payload length header slice is invalid")?,
    ) as usize;
    validate_payload_len(payload_len)?;

    let total_len = AGENT_FRAME_HEADER_LEN
        .checked_add(payload_len)
        .context("agent frame length overflow")?;
    if buf.len() < total_len {
        return Ok(None);
    }

    let mut raw = buf.split_to(total_len);
    raw.advance(AGENT_FRAME_HEADER_LEN);
    Ok(Some(AgentFrame {
        kind,
        flags,
        stream_id,
        credit,
        payload: raw.freeze(),
    }))
}

fn validate_payload_len(len: usize) -> Result<()> {
    if len > AGENT_MAX_FRAME_PAYLOAD {
        bail!("agent frame payload exceeds {AGENT_MAX_FRAME_PAYLOAD} bytes: {len}");
    }
    Ok(())
}

fn validate_agent_host(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("agent host open destination must not be empty");
    }
    if host.len() > AGENT_MAX_HOST_LEN {
        bail!(
            "agent host open destination exceeds {AGENT_MAX_HOST_LEN} bytes: {}",
            host.len()
        );
    }
    if host.as_bytes().contains(&0) {
        bail!("agent host open destination must not contain NUL bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_header_and_payload() {
        let frame = AgentFrame::new(AgentFrameKind::Data, 42, Bytes::from_static(b"payload"))
            .unwrap()
            .with_credit(8192);
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(&encoded[..4], &AGENT_MAGIC);

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = try_decode_frame(&mut buf).unwrap().unwrap();

        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn opened_timing_payload_is_optional_and_stable() {
        assert_eq!(AgentOpenedTiming::decode_optional(&[]).unwrap(), None);

        let timing = AgentOpenedTiming {
            remote_connect_us: 123_456,
        };
        assert_eq!(
            AgentOpenedTiming::decode_optional(&timing.encode())
                .unwrap()
                .expect("timing payload"),
            timing
        );

        let err = AgentOpenedTiming::decode_optional(&[0; 7])
            .expect_err("truncated timing payload should fail");
        assert!(
            err.to_string().contains("opened timing payload"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn eof_timing_payload_is_optional_and_stable() {
        assert_eq!(AgentEofTiming::decode_optional(&[]).unwrap(), None);

        let timing = AgentEofTiming {
            remote_read_wait_us: 1,
            remote_read_wait_max_us: 2,
            remote_read_events: 3,
            output_credit_wait_us: 4,
            output_credit_wait_max_us: 5,
            output_send_wait_us: 6,
            output_send_wait_max_us: 7,
            output_frames: 8,
            remote_bytes: 9,
        };
        assert_eq!(
            AgentEofTiming::decode_optional(&timing.encode())
                .unwrap()
                .expect("timing payload"),
            timing
        );

        let err = AgentEofTiming::decode_optional(&[0; 71])
            .expect_err("truncated timing payload should fail");
        assert!(
            err.to_string().contains("EOF timing payload"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn carrier_read_buffer_matches_frame_payload_target() {
        assert_eq!(AGENT_CARRIER_READ_BUFFER_BYTES, 64 * 1024);
        assert_eq!(AGENT_MAX_FRAME_PAYLOAD / AGENT_CARRIER_READ_BUFFER_BYTES, 4);
        assert_eq!(AGENT_MAX_FRAME_PAYLOAD % AGENT_CARRIER_READ_BUFFER_BYTES, 0);
    }

    #[test]
    fn frame_batch_encoding_matches_individual_frames() {
        let frames = [
            AgentFrame::new(AgentFrameKind::Window, 7, Bytes::new())
                .unwrap()
                .with_credit(4096),
            AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from_static(b"payload")).unwrap(),
            AgentFrame::new(AgentFrameKind::Close, 7, Bytes::new()).unwrap(),
        ];
        let mut batched = BytesMut::with_capacity(encoded_frames_len(frames.iter()).unwrap());

        for frame in &frames {
            encode_frame_into(frame, &mut batched).unwrap();
        }

        let mut expected = BytesMut::new();
        for frame in &frames {
            expected.extend_from_slice(&encode_frame(frame).unwrap());
        }

        assert_eq!(&batched[..], &expected[..]);
        let mut decoded = batched;
        for frame in frames {
            assert_eq!(try_decode_frame(&mut decoded).unwrap().unwrap(), frame);
        }
        assert!(decoded.is_empty());
    }

    #[test]
    fn decoder_waits_for_complete_payload() {
        let frame = AgentFrame::new(AgentFrameKind::Data, 7, Bytes::from_static(b"hello")).unwrap();
        let encoded = encode_frame(&frame).unwrap();
        let split = encoded.len() - 2;
        let mut buf = BytesMut::from(&encoded[..split]);

        assert!(try_decode_frame(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&encoded[split..]);

        assert_eq!(try_decode_frame(&mut buf).unwrap().unwrap(), frame);
    }

    #[test]
    fn decoder_rejects_oversized_payload_before_allocation() {
        let mut encoded = BytesMut::with_capacity(AGENT_FRAME_HEADER_LEN);
        encoded.put_slice(&AGENT_MAGIC);
        encoded.put_u8(AgentFrameKind::Data as u8);
        encoded.put_u8(0);
        encoded.put_u16(0);
        encoded.put_u64(1);
        encoded.put_u32(0);
        encoded.put_u32((AGENT_MAX_FRAME_PAYLOAD + 1) as u32);

        let err = try_decode_frame(&mut encoded).unwrap_err().to_string();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn hello_payload_round_trips_capabilities() {
        let hello = AgentHello::current(1300);
        let decoded = AgentHello::decode(&hello.encode()).unwrap();
        let expected_capabilities = CAP_TCP_CONNECT
            | CAP_UDP_ASSOCIATE
            | CAP_DNS_RELAY
            | CAP_FLOW_CONTROL
            | CAP_HEARTBEAT
            | CAP_TCP_CONNECT_HOST;

        assert_eq!(decoded, hello);
        assert_eq!(decoded.protocol_version, AGENT_PROTOCOL_VERSION);
        assert_eq!(decoded.max_frame_payload, AGENT_MAX_FRAME_PAYLOAD as u32);
        assert_eq!(decoded.capabilities, expected_capabilities);
    }

    #[test]
    fn capability_wire_bits_are_stable() {
        assert_eq!(CAP_TCP_CONNECT, 1);
        assert_eq!(CAP_UDP_ASSOCIATE, 2);
        assert_eq!(CAP_DNS_RELAY, 4);
        assert_eq!(CAP_FLOW_CONTROL, 8);
        assert_eq!(CAP_HEARTBEAT, 16);
        assert_eq!(CAP_TCP_CONNECT_HOST, 32);
    }

    #[test]
    fn frame_kind_wire_values_are_stable() {
        let kinds = [
            (1, AgentFrameKind::Hello),
            (2, AgentFrameKind::OpenTcp),
            (3, AgentFrameKind::OpenUdp),
            (4, AgentFrameKind::Data),
            (5, AgentFrameKind::Window),
            (6, AgentFrameKind::Eof),
            (7, AgentFrameKind::Close),
            (8, AgentFrameKind::Reset),
            (9, AgentFrameKind::Opened),
            (10, AgentFrameKind::Ping),
            (11, AgentFrameKind::Pong),
            (12, AgentFrameKind::OpenTcpHost),
        ];

        for (wire, kind) in kinds {
            assert_eq!(AgentFrameKind::try_from(wire).unwrap(), kind);
            assert_eq!(kind as u8, wire);
        }
        assert!(AgentFrameKind::try_from(0).is_err());
        assert!(AgentFrameKind::try_from(13).is_err());
    }

    #[test]
    fn ipv4_open_payload_round_trips_destination_and_originator() {
        let open = AgentOpenIpv4 {
            destination_ip: Ipv4Addr::new(192, 168, 190, 45),
            destination_port: 443,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 64488,
        };

        assert_eq!(AgentOpenIpv4::decode(&open.encode()).unwrap(), open);
    }

    #[test]
    fn host_open_payload_round_trips_destination_and_originator() {
        let open = AgentOpenHost {
            destination_host: "resolver.internal".to_owned(),
            destination_port: 53,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 0,
        };

        assert_eq!(
            AgentOpenHost::decode(&open.encode().unwrap()).unwrap(),
            open
        );
    }

    #[test]
    fn host_open_payload_rejects_invalid_hostnames() {
        let mut empty = BytesMut::new();
        empty.put_u16(53);
        empty.put_slice(&Ipv4Addr::new(10, 255, 255, 1).octets());
        empty.put_u16(0);

        let err = AgentOpenHost::decode(&empty).unwrap_err().to_string();
        assert!(err.contains("at least 9 bytes") || err.contains("must not be empty"));

        let open = AgentOpenHost {
            destination_host: "bad\0host".to_owned(),
            destination_port: 53,
            originator_ip: Ipv4Addr::new(10, 255, 255, 1),
            originator_port: 0,
        };
        let err = open.encode().unwrap_err().to_string();
        assert!(err.contains("NUL"));
    }

    #[test]
    fn decoder_rejects_nonzero_reserved_header_bits() {
        let frame = AgentFrame::new(AgentFrameKind::Window, 9, Bytes::new()).unwrap();
        let mut encoded = BytesMut::from(&encode_frame(&frame).unwrap()[..]);
        encoded[7] = 1;

        let err = try_decode_frame(&mut encoded).unwrap_err().to_string();
        assert!(err.contains("reserved"));
    }

    #[test]
    fn decoder_fuzzes_random_inputs_without_panics() {
        let mut seed = 0x5275_7374_6c65_0001_u64;

        for case in 0..4096 {
            let len = case % 257;
            let mut raw = BytesMut::with_capacity(len);
            for _ in 0..len {
                raw.extend_from_slice(&[next_fuzz_byte(&mut seed)]);
            }

            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                try_decode_frame(&mut raw)
            }));
            assert!(decoded.is_ok(), "decoder panicked for len={len}");
            if let Ok(Ok(Some(frame))) = decoded {
                assert!(frame.payload.len() <= AGENT_MAX_FRAME_PAYLOAD);
            }
        }
    }

    #[test]
    fn decoder_fuzzes_structured_headers_without_panics_or_large_allocations() {
        let mut seed = 0x5275_7374_6c65_0002_u64;
        let interesting_lengths = [
            0_u32,
            1,
            23,
            24,
            64,
            AGENT_MAX_FRAME_PAYLOAD as u32,
            (AGENT_MAX_FRAME_PAYLOAD + 1) as u32,
            u32::MAX,
        ];

        for payload_len in interesting_lengths {
            for available_payload in [0_usize, 1, 7, 31] {
                let mut raw = BytesMut::with_capacity(AGENT_FRAME_HEADER_LEN + available_payload);
                raw.put_slice(&AGENT_MAGIC);
                raw.put_u8(AgentFrameKind::Data as u8);
                raw.put_u8(next_fuzz_byte(&mut seed));
                raw.put_u16(0);
                raw.put_u64(next_fuzz_u64(&mut seed));
                raw.put_u32(next_fuzz_u64(&mut seed) as u32);
                raw.put_u32(payload_len);
                for _ in 0..available_payload {
                    raw.extend_from_slice(&[next_fuzz_byte(&mut seed)]);
                }

                let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    try_decode_frame(&mut raw)
                }));
                assert!(
                    decoded.is_ok(),
                    "decoder panicked for declared payload len {payload_len}"
                );
            }
        }
    }

    fn next_fuzz_byte(seed: &mut u64) -> u8 {
        next_fuzz_u64(seed) as u8
    }

    fn next_fuzz_u64(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed
    }
}
