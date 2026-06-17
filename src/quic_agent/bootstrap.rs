use anyhow::{bail, Context, Result};
use ring::digest;

use super::auth::QUIC_AUTH_TOKEN_BYTES;

pub const QUIC_AGENT_BOOTSTRAP_MAGIC: &str = "RUSTLE_QUIC_AGENT_V2";
pub const QUIC_BRIDGE_BOOTSTRAP_MAGIC: &str = "RUSTLE_QUIC_BRIDGE_V2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicAgentBootstrap {
    pub port: u16,
    pub cert_sha256: String,
    pub cert_der: Vec<u8>,
    pub auth_token: Vec<u8>,
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
            "{magic} {} {} {} {}",
            self.port,
            self.cert_sha256,
            lower_hex(&self.cert_der),
            lower_hex(&self.auth_token)
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
        let auth_token = decode_hex(fields.next().context("missing QUIC agent auth token")?)
            .context("invalid QUIC agent auth token")?;
        if auth_token.len() != QUIC_AUTH_TOKEN_BYTES {
            bail!(
                "invalid QUIC agent auth token length {}, expected {QUIC_AUTH_TOKEN_BYTES}",
                auth_token.len()
            );
        }
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
            auth_token,
        })
    }
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

pub(super) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
    use super::*;

    fn test_auth_token() -> Vec<u8> {
        (0..QUIC_AUTH_TOKEN_BYTES)
            .map(|index| index as u8)
            .collect()
    }

    fn test_bootstrap(port: u16) -> QuicAgentBootstrap {
        let cert_der = vec![0, 1, 2, 0xfe, 0xff];
        QuicAgentBootstrap {
            port,
            cert_sha256: sha256_hex(&cert_der),
            cert_der,
            auth_token: test_auth_token(),
        }
    }

    #[test]
    fn bootstrap_line_round_trips_and_verifies_hash() {
        let bootstrap = test_bootstrap(4433);

        assert_eq!(
            QuicAgentBootstrap::decode_line(&bootstrap.encode_line()).unwrap(),
            bootstrap
        );
    }

    #[test]
    fn bridge_bootstrap_line_round_trips_with_bridge_magic() {
        let bootstrap = test_bootstrap(4434);
        let line = bootstrap.encode_bridge_line();

        assert!(line.starts_with(QUIC_BRIDGE_BOOTSTRAP_MAGIC));
        assert_eq!(
            QuicAgentBootstrap::decode_bridge_line(&line).unwrap(),
            bootstrap
        );
    }

    #[test]
    fn bridge_bootstrap_line_rejects_agent_magic() {
        let bootstrap = test_bootstrap(4434);

        assert!(QuicAgentBootstrap::decode_bridge_line(&bootstrap.encode_line()).is_err());
        assert!(QuicAgentBootstrap::decode_line(&bootstrap.encode_bridge_line()).is_err());
    }

    #[test]
    fn bootstrap_line_rejects_tampered_cert() {
        let bootstrap = test_bootstrap(4433);
        let mut line = bootstrap.encode_line();
        line.push_str("00");

        assert!(QuicAgentBootstrap::decode_line(&line).is_err());
    }

    #[test]
    fn bootstrap_line_requires_valid_auth_token() {
        let bootstrap = test_bootstrap(4433);
        let cert_hex = lower_hex(&bootstrap.cert_der);
        let missing = format!(
            "{} {} {} {}",
            QUIC_AGENT_BOOTSTRAP_MAGIC, bootstrap.port, bootstrap.cert_sha256, cert_hex
        );
        let short = format!("{missing} aa");
        let non_hex = format!("{missing} {}", "x".repeat(QUIC_AUTH_TOKEN_BYTES * 2));
        let mut trailing = bootstrap.encode_line();
        trailing.push_str(" extra");

        assert!(QuicAgentBootstrap::decode_line(&missing).is_err());
        assert!(QuicAgentBootstrap::decode_line(&short).is_err());
        assert!(QuicAgentBootstrap::decode_line(&non_hex).is_err());
        assert!(QuicAgentBootstrap::decode_line(&trailing).is_err());
    }
}
