use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use tokio::io::AsyncWriteExt;

pub(super) const QUIC_AUTH_TOKEN_BYTES: usize = 32;
pub(super) const QUIC_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const QUIC_AUTH_FAILED_CODE: u32 = 0x5255_4155;
const QUIC_AUTH_STATUS_OK: u8 = 0;

#[derive(Debug)]
struct QuicAuthError;

impl std::fmt::Display for QuicAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid QUIC helper auth token")
    }
}

impl std::error::Error for QuicAuthError {}

pub(super) async fn open_quic_bi_stream_with_timeout(
    connection: &quinn::Connection,
    timeout: Duration,
    label: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    tokio::time::timeout(timeout, connection.open_bi())
        .await
        .with_context(|| format!("timed out opening {label} after {}ms", timeout.as_millis()))?
        .with_context(|| format!("failed to open {label}"))
}

pub(super) fn generate_quic_auth_token() -> Result<Vec<u8>> {
    let mut token = vec![0_u8; QUIC_AUTH_TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut token)
        .map_err(|_| anyhow!("failed to generate QUIC helper auth token"))?;
    Ok(token)
}

pub(super) async fn write_quic_auth_token(
    send: &mut quinn::SendStream,
    auth_token: &[u8],
) -> Result<()> {
    if auth_token.len() != QUIC_AUTH_TOKEN_BYTES {
        bail!(
            "invalid QUIC helper auth token length {}, expected {QUIC_AUTH_TOKEN_BYTES}",
            auth_token.len()
        );
    }
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, send.write_all(auth_token))
        .await
        .context("timed out writing QUIC helper auth token")?
        .context("failed to write QUIC helper auth token")
}

pub(super) async fn verify_quic_auth_token(
    recv: &mut quinn::RecvStream,
    expected: &[u8],
) -> Result<()> {
    if expected.len() != QUIC_AUTH_TOKEN_BYTES {
        bail!(
            "invalid expected QUIC helper auth token length {}, expected {QUIC_AUTH_TOKEN_BYTES}",
            expected.len()
        );
    }
    let mut actual = [0_u8; QUIC_AUTH_TOKEN_BYTES];
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, recv.read_exact(&mut actual))
        .await
        .context("timed out waiting for QUIC helper auth token")?
        .context("failed to read QUIC helper auth token")?;
    if !quic_auth_tokens_match(&actual, expected) {
        return Err(QuicAuthError.into());
    }
    Ok(())
}

fn quic_auth_tokens_match(actual: &[u8; QUIC_AUTH_TOKEN_BYTES], expected: &[u8]) -> bool {
    if expected.len() != QUIC_AUTH_TOKEN_BYTES {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in actual.iter().zip(expected.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

pub(super) async fn write_quic_auth_ok(send: &mut quinn::SendStream) -> Result<()> {
    send.write_all(&[QUIC_AUTH_STATUS_OK])
        .await
        .context("failed to write QUIC helper auth acknowledgement")
}

pub(super) async fn read_quic_auth_ok(recv: &mut quinn::RecvStream) -> Result<()> {
    let mut status = [0_u8; 1];
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, recv.read_exact(&mut status))
        .await
        .context("timed out waiting for QUIC helper auth acknowledgement")?
        .context("failed to read QUIC helper auth acknowledgement")?;
    if status[0] != QUIC_AUTH_STATUS_OK {
        bail!(
            "QUIC helper returned invalid auth acknowledgement {}",
            status[0]
        );
    }
    Ok(())
}

pub(super) async fn authenticate_quic_bridge_connection_on_client(
    connection: &quinn::Connection,
    auth_token: &[u8],
) -> Result<()> {
    let (mut send, mut recv) = open_quic_bi_stream_with_timeout(
        connection,
        QUIC_AUTH_TIMEOUT,
        "native QUIC bridge auth stream",
    )
    .await
    .context("native QUIC bridge auth stage=open_stream")?;
    write_quic_auth_token(&mut send, auth_token)
        .await
        .context("native QUIC bridge auth stage=write_token")?;
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, send.shutdown())
        .await
        .context("native QUIC bridge auth stage=finish_send timed out")?
        .context("native QUIC bridge auth stage=finish_send failed")?;
    read_quic_auth_ok(&mut recv)
        .await
        .context("native QUIC bridge auth stage=read_ack")
}

pub(super) async fn authenticate_quic_bridge_connection_on_server(
    connection: &quinn::Connection,
    expected_token: &[u8],
) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(QUIC_AUTH_TIMEOUT, connection.accept_bi())
        .await
        .context("timed out waiting for native QUIC bridge auth stream")?
        .context("failed to accept native QUIC bridge auth stream")?;
    verify_quic_auth_token(&mut recv, expected_token).await?;
    write_quic_auth_ok(&mut send).await?;
    let _ = send.shutdown().await;
    Ok(())
}
