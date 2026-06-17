use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use tokio::io::AsyncWriteExt;

use super::bootstrap::sha256_hex;

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

pub(super) fn quic_auth_stage_context(label: &str, stage: &str, started: Instant) -> String {
    format!(
        "{label} stage={stage} elapsed_ms={}",
        started.elapsed().as_millis()
    )
}

pub(super) fn quic_auth_peer_stage_context(
    label: &str,
    remote: SocketAddr,
    stage: &str,
    started: Instant,
) -> String {
    format!(
        "{label} remote={remote} stage={stage} elapsed_ms={}",
        started.elapsed().as_millis()
    )
}

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
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, send.write_all(&[QUIC_AUTH_STATUS_OK]))
        .await
        .context("timed out writing QUIC helper auth acknowledgement")?
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
    let remote = connection.remote_address();
    let token_prefix = quic_auth_token_sha256_prefix(auth_token);
    let stage_started = Instant::now();
    let (mut send, mut recv) = open_quic_bi_stream_with_timeout(
        connection,
        QUIC_AUTH_TIMEOUT,
        "native QUIC bridge auth stream",
    )
    .await
    .with_context(|| {
        quic_auth_stage_context("native QUIC bridge auth", "open_stream", stage_started)
    })?;
    log_quic_bridge_auth_stage(
        "client",
        remote,
        "open_stream",
        "ok",
        stage_started,
        &token_prefix,
    );
    let stage_started = Instant::now();
    write_quic_auth_token(&mut send, auth_token)
        .await
        .with_context(|| {
            quic_auth_stage_context("native QUIC bridge auth", "write_token", stage_started)
        })?;
    log_quic_bridge_auth_stage(
        "client",
        remote,
        "write_token",
        "ok",
        stage_started,
        &token_prefix,
    );
    let stage_started = Instant::now();
    read_quic_auth_ok(&mut recv).await.with_context(|| {
        quic_auth_stage_context("native QUIC bridge auth", "read_ack", stage_started)
    })?;
    log_quic_bridge_auth_stage(
        "client",
        remote,
        "read_ack",
        "ok",
        stage_started,
        &token_prefix,
    );
    let stage_started = Instant::now();
    match tokio::time::timeout(QUIC_AUTH_TIMEOUT, send.shutdown()).await {
        Ok(Ok(())) => log_quic_bridge_auth_stage(
            "client",
            remote,
            "finish_send",
            "ok",
            stage_started,
            &token_prefix,
        ),
        Ok(Err(err)) => eprintln!(
            "quic-auth: transport=quic-native side=client remote={remote} stage=finish_send result=error elapsed_ms={} timeout_ms={} auth_token_sha256_prefix={} error={err:#}",
            stage_started.elapsed().as_millis(),
            QUIC_AUTH_TIMEOUT.as_millis(),
            token_prefix
        ),
        Err(_) => eprintln!(
            "quic-auth: transport=quic-native side=client remote={remote} stage=finish_send result=timeout elapsed_ms={} timeout_ms={} auth_token_sha256_prefix={}",
            stage_started.elapsed().as_millis(),
            QUIC_AUTH_TIMEOUT.as_millis(),
            token_prefix
        ),
    }
    Ok(())
}

pub(super) async fn authenticate_quic_bridge_connection_on_server(
    connection: &quinn::Connection,
    expected_token: &[u8],
) -> Result<()> {
    let remote = connection.remote_address();
    let token_prefix = quic_auth_token_sha256_prefix(expected_token);
    let stage_started = Instant::now();
    let (mut send, mut recv) = tokio::time::timeout(QUIC_AUTH_TIMEOUT, connection.accept_bi())
        .await
        .with_context(|| {
            format!(
                "{} timed_out",
                quic_auth_peer_stage_context(
                    "native QUIC bridge server auth",
                    remote,
                    "accept_stream",
                    stage_started,
                )
            )
        })?
        .with_context(|| {
            format!(
                "{} failed",
                quic_auth_peer_stage_context(
                    "native QUIC bridge server auth",
                    remote,
                    "accept_stream",
                    stage_started,
                )
            )
        })?;
    log_quic_bridge_auth_stage(
        "server",
        remote,
        "accept_stream",
        "ok",
        stage_started,
        &token_prefix,
    );
    let stage_started = Instant::now();
    verify_quic_auth_token(&mut recv, expected_token)
        .await
        .with_context(|| {
            quic_auth_peer_stage_context(
                "native QUIC bridge server auth",
                remote,
                "read_token",
                stage_started,
            )
        })?;
    log_quic_bridge_auth_stage(
        "server",
        remote,
        "read_token",
        "ok",
        stage_started,
        &token_prefix,
    );
    let stage_started = Instant::now();
    write_quic_auth_ok(&mut send).await.with_context(|| {
        quic_auth_peer_stage_context(
            "native QUIC bridge server auth",
            remote,
            "write_ack",
            stage_started,
        )
    })?;
    log_quic_bridge_auth_stage(
        "server",
        remote,
        "write_ack",
        "ok",
        stage_started,
        &token_prefix,
    );
    let _ = send.shutdown().await;
    Ok(())
}

fn quic_auth_token_sha256_prefix(token: &[u8]) -> String {
    sha256_hex(token).chars().take(12).collect()
}

fn log_quic_bridge_auth_stage(
    side: &'static str,
    remote: SocketAddr,
    stage: &'static str,
    result: &'static str,
    started_at: Instant,
    token_prefix: &str,
) {
    eprintln!(
        "quic-auth: transport=quic-native side={side} remote={remote} stage={stage} result={result} elapsed_ms={} timeout_ms={} auth_token_sha256_prefix={token_prefix}",
        started_at.elapsed().as_millis(),
        QUIC_AUTH_TIMEOUT.as_millis()
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    use super::quic_auth_peer_stage_context;

    #[test]
    fn quic_auth_peer_stage_context_reports_remote_stage_and_elapsed() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4444);
        let detail = quic_auth_peer_stage_context(
            "QUIC agent server auth",
            remote,
            "read_token",
            Instant::now(),
        );

        assert!(detail.contains("QUIC agent server auth"));
        assert!(detail.contains("remote=203.0.113.9:4444"));
        assert!(detail.contains("stage=read_token"));
        assert!(detail.contains("elapsed_ms="));
    }
}
