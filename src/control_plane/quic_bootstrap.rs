use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use ring::digest;
use russh::{
    client::{Handle, Msg},
    ChannelStream,
};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::quic_agent;
use crate::remote_helper::{read_quic_helper_bootstrap, QuicHelperBootstrapRole};
use crate::ssh_control::Client;

use super::quic_connect::{format_socket_addrs, resolve_quic_helper_addrs};

const QUIC_AGENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct StartedQuicHelperSsh {
    pub(super) bootstrap: quic_agent::QuicAgentBootstrap,
    pub(super) remote_addrs: Vec<SocketAddr>,
    pub(super) reader: BufReader<ChannelStream<Msg>>,
}

pub(super) async fn start_quic_helper_ssh_bootstrap(
    handle: &Handle<Client>,
    role: QuicHelperBootstrapRole,
    remote_host: &str,
    helper_command: &str,
) -> Result<StartedQuicHelperSsh> {
    let channel = handle
        .channel_open_session()
        .await
        .context(role.open_session_context)?;
    channel
        .exec(true, helper_command.to_owned())
        .await
        .with_context(|| format!("{}: {helper_command}", role.exec_context))?;

    let mut reader = BufReader::new(channel.into_stream());
    let bootstrap =
        read_quic_helper_bootstrap(&mut reader, role, QUIC_AGENT_BOOTSTRAP_TIMEOUT).await?;
    let remote_addrs = resolve_quic_helper_addrs(role.label, remote_host, bootstrap.port)?;
    let token_prefix = auth_token_sha256_prefix(&bootstrap.auth_token);
    eprintln!(
        "{} role={} remote_host={} bootstrap_port={} resolved_addrs={} cert_sha256={} cert_der_len={} auth_token_sha256_prefix={}",
        role.connect_log_prefix,
        role.label,
        remote_host,
        bootstrap.port,
        format_socket_addrs(&remote_addrs),
        bootstrap.cert_sha256,
        bootstrap.cert_der.len(),
        token_prefix
    );

    Ok(StartedQuicHelperSsh {
        bootstrap,
        remote_addrs,
        reader,
    })
}

fn auth_token_sha256_prefix(auth_token: &[u8]) -> String {
    lower_hex(digest::digest(&digest::SHA256, auth_token).as_ref())
        .chars()
        .take(12)
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) async fn drain_quic_helper_ssh_output<R>(label: &'static str, mut reader: BufReader<R>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if let Some(log_line) = quic_helper_ssh_output_log_line(label, &line) {
                    eprintln!("{log_line}");
                }
            }
            Err(err) => {
                eprintln!("{label}: failed to drain remote output: {err:#}");
                break;
            }
        }
    }
}

fn quic_helper_ssh_output_log_line(label: &str, line: &str) -> Option<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        None
    } else {
        Some(format!("{label}: remote output: {line}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    #[test]
    fn auth_token_sha256_prefix_is_lowercase_twelve_hex_chars() {
        assert_eq!(lower_hex(&[0x00, 0x0f, 0x10, 0xab, 0xff]), "000f10abff");
        assert_eq!(auth_token_sha256_prefix(b"rustle-token"), "ed2cf6522e2a");
    }

    #[test]
    fn quic_helper_output_log_line_trims_line_endings_and_skips_empty_lines() {
        assert_eq!(
            quic_helper_ssh_output_log_line("quic-agent", "ready\r\n"),
            Some("quic-agent: remote output: ready".to_owned())
        );
        assert_eq!(quic_helper_ssh_output_log_line("quic-agent", "\r\n"), None);
        assert_eq!(quic_helper_ssh_output_log_line("quic-agent", ""), None);
    }

    #[tokio::test]
    async fn drain_quic_helper_ssh_output_reads_until_eof() {
        let polls = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            bytes: b"first\n\nsecond\r\n".to_vec(),
            offset: 0,
            polls: Arc::clone(&polls),
        };

        drain_quic_helper_ssh_output("quic-agent", BufReader::new(reader)).await;

        assert!(
            polls.load(Ordering::SeqCst) > 0,
            "drain task should poll the SSH output reader"
        );
    }

    struct CountingReader {
        bytes: Vec<u8>,
        offset: usize,
        polls: Arc<AtomicUsize>,
    }

    impl tokio::io::AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.offset >= self.bytes.len() {
                return Poll::Ready(Ok(()));
            }

            let remaining = &self.bytes[self.offset..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.offset += len;
            Poll::Ready(Ok(()))
        }
    }
}
