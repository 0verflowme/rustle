use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::quic_agent;
use crate::ssh_control::{connect_prepared_ssh, Client, PreparedSshConnection};

use super::command::HelperCommandPlan;
use super::upload::{stage_uploaded_helper_command, UploadedHelperCommand};

#[derive(Clone, Copy)]
pub(crate) struct QuicHelperBootstrapRole {
    pub(crate) label: &'static str,
    pub(crate) connect_log_prefix: &'static str,
    pub(crate) open_session_context: &'static str,
    pub(crate) exec_context: &'static str,
    timeout_context: &'static str,
    read_context: &'static str,
    eof_context: &'static str,
    invalid_context: &'static str,
    decode: fn(&str) -> Result<quic_agent::QuicAgentBootstrap>,
}

pub(crate) const QUIC_AGENT_BOOTSTRAP_ROLE: QuicHelperBootstrapRole = QuicHelperBootstrapRole {
    label: "quic-agent",
    connect_log_prefix: "quic-agent: connecting UDP data plane",
    open_session_context: "failed to open SSH session channel for Rustle QUIC agent",
    exec_context: "failed to exec remote Rustle QUIC agent",
    timeout_context: "timed out waiting for QUIC agent bootstrap line",
    read_context: "failed to read QUIC agent bootstrap line",
    eof_context: "remote QUIC agent exited before writing its bootstrap line",
    invalid_context: "invalid QUIC agent bootstrap line",
    decode: quic_agent::QuicAgentBootstrap::decode_line,
};

pub(crate) const QUIC_NATIVE_BOOTSTRAP_ROLE: QuicHelperBootstrapRole = QuicHelperBootstrapRole {
    label: "quic-native",
    connect_log_prefix: "quic-native: connecting UDP data plane",
    open_session_context: "failed to open SSH session channel for native QUIC bridge helper",
    exec_context: "failed to exec remote native QUIC bridge helper",
    timeout_context: "timed out waiting for native QUIC bridge bootstrap line",
    read_context: "failed to read native QUIC bridge bootstrap line",
    eof_context: "remote native QUIC bridge helper exited before writing its bootstrap line",
    invalid_context: "invalid native QUIC bridge bootstrap line",
    decode: quic_agent::QuicAgentBootstrap::decode_bridge_line,
};

pub(super) struct BootstrappedHelper {
    handle: Handle<Client>,
    helper: UploadedHelperCommand,
}

impl BootstrappedHelper {
    pub(super) fn into_connect_parts(self) -> (Handle<Client>, String, String) {
        let command = self.helper.command;
        let remote_path = self.helper.remote_path;
        (self.handle, command, remote_path)
    }
}

pub(super) async fn bootstrap_helper(
    prepared: &PreparedSshConnection,
    plan: &HelperCommandPlan,
) -> Result<BootstrappedHelper> {
    if !plan.allows_upload_fallback() {
        bail!(
            "{}: upload bootstrap is not allowed for this helper startup policy",
            plan.kind.controller_log_prefix()
        );
    }
    let handle = connect_prepared_ssh(prepared).await?;
    let helper = stage_uploaded_helper_command(&handle, plan.kind).await?;
    Ok(BootstrappedHelper { handle, helper })
}

pub(crate) async fn read_quic_helper_bootstrap<R>(
    reader: &mut BufReader<R>,
    role: QuicHelperBootstrapRole,
    timeout: Duration,
) -> Result<quic_agent::QuicAgentBootstrap>
where
    R: AsyncRead + Unpin,
{
    let mut line = String::new();
    let read = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .context(role.timeout_context)?
        .context(role.read_context)?;
    if read == 0 {
        bail!("{}", role.eof_context);
    }
    (role.decode)(&line).context(role.invalid_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn test_bootstrap(port: u16) -> quic_agent::QuicAgentBootstrap {
        quic_agent::QuicAgentBootstrap {
            port,
            cert_sha256: "103597c5abb6113da596c18e9d1da69364eafe00a2bfaa8b12e53c44bd6b0429"
                .to_owned(),
            cert_der: vec![0, 1, 2, 0xfe, 0xff],
            auth_token: vec![0x5a; 32],
        }
    }

    async fn bootstrap_reader_for(line: Option<String>) -> BufReader<tokio::io::DuplexStream> {
        let (mut writer, reader) = tokio::io::duplex(4096);
        if let Some(line) = line {
            writer
                .write_all(line.as_bytes())
                .await
                .expect("write bootstrap line");
            writer.write_all(b"\n").await.expect("write newline");
        }
        drop(writer);
        BufReader::new(reader)
    }

    #[tokio::test]
    async fn quic_helper_bootstrap_reader_accepts_agent_line() {
        let bootstrap = test_bootstrap(4433);
        let mut reader = bootstrap_reader_for(Some(bootstrap.encode_line())).await;

        let decoded = read_quic_helper_bootstrap(
            &mut reader,
            QUIC_AGENT_BOOTSTRAP_ROLE,
            Duration::from_secs(1),
        )
        .await
        .expect("decode agent bootstrap");

        assert_eq!(decoded, bootstrap);
    }

    #[tokio::test]
    async fn quic_helper_bootstrap_reader_accepts_native_bridge_line() {
        let bootstrap = test_bootstrap(4434);
        let mut reader = bootstrap_reader_for(Some(bootstrap.encode_bridge_line())).await;

        let decoded = read_quic_helper_bootstrap(
            &mut reader,
            QUIC_NATIVE_BOOTSTRAP_ROLE,
            Duration::from_secs(1),
        )
        .await
        .expect("decode native bridge bootstrap");

        assert_eq!(decoded, bootstrap);
    }

    #[tokio::test]
    async fn quic_helper_bootstrap_reader_reports_eof_before_line() {
        let mut reader = bootstrap_reader_for(None).await;

        let err = read_quic_helper_bootstrap(
            &mut reader,
            QUIC_AGENT_BOOTSTRAP_ROLE,
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected EOF error");
        let detail = format!("{err:#}");

        assert!(detail.contains("remote QUIC agent exited before writing its bootstrap line"));
    }

    #[tokio::test]
    async fn quic_helper_bootstrap_reader_rejects_wrong_role_magic() {
        let bootstrap = test_bootstrap(4434);
        let mut reader = bootstrap_reader_for(Some(bootstrap.encode_line())).await;

        let err = read_quic_helper_bootstrap(
            &mut reader,
            QUIC_NATIVE_BOOTSTRAP_ROLE,
            Duration::from_secs(1),
        )
        .await
        .expect_err("expected invalid magic");
        let detail = format!("{err:#}");

        assert!(detail.contains("invalid native QUIC bridge bootstrap line"));
        assert!(detail.contains("unexpected QUIC bootstrap magic"));
    }

    #[tokio::test]
    async fn quic_helper_bootstrap_reader_reports_timeout() {
        let (_writer, reader) = tokio::io::duplex(64);
        let mut reader = BufReader::new(reader);

        let err = read_quic_helper_bootstrap(
            &mut reader,
            QUIC_AGENT_BOOTSTRAP_ROLE,
            Duration::from_millis(1),
        )
        .await
        .expect_err("expected timeout");
        let detail = format!("{err:#}");

        assert!(detail.contains("timed out waiting for QUIC agent bootstrap line"));
    }
}
