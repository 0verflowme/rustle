use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::{
    client::{Handle, Msg},
    ChannelStream,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge,
};
use crate::agent_transport::AgentTransport;
use crate::remote_helper::{HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::{quic_agent, SshArgs};

use super::{
    connect_agent_bridge_transports_from_connector, connect_prepared_helper_with_upload_fallback,
};

const QUIC_AGENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);
const QUIC_DATA_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy)]
struct QuicHelperBootstrapRole {
    label: &'static str,
    connect_log_prefix: &'static str,
    open_session_context: &'static str,
    exec_context: &'static str,
    timeout_context: &'static str,
    read_context: &'static str,
    eof_context: &'static str,
    invalid_context: &'static str,
    decode: fn(&str) -> Result<quic_agent::QuicAgentBootstrap>,
}

const QUIC_AGENT_BOOTSTRAP_ROLE: QuicHelperBootstrapRole = QuicHelperBootstrapRole {
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

const QUIC_NATIVE_BOOTSTRAP_ROLE: QuicHelperBootstrapRole = QuicHelperBootstrapRole {
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

struct StartedQuicHelperSsh {
    bootstrap: quic_agent::QuicAgentBootstrap,
    remote_addrs: Vec<SocketAddr>,
    reader: BufReader<ChannelStream<Msg>>,
}

pub(super) struct SshQuicAgentBridgeConnector {
    prepared: Arc<PreparedSshConnection>,
    helper_plan: HelperCommandPlan,
    mtu: u16,
}

impl SshQuicAgentBridgeConnector {
    pub(super) fn new(ssh: SshArgs, helper_plan: HelperCommandPlan, mtu: u16) -> Result<Self> {
        Ok(Self {
            prepared: Arc::new(prepare_ssh_connection(&ssh)?),
            helper_plan,
            mtu,
        })
    }

    async fn connect_primary_transport(&self) -> Result<AgentBridgeTransport> {
        let primary_remote_host = self.prepared.remote_host().to_owned();
        let uploaded_remote_host = primary_remote_host.clone();
        let mtu = self.mtu;
        connect_prepared_helper_with_upload_fallback(
            &self.prepared,
            &self.helper_plan,
            HelperKind::QuicAgent,
            move |handle, command| async move {
                connect_quic_agent_bridge_transport_on_handle(
                    handle,
                    &primary_remote_host,
                    &command,
                    mtu,
                )
                .await
            },
            move |handle, command| async move {
                connect_quic_agent_bridge_transport_on_handle(
                    handle,
                    &uploaded_remote_host,
                    &command,
                    mtu,
                )
                .await
            },
            "Rustle QUIC agent",
            Some("quic-agent: bootstrapped remote helper from local binary"),
        )
        .await
    }
}

impl AgentBridgeConnector for SshQuicAgentBridgeConnector {
    fn primary_command(&self) -> &str {
        &self.helper_plan.command
    }

    fn connect_initial(&self, desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_> {
        Box::pin(async move {
            connect_agent_bridge_transports_from_connector(self, desired_sessions).await
        })
    }

    fn connect_primary(&self) -> AgentBridgeConnectFuture<'_> {
        Box::pin(async move { self.connect_primary_transport().await })
    }

    fn connect_command<'a>(&'a self, agent_command: &'a str) -> AgentBridgeConnectFuture<'a> {
        Box::pin(async move {
            connect_quic_agent_bridge_transport_fresh_prepared_ssh_command(
                &self.prepared,
                agent_command,
                self.mtu,
            )
            .await
        })
    }
}

async fn connect_quic_agent_bridge_transport_fresh_prepared_ssh_command(
    prepared: &PreparedSshConnection,
    agent_command: &str,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    let handle = connect_prepared_ssh(prepared).await?;
    connect_quic_agent_bridge_transport_on_handle(
        handle,
        prepared.remote_host(),
        agent_command,
        mtu,
    )
    .await
}

async fn connect_quic_agent_bridge_transport_on_handle(
    handle: Handle<Client>,
    remote_host: &str,
    agent_command: &str,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    let started = start_quic_helper_ssh_bootstrap(
        &handle,
        QUIC_AGENT_BOOTSTRAP_ROLE,
        remote_host,
        agent_command,
    )
    .await?;

    let drain_task = tokio::spawn(drain_quic_helper_ssh_output(
        QUIC_AGENT_BOOTSTRAP_ROLE.label,
        started.reader,
    ));
    let (recv, send, session) = connect_quic_data_plane_any(
        QUIC_AGENT_BOOTSTRAP_ROLE.label,
        &started.remote_addrs,
        |remote_addr| quic_agent::connect_quic_agent_stream(remote_addr, &started.bootstrap),
    )
    .await?;
    let transport = AgentTransport::connect(recv, send, mtu)
        .await
        .context("failed to negotiate Rustle agent protocol over QUIC")?;

    Ok(AgentBridgeTransport::quic(
        handle,
        session,
        drain_task,
        transport,
        agent_command,
    ))
}

pub(super) async fn connect_quic_native_bridge_fresh_ssh_command(
    ssh: &SshArgs,
    helper_plan: &HelperCommandPlan,
) -> Result<QuicNativeBridge> {
    let prepared = prepare_ssh_connection(ssh)?;
    let primary_remote_host = prepared.remote_host().to_owned();
    let uploaded_remote_host = primary_remote_host.clone();
    connect_prepared_helper_with_upload_fallback(
        &prepared,
        helper_plan,
        HelperKind::QuicBridgeNative,
        move |handle, command| async move {
            connect_quic_native_bridge_on_handle(handle, &primary_remote_host, &command).await
        },
        move |handle, command| async move {
            connect_quic_native_bridge_on_handle(handle, &uploaded_remote_host, &command).await
        },
        "native QUIC bridge",
        None,
    )
    .await
}

async fn connect_quic_native_bridge_on_handle(
    handle: Handle<Client>,
    remote_host: &str,
    agent_command: &str,
) -> Result<QuicNativeBridge> {
    let started = start_quic_helper_ssh_bootstrap(
        &handle,
        QUIC_NATIVE_BOOTSTRAP_ROLE,
        remote_host,
        agent_command,
    )
    .await?;

    let drain_task = tokio::spawn(drain_quic_helper_ssh_output(
        QUIC_NATIVE_BOOTSTRAP_ROLE.label,
        started.reader,
    ));
    let client = connect_quic_data_plane_any(
        QUIC_NATIVE_BOOTSTRAP_ROLE.label,
        &started.remote_addrs,
        |remote_addr| quic_agent::connect_quic_bridge(remote_addr, &started.bootstrap),
    )
    .await?;

    Ok(QuicNativeBridge::with_ssh_carrier(
        client, handle, drain_task,
    ))
}

async fn start_quic_helper_ssh_bootstrap(
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
    eprintln!(
        "{} to {} cert_sha256={}",
        role.connect_log_prefix,
        format_socket_addrs(&remote_addrs),
        bootstrap.cert_sha256
    );

    Ok(StartedQuicHelperSsh {
        bootstrap,
        remote_addrs,
        reader,
    })
}

async fn read_quic_helper_bootstrap<R>(
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

async fn connect_quic_data_plane_any<T, F, Connect>(
    label: &'static str,
    remote_addrs: &[SocketAddr],
    connect: Connect,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    Connect: FnMut(SocketAddr) -> F,
{
    connect_quic_data_plane_any_with_timeout(
        label,
        remote_addrs,
        QUIC_DATA_PLANE_CONNECT_TIMEOUT,
        connect,
    )
    .await
}

async fn connect_quic_data_plane_any_with_timeout<T, F, Connect>(
    label: &'static str,
    remote_addrs: &[SocketAddr],
    timeout: Duration,
    mut connect: Connect,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    Connect: FnMut(SocketAddr) -> F,
{
    if remote_addrs.is_empty() {
        bail!("{label}: no resolved UDP data-plane addresses after SSH bootstrap");
    }

    let attempt_timeout = quic_data_plane_attempt_timeout(timeout, remote_addrs.len());
    let mut failures = Vec::new();
    for remote_addr in remote_addrs.iter().copied() {
        match connect_quic_data_plane_with_timeout(
            label,
            remote_addr,
            attempt_timeout,
            connect(remote_addr),
        )
        .await
        {
            Ok(connected) => return Ok(connected),
            Err(err) => failures.push(format!("{remote_addr}: {err:#}")),
        }
    }

    bail!(
        "{}",
        quic_data_plane_all_addrs_failed_context(label, remote_addrs, &failures)
    )
}

async fn connect_quic_data_plane_with_timeout<T, F>(
    label: &'static str,
    remote_addr: SocketAddr,
    timeout: Duration,
    future: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result.with_context(|| quic_data_plane_error_context(label, remote_addr)),
        Err(_) => bail!(
            "{}",
            quic_data_plane_timeout_context(label, remote_addr, timeout)
        ),
    }
}

fn quic_data_plane_attempt_timeout(total_timeout: Duration, attempts: usize) -> Duration {
    let attempts = attempts.max(1);
    let divisor = u32::try_from(attempts).unwrap_or(u32::MAX);
    let per_attempt = total_timeout / divisor;
    if per_attempt < Duration::from_millis(1) {
        Duration::from_millis(1)
    } else {
        per_attempt
    }
}

fn quic_data_plane_error_context(label: &str, remote_addr: SocketAddr) -> String {
    format!(
        "{label}: failed to establish UDP data plane to {remote_addr} after SSH bootstrap; inbound UDP to the helper port may be blocked, or the advertised address may be unreachable"
    )
}

fn quic_data_plane_timeout_context(
    label: &str,
    remote_addr: SocketAddr,
    timeout: Duration,
) -> String {
    format!(
        "{label}: timed out after {}ms establishing UDP data plane to {remote_addr} after SSH bootstrap; inbound UDP to the helper port may be blocked, or the advertised address may be unreachable",
        timeout.as_millis()
    )
}

fn quic_data_plane_all_addrs_failed_context(
    label: &str,
    remote_addrs: &[SocketAddr],
    failures: &[String],
) -> String {
    format!(
        "{label}: failed to establish UDP data plane to any resolved address after SSH bootstrap; tried=[{}]; failures=[{}]",
        format_socket_addrs(remote_addrs),
        failures.join(" | ")
    )
}

async fn drain_quic_helper_ssh_output<R>(label: &'static str, mut reader: BufReader<R>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let line = line.trim_end_matches(['\r', '\n']);
                if !line.is_empty() {
                    eprintln!("{label}: remote output: {line}");
                }
            }
            Err(err) => {
                eprintln!("{label}: failed to drain remote output: {err:#}");
                break;
            }
        }
    }
}

fn resolve_quic_helper_addrs(
    label: &'static str,
    remote_host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = (remote_host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {label} address for {remote_host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no socket addresses found for {label} {remote_host}:{port}");
    }
    Ok(addrs)
}

fn format_socket_addrs(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use tokio::io::{AsyncWriteExt, BufReader};

    use super::{
        connect_quic_data_plane_any_with_timeout, connect_quic_data_plane_with_timeout,
        quic_data_plane_attempt_timeout, read_quic_helper_bootstrap, resolve_quic_helper_addrs,
        QUIC_AGENT_BOOTSTRAP_ROLE, QUIC_NATIVE_BOOTSTRAP_ROLE,
    };
    use crate::quic_agent::QuicAgentBootstrap;

    fn test_bootstrap(port: u16) -> QuicAgentBootstrap {
        QuicAgentBootstrap {
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

    #[test]
    fn resolve_quic_helper_addrs_preserves_loopback_port() {
        let addrs = resolve_quic_helper_addrs("quic-native", "127.0.0.1", 4433)
            .expect("loopback should resolve");

        assert_eq!(
            addrs,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4433
            )]
        );
    }

    #[tokio::test]
    async fn quic_data_plane_any_tries_later_resolved_address() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 4433);
        let attempts = Arc::new(Mutex::new(Vec::new()));

        let connected = connect_quic_data_plane_any_with_timeout(
            "quic-native",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().expect("attempts lock").push(remote_addr);
                    if remote_addr == first {
                        Err(anyhow!("first address failed"))
                    } else {
                        Ok(remote_addr)
                    }
                }
            },
        )
        .await
        .expect("second address should connect");

        assert_eq!(connected, second);
        assert_eq!(
            *attempts.lock().expect("attempts lock"),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn quic_data_plane_any_reports_all_resolved_addresses() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 4434);

        let err = connect_quic_data_plane_any_with_timeout(
            "quic-agent",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| async move { Err::<(), _>(anyhow!("failed {remote_addr}")) },
        )
        .await
        .expect_err("all addresses should fail");
        let detail = format!("{err:#}");

        assert!(detail
            .contains("quic-agent: failed to establish UDP data plane to any resolved address"));
        assert!(detail.contains("tried=[203.0.113.1:4433,203.0.113.2:4434]"));
        assert!(detail.contains("failed 203.0.113.1:4433"));
        assert!(detail.contains("failed 203.0.113.2:4434"));
    }

    #[test]
    fn quic_data_plane_attempt_timeout_splits_total_budget() {
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_secs(8), 1),
            Duration::from_secs(8)
        );
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_secs(8), 2),
            Duration::from_secs(4)
        );
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_millis(1), 4),
            Duration::from_millis(1)
        );
    }

    #[tokio::test]
    async fn quic_data_plane_success_stops_fallback_before_protocol_negotiation() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 4433);
        let attempts = Arc::new(Mutex::new(Vec::new()));

        let connected = connect_quic_data_plane_any_with_timeout(
            "quic-agent",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().expect("attempts lock").push(remote_addr);
                    Ok(remote_addr)
                }
            },
        )
        .await
        .expect("first authenticated address should stop fallback");

        assert_eq!(connected, first);
        assert_eq!(*attempts.lock().expect("attempts lock"), vec![first]);
    }

    #[tokio::test]
    async fn quic_data_plane_error_context_explains_udp_reachability() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4433);
        let err = connect_quic_data_plane_with_timeout(
            "quic-native",
            remote,
            Duration::from_secs(1),
            async { Err::<(), _>(anyhow!("handshake failed")) },
        )
        .await
        .expect_err("expected wrapped QUIC data-plane error");
        let detail = format!("{err:#}");

        assert!(detail.contains("quic-native: failed to establish UDP data plane"));
        assert!(detail.contains("203.0.113.7:4433"));
        assert!(detail.contains("after SSH bootstrap"));
        assert!(detail.contains("inbound UDP to the helper port may be blocked"));
        assert!(detail.contains("handshake failed"));
    }

    #[tokio::test]
    async fn quic_data_plane_timeout_context_explains_udp_reachability() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 4444);
        let err = connect_quic_data_plane_with_timeout(
            "quic-agent",
            remote,
            Duration::from_millis(1),
            future::pending::<Result<()>>(),
        )
        .await
        .expect_err("expected QUIC data-plane timeout");
        let detail = format!("{err:#}");

        assert!(detail.contains("quic-agent: timed out after 1ms"));
        assert!(detail.contains("198.51.100.9:4444"));
        assert!(detail.contains("after SSH bootstrap"));
        assert!(detail.contains("advertised address may be unreachable"));
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
