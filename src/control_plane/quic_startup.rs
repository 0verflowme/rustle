use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::{
    client::{Handle, Msg},
    ChannelStream,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge,
};
use crate::remote_helper::{HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::{quic_agent, quic_agent_runtime, SshArgs};

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
    remote_addr: SocketAddr,
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
    let client = connect_quic_data_plane(
        QUIC_AGENT_BOOTSTRAP_ROLE.label,
        started.remote_addr,
        quic_agent_runtime::connect_quic_agent(started.remote_addr, &started.bootstrap, mtu),
    )
    .await?;
    let (transport, session) = client.into_transport_and_session();

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
    let client = connect_quic_data_plane(
        QUIC_NATIVE_BOOTSTRAP_ROLE.label,
        started.remote_addr,
        quic_agent::connect_quic_bridge(started.remote_addr, &started.bootstrap),
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
    let remote_addr = resolve_quic_helper_addr(role.label, remote_host, bootstrap.port)?;
    eprintln!(
        "{} to {remote_addr} cert_sha256={}",
        role.connect_log_prefix, bootstrap.cert_sha256
    );

    Ok(StartedQuicHelperSsh {
        bootstrap,
        remote_addr,
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

async fn connect_quic_data_plane<T, F>(
    label: &'static str,
    remote_addr: SocketAddr,
    future: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    connect_quic_data_plane_with_timeout(
        label,
        remote_addr,
        QUIC_DATA_PLANE_CONNECT_TIMEOUT,
        future,
    )
    .await
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

fn resolve_quic_helper_addr(
    label: &'static str,
    remote_host: &str,
    port: u16,
) -> Result<SocketAddr> {
    (remote_host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {label} address for {remote_host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no socket addresses found for {label} {remote_host}:{port}"))
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use tokio::io::{AsyncWriteExt, BufReader};

    use super::{
        connect_quic_data_plane_with_timeout, read_quic_helper_bootstrap, resolve_quic_helper_addr,
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
    fn resolve_quic_helper_addr_preserves_loopback_port() {
        let addr = resolve_quic_helper_addr("quic-native", "127.0.0.1", 4433)
            .expect("loopback should resolve");

        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4433)
        );
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
