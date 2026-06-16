use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge,
};
use crate::remote_helper::{bootstrap_helper, HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::{quic_agent, quic_agent_runtime, SshArgs};

use super::{
    connect_agent_bridge_transports_from_connector, connect_helper_with_upload_fallback,
    ensure_helper_plan_kind,
};

const QUIC_AGENT_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);
const QUIC_DATA_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

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
        connect_helper_with_upload_fallback(
            &self.helper_plan,
            connect_quic_agent_bridge_transport_fresh_prepared_ssh_command(
                &self.prepared,
                &self.helper_plan.command,
                self.mtu,
            ),
            || {
                connect_uploaded_quic_agent_bridge_transport_prepared(
                    &self.prepared,
                    &self.helper_plan,
                    self.mtu,
                )
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
    let channel = handle
        .channel_open_session()
        .await
        .context("failed to open SSH session channel for Rustle QUIC agent")?;
    channel
        .exec(true, agent_command.to_owned())
        .await
        .with_context(|| format!("failed to exec remote Rustle QUIC agent: {agent_command}"))?;

    let mut reader = BufReader::new(channel.into_stream());
    let mut line = String::new();
    let read = tokio::time::timeout(QUIC_AGENT_BOOTSTRAP_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("timed out waiting for QUIC agent bootstrap line")?
        .context("failed to read QUIC agent bootstrap line")?;
    if read == 0 {
        bail!("remote QUIC agent exited before writing its bootstrap line");
    }
    let bootstrap = quic_agent::QuicAgentBootstrap::decode_line(&line)
        .context("invalid QUIC agent bootstrap line")?;
    let remote_addr = resolve_quic_agent_addr(remote_host, bootstrap.port)?;
    eprintln!(
        "quic-agent: connecting UDP data plane to {remote_addr} cert_sha256={}",
        bootstrap.cert_sha256
    );

    let drain_task = tokio::spawn(drain_quic_agent_ssh_output(reader));
    let client = connect_quic_data_plane(
        "quic-agent",
        remote_addr,
        quic_agent_runtime::connect_quic_agent(remote_addr, &bootstrap, mtu),
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
    let handle = connect_prepared_ssh(&prepared).await?;
    connect_helper_with_upload_fallback(
        helper_plan,
        connect_quic_native_bridge_on_handle(handle, prepared.remote_host(), &helper_plan.command),
        || connect_uploaded_quic_native_bridge_prepared(&prepared, helper_plan),
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
    let channel = handle
        .channel_open_session()
        .await
        .context("failed to open SSH session channel for native QUIC bridge helper")?;
    channel
        .exec(true, agent_command.to_owned())
        .await
        .with_context(|| {
            format!("failed to exec remote native QUIC bridge helper: {agent_command}")
        })?;

    let mut reader = BufReader::new(channel.into_stream());
    let mut line = String::new();
    let read = tokio::time::timeout(QUIC_AGENT_BOOTSTRAP_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("timed out waiting for native QUIC bridge bootstrap line")?
        .context("failed to read native QUIC bridge bootstrap line")?;
    if read == 0 {
        bail!("remote native QUIC bridge helper exited before writing its bootstrap line");
    }
    let bootstrap = quic_agent::QuicAgentBootstrap::decode_bridge_line(&line)
        .context("invalid native QUIC bridge bootstrap line")?;
    let remote_addr = resolve_quic_agent_addr(remote_host, bootstrap.port)?;
    eprintln!(
        "quic-native: connecting UDP data plane to {remote_addr} cert_sha256={}",
        bootstrap.cert_sha256
    );

    let drain_task = tokio::spawn(drain_quic_agent_ssh_output(reader));
    let client = connect_quic_data_plane(
        "quic-native",
        remote_addr,
        quic_agent::connect_quic_bridge(remote_addr, &bootstrap),
    )
    .await?;

    Ok(QuicNativeBridge::with_ssh_carrier(
        client, handle, drain_task,
    ))
}

async fn connect_uploaded_quic_agent_bridge_transport_prepared(
    prepared: &PreparedSshConnection,
    helper_plan: &HelperCommandPlan,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    let kind = HelperKind::QuicAgent;
    ensure_helper_plan_kind(helper_plan, kind)?;
    let started = bootstrap_helper(prepared, helper_plan).await?;
    connect_quic_agent_bridge_transport_on_handle(
        started.handle,
        prepared.remote_host(),
        &started.helper.command,
        mtu,
    )
    .await
    .with_context(|| kind.uploaded_start_context(&started.helper.remote_path))
}

async fn connect_uploaded_quic_native_bridge_prepared(
    prepared: &PreparedSshConnection,
    helper_plan: &HelperCommandPlan,
) -> Result<QuicNativeBridge> {
    let kind = HelperKind::QuicBridgeNative;
    ensure_helper_plan_kind(helper_plan, kind)?;
    let started = bootstrap_helper(prepared, helper_plan).await?;
    connect_quic_native_bridge_on_handle(
        started.handle,
        prepared.remote_host(),
        &started.helper.command,
    )
    .await
    .with_context(|| kind.uploaded_start_context(&started.helper.remote_path))
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

async fn drain_quic_agent_ssh_output<R>(mut reader: BufReader<R>)
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
                    eprintln!("quic-agent: remote output: {line}");
                }
            }
            Err(err) => {
                eprintln!("quic-agent: failed to drain remote output: {err:#}");
                break;
            }
        }
    }
}

fn resolve_quic_agent_addr(remote_host: &str, port: u16) -> Result<SocketAddr> {
    (remote_host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve QUIC agent address for {remote_host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no socket addresses found for QUIC agent {remote_host}:{port}"))
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use anyhow::{anyhow, Result};

    use super::{connect_quic_data_plane_with_timeout, resolve_quic_agent_addr};

    #[test]
    fn resolve_quic_agent_addr_preserves_loopback_port() {
        let addr = resolve_quic_agent_addr("127.0.0.1", 4433).expect("loopback should resolve");

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
}
