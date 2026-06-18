use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge,
};
use crate::agent_transport::AgentTransport;
use crate::remote_helper::{
    connect_prepared_helper_with_upload_fallback, HelperCommandPlan, HelperKind,
    QUIC_AGENT_BOOTSTRAP_ROLE, QUIC_NATIVE_BOOTSTRAP_ROLE,
};
use crate::ssh_control::{
    connect_prepared_ssh, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::{quic_agent, SshArgs};

use super::connect_agent_bridge_transports_from_connector;
use super::quic_bootstrap::{drain_quic_helper_ssh_output, start_quic_helper_ssh_bootstrap};
use super::quic_connect::{
    connect_quic_data_plane_any, connect_quic_data_plane_any_with_timeout, format_socket_addrs,
};

const QUIC_AGENT_PROTOCOL_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);

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
    let (recv, send, session) = match connect_quic_data_plane_any(
        QUIC_AGENT_BOOTSTRAP_ROLE.label,
        &started.remote_addrs,
        |remote_addr| quic_agent::connect_quic_agent_stream(remote_addr, &started.bootstrap),
    )
    .await
    {
        Ok(connected) => connected,
        Err(err) => {
            cleanup_failed_quic_helper_startup(
                QUIC_AGENT_BOOTSTRAP_ROLE.label,
                &handle,
                drain_task,
                "quic agent data-plane connect failed",
            )
            .await;
            return Err(err);
        }
    };
    let remote_addrs = format_socket_addrs(&started.remote_addrs);
    let transport = match negotiate_quic_agent_transport(recv, send, mtu, &remote_addrs).await {
        Ok(transport) => transport,
        Err(err) => {
            session.close(0, b"quic agent protocol negotiation failed");
            cleanup_failed_quic_helper_startup(
                QUIC_AGENT_BOOTSTRAP_ROLE.label,
                &handle,
                drain_task,
                "quic agent protocol negotiation failed",
            )
            .await;
            return Err(err);
        }
    };

    Ok(AgentBridgeTransport::quic(
        handle,
        session,
        drain_task,
        transport,
        agent_command,
    ))
}

async fn negotiate_quic_agent_transport<R, W>(
    reader: R,
    writer: W,
    mtu: u16,
    remote: &str,
) -> Result<AgentTransport>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    negotiate_quic_agent_transport_with_timeout(
        reader,
        writer,
        mtu,
        remote,
        QUIC_AGENT_PROTOCOL_NEGOTIATION_TIMEOUT,
    )
    .await
}

async fn negotiate_quic_agent_transport_with_timeout<R, W>(
    reader: R,
    writer: W,
    mtu: u16,
    remote: &str,
    timeout: Duration,
) -> Result<AgentTransport>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let started_at = Instant::now();
    log_quic_agent_protocol_stage(remote, "agent_hello", "start", started_at, timeout, mtu);
    match tokio::time::timeout(timeout, AgentTransport::connect(reader, writer, mtu)).await {
        Ok(Ok(transport)) => {
            log_quic_agent_protocol_stage(remote, "agent_hello", "ok", started_at, timeout, mtu);
            Ok(transport)
        }
        Ok(Err(err)) => {
            log_quic_agent_protocol_stage(remote, "agent_hello", "error", started_at, timeout, mtu);
            Err(err).context(
                "failed to negotiate Rustle agent protocol over QUIC after successful QUIC auth",
            )
        }
        Err(_) => {
            log_quic_agent_protocol_stage(
                remote,
                "agent_hello",
                "timeout",
                started_at,
                timeout,
                mtu,
            );
            bail!(
                "timed out after {}ms negotiating Rustle agent protocol over QUIC after successful QUIC auth",
                timeout.as_millis()
            )
        }
    }
}

fn log_quic_agent_protocol_stage(
    remote: &str,
    stage: &'static str,
    result: &'static str,
    started_at: Instant,
    timeout: Duration,
    mtu: u16,
) {
    eprintln!(
        "quic-agent-protocol: transport=quic-agent remote={remote} stage={stage} result={result} elapsed_ms={} timeout_ms={} mtu={mtu}",
        started_at.elapsed().as_millis(),
        timeout.as_millis()
    );
}

pub(super) async fn connect_quic_native_bridge_fresh_ssh_command(
    ssh: &SshArgs,
    helper_plan: &HelperCommandPlan,
) -> Result<QuicNativeBridge> {
    connect_quic_native_bridge_fresh_ssh_command_with_data_plane_timeout(ssh, helper_plan, None)
        .await
}

pub(super) async fn connect_quic_native_bridge_fresh_ssh_command_with_data_plane_timeout(
    ssh: &SshArgs,
    helper_plan: &HelperCommandPlan,
    data_plane_timeout: Option<Duration>,
) -> Result<QuicNativeBridge> {
    let prepared = prepare_ssh_connection(ssh)?;
    let primary_remote_host = prepared.remote_host().to_owned();
    let uploaded_remote_host = primary_remote_host.clone();
    connect_prepared_helper_with_upload_fallback(
        &prepared,
        helper_plan,
        HelperKind::QuicBridgeNative,
        move |handle, command| async move {
            connect_quic_native_bridge_on_handle(
                handle,
                &primary_remote_host,
                &command,
                data_plane_timeout,
            )
            .await
        },
        move |handle, command| async move {
            connect_quic_native_bridge_on_handle(
                handle,
                &uploaded_remote_host,
                &command,
                data_plane_timeout,
            )
            .await
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
    data_plane_timeout: Option<Duration>,
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
    let connect = |remote_addr| quic_agent::connect_quic_bridge(remote_addr, &started.bootstrap);
    let client = match match data_plane_timeout {
        Some(timeout) => {
            connect_quic_data_plane_any_with_timeout(
                QUIC_NATIVE_BOOTSTRAP_ROLE.label,
                &started.remote_addrs,
                timeout,
                connect,
            )
            .await
        }
        None => {
            connect_quic_data_plane_any(
                QUIC_NATIVE_BOOTSTRAP_ROLE.label,
                &started.remote_addrs,
                connect,
            )
            .await
        }
    } {
        Ok(client) => client,
        Err(err) => {
            cleanup_failed_quic_helper_startup(
                QUIC_NATIVE_BOOTSTRAP_ROLE.label,
                &handle,
                drain_task,
                "native quic data-plane connect failed",
            )
            .await;
            return Err(err);
        }
    };

    Ok(QuicNativeBridge::with_ssh_carrier(
        client, handle, drain_task,
    ))
}

async fn cleanup_failed_quic_helper_startup(
    label: &'static str,
    handle: &Handle<Client>,
    drain_task: JoinHandle<()>,
    reason: &str,
) {
    drain_task.abort();
    match drain_task.await {
        Ok(()) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) => eprintln!("{label}: SSH helper output task failed during cleanup: {err:#}"),
    }

    if let Err(err) = handle
        .disconnect(russh::Disconnect::ByApplication, reason, "en")
        .await
    {
        eprintln!("{label}: failed to disconnect SSH helper after failed startup: {err:#}");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::negotiate_quic_agent_transport_with_timeout;

    #[tokio::test]
    async fn quic_agent_transport_negotiation_times_out_without_remote_hello() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client_io);

        let err = negotiate_quic_agent_transport_with_timeout(
            reader,
            writer,
            crate::defaults::DEFAULT_MTU,
            "203.0.113.9:4433",
            Duration::from_millis(10),
        )
        .await
        .expect_err("hung QUIC agent negotiation should time out");
        let detail = format!("{err:#}");

        assert!(detail.contains(
            "timed out after 10ms negotiating Rustle agent protocol over QUIC after successful QUIC auth"
        ));
    }
}
