use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport,
};
use crate::remote_helper::{HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::{agent_transport, SshArgs};

use super::{
    connect_agent_bridge_transports_from_connector, connect_prepared_helper_with_upload_fallback,
};

const AGENT_TRANSPORT_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct SshAgentBridgeConnector {
    prepared: Arc<PreparedSshConnection>,
    helper_plan: HelperCommandPlan,
    mtu: u16,
}

impl SshAgentBridgeConnector {
    pub(crate) fn new(ssh: SshArgs, helper_plan: HelperCommandPlan, mtu: u16) -> Result<Self> {
        Ok(Self {
            prepared: Arc::new(prepare_ssh_connection(&ssh)?),
            helper_plan,
            mtu,
        })
    }

    async fn connect_primary_transport(&self) -> Result<AgentBridgeTransport> {
        let mtu = self.mtu;
        connect_prepared_helper_with_upload_fallback(
            &self.prepared,
            &self.helper_plan,
            HelperKind::StdioAgent,
            move |handle, command| async move {
                connect_agent_bridge_transport_on_handle(handle, &command, mtu).await
            },
            move |handle, command| async move {
                connect_agent_bridge_transport_on_handle(handle, &command, mtu).await
            },
            "Rustle agent",
            Some("agent: bootstrapped remote agent from local binary"),
        )
        .await
    }
}

impl AgentBridgeConnector for SshAgentBridgeConnector {
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
            connect_agent_bridge_transport_fresh_prepared_ssh_command(
                &self.prepared,
                agent_command,
                self.mtu,
            )
            .await
        })
    }
}

async fn connect_agent_bridge_transport_fresh_prepared_ssh_command(
    prepared: &PreparedSshConnection,
    agent_command: &str,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    // A Rustle agent lane is deliberately a fresh SSH connection with one exec
    // channel, not another channel multiplexed over an existing SSH carrier.
    let handle = connect_prepared_ssh(prepared).await?;
    connect_agent_bridge_transport_on_handle(handle, agent_command, mtu).await
}

async fn connect_agent_bridge_transport_on_handle(
    handle: Handle<Client>,
    agent_command: &str,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    let channel = handle
        .channel_open_session()
        .await
        .context("failed to open SSH session channel for Rustle agent")?;
    channel
        .exec(true, agent_command.to_owned())
        .await
        .with_context(|| format!("failed to exec remote Rustle agent: {agent_command}"))?;

    let stream = channel.into_stream();
    let (reader, writer) = tokio::io::split(stream);
    let transport = negotiate_agent_transport(reader, writer, mtu).await?;

    Ok(AgentBridgeTransport::ssh(handle, transport, agent_command))
}

async fn negotiate_agent_transport<R, W>(
    reader: R,
    writer: W,
    mtu: u16,
) -> Result<agent_transport::AgentTransport>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    negotiate_agent_transport_with_timeout(reader, writer, mtu, AGENT_TRANSPORT_NEGOTIATION_TIMEOUT)
        .await
}

async fn negotiate_agent_transport_with_timeout<R, W>(
    reader: R,
    writer: W,
    mtu: u16,
    timeout: Duration,
) -> Result<agent_transport::AgentTransport>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let transport = tokio::time::timeout(
        timeout,
        agent_transport::AgentTransport::connect(reader, writer, mtu),
    )
    .await
    .with_context(|| {
        format!(
            "timed out after {}ms negotiating Rustle agent protocol over SSH",
            timeout.as_millis()
        )
    })?
    .context("failed to negotiate Rustle agent protocol over SSH")?;
    if transport.peer_hello().max_frame_payload == 0 {
        bail!("remote Rustle agent advertised a zero max frame payload");
    }

    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_transport_negotiation_times_out_without_remote_hello() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client_io);

        let err = negotiate_agent_transport_with_timeout(
            reader,
            writer,
            crate::defaults::DEFAULT_MTU,
            Duration::from_millis(10),
        )
        .await
        .expect_err("hung agent negotiation should time out");
        let detail = format!("{err:#}");

        assert!(detail.contains("timed out after 10ms negotiating Rustle agent protocol over SSH"));
    }
}
