use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use russh::client::Handle;

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, ReconnectingAgentBridge,
};
use crate::data_plane::{
    DataPlane, DirectTcpipDataPlane, FramedAgentDataPlane, QuicNativeDataPlane,
};
use crate::remote_helper::{HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, connect_ssh_pool, prepare_ssh_connection, Client, PreparedSshConnection,
};
use crate::transport_model::{BridgeTransportKind, Destination, TunnelRuntimeOptions};
use crate::{agent_proto, agent_transport, SshArgs};

mod agent_startup;
mod helper_startup;
mod quic_startup;

pub(crate) use agent_startup::{
    connect_agent_bridge_transports_from_connector,
    connect_auto_agent_bridge_transports_from_connector, resolve_agent_session_count,
    should_fast_start_agent_lanes, validate_agent_session_request_count,
};
use helper_startup::connect_prepared_helper_with_upload_fallback;
use quic_startup::{connect_quic_native_bridge_fresh_ssh_command, SshQuicAgentBridgeConnector};

const AGENT_FAST_START_WARMUP_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

pub(crate) struct TunnelRuntime {
    data_plane: Arc<dyn DataPlane>,
}

impl TunnelRuntime {
    fn new<D>(data_plane: D) -> Self
    where
        D: DataPlane + 'static,
    {
        Self {
            data_plane: Arc::new(data_plane),
        }
    }

    pub(crate) fn data_plane(&self) -> Arc<dyn DataPlane> {
        Arc::clone(&self.data_plane)
    }
}

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
    let transport = agent_transport::AgentTransport::connect(reader, writer, mtu)
        .await
        .context("failed to negotiate Rustle agent protocol over SSH")?;
    if transport.peer_hello().max_frame_payload == 0 {
        bail!("remote Rustle agent advertised a zero max frame payload");
    }

    Ok(AgentBridgeTransport::ssh(handle, transport, agent_command))
}

pub(crate) async fn connect_tunnel_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: HelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    match requested {
        BridgeTransportKind::DirectTcpip => {
            let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
            Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)))
        }
        BridgeTransportKind::Agent => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> =
                Arc::new(SshAgentBridgeConnector::new(ssh.clone(), helper_plan, mtu)?);
            let fast_start_agent_lanes = should_fast_start_agent_lanes(
                options.fast_start_auto_agent_lanes,
                options.agent_sessions,
                desired_agent_sessions,
            );
            let agent = if fast_start_agent_lanes {
                connect_auto_agent_bridge_transports_from_connector(
                    connector.as_ref(),
                    desired_agent_sessions,
                )
                .await?
            } else {
                connector.connect_initial(desired_agent_sessions).await?
            };
            ensure_agent_dns_remote_supported(&agent, dns_remote)?;
            let agent = if fast_start_agent_lanes {
                ReconnectingAgentBridge::new_with_desired_lanes_and_missing_repair_delay(
                    connector,
                    agent,
                    desired_agent_sessions,
                    Some(AGENT_FAST_START_WARMUP_DELAY),
                )
            } else {
                ReconnectingAgentBridge::new_with_desired_lanes(
                    connector,
                    agent,
                    desired_agent_sessions,
                )
            };
            Ok(TunnelRuntime::new(FramedAgentDataPlane::new(agent)))
        }
        BridgeTransportKind::QuicAgent => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> = Arc::new(
                SshQuicAgentBridgeConnector::new(ssh.clone(), helper_plan, mtu)?,
            );
            let agent = connector.connect_initial(desired_agent_sessions).await?;
            ensure_agent_dns_remote_supported(&agent, dns_remote)?;
            let agent = ReconnectingAgentBridge::new_with_desired_lanes(
                connector,
                agent,
                desired_agent_sessions,
            );
            Ok(TunnelRuntime::new(FramedAgentDataPlane::new(agent)))
        }
        BridgeTransportKind::QuicNative => {
            let bridge = connect_quic_native_bridge_fresh_ssh_command(ssh, &helper_plan).await?;
            Ok(TunnelRuntime::new(QuicNativeDataPlane::new(bridge)))
        }
        BridgeTransportKind::Auto => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> =
                Arc::new(SshAgentBridgeConnector::new(ssh.clone(), helper_plan, mtu)?);
            let fast_start_agent_lanes = should_fast_start_agent_lanes(
                options.fast_start_auto_agent_lanes,
                options.agent_sessions,
                desired_agent_sessions,
            );
            let agent_result = if fast_start_agent_lanes {
                connect_auto_agent_bridge_transports_from_connector(
                    connector.as_ref(),
                    desired_agent_sessions,
                )
                .await
            } else {
                connector.connect_initial(desired_agent_sessions).await
            };
            match agent_result {
                Ok(agent) => {
                    if let Err(err) = ensure_agent_dns_remote_supported(&agent, dns_remote) {
                        eprintln!(
                            "transport: auto selected direct-tcpip because the agent cannot support the configured DNS resolver ({err:#})"
                        );
                        let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
                        return Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)));
                    }
                    eprintln!("transport: auto selected agent");
                    let agent = if fast_start_agent_lanes {
                        ReconnectingAgentBridge::new_with_desired_lanes_and_missing_repair_delay(
                            connector,
                            agent,
                            desired_agent_sessions,
                            Some(AGENT_FAST_START_WARMUP_DELAY),
                        )
                    } else {
                        ReconnectingAgentBridge::new_with_desired_lanes(
                            connector,
                            agent,
                            desired_agent_sessions,
                        )
                    };
                    Ok(TunnelRuntime::new(FramedAgentDataPlane::new(agent)))
                }
                Err(err) => {
                    eprintln!(
                        "transport: auto could not start agent ({err:#}); falling back to direct-tcpip"
                    );
                    let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
                    Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)))
                }
            }
        }
    }
}

fn ensure_agent_dns_remote_supported(
    transports: &[AgentBridgeTransport],
    remote: Option<&Destination>,
) -> Result<()> {
    let Some(remote) = remote else {
        return Ok(());
    };
    if remote.host.parse::<Ipv4Addr>().is_ok() {
        if transports
            .iter()
            .all(|transport| transport.peer_capabilities() & agent_proto::CAP_UDP_ASSOCIATE != 0)
        {
            return Ok(());
        }
        bail!(
            "agent DNS transport to IPv4 resolver {} requires UDP associate support",
            remote.host
        );
    }
    if transports
        .iter()
        .all(|transport| transport.peer_capabilities() & agent_proto::CAP_TCP_CONNECT_HOST != 0)
    {
        return Ok(());
    }
    bail!(
        "agent DNS transport to hostname {} requires hostname TCP connect support",
        remote.host
    )
}
