use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge, ReconnectingAgentBridge,
};
use crate::bridge_runtime::{BridgeRuntime, DnsTransport};
use crate::remote_helper::{bootstrap_helper, HelperCommandPlan, HelperKind};
use crate::ssh_control::{
    connect_prepared_ssh, connect_ssh_pool, prepare_ssh_connection, resolve_agent_session_count,
    Client, PreparedSshConnection,
};
use crate::transport_model::{BridgeRuntimeOptions, BridgeTransportKind, Destination};
use crate::{agent_proto, agent_transport, quic_agent, quic_agent_runtime, SshArgs};

mod agent_startup;

pub(crate) use agent_startup::{
    connect_agent_bridge_transports_from_connector,
    connect_auto_agent_bridge_transports_from_connector, should_fast_start_agent_lanes,
};

const AGENT_FAST_START_WARMUP_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
const QUIC_AGENT_BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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
        connect_helper_with_upload_fallback(
            &self.helper_plan,
            connect_agent_bridge_transport_fresh_prepared_ssh_command(
                &self.prepared,
                &self.helper_plan.command,
                self.mtu,
            ),
            || {
                connect_uploaded_agent_bridge_transport_prepared(
                    &self.prepared,
                    &self.helper_plan,
                    self.mtu,
                )
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

pub(crate) struct SshQuicAgentBridgeConnector {
    prepared: Arc<PreparedSshConnection>,
    helper_plan: HelperCommandPlan,
    mtu: u16,
}

impl SshQuicAgentBridgeConnector {
    pub(crate) fn new(ssh: SshArgs, helper_plan: HelperCommandPlan, mtu: u16) -> Result<Self> {
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
    let client = quic_agent_runtime::connect_quic_agent(remote_addr, &bootstrap, mtu).await?;
    let (transport, session) = client.into_transport_and_session();

    Ok(AgentBridgeTransport::quic(
        handle,
        session,
        drain_task,
        transport,
        agent_command,
    ))
}

async fn connect_quic_native_bridge_fresh_ssh_command(
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
    let client = quic_agent::connect_quic_bridge(remote_addr, &bootstrap).await?;

    Ok(QuicNativeBridge::with_ssh_carrier(
        client, handle, drain_task,
    ))
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

async fn connect_helper_with_upload_fallback<T, PrimaryFut, UploadFn, UploadFut>(
    helper_plan: &HelperCommandPlan,
    primary: PrimaryFut,
    upload: UploadFn,
    helper_name: &str,
    upload_success_log: Option<&str>,
) -> Result<T>
where
    PrimaryFut: Future<Output = Result<T>>,
    UploadFn: FnOnce() -> UploadFut,
    UploadFut: Future<Output = Result<T>>,
{
    match primary.await {
        Ok(started) => Ok(started),
        Err(initial_err) => {
            if !helper_plan.allows_upload_fallback() {
                return Err(initial_err).with_context(|| {
                    format!(
                        "failed to start {helper_name} via explicit command: {}",
                        helper_plan.command
                    )
                });
            }

            let initial_err_detail = format!("{initial_err:#}");
            eprintln!(
                "{}: remote command failed ({initial_err_detail}); trying upload bootstrap",
                helper_plan.kind.controller_log_prefix()
            );
            match upload().await {
                Ok(started) => {
                    if let Some(message) = upload_success_log {
                        eprintln!("{message}");
                    }
                    Ok(started)
                }
                Err(bootstrap_err) => Err(bootstrap_err).with_context(|| {
                    format!(
                        "failed to start {helper_name} via command ({initial_err_detail}) or upload bootstrap"
                    )
                }),
            }
        }
    }
}

async fn connect_uploaded_agent_bridge_transport_prepared(
    prepared: &PreparedSshConnection,
    helper_plan: &HelperCommandPlan,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    connect_uploaded_stdio_agent_bridge_transport_prepared(prepared, helper_plan, mtu)
        .await
        .map(|(transport, _)| transport)
}

async fn connect_uploaded_stdio_agent_bridge_transport_prepared(
    prepared: &PreparedSshConnection,
    helper_plan: &HelperCommandPlan,
    mtu: u16,
) -> Result<(AgentBridgeTransport, String)> {
    let kind = HelperKind::StdioAgent;
    ensure_helper_plan_kind(helper_plan, kind)?;
    let started = bootstrap_helper(prepared, helper_plan).await?;
    let transport =
        connect_agent_bridge_transport_on_handle(started.handle, &started.helper.command, mtu)
            .await
            .with_context(|| kind.uploaded_start_context(&started.helper.remote_path))?;
    Ok((transport, started.helper.command))
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

fn ensure_helper_plan_kind(plan: &HelperCommandPlan, expected: HelperKind) -> Result<()> {
    if plan.kind != expected {
        bail!(
            "helper startup plan kind mismatch: expected {:?}, got {:?}",
            expected,
            plan.kind
        );
    }
    Ok(())
}

pub(crate) async fn connect_bridge_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: HelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: BridgeRuntimeOptions,
) -> Result<(BridgeRuntime, DnsTransport)> {
    match requested {
        BridgeTransportKind::DirectTcpip => {
            let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
            Ok((
                BridgeRuntime::DirectTcpip(ssh.clone()),
                DnsTransport::DirectTcpip(ssh),
            ))
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
            let dns_transport = DnsTransport::Agent(agent.clone());
            Ok((BridgeRuntime::Agent(agent), dns_transport))
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
            let dns_transport = DnsTransport::Agent(agent.clone());
            Ok((BridgeRuntime::Agent(agent), dns_transport))
        }
        BridgeTransportKind::QuicNative => {
            let bridge = connect_quic_native_bridge_fresh_ssh_command(ssh, &helper_plan).await?;
            Ok((
                BridgeRuntime::QuicNative(bridge.clone()),
                DnsTransport::QuicNative(bridge),
            ))
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
                        return Ok((
                            BridgeRuntime::DirectTcpip(ssh.clone()),
                            DnsTransport::DirectTcpip(ssh),
                        ));
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
                    let dns_transport = DnsTransport::Agent(agent.clone());
                    Ok((BridgeRuntime::Agent(agent), dns_transport))
                }
                Err(err) => {
                    eprintln!(
                        "transport: auto could not start agent ({err:#}); falling back to direct-tcpip"
                    );
                    let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
                    Ok((
                        BridgeRuntime::DirectTcpip(ssh.clone()),
                        DnsTransport::DirectTcpip(ssh),
                    ))
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
