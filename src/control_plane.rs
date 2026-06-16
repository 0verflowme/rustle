use std::env;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::Handle;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::agent_bridge::{
    AgentBridgeConnectFuture, AgentBridgeConnectManyFuture, AgentBridgeConnector,
    AgentBridgeTransport, QuicNativeBridge, ReconnectingAgentBridge,
};
use crate::data_plane::{
    BridgeRuntime, BridgeRuntimeOptions, BridgeTransportKind, Destination, DnsTransport,
};
use crate::remote_helper::{
    local_agent_binary_for_platform, probe_remote_platform, upload_agent_binary,
    uploaded_agent_command, uploaded_helper_command,
};
use crate::ssh_control::{
    connect_prepared_ssh, connect_ssh, connect_ssh_pool, prepare_ssh_connection,
    resolve_agent_session_count, resolve_ssh_target, validate_agent_session_count, Client,
    PreparedSshConnection, AUTO_AGENT_SESSIONS,
};
use crate::{agent_proto, agent_transport, quic_agent, SshArgs};

const AGENT_FAST_START_WARMUP_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
const AGENT_INITIAL_CONNECT_BATCH: usize = 4;
const AGENT_INITIAL_CONNECT_RETRY_ROUNDS: usize = 1;
const QUIC_AGENT_BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct SshAgentBridgeConnector {
    prepared: Arc<PreparedSshConnection>,
    agent_command: String,
    mtu: u16,
}

impl SshAgentBridgeConnector {
    pub(crate) fn new(ssh: SshArgs, agent_command: String, mtu: u16) -> Result<Self> {
        Ok(Self {
            prepared: Arc::new(prepare_ssh_connection(&ssh)?),
            agent_command,
            mtu,
        })
    }

    async fn connect_primary_transport(&self) -> Result<AgentBridgeTransport> {
        match connect_agent_bridge_transport_fresh_prepared_ssh_command(
            &self.prepared,
            &self.agent_command,
            self.mtu,
        )
        .await
        {
            Ok(agent) => Ok(agent),
            Err(initial_err) => {
                eprintln!(
                    "agent: remote command failed ({initial_err:#}); trying upload bootstrap"
                );
                match connect_uploaded_agent_bridge_transport_prepared(&self.prepared, self.mtu)
                    .await
                {
                    Ok(agent) => {
                        eprintln!("agent: bootstrapped remote agent from local binary");
                        Ok(agent)
                    }
                    Err(bootstrap_err) => Err(bootstrap_err).with_context(|| {
                        format!(
                            "failed to start Rustle agent via command ({initial_err:#}) or upload bootstrap"
                        )
                    }),
                }
            }
        }
    }
}

impl AgentBridgeConnector for SshAgentBridgeConnector {
    fn primary_command(&self) -> &str {
        &self.agent_command
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
    agent_command: String,
    mtu: u16,
}

impl SshQuicAgentBridgeConnector {
    pub(crate) fn new(ssh: SshArgs, agent_command: String, mtu: u16) -> Result<Self> {
        Ok(Self {
            prepared: Arc::new(prepare_ssh_connection(&ssh)?),
            agent_command,
            mtu,
        })
    }

    async fn connect_primary_transport(&self) -> Result<AgentBridgeTransport> {
        match connect_quic_agent_bridge_transport_fresh_prepared_ssh_command(
            &self.prepared,
            &self.agent_command,
            self.mtu,
        )
        .await
        {
            Ok(agent) => Ok(agent),
            Err(initial_err) => {
                eprintln!(
                    "quic-agent: remote command failed ({initial_err:#}); trying upload bootstrap"
                );
                match connect_uploaded_quic_agent_bridge_transport_prepared(
                    &self.prepared,
                    self.mtu,
                )
                .await
                {
                    Ok(agent) => {
                        eprintln!("quic-agent: bootstrapped remote helper from local binary");
                        Ok(agent)
                    }
                    Err(bootstrap_err) => Err(bootstrap_err).with_context(|| {
                        format!(
                            "failed to start Rustle QUIC agent via command ({initial_err:#}) or upload bootstrap"
                        )
                    }),
                }
            }
        }
    }
}

impl AgentBridgeConnector for SshQuicAgentBridgeConnector {
    fn primary_command(&self) -> &str {
        &self.agent_command
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

pub(crate) async fn connect_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;
    let mut transports = Vec::with_capacity(desired_sessions);

    let first = connector.connect_primary().await?;
    let additional_agent_command = first.agent_command().to_owned();
    transports.push(first);

    let mut index = 1;
    while index < desired_sessions {
        let batch = (desired_sessions - index).min(AGENT_INITIAL_CONNECT_BATCH);
        for (offset, result) in connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            batch,
        )
        .await
        .into_iter()
        .enumerate()
        {
            match result {
                Ok(transport) => transports.push(transport),
                Err(err) => {
                    eprintln!(
                        "agent: additional exec transport {}/{} failed: {err:#}; continuing with {} transport(s)",
                        index + offset + 1,
                        desired_sessions,
                        transports.len()
                    );
                }
            }
        }
        index += batch;
    }

    for retry_round in 1..=AGENT_INITIAL_CONNECT_RETRY_ROUNDS {
        let missing = desired_sessions.saturating_sub(transports.len());
        if missing == 0 {
            break;
        }
        eprintln!(
            "agent: retrying {missing} missing exec transport(s) after partial startup (round {retry_round}/{AGENT_INITIAL_CONNECT_RETRY_ROUNDS})"
        );
        for result in connect_additional_agent_bridge_transport_batch(
            connector,
            &additional_agent_command,
            missing.min(AGENT_INITIAL_CONNECT_BATCH),
        )
        .await
        {
            match result {
                Ok(transport) => transports.push(transport),
                Err(err) => {
                    eprintln!(
                        "agent: retry for missing exec transport failed: {err:#}; continuing with {} transport(s)",
                        transports.len()
                    );
                }
            }
        }
    }

    eprintln!(
        "{}",
        format_agent_established_message(transports.len(), desired_sessions)
    );
    Ok(transports)
}

pub(crate) async fn connect_auto_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;

    let first = connector.connect_primary().await?;
    eprintln!("{}", format_agent_fast_start_message(1, desired_sessions));
    Ok(vec![first])
}

pub(crate) fn format_agent_established_message(established: usize, desired: usize) -> String {
    format!("agent: established {established}/{desired} exec transport(s)")
}

pub(crate) fn format_agent_fast_start_message(established: usize, desired: usize) -> String {
    let message = format_agent_established_message(established, desired);
    let warming = desired.saturating_sub(established);
    if warming == 0 {
        message
    } else {
        format!("{message}; warming {warming} remaining exec transport(s) in background")
    }
}

pub(crate) fn should_fast_start_agent_lanes(
    fast_start_auto_lanes: bool,
    requested_sessions: usize,
    desired_sessions: usize,
) -> bool {
    fast_start_auto_lanes && requested_sessions == AUTO_AGENT_SESSIONS && desired_sessions > 1
}

async fn connect_additional_agent_bridge_transport_batch(
    connector: &dyn AgentBridgeConnector,
    agent_command: &str,
    batch: usize,
) -> Vec<Result<AgentBridgeTransport>> {
    match batch {
        0 => Vec::new(),
        1 => vec![connector.connect_command(agent_command).await],
        2 => {
            let (first, second) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second]
        }
        3 => {
            let (first, second, third) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second, third]
        }
        _ => {
            let (first, second, third, fourth) = tokio::join!(
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
                connector.connect_command(agent_command),
            );
            vec![first, second, third, fourth]
        }
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
    let client = quic_agent::connect_quic_agent(remote_addr, &bootstrap, mtu).await?;
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
    agent_command: &str,
) -> Result<QuicNativeBridge> {
    let target = resolve_ssh_target(ssh)?;
    let handle = connect_ssh(ssh).await?;
    match connect_quic_native_bridge_on_handle(handle, &target.host, agent_command).await {
        Ok(bridge) => Ok(bridge),
        Err(initial_err) => {
            eprintln!(
                "quic-native: remote command failed ({initial_err:#}); trying upload bootstrap"
            );
            connect_uploaded_quic_native_bridge(ssh)
                .await
                .map_err(|bootstrap_err| {
                    bootstrap_err.context(format!(
                        "failed to start native QUIC bridge via command ({initial_err:#}) or upload bootstrap"
                    ))
                })
        }
    }
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

async fn connect_uploaded_agent_bridge_transport_prepared(
    prepared: &PreparedSshConnection,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    connect_uploaded_agent_bridge_transport_with_command_prepared(prepared, mtu, "agent")
        .await
        .map(|(transport, _)| transport)
}

async fn connect_uploaded_agent_bridge_transport_with_command_prepared(
    prepared: &PreparedSshConnection,
    mtu: u16,
    helper_subcommand: &str,
) -> Result<(AgentBridgeTransport, String)> {
    let handle = connect_prepared_ssh(prepared).await?;
    let platform = probe_remote_platform(&handle)
        .await
        .context("failed to determine remote platform for Rustle agent bootstrap")?;
    let current_exe = env::current_exe().context("failed to locate current Rustle executable")?;
    let local_agent = local_agent_binary_for_platform(&current_exe, platform)?;
    if local_agent != current_exe {
        eprintln!(
            "agent: using local {} agent sidecar {}",
            platform.label(),
            local_agent.display()
        );
    }
    let remote_path = upload_agent_binary(&handle, &local_agent, platform).await?;
    let agent_command = if helper_subcommand == "agent" {
        uploaded_agent_command(&remote_path, platform)
    } else {
        uploaded_helper_command(&remote_path, platform, helper_subcommand)
    };
    let transport = connect_agent_bridge_transport_on_handle(handle, &agent_command, mtu)
        .await
        .with_context(|| format!("uploaded Rustle agent failed to start from {remote_path}"))?;
    Ok((transport, agent_command))
}

async fn connect_uploaded_quic_agent_bridge_transport_prepared(
    prepared: &PreparedSshConnection,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    let handle = connect_prepared_ssh(prepared).await?;
    let platform = probe_remote_platform(&handle)
        .await
        .context("failed to determine remote platform for Rustle QUIC agent bootstrap")?;
    let current_exe = env::current_exe().context("failed to locate current Rustle executable")?;
    let local_agent = local_agent_binary_for_platform(&current_exe, platform)?;
    if local_agent != current_exe {
        eprintln!(
            "quic-agent: using local {} helper sidecar {}",
            platform.label(),
            local_agent.display()
        );
    }
    let remote_path = upload_agent_binary(&handle, &local_agent, platform).await?;
    let agent_command = uploaded_helper_command(&remote_path, platform, "quic-agent");
    connect_quic_agent_bridge_transport_on_handle(
        handle,
        prepared.remote_host(),
        &agent_command,
        mtu,
    )
    .await
    .with_context(|| format!("uploaded Rustle QUIC agent failed to start from {remote_path}"))
}

async fn connect_uploaded_quic_native_bridge(ssh: &SshArgs) -> Result<QuicNativeBridge> {
    let prepared = prepare_ssh_connection(ssh)?;
    let handle = connect_prepared_ssh(&prepared).await?;
    let platform = probe_remote_platform(&handle)
        .await
        .context("failed to determine remote platform for native QUIC bridge bootstrap")?;
    let current_exe = env::current_exe().context("failed to locate current Rustle executable")?;
    let local_agent = local_agent_binary_for_platform(&current_exe, platform)?;
    if local_agent != current_exe {
        eprintln!(
            "quic-native: using local {} helper sidecar {}",
            platform.label(),
            local_agent.display()
        );
    }
    let remote_path = upload_agent_binary(&handle, &local_agent, platform).await?;
    let agent_command = uploaded_helper_command(&remote_path, platform, "quic-bridge-agent");
    connect_quic_native_bridge_on_handle(handle, prepared.remote_host(), &agent_command)
        .await
        .with_context(|| {
            format!("uploaded native QUIC bridge helper failed to start from {remote_path}")
        })
}

pub(crate) async fn connect_bridge_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    agent_command: &str,
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
            let connector: Arc<dyn AgentBridgeConnector> = Arc::new(SshAgentBridgeConnector::new(
                ssh.clone(),
                agent_command.to_owned(),
                mtu,
            )?);
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
                SshQuicAgentBridgeConnector::new(ssh.clone(), agent_command.to_owned(), mtu)?,
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
            let bridge = connect_quic_native_bridge_fresh_ssh_command(ssh, agent_command).await?;
            Ok((
                BridgeRuntime::QuicNative(bridge.clone()),
                DnsTransport::QuicNative(bridge),
            ))
        }
        BridgeTransportKind::Auto => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> = Arc::new(SshAgentBridgeConnector::new(
                ssh.clone(),
                agent_command.to_owned(),
                mtu,
            )?);
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
