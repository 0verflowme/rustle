use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::agent_bridge::{AgentBridgeConnector, AgentBridgeTransport, ReconnectingAgentBridge};
use crate::data_plane::{
    DataPlane, DirectTcpipDataPlane, FramedAgentDataPlane, QuicNativeDataPlane,
};
use crate::remote_helper::HelperCommandPlan;
use crate::ssh_control::connect_ssh_pool;
use crate::transport_model::{BridgeTransportKind, Destination, TunnelRuntimeOptions};
use crate::{agent_proto, SshArgs};

use super::agent_policy::{resolve_agent_session_count, should_fast_start_agent_lanes};
use super::agent_startup::connect_auto_agent_bridge_transports_from_connector;
use super::helper_plan::BridgeHelperCommandPlan;
use super::quic_startup::{
    connect_quic_native_bridge_fresh_ssh_command,
    connect_quic_native_bridge_fresh_ssh_command_with_data_plane_timeout,
    SshQuicAgentBridgeConnector,
};
use super::ssh_agent_startup::SshAgentBridgeConnector;

const AGENT_FAST_START_WARMUP_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
const AUTO_QUIC_DATA_PLANE_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

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

pub(crate) async fn connect_tunnel_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: BridgeHelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    match requested {
        BridgeTransportKind::DirectTcpip => {
            connect_direct_tcpip_runtime(ssh, options.ssh_sessions).await
        }
        BridgeTransportKind::Agent => {
            connect_agent_runtime(ssh, requested, helper_plan, mtu, dns_remote, options).await
        }
        BridgeTransportKind::QuicAgent => {
            connect_quic_agent_runtime(ssh, requested, helper_plan, mtu, dns_remote, options).await
        }
        BridgeTransportKind::QuicNative => {
            connect_quic_native_runtime(ssh, requested, helper_plan).await
        }
        BridgeTransportKind::Auto => {
            connect_auto_runtime(ssh, requested, helper_plan, mtu, dns_remote, options).await
        }
        BridgeTransportKind::AutoQuic => {
            connect_auto_quic_runtime(ssh, helper_plan, mtu, dns_remote, options).await
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutoAgentRuntimeDecision {
    Agent,
    DirectTcpipFallback(AutoAgentFallbackReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutoAgentFallbackReason {
    AgentStartupFailed,
    DnsUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutoQuicProbeSelection {
    QuicNative,
    AgentFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentDnsCapabilityRequirement {
    UdpAssociateForIpv4,
    TcpConnectHostForHostname,
}

struct AutoQuicHelperPlans {
    agent: HelperCommandPlan,
    quic_native: HelperCommandPlan,
}

impl AutoQuicProbeSelection {
    fn result_label(self) -> &'static str {
        match self {
            Self::QuicNative => "quic-native",
            Self::AgentFallback => "agent-fallback",
        }
    }
}

async fn connect_direct_tcpip_runtime(ssh: &SshArgs, ssh_sessions: usize) -> Result<TunnelRuntime> {
    let ssh = connect_ssh_pool(ssh, ssh_sessions).await?;
    Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)))
}

async fn connect_agent_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: BridgeHelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    let helper_plan = single_helper_plan(helper_plan, requested)?;
    let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
    let connector = ssh_agent_connector(ssh, helper_plan, mtu)?;
    let fast_start_agent_lanes = auto_agent_fast_start_enabled(options, desired_agent_sessions);
    let data_plane = connect_framed_agent_data_plane(
        connector,
        desired_agent_sessions,
        fast_start_agent_lanes,
        dns_remote,
    )
    .await?;
    Ok(TunnelRuntime::new(data_plane))
}

async fn connect_quic_agent_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: BridgeHelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    let helper_plan = single_helper_plan(helper_plan, requested)?;
    let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
    let connector = ssh_quic_agent_connector(ssh, helper_plan, mtu)?;
    let data_plane =
        connect_framed_agent_data_plane(connector, desired_agent_sessions, false, dns_remote)
            .await?;
    Ok(TunnelRuntime::new(data_plane))
}

async fn connect_quic_native_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: BridgeHelperCommandPlan,
) -> Result<TunnelRuntime> {
    let helper_plan = single_helper_plan(helper_plan, requested)?;
    let bridge = connect_quic_native_bridge_fresh_ssh_command(ssh, &helper_plan).await?;
    Ok(TunnelRuntime::new(QuicNativeDataPlane::new(bridge)))
}

async fn connect_auto_runtime(
    ssh: &SshArgs,
    requested: BridgeTransportKind,
    helper_plan: BridgeHelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    let helper_plan = single_helper_plan(helper_plan, requested)?;
    let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
    let connector = ssh_agent_connector(ssh, helper_plan, mtu)?;
    let fast_start_agent_lanes = auto_agent_fast_start_enabled(options, desired_agent_sessions);
    let transports = match connect_initial_agent_transports(
        connector.as_ref(),
        desired_agent_sessions,
        fast_start_agent_lanes,
    )
    .await
    {
        Ok(transports) => transports,
        Err(err) => {
            let decision = decide_auto_agent_runtime(false, true);
            return connect_auto_agent_fallback_runtime(ssh, options.ssh_sessions, decision, err)
                .await;
        }
    };
    if let Err(err) = ensure_agent_dns_remote_supported(&transports, dns_remote) {
        let decision = decide_auto_agent_runtime(true, false);
        return connect_auto_agent_fallback_runtime(ssh, options.ssh_sessions, decision, err).await;
    }
    eprintln!("transport: auto selected agent");
    Ok(TunnelRuntime::new(framed_agent_data_plane_from_transports(
        connector,
        transports,
        desired_agent_sessions,
        fast_start_agent_lanes,
    )))
}

async fn connect_auto_quic_runtime(
    ssh: &SshArgs,
    helper_plan: BridgeHelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
) -> Result<TunnelRuntime> {
    let AutoQuicHelperPlans { agent, quic_native } = auto_quic_helper_plans(helper_plan)?;
    let probe_started_at = start_auto_quic_probe();
    match connect_quic_native_bridge_fresh_ssh_command_with_data_plane_timeout(
        ssh,
        &quic_native,
        Some(AUTO_QUIC_DATA_PLANE_PROBE_TIMEOUT),
    )
    .await
    {
        Ok(bridge) => {
            log_auto_quic_selection(decide_auto_quic_probe(true), probe_started_at);
            eprintln!("transport: auto-quic selected quic-native");
            Ok(TunnelRuntime::new(QuicNativeDataPlane::new(bridge)))
        }
        Err(err) => {
            log_auto_quic_selection(decide_auto_quic_probe(false), probe_started_at);
            connect_auto_quic_agent_fallback_runtime(ssh, agent, mtu, dns_remote, options, err)
                .await
        }
    }
}

async fn connect_auto_agent_fallback_runtime(
    ssh: &SshArgs,
    ssh_sessions: usize,
    decision: AutoAgentRuntimeDecision,
    err: anyhow::Error,
) -> Result<TunnelRuntime> {
    let AutoAgentRuntimeDecision::DirectTcpipFallback(reason) = decision else {
        unreachable!("auto fallback runtime requires a direct-tcpip fallback decision");
    };
    log_auto_agent_fallback(reason, &err);
    connect_direct_tcpip_runtime(ssh, ssh_sessions).await
}

async fn connect_auto_quic_agent_fallback_runtime(
    ssh: &SshArgs,
    helper_plan: HelperCommandPlan,
    mtu: u16,
    dns_remote: Option<&Destination>,
    options: TunnelRuntimeOptions,
    err: anyhow::Error,
) -> Result<TunnelRuntime> {
    eprintln!("transport: auto-quic could not start quic-native ({err:#}); falling back to agent");
    let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
    let connector = ssh_agent_connector(ssh, helper_plan, mtu)?;
    let fast_start_agent_lanes = auto_agent_fast_start_enabled(options, desired_agent_sessions);
    let data_plane = connect_framed_agent_data_plane(
        connector,
        desired_agent_sessions,
        fast_start_agent_lanes,
        dns_remote,
    )
    .await?;
    Ok(TunnelRuntime::new(data_plane))
}

fn ssh_agent_connector(
    ssh: &SshArgs,
    helper_plan: HelperCommandPlan,
    mtu: u16,
) -> Result<Arc<dyn AgentBridgeConnector>> {
    Ok(Arc::new(SshAgentBridgeConnector::new(
        ssh.clone(),
        helper_plan,
        mtu,
    )?))
}

fn ssh_quic_agent_connector(
    ssh: &SshArgs,
    helper_plan: HelperCommandPlan,
    mtu: u16,
) -> Result<Arc<dyn AgentBridgeConnector>> {
    Ok(Arc::new(SshQuicAgentBridgeConnector::new(
        ssh.clone(),
        helper_plan,
        mtu,
    )?))
}

fn auto_agent_fast_start_enabled(
    options: TunnelRuntimeOptions,
    desired_agent_sessions: usize,
) -> bool {
    should_fast_start_agent_lanes(
        options.fast_start_auto_agent_lanes,
        options.agent_sessions,
        desired_agent_sessions,
    )
}

fn decide_auto_agent_runtime(agent_started: bool, dns_supported: bool) -> AutoAgentRuntimeDecision {
    if !agent_started {
        AutoAgentRuntimeDecision::DirectTcpipFallback(AutoAgentFallbackReason::AgentStartupFailed)
    } else if !dns_supported {
        AutoAgentRuntimeDecision::DirectTcpipFallback(AutoAgentFallbackReason::DnsUnsupported)
    } else {
        AutoAgentRuntimeDecision::Agent
    }
}

fn log_auto_agent_fallback(reason: AutoAgentFallbackReason, err: &anyhow::Error) {
    match reason {
        AutoAgentFallbackReason::AgentStartupFailed => {
            eprintln!(
                "transport: auto could not start agent ({err:#}); falling back to direct-tcpip"
            );
        }
        AutoAgentFallbackReason::DnsUnsupported => {
            eprintln!(
                "transport: auto selected direct-tcpip because the agent cannot support the configured DNS resolver ({err:#})"
            );
        }
    }
}

fn auto_quic_helper_plans(plan: BridgeHelperCommandPlan) -> Result<AutoQuicHelperPlans> {
    let BridgeHelperCommandPlan::AutoQuic { agent, quic_native } = plan else {
        bail!("auto-quic runtime requires distinct QUIC-native and agent helper plans");
    };
    Ok(AutoQuicHelperPlans { agent, quic_native })
}

fn start_auto_quic_probe() -> Instant {
    let started_at = Instant::now();
    log_auto_quic_decision(
        "probe",
        "start",
        started_at,
        AUTO_QUIC_DATA_PLANE_PROBE_TIMEOUT,
    );
    eprintln!(
        "transport: auto-quic probing quic-native with data-plane timeout {}ms",
        AUTO_QUIC_DATA_PLANE_PROBE_TIMEOUT.as_millis()
    );
    started_at
}

fn decide_auto_quic_probe(probe_succeeded: bool) -> AutoQuicProbeSelection {
    if probe_succeeded {
        AutoQuicProbeSelection::QuicNative
    } else {
        AutoQuicProbeSelection::AgentFallback
    }
}

fn log_auto_quic_selection(selection: AutoQuicProbeSelection, started_at: Instant) {
    log_auto_quic_decision(
        "select",
        selection.result_label(),
        started_at,
        AUTO_QUIC_DATA_PLANE_PROBE_TIMEOUT,
    );
}

fn log_auto_quic_decision(
    stage: &'static str,
    result: &'static str,
    started_at: Instant,
    timeout: Duration,
) {
    eprintln!(
        "auto-quic-decision: transport=auto-quic stage={stage} result={result} elapsed_ms={} timeout_ms={} fallback=agent",
        started_at.elapsed().as_millis(),
        timeout.as_millis()
    );
}

fn single_helper_plan(
    plan: BridgeHelperCommandPlan,
    requested: BridgeTransportKind,
) -> Result<HelperCommandPlan> {
    match plan {
        BridgeHelperCommandPlan::Single(plan) => Ok(plan),
        BridgeHelperCommandPlan::AutoQuic { .. } => {
            bail!("transport {requested:?} received auto-quic helper plans")
        }
    }
}

async fn connect_framed_agent_data_plane(
    connector: Arc<dyn AgentBridgeConnector>,
    desired_agent_sessions: usize,
    fast_start_agent_lanes: bool,
    dns_remote: Option<&Destination>,
) -> Result<FramedAgentDataPlane> {
    let transports = connect_initial_agent_transports(
        connector.as_ref(),
        desired_agent_sessions,
        fast_start_agent_lanes,
    )
    .await?;
    ensure_agent_dns_remote_supported(&transports, dns_remote)?;
    Ok(framed_agent_data_plane_from_transports(
        connector,
        transports,
        desired_agent_sessions,
        fast_start_agent_lanes,
    ))
}

async fn connect_initial_agent_transports(
    connector: &dyn AgentBridgeConnector,
    desired_agent_sessions: usize,
    fast_start_agent_lanes: bool,
) -> Result<Vec<AgentBridgeTransport>> {
    if fast_start_agent_lanes {
        connect_auto_agent_bridge_transports_from_connector(connector, desired_agent_sessions).await
    } else {
        connector.connect_initial(desired_agent_sessions).await
    }
}

fn framed_agent_data_plane_from_transports(
    connector: Arc<dyn AgentBridgeConnector>,
    transports: Vec<AgentBridgeTransport>,
    desired_agent_sessions: usize,
    fast_start_agent_lanes: bool,
) -> FramedAgentDataPlane {
    let agent = if fast_start_agent_lanes {
        ReconnectingAgentBridge::new_with_desired_lanes_and_missing_repair_delay(
            connector,
            transports,
            desired_agent_sessions,
            Some(AGENT_FAST_START_WARMUP_DELAY),
        )
    } else {
        ReconnectingAgentBridge::new_with_desired_lanes(
            connector,
            transports,
            desired_agent_sessions,
        )
    };
    FramedAgentDataPlane::new(agent)
}

fn ensure_agent_dns_remote_supported(
    transports: &[AgentBridgeTransport],
    remote: Option<&Destination>,
) -> Result<()> {
    let Some(remote) = remote else {
        return Ok(());
    };
    let capabilities = transports
        .iter()
        .map(AgentBridgeTransport::peer_capabilities)
        .collect::<Vec<_>>();
    ensure_agent_dns_capabilities_supported(&capabilities, remote)
}

fn ensure_agent_dns_capabilities_supported(
    capabilities: &[u64],
    remote: &Destination,
) -> Result<()> {
    let requirement = agent_dns_capability_requirement(remote);
    if !capabilities.is_empty()
        && capabilities
            .iter()
            .all(|capabilities| requirement.is_satisfied_by(*capabilities))
    {
        return Ok(());
    }
    match requirement {
        AgentDnsCapabilityRequirement::UdpAssociateForIpv4 => {
            bail!(
                "agent DNS transport to IPv4 resolver {} requires UDP associate support",
                remote.host
            );
        }
        AgentDnsCapabilityRequirement::TcpConnectHostForHostname => {
            bail!(
                "agent DNS transport to hostname {} requires hostname TCP connect support",
                remote.host
            );
        }
    }
}

fn agent_dns_capability_requirement(remote: &Destination) -> AgentDnsCapabilityRequirement {
    if remote.host.parse::<Ipv4Addr>().is_ok() {
        AgentDnsCapabilityRequirement::UdpAssociateForIpv4
    } else {
        AgentDnsCapabilityRequirement::TcpConnectHostForHostname
    }
}

impl AgentDnsCapabilityRequirement {
    fn is_satisfied_by(self, capabilities: u64) -> bool {
        match self {
            Self::UdpAssociateForIpv4 => capabilities & agent_proto::CAP_UDP_ASSOCIATE != 0,
            Self::TcpConnectHostForHostname => {
                capabilities & agent_proto::CAP_TCP_CONNECT_HOST != 0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(host: &str) -> Destination {
        Destination {
            host: host.to_owned(),
            port: 53,
        }
    }

    #[test]
    fn auto_agent_runtime_decision_falls_back_to_direct_tcpip_for_startup_or_dns() {
        assert_eq!(
            decide_auto_agent_runtime(false, true),
            AutoAgentRuntimeDecision::DirectTcpipFallback(
                AutoAgentFallbackReason::AgentStartupFailed
            )
        );
        assert_eq!(
            decide_auto_agent_runtime(false, false),
            AutoAgentRuntimeDecision::DirectTcpipFallback(
                AutoAgentFallbackReason::AgentStartupFailed
            )
        );
        assert_eq!(
            decide_auto_agent_runtime(true, false),
            AutoAgentRuntimeDecision::DirectTcpipFallback(AutoAgentFallbackReason::DnsUnsupported)
        );
        assert_eq!(
            decide_auto_agent_runtime(true, true),
            AutoAgentRuntimeDecision::Agent
        );
    }

    #[test]
    fn auto_quic_probe_decision_selects_native_or_agent_fallback() {
        assert_eq!(
            decide_auto_quic_probe(true),
            AutoQuicProbeSelection::QuicNative
        );
        assert_eq!(
            decide_auto_quic_probe(false),
            AutoQuicProbeSelection::AgentFallback
        );
        assert_eq!(
            AutoQuicProbeSelection::QuicNative.result_label(),
            "quic-native"
        );
        assert_eq!(
            AutoQuicProbeSelection::AgentFallback.result_label(),
            "agent-fallback"
        );
    }

    #[test]
    fn dns_capability_requirement_tracks_remote_host_kind() {
        assert_eq!(
            agent_dns_capability_requirement(&remote("1.1.1.1")),
            AgentDnsCapabilityRequirement::UdpAssociateForIpv4
        );
        assert_eq!(
            agent_dns_capability_requirement(&remote("dns.example.test")),
            AgentDnsCapabilityRequirement::TcpConnectHostForHostname
        );
        assert!(AgentDnsCapabilityRequirement::UdpAssociateForIpv4
            .is_satisfied_by(agent_proto::CAP_UDP_ASSOCIATE));
        assert!(AgentDnsCapabilityRequirement::TcpConnectHostForHostname
            .is_satisfied_by(agent_proto::CAP_TCP_CONNECT_HOST));
    }

    #[test]
    fn dns_remote_ipv4_requires_udp_capability_on_every_agent_lane() {
        let remote = remote("1.1.1.1");

        ensure_agent_dns_capabilities_supported(
            &[
                agent_proto::CAP_UDP_ASSOCIATE,
                agent_proto::CAP_UDP_ASSOCIATE | agent_proto::CAP_TCP_CONNECT_HOST,
            ],
            &remote,
        )
        .expect("all lanes support UDP DNS");

        let err = ensure_agent_dns_capabilities_supported(
            &[
                agent_proto::CAP_UDP_ASSOCIATE,
                agent_proto::CAP_TCP_CONNECT_HOST,
            ],
            &remote,
        )
        .expect_err("one lane lacks UDP DNS support");
        assert!(err.to_string().contains(
            "agent DNS transport to IPv4 resolver 1.1.1.1 requires UDP associate support"
        ));
    }

    #[test]
    fn dns_remote_hostname_requires_host_tcp_capability_on_every_agent_lane() {
        let remote = remote("dns.example.test");

        ensure_agent_dns_capabilities_supported(
            &[
                agent_proto::CAP_TCP_CONNECT_HOST,
                agent_proto::CAP_TCP_CONNECT_HOST | agent_proto::CAP_UDP_ASSOCIATE,
            ],
            &remote,
        )
        .expect("all lanes support hostname DNS");

        let err = ensure_agent_dns_capabilities_supported(
            &[
                agent_proto::CAP_TCP_CONNECT_HOST,
                agent_proto::CAP_UDP_ASSOCIATE,
            ],
            &remote,
        )
        .expect_err("one lane lacks hostname TCP DNS support");
        assert!(err.to_string().contains(
            "agent DNS transport to hostname dns.example.test requires hostname TCP connect support"
        ));
    }

    #[test]
    fn dns_remote_capability_check_rejects_empty_agent_lane_sets() {
        let ipv4 = remote("1.1.1.1");
        let err = ensure_agent_dns_capabilities_supported(&[], &ipv4)
            .expect_err("IPv4 DNS should require at least one UDP-capable lane");
        assert!(err.to_string().contains(
            "agent DNS transport to IPv4 resolver 1.1.1.1 requires UDP associate support"
        ));

        let hostname = remote("dns.example.test");
        let err = ensure_agent_dns_capabilities_supported(&[], &hostname)
            .expect_err("hostname DNS should require at least one hostname-capable lane");
        assert!(err.to_string().contains(
            "agent DNS transport to hostname dns.example.test requires hostname TCP connect support"
        ));
    }
}
