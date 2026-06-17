use std::net::Ipv4Addr;
use std::sync::Arc;

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
use super::quic_startup::{
    connect_quic_native_bridge_fresh_ssh_command, SshQuicAgentBridgeConnector,
};
use super::ssh_agent_startup::SshAgentBridgeConnector;

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
            let data_plane = connect_framed_agent_data_plane(
                connector,
                desired_agent_sessions,
                fast_start_agent_lanes,
                dns_remote,
            )
            .await?;
            Ok(TunnelRuntime::new(data_plane))
        }
        BridgeTransportKind::QuicAgent => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> = Arc::new(
                SshQuicAgentBridgeConnector::new(ssh.clone(), helper_plan, mtu)?,
            );
            let data_plane = connect_framed_agent_data_plane(
                connector,
                desired_agent_sessions,
                false,
                dns_remote,
            )
            .await?;
            Ok(TunnelRuntime::new(data_plane))
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
            let transports = match connect_initial_agent_transports(
                connector.as_ref(),
                desired_agent_sessions,
                fast_start_agent_lanes,
            )
            .await
            {
                Ok(transports) => transports,
                Err(err) => {
                    eprintln!(
                        "transport: auto could not start agent ({err:#}); falling back to direct-tcpip"
                    );
                    let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
                    return Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)));
                }
            };
            if let Err(err) = ensure_agent_dns_remote_supported(&transports, dns_remote) {
                eprintln!(
                    "transport: auto selected direct-tcpip because the agent cannot support the configured DNS resolver ({err:#})"
                );
                let ssh = connect_ssh_pool(ssh, options.ssh_sessions).await?;
                return Ok(TunnelRuntime::new(DirectTcpipDataPlane::new(ssh)));
            }
            eprintln!("transport: auto selected agent");
            Ok(TunnelRuntime::new(framed_agent_data_plane_from_transports(
                connector,
                transports,
                desired_agent_sessions,
                fast_start_agent_lanes,
            )))
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
    if remote.host.parse::<Ipv4Addr>().is_ok() {
        if capabilities
            .iter()
            .all(|capabilities| capabilities & agent_proto::CAP_UDP_ASSOCIATE != 0)
        {
            return Ok(());
        }
        bail!(
            "agent DNS transport to IPv4 resolver {} requires UDP associate support",
            remote.host
        );
    }
    if capabilities
        .iter()
        .all(|capabilities| capabilities & agent_proto::CAP_TCP_CONNECT_HOST != 0)
    {
        return Ok(());
    }
    bail!(
        "agent DNS transport to hostname {} requires hostname TCP connect support",
        remote.host
    )
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
}
