use std::time::Duration;

use anyhow::{Context, Result};

use crate::control_plane::connect_tunnel_runtime;
use crate::remote_helper::bridge_agent_command_plan;
use crate::routing::{expand_target_routes, ssh_control_ip_to_protect};
use crate::transport_model::{parse_destination, TunnelRuntimeOptions};
use crate::tunnel_lifecycle::{
    open_tun, open_tunnel_host, ShutdownSignal, TunConfig, TunnelCleanup, TunnelHostConfig,
};
use crate::{tcp_core, TunnelArgs};

use super::super::TunnelSupervisor;

pub(super) struct PreparedTunnel {
    supervisor: TunnelSupervisor,
    cleanup: TunnelCleanup,
}

impl PreparedTunnel {
    pub(super) async fn prepare(args: TunnelArgs, shutdown: ShutdownSignal) -> Result<Self> {
        let helper_plan = bridge_agent_command_plan(
            args.bridge_transport,
            args.agent_command.as_deref(),
            args.agent_path.as_deref(),
        )?;
        let target_routes = expand_target_routes(&args.targets)?;
        let dns_remote = parse_destination(&args.dns_remote)
            .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
        let ssh_control_ip = args
            .ssh
            .ssh_server
            .as_deref()
            .map(|_| ssh_control_ip_to_protect(&args.ssh, &target_routes))
            .transpose()?
            .flatten();
        let tun_config = TunConfig::new(args.tun_ip, args.tun_prefix, args.mtu, args.name);
        let tun = open_tun(&tun_config)?;

        let runtime = connect_tunnel_runtime(
            &args.ssh,
            args.bridge_transport,
            helper_plan,
            args.mtu,
            Some(&dns_remote),
            TunnelRuntimeOptions {
                ssh_sessions: args.ssh_sessions,
                agent_sessions: args.agent_sessions,
                fast_start_auto_agent_lanes: true,
            },
        )
        .await?;
        let data_plane = runtime.data_plane();
        let host = open_tunnel_host(TunnelHostConfig {
            tun_config,
            tun,
            target_routes,
            ssh_control_ip,
            configure_dns: args.configure_dns,
            dns_remote: dns_remote.clone(),
            data_plane: data_plane.clone(),
        })
        .await?;

        let flow_manager = tcp_core::FlowManager::new(
            args.tun_ip,
            args.tun_prefix,
            &host.route_parts,
            usize::from(args.mtu),
        )
        .context("failed to initialize userspace TCP flow manager")?;

        Ok(Self {
            supervisor: TunnelSupervisor::new(
                host.tun.dev,
                flow_manager,
                data_plane,
                dns_remote,
                Duration::from_millis(args.udp_idle_timeout_ms),
                shutdown,
            ),
            cleanup: host.cleanup,
        })
    }

    pub(super) async fn run(mut self) -> Result<()> {
        let result = self.supervisor.run().await;
        let Self { cleanup, .. } = self;
        drop(cleanup);
        result
    }
}
