use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::TunnelSupervisor;
use crate::control_plane::{connect_tunnel_runtime, validate_agent_session_request_count};
use crate::packet_engine::PACKET_BUF_SIZE;
use crate::remote_helper::bridge_agent_command_plan;
use crate::routing::{expand_target_routes, ssh_control_ip_to_protect};
use crate::ssh_control::validate_ssh_session_count;
use crate::transport_model::{parse_destination, BridgeTransportKind, TunnelRuntimeOptions};
use crate::tunnel_lifecycle::{
    open_tun, open_tunnel_host, shutdown_signal, virtual_dns_ip, ShutdownSignal, TunConfig,
    TunnelCleanup, TunnelHostConfig,
};
use crate::{platform, tcp_core, TunnelArgs};

pub(crate) async fn run_tunnel(args: TunnelArgs) -> Result<()> {
    validate_tunnel_args(&args)?;
    let shutdown = shutdown_signal().await?;
    let mut startup_shutdown = shutdown.clone();
    let Some(tunnel) = await_startup_or_shutdown(
        &mut startup_shutdown,
        PreparedTunnel::prepare(args, shutdown),
    )
    .await?
    else {
        return Ok(());
    };
    tunnel.run().await
}

struct PreparedTunnel {
    supervisor: TunnelSupervisor,
    cleanup: TunnelCleanup,
}

impl PreparedTunnel {
    async fn prepare(args: TunnelArgs, shutdown: ShutdownSignal) -> Result<Self> {
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

    async fn run(mut self) -> Result<()> {
        let result = self.supervisor.run().await;
        let Self { cleanup, .. } = self;
        drop(cleanup);
        result
    }
}

async fn await_startup_or_shutdown<T, Fut>(
    shutdown: &mut ShutdownSignal,
    startup: Fut,
) -> Result<Option<T>>
where
    Fut: std::future::Future<Output = Result<T>>,
{
    tokio::select! {
        result = startup => result.map(Some),
        signal = shutdown.recv() => {
            eprintln!("signal: {} received during startup", signal?);
            Ok(None)
        }
    }
}

pub(crate) fn validate_tunnel_args(args: &TunnelArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
    let Some(remote) = args.ssh.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    let _ = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto
            | BridgeTransportKind::DirectTcpip
            | BridgeTransportKind::QuicNative
    ) {
        validate_ssh_session_count(args.ssh_sessions)?;
    }
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto | BridgeTransportKind::Agent | BridgeTransportKind::QuicAgent
    ) {
        validate_agent_session_request_count(args.agent_sessions)?;
    }
    if args.udp_idle_timeout_ms == 0 {
        bail!("udp-idle-timeout-ms must be at least 1");
    }
    platform::preflight_route_management().context("route preflight failed")?;
    if args.tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if args.mtu < 576 {
        bail!("mtu must be at least the IPv4 minimum of 576 bytes");
    }
    if args.mtu as usize > PACKET_BUF_SIZE {
        bail!("mtu must not exceed packet buffer size {PACKET_BUF_SIZE}");
    }
    if args.configure_dns {
        virtual_dns_ip(args.tun_ip, args.tun_prefix)?;
        platform::preflight_system_dns().context("DNS preflight failed")?;
    }
    let _ = remote;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, CommandKind};

    #[test]
    fn tunnel_subcommand_rejects_zero_udp_idle_timeout() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--udp-idle-timeout-ms",
            "0",
        ])
        .expect("tunnel CLI with zero UDP timeout");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        let err = validate_tunnel_args(&args).expect_err("zero UDP timeout must be rejected");
        assert!(err.to_string().contains("udp-idle-timeout-ms"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote_by_default() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        validate_tunnel_args(&args).expect("agent can use hostname DNS");
    }

    #[test]
    fn explicit_auto_tunnel_validates_direct_fallback_session_count() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "auto",
            "--ssh-sessions",
            "0",
        ])
        .expect("tunnel CLI with zero SSH sessions");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Auto);
        let err = validate_tunnel_args(&args)
            .expect_err("explicit auto fallback needs valid ssh sessions");
        assert!(err.to_string().contains("--ssh-sessions"));
    }

    #[test]
    fn agent_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("agent supports hostname DNS remote through OpenTcpHost");
    }

    #[test]
    fn quic_native_tunnel_accepts_hostname_dns_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "quic-native",
            "--dns-remote",
            "localhost:53",
        ])
        .expect("tunnel CLI with native QUIC hostname DNS remote");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        validate_tunnel_args(&args)
            .expect("native QUIC supports hostname DNS remote through TCP host open");
    }

    #[tokio::test]
    async fn startup_shutdown_wins_over_pending_startup() {
        let mut shutdown = ShutdownSignal::triggered_for_test("interrupt");
        let startup = std::future::pending::<Result<&'static str>>();

        let result = await_startup_or_shutdown(&mut shutdown, startup)
            .await
            .expect("shutdown should be clean");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn ready_startup_wins_when_shutdown_is_pending() {
        let mut shutdown = ShutdownSignal::pending_for_test();

        let result =
            await_startup_or_shutdown(&mut shutdown, async { Ok::<_, anyhow::Error>("prepared") })
                .await
                .expect("startup should complete");

        assert_eq!(result, Some("prepared"));
    }
}
