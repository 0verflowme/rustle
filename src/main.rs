use anyhow::Result;
use clap::Parser;

mod agent_bridge;
#[cfg(test)]
mod agent_client;
mod agent_io;
mod agent_lab;
#[allow(dead_code)]
mod agent_proto;
mod agent_runtime;
mod agent_transport;
mod agent_window;
mod bridge_lab;
mod cli;
mod command_runtime;
mod control_plane;
mod data_plane;
mod defaults;
mod dns;
mod helper_runtime;
mod hotpath_trace;
mod known_hosts;
mod lab_support;
mod packet_engine;
mod platform;
mod quic_agent;
mod quic_agent_runtime;
mod remote_exec;
mod remote_helper;
mod remote_platform;
mod routing;
mod sidecar_store;
mod ssh_bridge;
mod ssh_control;
mod supervisor;
#[allow(dead_code)]
mod tcp_core;
mod transport_model;
mod tun_io;
mod tunnel_lifecycle;

use agent_lab::{run_agent_dns_lab, run_agent_lab, run_agent_udp_lab};
use bridge_lab::run_bridge_lab;
use cli::{Cli, CommandKind};
pub(crate) use cli::{SshArgs, TunCaptureArgs, TunnelArgs};
use command_runtime::{run_compact_tunnel, run_direct_tcpip};
use helper_runtime::{run_agent, run_quic_agent, run_quic_bridge_agent};
use supervisor::{run_tun_capture, run_tunnel};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(CommandKind::DirectTcpip(args)) => run_direct_tcpip(args).await,
        Some(CommandKind::TunCapture(args)) => run_tun_capture(args).await,
        Some(CommandKind::Tunnel(args)) => run_tunnel(args).await,
        Some(CommandKind::BridgeLab(args)) => run_bridge_lab(args).await,
        Some(CommandKind::AgentLab(args)) => run_agent_lab(args).await,
        Some(CommandKind::AgentUdpLab(args)) => run_agent_udp_lab(args).await,
        Some(CommandKind::AgentDnsLab(args)) => run_agent_dns_lab(args).await,
        Some(CommandKind::QuicAgent(args)) => run_quic_agent(args).await,
        Some(CommandKind::QuicBridgeAgent(args)) => run_quic_bridge_agent(args).await,
        Some(CommandKind::Agent(args)) => run_agent(args).await,
        None => run_compact_tunnel(cli.compact).await,
    }
}
