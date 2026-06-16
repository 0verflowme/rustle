use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use ipnet::Ipv4Net;

use crate::routing::parse_target_cidr;
use crate::ssh_control::DEFAULT_SSH_CONNECT_TIMEOUT_SECS;
use crate::transport_model::{BridgeTransportKind, UDP_DATAGRAMS_PER_ASSOCIATION};
use crate::{
    DEFAULT_AGENT_SESSIONS, DEFAULT_MTU, DEFAULT_SSH_SESSIONS, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX,
    DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
};

#[derive(Debug, Parser)]
#[command(name = "rustle", about = "User-space SSH network pivot")]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) compact: CompactTunnelArgs,

    #[command(subcommand)]
    pub(crate) command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CommandKind {
    /// Phase 1: authenticate to SSH and open one direct-tcpip channel.
    #[command(hide = true)]
    DirectTcpip(DirectTcpipArgs),

    /// Phase 2: create a TUN, route CIDRs into it, and log raw packets.
    #[command(hide = true)]
    TunCapture(TunCaptureArgs),

    /// Phase 4: create a TUN, terminate TCP locally, and bridge flows over SSH.
    #[command(hide = true)]
    Tunnel(TunnelArgs),

    /// Lab: exercise FlowManager and the real SSH bridge without TUN privileges.
    #[command(hide = true)]
    BridgeLab(BridgeLabArgs),

    /// Lab: exercise the framed agent transport over SSH exec.
    #[command(hide = true)]
    AgentLab(AgentLabArgs),

    /// Lab: exercise framed agent UDP over SSH exec.
    #[command(hide = true)]
    AgentUdpLab(AgentUdpLabArgs),

    /// Lab: measure DNS query latency through Rustle's DNS transport.
    #[command(hide = true)]
    AgentDnsLab(AgentDnsLabArgs),

    /// Remote helper: run the Rustle agent protocol over a QUIC listener.
    #[command(hide = true)]
    QuicAgent(QuicAgentArgs),

    /// Remote helper: run native per-flow QUIC bridge streams.
    #[command(hide = true)]
    QuicBridgeAgent(QuicBridgeAgentArgs),

    /// Remote helper: run the Rustle agent protocol on stdin/stdout.
    #[command(hide = true)]
    Agent(AgentArgs),
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct SshArgs {
    /// SSH server, either host or host:port.
    #[arg(short = 'r', long = "remote")]
    pub(crate) ssh_server: Option<String>,

    /// SSH username. Usually supplied as user@host in --remote.
    #[arg(short = 'u', long = "user")]
    pub(crate) ssh_user: Option<String>,

    /// Private key path for public-key authentication.
    #[arg(short = 'i', long = "identity")]
    pub(crate) identity: Option<PathBuf>,

    /// Use password authentication. If no value is supplied, prompt interactively.
    #[arg(
        short = 'p',
        long = "password",
        num_args = 0..=1,
        require_equals = true,
        conflicts_with = "password_file"
    )]
    pub(crate) password: Option<Option<String>>,

    /// Read the SSH password from a local file instead of argv or a prompt.
    #[arg(
        long = "password-file",
        value_name = "PATH",
        conflicts_with = "password"
    )]
    pub(crate) password_file: Option<PathBuf>,

    /// Skip host-key verification. Intended for controlled development labs only.
    #[arg(long = "insecure-accept-host-key")]
    pub(crate) insecure_accept_host_key: bool,

    /// Trust and record a new SSH host key, but still reject changed known keys.
    #[arg(
        long = "accept-new-host-key",
        conflicts_with = "insecure_accept_host_key"
    )]
    pub(crate) accept_new_host_key: bool,

    /// OpenSSH known_hosts file to use for host-key verification.
    #[arg(long = "known-hosts")]
    pub(crate) known_hosts: Option<PathBuf>,

    /// OpenSSH client config file to use for Host aliases.
    #[arg(long = "ssh-config", value_name = "PATH", hide = true)]
    pub(crate) ssh_config: Option<PathBuf>,

    /// Timeout for establishing the SSH control TCP connection.
    #[arg(
        long = "ssh-connect-timeout",
        default_value_t = DEFAULT_SSH_CONNECT_TIMEOUT_SECS,
        value_name = "SECONDS",
        hide = true
    )]
    pub(crate) ssh_connect_timeout_secs: u64,
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct CompactTunnelArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// Explicit IPv4 CIDRs to route into the tunnel.
    #[arg(value_name = "CIDR", value_parser = parse_target_cidr)]
    pub(crate) targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP, hide = true)]
    pub(crate) tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX, hide = true)]
    pub(crate) tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU, hide = true)]
    pub(crate) mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name", hide = true)]
    pub(crate) name: Option<String>,

    /// Configure the host resolver to send DNS queries through Rustle.
    #[arg(long = "dns")]
    pub(crate) configure_dns: bool,

    /// Remote DNS TCP resolver to use for intercepted UDP/53 queries.
    #[arg(long = "dns-remote", default_value = "127.0.0.53:53")]
    pub(crate) dns_remote: String,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    pub(crate) ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    pub(crate) agent_sessions: usize,

    /// Hidden switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    pub(crate) bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Hidden lab override for generic UDP association idle cleanup.
    #[arg(
        long = "udp-idle-timeout-ms",
        default_value_t = DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
        hide = true
    )]
    pub(crate) udp_idle_timeout_ms: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct DirectTcpipArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// TCP target to open from the remote SSH server, in host:port form.
    #[arg(short = 'd', long = "destination", default_value = "1.1.1.1:80")]
    pub(crate) destination: String,

    /// Raw request payload to send through the direct-tcpip channel.
    #[arg(long = "request")]
    pub(crate) request: Option<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct TunCaptureArgs {
    /// Explicit IPv4 CIDRs to route into the TUN device.
    #[arg(short = 't', long = "target", required = true, num_args = 1.., value_parser = parse_target_cidr)]
    pub(crate) targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    pub(crate) tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX)]
    pub(crate) tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name")]
    pub(crate) name: Option<String>,

    /// Exit cleanly after capturing this many packets. Intended for smoke tests.
    #[arg(long = "exit-after-packets", hide = true)]
    pub(crate) exit_after_packets: Option<u64>,
}

#[derive(Debug, Parser)]
pub(crate) struct TunnelArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// Explicit IPv4 CIDRs to route into the TUN device.
    #[arg(short = 't', long = "target", required = true, num_args = 1.., value_parser = parse_target_cidr)]
    pub(crate) targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    pub(crate) tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX)]
    pub(crate) tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name")]
    pub(crate) name: Option<String>,

    /// Configure the host resolver to send DNS queries through Rustle.
    #[arg(long = "dns")]
    pub(crate) configure_dns: bool,

    /// Remote DNS TCP resolver to use for intercepted UDP/53 queries.
    #[arg(long = "dns-remote", default_value = "127.0.0.53:53")]
    pub(crate) dns_remote: String,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    pub(crate) ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    pub(crate) agent_sessions: usize,

    /// Hidden switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    pub(crate) bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Hidden lab override for generic UDP association idle cleanup.
    #[arg(
        long = "udp-idle-timeout-ms",
        default_value_t = DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
        hide = true
    )]
    pub(crate) udp_idle_timeout_ms: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct BridgeLabArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// IPv4 TCP target to open from the remote SSH server, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    pub(crate) destination: String,

    /// Raw request payload to send through the synthetic local TCP flow.
    #[arg(long = "request")]
    pub(crate) request: Option<String>,

    /// Synthetic client IPv4 address.
    #[arg(long = "client-ip", default_value_t = Ipv4Addr::new(10, 255, 255, 2))]
    pub(crate) client_ip: Ipv4Addr,

    /// Synthetic gateway/TUN IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    pub(crate) tun_ip: Ipv4Addr,

    /// Number of synthetic TCP flows to multiplex through one SSH connection.
    #[arg(long = "connections", default_value_t = 1)]
    pub(crate) connections: usize,

    /// Hidden lab tolerance for chaos tests that intentionally fail some flows.
    #[arg(long = "min-completed", hide = true)]
    pub(crate) min_completed: Option<usize>,

    /// Hidden lab deadline override in milliseconds.
    #[arg(long = "deadline-ms", hide = true)]
    pub(crate) deadline_ms: Option<u64>,

    /// Hidden lab switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    pub(crate) bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Print a compact benchmark summary instead of response bodies.
    #[arg(long = "summary", hide = true)]
    pub(crate) summary: bool,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    pub(crate) ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    pub(crate) agent_sessions: usize,
}

#[derive(Debug, Parser)]
pub(crate) struct AgentLabArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// IPv4 TCP target to open from the remote agent, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    pub(crate) destination: String,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Raw request payload to send through the agent stream.
    #[arg(long = "request")]
    pub(crate) request: Option<String>,

    /// MTU advertised to the remote agent.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct AgentUdpLabArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// IPv4 UDP target to open from the remote agent, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    pub(crate) destination: String,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Raw UDP datagram payload to send through the agent stream.
    #[arg(long = "request", default_value = "rustle-agent-udp-ping")]
    pub(crate) request: String,

    /// Number of UDP datagrams to send on one agent association.
    #[arg(long = "messages", default_value_t = 2)]
    pub(crate) messages: usize,

    /// Maximum datagrams to keep outstanding before reading responses.
    #[arg(long = "pipeline", default_value_t = UDP_DATAGRAMS_PER_ASSOCIATION)]
    pub(crate) pipeline: usize,

    /// Print a compact benchmark summary instead of response datagrams.
    #[arg(long = "summary", hide = true)]
    pub(crate) summary: bool,

    /// MTU advertised to the remote agent.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct AgentDnsLabArgs {
    #[command(flatten)]
    pub(crate) ssh: SshArgs,

    /// Remote DNS resolver to query through the selected Rustle transport.
    #[arg(long = "dns-remote")]
    pub(crate) dns_remote: String,

    /// DNS name to query.
    #[arg(long = "name", default_value = "rustle-smoke.example.com")]
    pub(crate) name: String,

    /// Number of DNS queries to send sequentially.
    #[arg(long = "queries", default_value_t = 32)]
    pub(crate) queries: usize,

    /// Hidden transport switch for DNS latency labs.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    pub(crate) bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    pub(crate) agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    pub(crate) agent_path: Option<String>,

    /// Number of Rustle agent exec transports to open for DNS queries.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    pub(crate) agent_sessions: usize,

    /// MTU advertised to the remote agent.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct AgentArgs {
    /// MTU advertised to the local Rustle controller.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct QuicAgentArgs {
    /// UDP address the QUIC agent should listen on.
    #[arg(long = "bind", default_value = "0.0.0.0:0")]
    pub(crate) bind: SocketAddr,

    /// MTU advertised to the local Rustle controller.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    pub(crate) mtu: u16,
}

#[derive(Debug, Parser)]
pub(crate) struct QuicBridgeAgentArgs {
    /// UDP address the native QUIC bridge helper should listen on.
    #[arg(long = "bind", default_value = "0.0.0.0:0")]
    pub(crate) bind: SocketAddr,
}
