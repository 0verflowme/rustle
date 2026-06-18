use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::{Args as ClapArgs, Parser, Subcommand};
use ipnet::Ipv4Net;

use crate::defaults::{
    DEFAULT_AGENT_SESSIONS, DEFAULT_MTU, DEFAULT_SSH_SESSIONS, DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX,
    DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
};
use crate::routing::parse_target_cidr;
use crate::ssh_control::DEFAULT_SSH_CONNECT_TIMEOUT_SECS;
use crate::transport_model::{BridgeTransportKind, UDP_DATAGRAMS_PER_ASSOCIATION};

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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use clap::{CommandFactory, Parser};
    use ipnet::Ipv4Net;

    use super::{Cli, CommandKind};
    use crate::defaults::{DEFAULT_AGENT_SESSIONS, DEFAULT_SSH_SESSIONS};
    use crate::remote_helper::{effective_agent_command, effective_bridge_agent_command};
    use crate::transport_model::BridgeTransportKind;

    #[test]
    fn compact_cli_accepts_multiple_targets_like_sshuttle() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ])
        .expect("compact CLI with multiple targets");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.ssh.ssh_server.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            cli.compact.targets,
            vec![
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                "172.16.0.0/12".parse::<Ipv4Net>().unwrap()
            ]
        );
        assert_eq!(cli.compact.dns_remote, "127.0.0.53:53");
        assert_eq!(cli.compact.ssh_sessions, DEFAULT_SSH_SESSIONS);
        assert_eq!(cli.compact.agent_sessions, DEFAULT_AGENT_SESSIONS);
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert!(!cli.compact.configure_dns);
    }

    #[test]
    fn compact_cli_accepts_sshuttle_abbreviated_targets() {
        let cli = Cli::try_parse_from(["rustle", "-r", "alice@example.com", "0/0", "10/8"])
            .expect("compact CLI with abbreviated targets");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.targets,
            vec![
                "0.0.0.0/0".parse::<Ipv4Net>().unwrap(),
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
            ]
        );
    }

    #[test]
    fn compact_cli_accepts_accept_new_host_key_flag() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--accept-new-host-key",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with accept-new host key flag");

        assert!(cli.compact.ssh.accept_new_host_key);
        assert!(!cli.compact.ssh.insecure_accept_host_key);
    }

    #[test]
    fn compact_cli_rejects_conflicting_host_key_modes() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--accept-new-host-key",
            "--insecure-accept-host-key",
            "10.0.0.0/8",
        ])
        .expect_err("host key modes must conflict");

        assert!(err.to_string().contains("insecure-accept-host-key"));
    }

    #[test]
    fn compact_cli_accepts_hidden_ssh_sessions_override() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--ssh-sessions",
            "2",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden SSH session override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.ssh_sessions, 2);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_sessions_override() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--agent-sessions",
            "3",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent session override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.agent_sessions, 3);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent transport");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(
            cli.compact.agent_command.as_deref(),
            Some("/tmp/rustle agent")
        );
        assert!(cli.compact.agent_path.is_none());
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_agent_path_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-path",
            "/tmp/rustle dir/rustle'bin",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden agent path");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::Agent);
        assert!(cli.compact.agent_command.is_none());
        assert_eq!(
            cli.compact.agent_path.as_deref(),
            Some("/tmp/rustle dir/rustle'bin")
        );
        assert_eq!(
            effective_agent_command(
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("agent path becomes effective command"),
            "'/tmp/rustle dir/rustle'\\''bin' agent"
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_quic_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "quic-agent",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden QUIC agent transport");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            effective_bridge_agent_command(
                cli.compact.bridge_transport,
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("QUIC agent path becomes effective command"),
            "'/tmp/rustle' quic-agent"
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_quic_native_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "quic-native",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden native QUIC transport");

        assert!(cli.command.is_none());
        assert_eq!(
            cli.compact.bridge_transport,
            BridgeTransportKind::QuicNative
        );
        assert_eq!(
            effective_bridge_agent_command(
                cli.compact.bridge_transport,
                cli.compact.agent_command.as_deref(),
                cli.compact.agent_path.as_deref()
            )
            .expect("native QUIC bridge path becomes effective command"),
            "'/tmp/rustle' quic-bridge-agent"
        );
    }

    #[test]
    fn compact_cli_accepts_hidden_auto_quic_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "auto-quic",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden auto QUIC transport");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.bridge_transport, BridgeTransportKind::AutoQuic);
        assert_eq!(cli.compact.agent_path.as_deref(), Some("/tmp/rustle"));
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_rejects_conflicting_agent_command_modes() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
            "--agent-path",
            "/tmp/rustle",
            "10.0.0.0/8",
        ])
        .expect_err("agent command modes must conflict");

        assert!(err.to_string().contains("agent-path"));
    }

    #[test]
    fn compact_cli_accepts_dns_remote_without_changing_target_shape() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--dns-remote",
            "127.0.0.1:5353",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with DNS override");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.dns_remote, "127.0.0.1:5353");
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_accepts_sshuttle_style_dns_flag() {
        let cli = Cli::try_parse_from(["rustle", "--dns", "-r", "alice@example.com", "10.0.0.0/8"])
            .expect("compact CLI with DNS takeover");

        assert!(cli.command.is_none());
        assert!(cli.compact.configure_dns);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_bare_password_does_not_consume_target_cidr() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password",
            "10.0.0.0/8",
        ])
        .expect("bare password flag before CIDR");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.ssh.password, Some(None));
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_password_value_requires_equals() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password=secret",
            "10.0.0.0/8",
        ])
        .expect("password value with equals");

        assert_eq!(cli.compact.ssh.password, Some(Some("secret".to_owned())));
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn compact_cli_rejects_conflicting_password_sources() {
        let err = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password",
            "--password-file",
            "/tmp/rustle-password",
            "10.0.0.0/8",
        ])
        .expect_err("password sources must conflict");

        assert!(err.to_string().contains("password-file"));
    }

    #[test]
    fn compact_cli_accepts_hidden_tun_overrides() {
        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--tun-ip",
            "10.88.0.1",
            "--tun-prefix",
            "30",
            "--mtu",
            "1200",
            "--name",
            "rustle-test0",
            "--udp-idle-timeout-ms",
            "500",
            "10.0.0.0/8",
        ])
        .expect("compact CLI with hidden TUN overrides");

        assert!(cli.command.is_none());
        assert_eq!(cli.compact.tun_ip, "10.88.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cli.compact.tun_prefix, 30);
        assert_eq!(cli.compact.mtu, 1200);
        assert_eq!(cli.compact.name.as_deref(), Some("rustle-test0"));
        assert_eq!(cli.compact.udp_idle_timeout_ms, 500);
        assert_eq!(
            cli.compact.targets,
            vec!["10.0.0.0/8".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn subcommand_cli_is_not_consumed_as_compact_cidr() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
        ])
        .expect("bridge-lab subcommand must parse");

        assert!(cli.compact.targets.is_empty());
        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 1);
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
    }

    #[test]
    fn bridge_lab_accepts_connection_count_for_load_smokes() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--connections",
            "8",
        ])
        .expect("bridge-lab load subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 8);
    }

    #[test]
    fn bridge_lab_accepts_hidden_summary_for_benchmarks() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "--destination",
            "127.0.0.1:8080",
            "--summary",
        ])
        .expect("bridge-lab summary subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert!(args.summary);
    }

    #[test]
    fn bridge_lab_accepts_hidden_chaos_completion_controls() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "--destination",
            "127.0.0.1:8080",
            "--connections",
            "3",
            "--min-completed",
            "2",
            "--deadline-ms",
            "1500",
        ])
        .expect("bridge-lab chaos controls must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.connections, 3);
        assert_eq!(args.min_completed, Some(2));
        assert_eq!(args.deadline_ms, Some(1500));
    }

    #[test]
    fn bridge_lab_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
        ])
        .expect("bridge-lab agent transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
    }

    #[test]
    fn bridge_lab_accepts_hidden_quic_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "quic-agent",
            "--agent-path",
            "/tmp/rustle",
        ])
        .expect("bridge-lab QUIC agent transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            effective_bridge_agent_command(
                args.bridge_transport,
                args.agent_command.as_deref(),
                args.agent_path.as_deref()
            )
            .expect("bridge-lab QUIC agent path becomes effective command"),
            "'/tmp/rustle' quic-agent"
        );
    }

    #[test]
    fn bridge_lab_accepts_hidden_quic_native_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "quic-native",
            "--agent-path",
            "/tmp/rustle",
        ])
        .expect("bridge-lab native QUIC transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicNative);
        assert_eq!(
            effective_bridge_agent_command(
                args.bridge_transport,
                args.agent_command.as_deref(),
                args.agent_path.as_deref()
            )
            .expect("bridge-lab native QUIC path becomes effective command"),
            "'/tmp/rustle' quic-bridge-agent"
        );
    }

    #[test]
    fn bridge_lab_accepts_hidden_auto_quic_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "bridge-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--bridge-transport",
            "auto-quic",
            "--agent-path",
            "/tmp/rustle",
        ])
        .expect("bridge-lab auto QUIC transport subcommand must parse");

        let Some(CommandKind::BridgeLab(args)) = cli.command else {
            panic!("expected bridge-lab subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::AutoQuic);
        assert_eq!(args.agent_path.as_deref(), Some("/tmp/rustle"));
    }

    #[test]
    fn quic_agent_subcommand_accepts_bind_and_mtu() {
        let cli = Cli::try_parse_from([
            "rustle",
            "quic-agent",
            "--bind",
            "127.0.0.1:0",
            "--mtu",
            "1200",
        ])
        .expect("quic-agent subcommand must parse");

        let Some(CommandKind::QuicAgent(args)) = cli.command else {
            panic!("expected quic-agent subcommand");
        };
        assert_eq!(args.bind, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn quic_bridge_agent_subcommand_accepts_bind() {
        let cli = Cli::try_parse_from(["rustle", "quic-bridge-agent", "--bind", "127.0.0.1:0"])
            .expect("quic-bridge-agent subcommand must parse");

        let Some(CommandKind::QuicBridgeAgent(args)) = cli.command else {
            panic!("expected quic-bridge-agent subcommand");
        };
        assert_eq!(args.bind, "127.0.0.1:0".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn agent_lab_accepts_hidden_exec_transport_options() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--agent-command",
            "/tmp/rustle agent",
            "--mtu",
            "1200",
        ])
        .expect("agent-lab subcommand must parse");

        let Some(CommandKind::AgentLab(args)) = cli.command else {
            panic!("expected agent-lab subcommand");
        };
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
        assert_eq!(args.destination, "127.0.0.1:8080");
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn agent_lab_accepts_agent_path_option() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:8080",
            "--agent-path",
            "/opt/rustle dir/rustle",
        ])
        .expect("agent-lab with agent path option");

        let Some(CommandKind::AgentLab(args)) = cli.command else {
            panic!("expected agent-lab subcommand");
        };
        assert!(args.agent_command.is_none());
        assert_eq!(args.agent_path.as_deref(), Some("/opt/rustle dir/rustle"));
    }

    #[test]
    fn agent_udp_lab_accepts_hidden_exec_transport_options() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-udp-lab",
            "-r",
            "alice@example.com",
            "--destination",
            "127.0.0.1:5353",
            "--agent-command",
            "/tmp/rustle agent",
            "--request",
            "ping",
            "--messages",
            "4",
            "--pipeline",
            "2",
            "--summary",
            "--mtu",
            "1200",
        ])
        .expect("agent-udp-lab subcommand must parse");

        let Some(CommandKind::AgentUdpLab(args)) = cli.command else {
            panic!("expected agent-udp-lab subcommand");
        };
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
        assert_eq!(args.destination, "127.0.0.1:5353");
        assert_eq!(args.request, "ping");
        assert_eq!(args.messages, 4);
        assert_eq!(args.pipeline, 2);
        assert!(args.summary);
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn agent_dns_lab_accepts_transport_queries_and_remote() {
        let cli = Cli::try_parse_from([
            "rustle",
            "agent-dns-lab",
            "-r",
            "alice@example.com",
            "--dns-remote",
            "127.0.0.1:53",
            "--name",
            "rustle-smoke.example.com",
            "--queries",
            "4",
            "--bridge-transport",
            "quic-agent",
            "--agent-command",
            "/tmp/rustle quic-agent",
            "--agent-sessions",
            "1",
            "--mtu",
            "1200",
        ])
        .expect("agent-dns-lab subcommand must parse");

        let Some(CommandKind::AgentDnsLab(args)) = cli.command else {
            panic!("expected agent-dns-lab subcommand");
        };
        assert_eq!(args.dns_remote, "127.0.0.1:53");
        assert_eq!(args.name, "rustle-smoke.example.com");
        assert_eq!(args.queries, 4);
        assert_eq!(args.bridge_transport, BridgeTransportKind::QuicAgent);
        assert_eq!(
            args.agent_command.as_deref(),
            Some("/tmp/rustle quic-agent")
        );
        assert!(args.agent_path.is_none());
        assert_eq!(args.agent_sessions, 1);
        assert_eq!(args.mtu, 1200);
    }

    #[test]
    fn top_level_help_hides_development_subcommands() {
        let help = Cli::command().render_long_help().to_string();

        assert!(help.contains("CIDR"));
        assert!(help.contains("--remote"));
        assert!(help.contains("--password-file"));
        assert!(help.contains("--dns"));
        assert!(help.contains("--dns-remote"));
        assert!(!help.contains("--tun-ip"));
        assert!(!help.contains("--tun-prefix"));
        assert!(!help.contains("--mtu"));
        assert!(!help.contains("--name"));
        assert!(!help.contains("--udp-idle-timeout-ms"));
        assert!(!help.contains("--ssh-sessions"));
        assert!(!help.contains("--agent-sessions"));
        assert!(!help.contains("--bridge-transport"));
        assert!(!help.contains("--agent-command"));
        assert!(!help.contains("--agent-path"));
        assert!(!help.contains("direct-tcpip"));
        assert!(!help.contains("tun-capture"));
        assert!(!help.contains("bridge-lab"));
        assert!(!help.contains("agent-lab"));
        assert!(!help.contains("agent-udp-lab"));
        assert!(!help.contains("agent"));
    }

    #[test]
    fn tunnel_subcommand_accepts_multiple_targets_before_later_flags() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "--mtu",
            "1200",
            "--udp-idle-timeout-ms",
            "250",
        ])
        .expect("tunnel CLI with multiple targets");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(
            args.targets,
            vec![
                "10.0.0.0/8".parse::<Ipv4Net>().unwrap(),
                "172.16.0.0/12".parse::<Ipv4Net>().unwrap()
            ]
        );
        assert_eq!(args.mtu, 1200);
        assert_eq!(args.udp_idle_timeout_ms, 250);
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
    }

    #[test]
    fn tunnel_subcommand_accepts_hidden_agent_transport_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--agent-command",
            "/tmp/rustle agent",
        ])
        .expect("tunnel CLI with hidden agent transport");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert_eq!(args.agent_command.as_deref(), Some("/tmp/rustle agent"));
        assert!(args.agent_path.is_none());
    }

    #[test]
    fn tunnel_subcommand_accepts_hidden_agent_path_switch() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tunnel",
            "-r",
            "alice@example.com",
            "--target",
            "10.0.0.0/8",
            "--bridge-transport",
            "agent",
            "--agent-path",
            "/opt/rustle dir/rustle",
        ])
        .expect("tunnel CLI with hidden agent path");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        assert_eq!(args.bridge_transport, BridgeTransportKind::Agent);
        assert!(args.agent_command.is_none());
        assert_eq!(args.agent_path.as_deref(), Some("/opt/rustle dir/rustle"));
    }

    #[test]
    fn tun_capture_accepts_hidden_packet_limit_for_smokes() {
        let cli = Cli::try_parse_from([
            "rustle",
            "tun-capture",
            "--target",
            "10.0.0.5/32",
            "--exit-after-packets",
            "1",
        ])
        .expect("tun-capture smoke packet limit");

        let Some(CommandKind::TunCapture(args)) = cli.command else {
            panic!("expected tun-capture subcommand");
        };
        assert_eq!(
            args.targets,
            vec!["10.0.0.5/32".parse::<Ipv4Net>().unwrap()]
        );
        assert_eq!(args.exit_after_packets, Some(1));
    }
}
