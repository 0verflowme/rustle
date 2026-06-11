use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::env;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Bytes, BytesMut};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use ipnet::Ipv4Net;
use ring::{digest, hmac};
use russh::client::{self, AuthResult, Config, Handle, Handler};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use smoltcp::iface::{Config as SmolConfig, Interface, Route, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Cidr};
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tun_rs::DeviceBuilder;

#[allow(dead_code)]
mod agent_client;
#[allow(dead_code)]
mod agent_proto;
mod agent_runtime;
mod agent_transport;
mod dns;
mod platform;
mod ssh_bridge;
#[allow(dead_code)]
mod tcp_core;

const DEFAULT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);
const DEFAULT_TUN_PREFIX: u8 = 24;
const DEFAULT_MTU: u16 = 1300;
const PACKET_BUF_SIZE: usize = 2048;
const REMOTE_BACKLOG_BYTES_PER_FLOW: usize = 2 * 1024 * 1024;
const REMOTE_BACKLOG_BYTES_TOTAL: usize = 128 * 1024 * 1024;
const TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const UDP_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS: u64 = 60_000;
#[cfg(test)]
const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration =
    Duration::from_millis(DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS);
const UDP_DATAGRAMS_PER_ASSOCIATION: usize = 128;
const MAX_AGENT_UDP_LAB_MESSAGES: usize = 1_000_000;
const MAX_IN_FLIGHT_DNS_QUERIES: usize = 128;
const MAX_ACTIVE_UDP_ASSOCIATIONS: usize = 512;
const DNS_EVENT_CHANNEL_DEPTH: usize = MAX_IN_FLIGHT_DNS_QUERIES;
const UDP_RESPONSE_EVENT_CHANNEL_DEPTH: usize = 1024;
const UDP_CLOSE_EVENT_CHANNEL_DEPTH: usize = MAX_ACTIVE_UDP_ASSOCIATIONS;
const _: () = assert!(DNS_EVENT_CHANNEL_DEPTH >= MAX_IN_FLIGHT_DNS_QUERIES);
const _: () = assert!(UDP_CLOSE_EVENT_CHANNEL_DEPTH >= MAX_ACTIVE_UDP_ASSOCIATIONS);
const MAX_DIRECT_ACTIVE_CHANNELS: usize = 512;
const MAX_DIRECT_OPENING_CHANNELS: usize = 32;
const MAX_AGENT_ACTIVE_STREAMS: usize = tcp_core::DEFAULT_MAX_ACTIVE_FLOWS;
const MAX_AGENT_OPENING_STREAMS: usize = 128;
const DEFAULT_SSH_SESSIONS: usize = 4;
const MAX_SSH_SESSIONS: usize = 16;
const AUTO_AGENT_SESSIONS: usize = 0;
const DEFAULT_AGENT_SESSIONS: usize = AUTO_AGENT_SESSIONS;
const MAX_AUTO_AGENT_SESSIONS: usize = 4;
const AGENT_LANE_BACKOFF_BASE: Duration = Duration::from_millis(250);
const AGENT_LANE_BACKOFF_MAX: Duration = Duration::from_secs(30);
const AGENT_FAST_START_WARMUP_DELAY: Duration = Duration::from_millis(100);
const DEFAULT_SSH_CONNECT_TIMEOUT_SECS: u64 = 15;
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);
const BRIDGE_LAB_EVENT_BATCH: usize = 64;
const REMOTE_CLOSE_DEFER_FLUSHES: u8 = 2;
const SSH_PASSWORD_FILE_ENV: &str = "RUSTLE_SSH_PASSWORD_FILE";
const AGENT_INITIAL_CONNECT_BATCH: usize = 4;
const AGENT_INITIAL_CONNECT_RETRY_ROUNDS: usize = 1;
const AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS: usize = 3;
const DEFAULT_AGENT_COMMAND: &str = "rustle agent";
const POSIX_REMOTE_PLATFORM_PROBE_COMMAND: &str = "uname -s 2>/dev/null; uname -m 2>/dev/null";
const WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Write-Output 'Windows'; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { Write-Output 'arm64' } else { Write-Output $env:PROCESSOR_ARCHITECTURE }\"";
const POSIX_REMOTE_AGENT_UPLOAD_COMMAND: &str = "set -eu; umask 077; base=${TMPDIR:-/tmp}; dir=; cleanup() { [ -n \"$dir\" ] && rm -rf \"$dir\"; }; trap cleanup EXIT HUP INT TERM; dir=$(mktemp -d \"$base/rustle-agent.XXXXXX\"); chmod 700 \"$dir\"; p=\"$dir/rustle-agent\"; cat > \"$p\"; chmod 700 \"$p\"; trap - EXIT HUP INT TERM; printf '%s\\n' \"$p\"";
const WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $d=$env:TEMP; if ([string]::IsNullOrWhiteSpace($d)) { $d=$env:TMP }; if ([string]::IsNullOrWhiteSpace($d)) { $d=[IO.Path]::GetTempPath() }; $dir=Join-Path -Path $d -ChildPath ('rustle-agent-{0}-{1}' -f $PID,[Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $dir -Force | Out-Null; $p=Join-Path -Path $dir -ChildPath 'rustle-agent.exe'; $stdin=[Console]::OpenStandardInput(); try { $out=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $stdin.CopyTo($out) } finally { $out.Dispose(); $stdin.Dispose() } } catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }; [Console]::Out.WriteLine($p)\"";
const RUSTLE_AGENT_DIR_ENV: &str = "RUSTLE_AGENT_DIR";

#[derive(Debug, Parser)]
#[command(name = "rustle", about = "User-space SSH network pivot")]
struct Cli {
    #[command(flatten)]
    compact: CompactTunnelArgs,

    #[command(subcommand)]
    command: Option<CommandKind>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
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

    /// Remote helper: run the Rustle agent protocol on stdin/stdout.
    #[command(hide = true)]
    Agent(AgentArgs),
}

#[derive(Debug, Clone, ClapArgs)]
struct SshArgs {
    /// SSH server, either host or host:port.
    #[arg(short = 'r', long = "remote")]
    ssh_server: Option<String>,

    /// SSH username. Usually supplied as user@host in --remote.
    #[arg(short = 'u', long = "user")]
    ssh_user: Option<String>,

    /// Private key path for public-key authentication.
    #[arg(short = 'i', long = "identity")]
    identity: Option<PathBuf>,

    /// Use password authentication. If no value is supplied, prompt interactively.
    #[arg(
        short = 'p',
        long = "password",
        num_args = 0..=1,
        require_equals = true,
        conflicts_with = "password_file"
    )]
    password: Option<Option<String>>,

    /// Read the SSH password from a local file instead of argv or a prompt.
    #[arg(
        long = "password-file",
        value_name = "PATH",
        conflicts_with = "password"
    )]
    password_file: Option<PathBuf>,

    /// Skip host-key verification. Intended for controlled development labs only.
    #[arg(long = "insecure-accept-host-key")]
    insecure_accept_host_key: bool,

    /// Trust and record a new SSH host key, but still reject changed known keys.
    #[arg(
        long = "accept-new-host-key",
        conflicts_with = "insecure_accept_host_key"
    )]
    accept_new_host_key: bool,

    /// OpenSSH known_hosts file to use for host-key verification.
    #[arg(long = "known-hosts")]
    known_hosts: Option<PathBuf>,

    /// Timeout for establishing the SSH control TCP connection.
    #[arg(
        long = "ssh-connect-timeout",
        default_value_t = DEFAULT_SSH_CONNECT_TIMEOUT_SECS,
        value_name = "SECONDS",
        hide = true
    )]
    ssh_connect_timeout_secs: u64,
}

#[derive(Debug, Clone, ClapArgs)]
struct CompactTunnelArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// Explicit IPv4 CIDRs to route into the tunnel.
    #[arg(value_name = "CIDR", value_parser = parse_target_cidr)]
    targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP, hide = true)]
    tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX, hide = true)]
    tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU, hide = true)]
    mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name", hide = true)]
    name: Option<String>,

    /// Configure the host resolver to send DNS queries through Rustle.
    #[arg(long = "dns")]
    configure_dns: bool,

    /// Remote DNS TCP resolver to use for intercepted UDP/53 queries.
    #[arg(long = "dns-remote", default_value = "127.0.0.53:53")]
    dns_remote: String,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    agent_sessions: usize,

    /// Hidden switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    agent_path: Option<String>,

    /// Hidden lab override for generic UDP association idle cleanup.
    #[arg(
        long = "udp-idle-timeout-ms",
        default_value_t = DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
        hide = true
    )]
    udp_idle_timeout_ms: u64,
}

#[derive(Debug, Parser)]
struct DirectTcpipArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// TCP target to open from the remote SSH server, in host:port form.
    #[arg(short = 'd', long = "destination", default_value = "1.1.1.1:80")]
    destination: String,

    /// Raw request payload to send through the direct-tcpip channel.
    #[arg(long = "request")]
    request: Option<String>,
}

#[derive(Debug, Parser)]
struct TunCaptureArgs {
    /// Explicit IPv4 CIDRs to route into the TUN device.
    #[arg(short = 't', long = "target", required = true, num_args = 1.., value_parser = parse_target_cidr)]
    targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX)]
    tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name")]
    name: Option<String>,

    /// Exit cleanly after capturing this many packets. Intended for smoke tests.
    #[arg(long = "exit-after-packets", hide = true)]
    exit_after_packets: Option<u64>,
}

#[derive(Debug, Parser)]
struct TunnelArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// Explicit IPv4 CIDRs to route into the TUN device.
    #[arg(short = 't', long = "target", required = true, num_args = 1.., value_parser = parse_target_cidr)]
    targets: Vec<Ipv4Net>,

    /// TUN interface IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    tun_ip: Ipv4Addr,

    /// TUN interface IPv4 prefix length.
    #[arg(long = "tun-prefix", default_value_t = DEFAULT_TUN_PREFIX)]
    tun_prefix: u8,

    /// TUN interface MTU.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    mtu: u16,

    /// Optional requested interface name. On macOS, omit this to let utun pick.
    #[arg(long = "name")]
    name: Option<String>,

    /// Configure the host resolver to send DNS queries through Rustle.
    #[arg(long = "dns")]
    configure_dns: bool,

    /// Remote DNS TCP resolver to use for intercepted UDP/53 queries.
    #[arg(long = "dns-remote", default_value = "127.0.0.53:53")]
    dns_remote: String,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    agent_sessions: usize,

    /// Hidden switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    agent_path: Option<String>,

    /// Hidden lab override for generic UDP association idle cleanup.
    #[arg(
        long = "udp-idle-timeout-ms",
        default_value_t = DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS,
        hide = true
    )]
    udp_idle_timeout_ms: u64,
}

#[derive(Debug, Parser)]
struct BridgeLabArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// IPv4 TCP target to open from the remote SSH server, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    destination: String,

    /// Raw request payload to send through the synthetic local TCP flow.
    #[arg(long = "request")]
    request: Option<String>,

    /// Synthetic client IPv4 address.
    #[arg(long = "client-ip", default_value_t = Ipv4Addr::new(10, 255, 255, 2))]
    client_ip: Ipv4Addr,

    /// Synthetic gateway/TUN IPv4 address.
    #[arg(long = "tun-ip", default_value_t = DEFAULT_TUN_IP)]
    tun_ip: Ipv4Addr,

    /// Number of synthetic TCP flows to multiplex through one SSH connection.
    #[arg(long = "connections", default_value_t = 1)]
    connections: usize,

    /// Hidden lab tolerance for chaos tests that intentionally fail some flows.
    #[arg(long = "min-completed", hide = true)]
    min_completed: Option<usize>,

    /// Hidden lab deadline override in milliseconds.
    #[arg(long = "deadline-ms", hide = true)]
    deadline_ms: Option<u64>,

    /// Hidden lab switch for comparing direct-tcpip with the framed agent transport.
    #[arg(
        long = "bridge-transport",
        value_enum,
        default_value = "agent",
        hide = true
    )]
    bridge_transport: BridgeTransportKind,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", hide = true, conflicts_with = "agent_path")]
    agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", hide = true, conflicts_with = "agent_command")]
    agent_path: Option<String>,

    /// Print a compact benchmark summary instead of response bodies.
    #[arg(long = "summary", hide = true)]
    summary: bool,

    /// Number of SSH transports to open for flow hashing.
    #[arg(long = "ssh-sessions", default_value_t = DEFAULT_SSH_SESSIONS, hide = true)]
    ssh_sessions: usize,

    /// Number of Rustle agent exec transports to open for flow hashing.
    #[arg(long = "agent-sessions", default_value_t = DEFAULT_AGENT_SESSIONS, hide = true)]
    agent_sessions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BridgeTransportKind {
    Auto,
    DirectTcpip,
    Agent,
}

#[derive(Clone, Copy, Debug)]
struct BridgeRuntimeOptions {
    ssh_sessions: usize,
    agent_sessions: usize,
    fast_start_auto_agent_lanes: bool,
}

#[derive(Debug, Parser)]
struct AgentLabArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// IPv4 TCP target to open from the remote agent, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    destination: String,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", conflicts_with = "agent_path")]
    agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", conflicts_with = "agent_command")]
    agent_path: Option<String>,

    /// Raw request payload to send through the agent stream.
    #[arg(long = "request")]
    request: Option<String>,

    /// MTU advertised to the remote agent.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    mtu: u16,
}

#[derive(Debug, Parser)]
struct AgentUdpLabArgs {
    #[command(flatten)]
    ssh: SshArgs,

    /// IPv4 UDP target to open from the remote agent, in ip:port form.
    #[arg(short = 'd', long = "destination")]
    destination: String,

    /// Raw remote shell command that starts the Rustle agent on stdin/stdout.
    #[arg(long = "agent-command", conflicts_with = "agent_path")]
    agent_command: Option<String>,

    /// Remote executable path to quote before appending the `agent` subcommand.
    #[arg(long = "agent-path", conflicts_with = "agent_command")]
    agent_path: Option<String>,

    /// Raw UDP datagram payload to send through the agent stream.
    #[arg(long = "request", default_value = "rustle-agent-udp-ping")]
    request: String,

    /// Number of UDP datagrams to send on one agent association.
    #[arg(long = "messages", default_value_t = 2)]
    messages: usize,

    /// Maximum datagrams to keep outstanding before reading responses.
    #[arg(long = "pipeline", default_value_t = UDP_DATAGRAMS_PER_ASSOCIATION)]
    pipeline: usize,

    /// Print a compact benchmark summary instead of response datagrams.
    #[arg(long = "summary", hide = true)]
    summary: bool,

    /// MTU advertised to the remote agent.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    mtu: u16,
}

#[derive(Debug, Parser)]
struct AgentArgs {
    /// MTU advertised to the local Rustle controller.
    #[arg(long = "mtu", default_value_t = DEFAULT_MTU)]
    mtu: u16,
}

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
        Some(CommandKind::Agent(args)) => run_agent(args).await,
        None => run_compact_tunnel(cli.compact).await,
    }
}

async fn run_agent(args: AgentArgs) -> Result<()> {
    agent_runtime::run_stdio(agent_runtime::AgentRuntimeConfig::new(args.mtu)).await
}

async fn run_agent_lab(args: AgentLabArgs) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), run_agent_lab_inner(args))
        .await
        .context("agent lab timed out")?
}

async fn run_agent_lab_inner(args: AgentLabArgs) -> Result<()> {
    let destination = parse_ipv4_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));

    let agent_command =
        effective_agent_command(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let connector = SshAgentBridgeConnector::new(args.ssh.clone(), agent_command, args.mtu);
    let agent_runtime = connector.connect_primary().await?;
    let mut stream = agent_runtime
        .transport
        .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: destination.ip,
            destination_port: destination.port,
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        })
        .await
        .with_context(|| {
            format!(
                "agent failed to open TCP stream to {}:{}",
                destination.ip, destination.port
            )
        })?;
    let stream_id = stream.stream_id();
    stream
        .send_data(Bytes::copy_from_slice(request.as_bytes()))
        .await
        .context("failed to send request through Rustle agent")?;
    stream
        .send_eof()
        .await
        .context("failed to send EOF through Rustle agent")?;

    let mut response = Vec::new();
    let mut saw_eof = false;
    loop {
        let frame = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("agent stream closed before response"))?;
        match frame.kind {
            agent_proto::AgentFrameKind::Data => {
                response.extend_from_slice(&frame.payload);
            }
            agent_proto::AgentFrameKind::Eof => {
                saw_eof = true;
            }
            agent_proto::AgentFrameKind::Close => break,
            agent_proto::AgentFrameKind::Reset => {
                let message = String::from_utf8_lossy(&frame.payload);
                bail!("agent reset stream {stream_id}: {message}");
            }
            other => bail!("unexpected Rustle agent frame {other:?}"),
        }
    }

    if !saw_eof {
        bail!("agent closed stream {stream_id} before EOF");
    }

    let mut stdout = io::stdout();
    stdout
        .write_all(&response)
        .await
        .context("failed to write agent response to stdout")?;
    stdout.flush().await.context("failed to flush stdout")?;

    let _ = stream.close().await;
    agent_runtime.disconnect("agent-lab done").await?;
    Ok(())
}

async fn run_agent_udp_lab(args: AgentUdpLabArgs) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), run_agent_udp_lab_inner(args))
        .await
        .context("agent UDP lab timed out")?
}

async fn run_agent_udp_lab_inner(args: AgentUdpLabArgs) -> Result<()> {
    if args.messages == 0 {
        bail!("agent-udp-lab --messages must be greater than zero");
    }
    if args.messages > MAX_AGENT_UDP_LAB_MESSAGES {
        bail!(
            "agent-udp-lab --messages must not exceed {}",
            MAX_AGENT_UDP_LAB_MESSAGES
        );
    }
    if args.pipeline == 0 {
        bail!("agent-udp-lab --pipeline must be greater than zero");
    }

    let destination = parse_ipv4_destination(&args.destination)?;
    let agent_command =
        effective_agent_command(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let connector = SshAgentBridgeConnector::new(args.ssh.clone(), agent_command, args.mtu);
    let agent_runtime = connector.connect_primary().await?;
    let mut stream = agent_runtime
        .transport
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: destination.ip,
            destination_port: destination.port,
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        })
        .await
        .with_context(|| {
            format!(
                "agent failed to open UDP stream to {}:{}",
                destination.ip, destination.port
            )
        })?;
    let stream_id = stream.stream_id();
    let request = Bytes::copy_from_slice(args.request.as_bytes());

    let mut stdout = io::stdout();
    let started_at = StdInstant::now();
    let mut sent = 0_usize;
    let mut received = 0_usize;
    let mut response_bytes = 0_usize;
    while received < args.messages {
        while sent < args.messages && sent.saturating_sub(received) < args.pipeline {
            stream
                .send_data(request.clone())
                .await
                .context("failed to send UDP datagram through Rustle agent")?;
            sent += 1;
        }

        let frame = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("agent UDP stream closed before response"))?;
        match frame.kind {
            agent_proto::AgentFrameKind::Data => {
                response_bytes = response_bytes.saturating_add(frame.payload.len());
                if !args.summary {
                    stdout
                        .write_all(&frame.payload)
                        .await
                        .context("failed to write UDP response to stdout")?;
                    stdout
                        .write_all(b"\n")
                        .await
                        .context("failed to write UDP response separator to stdout")?;
                }
                received += 1;
            }
            agent_proto::AgentFrameKind::Close => break,
            agent_proto::AgentFrameKind::Reset => {
                let message = String::from_utf8_lossy(&frame.payload);
                bail!("agent reset UDP stream {stream_id}: {message}");
            }
            other => bail!("unexpected Rustle agent UDP frame {other:?}"),
        }
    }

    if received != args.messages {
        bail!(
            "agent UDP stream {stream_id} returned {received} responses, expected {}",
            args.messages
        );
    }

    let elapsed = started_at.elapsed();
    if args.summary {
        println!(
            "agent_udp_lab_summary messages={} pipeline={} response_bytes={} elapsed_ms={}",
            args.messages,
            args.pipeline,
            response_bytes,
            elapsed.as_millis()
        );
    }

    stdout.flush().await.context("failed to flush stdout")?;
    let _ = stream.close().await;
    agent_runtime.disconnect("agent-udp-lab done").await?;
    Ok(())
}

type AgentBridgeConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AgentBridgeTransport>> + Send + 'a>>;
type AgentBridgeConnectManyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<AgentBridgeTransport>>> + Send + 'a>>;

trait AgentBridgeConnector: Send + Sync {
    fn primary_command(&self) -> &str;
    fn connect_initial(&self, desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_>;
    fn connect_primary(&self) -> AgentBridgeConnectFuture<'_>;
    fn connect_command<'a>(&'a self, agent_command: &'a str) -> AgentBridgeConnectFuture<'a>;
}

#[derive(Clone)]
struct SshAgentBridgeConnector {
    ssh: SshArgs,
    agent_command: String,
    mtu: u16,
}

impl SshAgentBridgeConnector {
    fn new(ssh: SshArgs, agent_command: String, mtu: u16) -> Self {
        Self {
            ssh,
            agent_command,
            mtu,
        }
    }

    async fn connect_primary_transport(&self) -> Result<AgentBridgeTransport> {
        match connect_agent_bridge_transport_fresh_ssh_command(
            &self.ssh,
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
                match connect_uploaded_agent_bridge_transport(&self.ssh, self.mtu).await {
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
            connect_agent_bridge_transport_fresh_ssh_command(&self.ssh, agent_command, self.mtu)
                .await
        })
    }
}

async fn connect_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;
    let mut transports = Vec::with_capacity(desired_sessions);

    let first = connector.connect_primary().await?;
    let additional_agent_command = first.agent_command.clone();
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

async fn connect_auto_agent_bridge_transports_from_connector(
    connector: &dyn AgentBridgeConnector,
    desired_sessions: usize,
) -> Result<Vec<AgentBridgeTransport>> {
    let desired_sessions = resolve_agent_session_count(desired_sessions);
    validate_agent_session_count(desired_sessions)?;

    let first = connector.connect_primary().await?;
    eprintln!("{}", format_agent_fast_start_message(1, desired_sessions));
    Ok(vec![first])
}

fn format_agent_established_message(established: usize, desired: usize) -> String {
    format!("agent: established {established}/{desired} exec transport(s)")
}

fn format_agent_fast_start_message(established: usize, desired: usize) -> String {
    let message = format_agent_established_message(established, desired);
    let warming = desired.saturating_sub(established);
    if warming == 0 {
        message
    } else {
        format!("{message}; warming {warming} remaining exec transport(s) in background")
    }
}

fn should_fast_start_agent_lanes(
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

async fn connect_agent_bridge_transport_fresh_ssh_command(
    ssh: &SshArgs,
    agent_command: &str,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    // A Rustle agent lane is deliberately a fresh SSH connection with one exec
    // channel, not another channel multiplexed over an existing SSH carrier.
    let handle = connect_ssh(ssh).await?;
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

    Ok(AgentBridgeTransport {
        carrier: AgentBridgeCarrier::Ssh(handle),
        transport,
        agent_command: agent_command.to_owned(),
    })
}

async fn connect_uploaded_agent_bridge_transport(
    ssh: &SshArgs,
    mtu: u16,
) -> Result<AgentBridgeTransport> {
    connect_uploaded_agent_bridge_transport_with_command(ssh, mtu)
        .await
        .map(|(transport, _)| transport)
}

async fn connect_uploaded_agent_bridge_transport_with_command(
    ssh: &SshArgs,
    mtu: u16,
) -> Result<(AgentBridgeTransport, String)> {
    let handle = connect_ssh(ssh).await?;
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
    let agent_command = uploaded_agent_command(&remote_path, platform);
    let transport = connect_agent_bridge_transport_on_handle(handle, &agent_command, mtu)
        .await
        .with_context(|| format!("uploaded Rustle agent failed to start from {remote_path}"))?;
    Ok((transport, agent_command))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemotePlatform {
    os: &'static str,
    arch: &'static str,
}

impl RemotePlatform {
    fn local() -> Result<Self> {
        let os = normalize_local_os(env::consts::OS)
            .ok_or_else(|| anyhow!("local OS {} is not supported for upload", env::consts::OS))?;
        let arch = normalize_local_arch(env::consts::ARCH).ok_or_else(|| {
            anyhow!(
                "local architecture {} is not supported for upload",
                env::consts::ARCH
            )
        })?;
        Ok(Self { os, arch })
    }

    fn is_windows(self) -> bool {
        self.os == "windows"
    }

    fn label(self) -> String {
        format!("{}/{}", self.os, self.arch)
    }
}

fn uploaded_agent_command(remote_path: &str, platform: RemotePlatform) -> String {
    if platform.is_windows() {
        uploaded_windows_agent_command(remote_path)
    } else {
        uploaded_posix_agent_command(remote_path)
    }
}

fn uploaded_posix_agent_command(remote_path: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "tmp={quoted_path}; refdir=\"$tmp.refs\"; marker=\"$refdir/$$\"; owner=$$; mkdir -p \"$refdir\"; : > \"$marker\"; cleanup_parent() {{ parent=${{tmp%/*}}; base=${{parent##*/}}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac; }}; cleanup() {{ rm -f \"$marker\"; for stale in \"$refdir\"/*; do [ -e \"$stale\" ] || continue; pid=${{stale##*/}}; case \"$pid\" in *[!0-9]*) continue;; esac; kill -0 \"$pid\" 2>/dev/null || rm -f \"$stale\"; done; if rmdir \"$refdir\" 2>/dev/null; then rm -f \"$tmp\"; cleanup_parent; fi; }}; ( trap '' HUP; while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup ) </dev/null >/dev/null 2>&1 & trap cleanup EXIT HUP INT TERM; \"$tmp\" agent; status=$?; trap - EXIT HUP INT TERM; cleanup; exit \"$status\""
    )
}

fn uploaded_windows_agent_command(remote_path: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $tmp={quoted_path}; $refdir=$tmp+'.refs'; $marker=Join-Path -Path $refdir -ChildPath $PID; New-Item -ItemType Directory -Force -LiteralPath $refdir | Out-Null; New-Item -ItemType File -Force -LiteralPath $marker | Out-Null; function CleanupParent {{ $parent=[IO.Path]::GetDirectoryName($tmp); if ($parent -and ([IO.Path]::GetFileName($parent) -like 'rustle-agent-*')) {{ Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }} }}; function Cleanup {{ Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $refdir) {{ Get-ChildItem -LiteralPath $refdir -ErrorAction SilentlyContinue | ForEach-Object {{ $id=0; if ([int]::TryParse($_.Name,[ref]$id)) {{ if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) {{ Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }} }} }}; try {{ Remove-Item -LiteralPath $refdir -Force -ErrorAction Stop; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; CleanupParent }} catch {{}} }} }}; try {{ & $tmp agent; $status=$LASTEXITCODE }} finally {{ Cleanup }}; exit $status\""
    )
}

async fn upload_agent_binary(
    handle: &Handle<Client>,
    local_path: &Path,
    platform: RemotePlatform,
) -> Result<String> {
    let expected_sha256 = sha256_file_hex(local_path).await?;
    let file = tokio::fs::File::open(local_path).await.with_context(|| {
        format!(
            "failed to open local Rustle binary {}",
            local_path.display()
        )
    })?;
    let output =
        run_remote_command_collect(handle, remote_agent_upload_command(platform), Some(file))
            .await
            .context("failed to upload Rustle agent binary")?;
    output.ensure_success("remote agent upload")?;
    let remote_path = String::from_utf8(output.stdout)
        .context("remote upload path was not valid UTF-8")?
        .trim()
        .to_owned();
    if remote_path.is_empty() {
        bail!("remote upload did not return a path");
    }
    if let Err(err) =
        verify_uploaded_agent_binary(handle, &remote_path, platform, &expected_sha256).await
    {
        if let Err(cleanup_err) =
            cleanup_uploaded_agent_binary(handle, &remote_path, platform).await
        {
            eprintln!(
                "agent: failed to remove unverified uploaded helper {remote_path}: {cleanup_err:#}"
            );
        }
        return Err(err).with_context(|| {
            format!("uploaded Rustle agent integrity verification failed for {remote_path}")
        });
    }
    Ok(remote_path)
}

fn remote_agent_upload_command(platform: RemotePlatform) -> &'static str {
    if platform.is_windows() {
        WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND
    } else {
        POSIX_REMOTE_AGENT_UPLOAD_COMMAND
    }
}

async fn verify_uploaded_agent_binary(
    handle: &Handle<Client>,
    remote_path: &str,
    platform: RemotePlatform,
    expected_sha256: &str,
) -> Result<()> {
    let command = uploaded_agent_sha256_command(remote_path, platform);
    let output = run_remote_command_collect(handle, &command, None)
        .await
        .context("failed to run remote uploaded-agent hash command")?;
    output.ensure_success("remote uploaded-agent hash")?;
    let actual = String::from_utf8(output.stdout)
        .context("remote uploaded-agent hash output was not valid UTF-8")?
        .trim()
        .to_ascii_lowercase();
    if !is_sha256_hex(&actual) {
        bail!("remote uploaded-agent hash output was not a SHA-256 digest: {actual:?}");
    }
    if actual != expected_sha256 {
        bail!("remote uploaded-agent SHA-256 mismatch: expected {expected_sha256}, got {actual}");
    }
    Ok(())
}

async fn cleanup_uploaded_agent_binary(
    handle: &Handle<Client>,
    remote_path: &str,
    platform: RemotePlatform,
) -> Result<()> {
    let command = uploaded_agent_cleanup_command(remote_path, platform);
    let output = run_remote_command_collect(handle, &command, None)
        .await
        .context("failed to run remote uploaded-agent cleanup command")?;
    output.ensure_success("remote uploaded-agent cleanup")
}

fn uploaded_agent_sha256_command(remote_path: &str, platform: RemotePlatform) -> String {
    if platform.is_windows() {
        uploaded_windows_agent_sha256_command(remote_path)
    } else {
        uploaded_posix_agent_sha256_command(remote_path)
    }
}

fn uploaded_posix_agent_sha256_command(remote_path: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "p={quoted_path}; if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$p\" | awk '{{print $1}}'; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 \"$p\" | awk '{{print $1}}'; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r \"$p\" | awk '{{print $1}}'; else echo 'no remote SHA-256 command found' >&2; exit 127; fi"
    )
}

fn uploaded_windows_agent_sha256_command(remote_path: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $p={quoted_path}; (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()\""
    )
}

fn uploaded_agent_cleanup_command(remote_path: &str, platform: RemotePlatform) -> String {
    if platform.is_windows() {
        uploaded_windows_agent_cleanup_command(remote_path)
    } else {
        uploaded_posix_agent_cleanup_command(remote_path)
    }
}

fn uploaded_posix_agent_cleanup_command(remote_path: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "p={quoted_path}; rm -f \"$p\"; rm -rf \"$p.refs\"; parent=${{p%/*}}; base=${{parent##*/}}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac"
    )
}

fn uploaded_windows_agent_cleanup_command(remote_path: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $p={quoted_path}; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath ($p+'.refs') -Recurse -Force -ErrorAction SilentlyContinue; $parent=[IO.Path]::GetDirectoryName($p); if ($parent -and ([IO.Path]::GetFileName($parent) -like 'rustle-agent-*')) {{ Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }}\""
    )
}

async fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("failed to open {} for SHA-256", path.display()))?;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("failed to read {} for SHA-256", path.display()))?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(lower_hex(context.finish().as_ref()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn local_agent_binary_for_platform(
    current_exe: &Path,
    platform: RemotePlatform,
) -> Result<PathBuf> {
    let local = RemotePlatform::local()?;
    if platform == local {
        return Ok(current_exe.to_path_buf());
    }

    let candidates = local_agent_binary_candidates(current_exe, platform);
    if let Some(candidate) = candidates.iter().find(|path| path.is_file()) {
        return Ok(candidate.clone());
    }

    let candidate_list = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "no local Rustle agent binary found for remote {}; install `rustle agent` on the remote host or place a matching sidecar beside the local binary. Checked: {candidate_list}",
        platform.label()
    )
}

fn local_agent_binary_candidates(current_exe: &Path, platform: RemotePlatform) -> Vec<PathBuf> {
    dedupe_paths(agent_binary_candidates_in_dirs(
        platform,
        &local_agent_search_dirs(current_exe),
    ))
}

fn local_agent_search_dirs(current_exe: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(paths) = env::var_os(RUSTLE_AGENT_DIR_ENV) {
        dirs.extend(env::split_paths(&paths));
    }
    if let Some(parent) = current_exe.parent() {
        dirs.push(parent.to_path_buf());
        if let Some(package_parent) = parent.parent() {
            dirs.push(package_parent.to_path_buf());
        }
    }
    if let Ok(cwd) = env::current_dir() {
        dirs.push(cwd);
    }
    dedupe_paths(dirs)
}

fn agent_binary_candidates_in_dirs(platform: RemotePlatform, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let suffix = if platform.is_windows() { ".exe" } else { "" };
    let binary = format!("rustle{suffix}");
    let platform_key = format!("{}-{}", platform.os, platform.arch);
    let mut candidates = Vec::new();

    for dir in dirs {
        candidates.push(dir.join(format!("rustle-agent-{platform_key}{suffix}")));
        candidates.push(dir.join(format!("rustle-{platform_key}{suffix}")));

        for triple in remote_platform_target_triples(platform) {
            candidates.push(dir.join(format!("rustle-agent-{triple}{suffix}")));
            candidates.push(dir.join(format!("rustle-{triple}{suffix}")));
            candidates.push(dir.join(format!("rustle-{triple}")).join(&binary));
            candidates.push(
                dir.join(format!("rustle-{triple}"))
                    .join(format!("rustle-agent{suffix}")),
            );
        }
    }

    dedupe_paths(candidates)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    deduped
}

fn remote_platform_target_triples(platform: RemotePlatform) -> &'static [&'static str] {
    match (platform.os, platform.arch) {
        ("linux", "x86_64") => &["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"],
        ("linux", "aarch64") => &["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"],
        ("macos", "x86_64") => &["x86_64-apple-darwin"],
        ("macos", "aarch64") => &["aarch64-apple-darwin"],
        ("windows", "x86_64") => &["x86_64-pc-windows-msvc"],
        ("windows", "aarch64") => &["aarch64-pc-windows-msvc"],
        _ => &[],
    }
}

async fn probe_remote_platform(handle: &Handle<Client>) -> Result<RemotePlatform> {
    match run_remote_command_collect(handle, POSIX_REMOTE_PLATFORM_PROBE_COMMAND, None).await {
        Ok(output) if output.exit_status == Some(0) => {
            if let Ok(platform) = parse_remote_platform_probe(&output.stdout) {
                return Ok(platform);
            }
        }
        _ => {}
    }

    let output = run_remote_command_collect(handle, WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND, None)
        .await
        .context("failed to probe remote platform")?;
    output.ensure_success("remote platform probe")?;
    parse_remote_platform_probe(&output.stdout)
}

fn parse_remote_platform_probe(stdout: &[u8]) -> Result<RemotePlatform> {
    let stdout =
        String::from_utf8(stdout.to_vec()).context("remote platform probe was not valid UTF-8")?;
    let mut lines = stdout.lines();
    let remote_os = lines
        .next()
        .and_then(normalize_remote_os)
        .ok_or_else(|| anyhow!("remote OS probe did not return a supported OS"))?;
    let remote_arch = lines
        .next()
        .and_then(normalize_remote_arch)
        .ok_or_else(|| anyhow!("remote architecture probe did not return a supported arch"))?;

    Ok(RemotePlatform {
        os: remote_os,
        arch: remote_arch,
    })
}

struct RemoteCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
}

impl RemoteCommandOutput {
    fn ensure_success(&self, context: &str) -> Result<()> {
        if self.exit_status == Some(0) {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&self.stderr);
        bail!(
            "{context} failed with exit status {:?}: {}",
            self.exit_status,
            stderr.trim()
        );
    }
}

async fn run_remote_command_collect(
    handle: &Handle<Client>,
    command: &str,
    input: Option<tokio::fs::File>,
) -> Result<RemoteCommandOutput> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("failed to open SSH session channel")?;
    channel
        .exec(true, command.as_bytes().to_vec())
        .await
        .with_context(|| format!("failed to exec remote command: {command}"))?;

    if let Some(file) = input {
        channel
            .data(file)
            .await
            .context("failed to write remote command stdin")?;
    }
    channel
        .eof()
        .await
        .context("failed to close remote command stdin")?;

    let mut output = RemoteCommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_status: None,
    };
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
            russh::ChannelMsg::ExtendedData { data, .. } => {
                output.stderr.extend_from_slice(&data);
            }
            russh::ChannelMsg::ExitStatus { exit_status } => {
                output.exit_status = Some(exit_status);
            }
            _ => {}
        }
    }
    Ok(output)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn effective_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    match (agent_command, agent_path) {
        (Some(_), Some(_)) => {
            bail!("--agent-command cannot be combined with --agent-path");
        }
        (Some(command), None) => {
            if command.trim().is_empty() {
                bail!("--agent-command must not be empty");
            }
            Ok(command.to_owned())
        }
        (None, Some(path)) => {
            if path.trim().is_empty() {
                bail!("--agent-path must not be empty");
            }
            Ok(format!("{} agent", shell_quote(path)))
        }
        (None, None) => Ok(DEFAULT_AGENT_COMMAND.to_owned()),
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn normalize_local_os(value: &str) -> Option<&'static str> {
    match value {
        "linux" => Some("linux"),
        "macos" => Some("macos"),
        "windows" => Some("windows"),
        _ => None,
    }
}

fn normalize_remote_os(value: &str) -> Option<&'static str> {
    let value = value.trim();
    match value {
        "Linux" => Some("linux"),
        "Darwin" => Some("macos"),
        "Windows" => Some("windows"),
        _ if value.starts_with("MINGW64_NT")
            || value.starts_with("MINGW32_NT")
            || value.starts_with("MSYS_NT")
            || value.starts_with("CYGWIN_NT") =>
        {
            Some("windows")
        }
        _ => None,
    }
}

fn normalize_local_arch(value: &str) -> Option<&'static str> {
    match value {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        _ => None,
    }
}

fn normalize_remote_arch(value: &str) -> Option<&'static str> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "x86_64" | "amd64" => Some("x86_64"),
        "aarch64" | "arm64" => Some("aarch64"),
        _ => None,
    }
}

async fn connect_bridge_runtime(
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
            ));
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
        BridgeTransportKind::Auto => {
            let desired_agent_sessions = resolve_agent_session_count(options.agent_sessions);
            let connector: Arc<dyn AgentBridgeConnector> = Arc::new(SshAgentBridgeConnector::new(
                ssh.clone(),
                agent_command.to_owned(),
                mtu,
            ));
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
        if transports.iter().all(|transport| {
            transport.transport.peer_hello().capabilities & agent_proto::CAP_UDP_ASSOCIATE != 0
        }) {
            return Ok(());
        }
        bail!(
            "agent DNS transport to IPv4 resolver {} requires UDP associate support",
            remote.host
        );
    }
    if transports.iter().all(|transport| {
        transport.transport.peer_hello().capabilities & agent_proto::CAP_TCP_CONNECT_HOST != 0
    }) {
        return Ok(());
    }
    bail!(
        "agent DNS transport to hostname {} requires hostname TCP connect support",
        remote.host
    )
}

async fn run_direct_tcpip(args: DirectTcpipArgs) -> Result<()> {
    let destination = parse_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));

    let handle = connect_ssh(&args.ssh).await?;

    let mut channel = handle
        .channel_open_direct_tcpip(
            destination.host.clone(),
            destination.port.into(),
            "127.0.0.1",
            0,
        )
        .await
        .with_context(|| {
            format!(
                "failed to open SSH direct-tcpip channel to {}:{}",
                destination.host, destination.port
            )
        })?;

    channel
        .data(request.as_bytes())
        .await
        .context("failed to write request to SSH channel")?;
    channel
        .eof()
        .await
        .context("failed to send EOF to SSH channel")?;

    let mut stdout = io::stdout();
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                stdout
                    .write_all(&data)
                    .await
                    .context("failed to write channel data to stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, .. } => {
                stdout
                    .write_all(&data)
                    .await
                    .context("failed to write channel extended data to stdout")?;
            }
            russh::ChannelMsg::Eof => break,
            russh::ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    bail!("remote channel returned non-zero exit status {exit_status}");
                }
            }
            _ => {}
        }
    }

    stdout.flush().await.context("failed to flush stdout")?;
    handle
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await?;
    Ok(())
}

async fn run_compact_tunnel(args: CompactTunnelArgs) -> Result<()> {
    if args.targets.is_empty() {
        bail!("missing target CIDR; usage: rustle -r user@host 10.0.0.0/8 [172.16.0.0/12]");
    }

    run_tunnel(TunnelArgs {
        ssh: args.ssh,
        targets: args.targets,
        tun_ip: args.tun_ip,
        tun_prefix: args.tun_prefix,
        mtu: args.mtu,
        name: args.name,
        configure_dns: args.configure_dns,
        dns_remote: args.dns_remote,
        ssh_sessions: args.ssh_sessions,
        agent_sessions: args.agent_sessions,
        bridge_transport: args.bridge_transport,
        agent_command: args.agent_command,
        agent_path: args.agent_path,
        udp_idle_timeout_ms: args.udp_idle_timeout_ms,
    })
    .await
}

async fn run_tun_capture(args: TunCaptureArgs) -> Result<()> {
    validate_tun_args(&args)?;
    let target_routes = expand_target_routes(&args.targets)?;

    let builder =
        configured_tun_builder(args.tun_ip, args.tun_prefix, args.mtu, args.name.as_deref())?;

    let dev = builder
        .build_async()
        .context("failed to create TUN device; root/administrator privileges are required")?;
    let if_name = dev.name().context("failed to read TUN interface name")?;
    let if_index = dev
        .if_index()
        .context("failed to read TUN interface index")?;

    eprintln!(
        "tun: created {if_name} index={if_index} mtu={} addr={}/{}",
        args.mtu, args.tun_ip, args.tun_prefix
    );

    let routes = add_target_routes(&target_routes, &if_name, if_index, args.tun_ip)?;
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = capture_packets(dev, flow_manager, args.exit_after_packets).await;
    drop(routes);
    result
}

async fn run_tunnel(args: TunnelArgs) -> Result<()> {
    validate_tunnel_args(&args)?;
    let agent_command =
        effective_agent_command(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let target_routes = expand_target_routes(&args.targets)?;
    let dns_remote = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    let ssh_control_ip = args
        .ssh
        .ssh_server
        .as_deref()
        .map(|remote| ssh_control_ip_to_protect(remote, &target_routes))
        .transpose()?
        .flatten();

    let builder =
        configured_tun_builder(args.tun_ip, args.tun_prefix, args.mtu, args.name.as_deref())?;
    let dev = builder
        .build_async()
        .context("failed to create TUN device; root/administrator privileges are required")?;
    let if_name = dev.name().context("failed to read TUN interface name")?;
    let if_index = dev
        .if_index()
        .context("failed to read TUN interface index")?;

    eprintln!(
        "tun: created {if_name} index={if_index} mtu={} addr={}/{}",
        args.mtu, args.tun_ip, args.tun_prefix
    );

    let (bridge_runtime, dns_transport) = connect_bridge_runtime(
        &args.ssh,
        args.bridge_transport,
        &agent_command,
        args.mtu,
        Some(&dns_remote),
        BridgeRuntimeOptions {
            ssh_sessions: args.ssh_sessions,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: true,
        },
    )
    .await?;
    let control_route = match ssh_control_ip {
        Some(ip) => add_ssh_control_route(ip)?,
        None => None,
    };
    let routes = add_target_routes(&target_routes, &if_name, if_index, args.tun_ip)?;
    let (dns_guard, local_dns_proxy) = if args.configure_dns {
        let virtual_dns_ip = virtual_dns_ip(args.tun_ip, args.tun_prefix)?;
        let system_dns_ip = platform::system_dns_server_ip(virtual_dns_ip);
        let local_dns_proxy = if system_dns_ip.is_loopback() {
            Some(
                start_local_dns_proxy(system_dns_ip, dns_transport.clone(), dns_remote.clone())
                    .await
                    .with_context(|| {
                        format!("failed to start local DNS proxy on {system_dns_ip}:53")
                    })?,
            )
        } else {
            None
        };
        let guard = platform::configure_system_dns(&if_name, system_dns_ip)
            .with_context(|| format!("failed to configure system DNS for {if_name}"))?;
        eprintln!("dns: configured host resolver to use DNS {system_dns_ip}");
        (Some(guard), local_dns_proxy)
    } else {
        (None, None)
    };
    let route_parts = target_route_parts(&target_routes);

    let flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        args.tun_prefix,
        &route_parts,
        usize::from(args.mtu),
    )
    .context("failed to initialize userspace TCP flow manager")?;

    let result = run_tunnel_loop(
        dev,
        flow_manager,
        bridge_runtime,
        dns_transport,
        dns_remote,
        Duration::from_millis(args.udp_idle_timeout_ms),
    )
    .await;
    drop(dns_guard);
    drop(local_dns_proxy);
    drop(routes);
    drop(control_route);
    result
}

fn configured_tun_builder(
    tun_ip: Ipv4Addr,
    tun_prefix: u8,
    mtu: u16,
    name: Option<&str>,
) -> Result<DeviceBuilder> {
    let mut builder = DeviceBuilder::new().ipv4(tun_ip, tun_prefix, None).mtu(mtu);
    if let Some(name) = name {
        builder = builder.name(name);
    }
    platform::prepare_tun_builder(builder)
}

struct BridgeLabClient {
    flow: tcp_core::FlowKey,
    client_ip: Ipv4Addr,
    client_port: u16,
    iface: Interface,
    device: tcp_core::PacketQueueDevice,
    sockets: SocketSet<'static>,
    handle: smoltcp::iface::SocketHandle,
    sent_request: bool,
    saw_bridge_close: bool,
    response: Vec<u8>,
}

fn receive_lab_client_response(client: &mut BridgeLabClient) -> Result<usize> {
    let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
    let mut received = 0_usize;
    while socket.can_recv() {
        let mut buf = [0_u8; 16 * 1024];
        let len = socket
            .recv_slice(&mut buf)
            .context("failed to receive synthetic lab response")?;
        if len == 0 {
            break;
        }
        client.response.extend_from_slice(&buf[..len]);
        received = received.saturating_add(len);
    }
    Ok(received)
}

fn bridge_lab_client_complete(client: &BridgeLabClient) -> bool {
    client.sent_request && client.saw_bridge_close && bridge_lab_response_complete(&client.response)
}

fn bridge_lab_response_complete(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = &response[..header_end];
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let Some(content_length) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    }) else {
        return false;
    };

    response.len() >= header_end + 4 + content_length
}

async fn run_bridge_lab(args: BridgeLabArgs) -> Result<()> {
    if args.connections == 0 {
        bail!("bridge-lab --connections must be greater than zero");
    }
    let min_completed = args.min_completed.unwrap_or(args.connections);
    if min_completed == 0 || min_completed > args.connections {
        bail!("bridge-lab --min-completed must be between 1 and --connections");
    }
    if args.deadline_ms.is_some_and(|deadline| deadline == 0) {
        bail!("bridge-lab --deadline-ms must be greater than zero");
    }
    let base_client_port = 49152_u16;
    if args.connections > usize::from(u16::MAX - base_client_port) + 1 {
        bail!("bridge-lab --connections is too large for the synthetic client port range");
    }

    let destination = parse_ipv4_destination(&args.destination)?;
    let request = args
        .request
        .clone()
        .unwrap_or_else(|| default_http_request(&destination.host));
    let agent_command =
        effective_agent_command(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let (bridge_runtime, _) = connect_bridge_runtime(
        &args.ssh,
        args.bridge_transport,
        &agent_command,
        DEFAULT_MTU,
        None,
        BridgeRuntimeOptions {
            ssh_sessions: args.ssh_sessions,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: false,
        },
    )
    .await?;

    let mut flow_manager = tcp_core::FlowManager::new(
        args.tun_ip,
        DEFAULT_TUN_PREFIX,
        &[tcp_core::Ipv4NetParts::new(destination.ip, 32)],
        usize::from(DEFAULT_MTU),
    )
    .context("failed to initialize bridge lab FlowManager")?;

    let mut clients = Vec::with_capacity(args.connections);
    for offset in 0..args.connections {
        let client_port = base_client_port + offset as u16;
        let flow = tcp_core::FlowKey::tcp(
            args.client_ip,
            client_port,
            destination.ip,
            destination.port,
        );
        let (iface, device, sockets, handle) = synthetic_lab_client(
            args.client_ip,
            args.tun_ip,
            destination.ip,
            destination.port,
            client_port,
        )?;
        clients.push(BridgeLabClient {
            flow,
            client_ip: args.client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            saw_bridge_close: false,
            response: Vec::new(),
        });
    }

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let mut bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
    let mut remote_backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
    let mut ready_flow_ids = Vec::new();
    let mut flow_keys = Vec::new();
    let mut backlog_flow_ids = Vec::new();
    let mut closed_flows = Vec::new();
    let mut bridge_event_closed_flows = Vec::new();
    let mut expired_flows = Vec::new();
    let mut removable_flows = Vec::new();
    let started_at = StdInstant::now();
    let deadline_secs = 15_u64.max((args.connections as u64).saturating_div(2));
    let deadline = tokio::time::Instant::now()
        + args
            .deadline_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(deadline_secs));

    loop {
        let now = smol_now(started_at);
        let mut made_progress = false;
        for index in 0..clients.len() {
            let packets = {
                let client = &mut clients[index];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut flow_manager)?
            };
            made_progress |= route_lab_packets_to_clients(packets, &mut clients)? > 0;
        }
        made_progress |= pump_lab_manager_to_clients(now, &mut flow_manager, &mut clients)? > 0;

        ensure_bridges(
            &mut flow_manager,
            &mut bridges,
            &bridge_runtime,
            event_tx.clone(),
            &mut ready_flow_ids,
        )?;

        for lab_client in &mut clients {
            let socket = lab_client.sockets.get_mut::<tcp::Socket>(lab_client.handle);
            if !lab_client.sent_request && socket.can_send() {
                socket
                    .send_slice(request.as_bytes())
                    .context("failed to send synthetic lab request")?;
                lab_client.sent_request = true;
                made_progress = true;
            }
            made_progress |= receive_lab_client_response(lab_client)? > 0;
        }

        for index in 0..clients.len() {
            let packets = {
                let client = &mut clients[index];
                drain_lab_client_to_manager(now, client, &mut flow_manager)?
            };
            made_progress |= route_lab_packets_to_clients(packets, &mut clients)? > 0;
        }
        let drain_stats =
            drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
        made_progress |= drain_stats.bytes_to_bridge > 0;

        let mut processed_bridge_events = 0_usize;
        while processed_bridge_events < BRIDGE_LAB_EVENT_BATCH
            && !remote_backlogs.should_pause_bridge_events()
        {
            let Ok(event) = event_rx.try_recv() else {
                break;
            };
            processed_bridge_events += 1;
            match &event {
                ssh_bridge::BridgeEvent::Closed { id }
                | ssh_bridge::BridgeEvent::RemoteEof { id }
                    if clients.iter().any(|client| client.flow == id.key) =>
                {
                    if let Some(client) = clients.iter_mut().find(|client| client.flow == id.key) {
                        client.saw_bridge_close = true;
                    }
                }
                _ => {}
            }
            let _ = handle_bridge_event_into(
                event,
                &mut flow_manager,
                &mut remote_backlogs,
                now,
                &mut bridge_event_closed_flows,
            )?;
            for closed_flow in bridge_event_closed_flows.drain(..) {
                bridges.remove(&closed_flow);
            }
        }
        made_progress |= processed_bridge_events > 0;
        let backlog_bytes_before_flush = remote_backlogs.total_bytes();
        remote_backlogs.flush_all_into(
            &mut flow_manager,
            now,
            &mut backlog_flow_ids,
            &mut closed_flows,
        )?;
        made_progress |= remote_backlogs.total_bytes() != backlog_bytes_before_flush;
        for closed_flow in closed_flows.drain(..) {
            bridges.remove(&closed_flow);
            made_progress = true;
        }
        made_progress |= expire_stale_flows(
            &mut flow_manager,
            &mut bridges,
            &mut remote_backlogs,
            now,
            &mut expired_flows,
        ) > 0;

        made_progress |= pump_lab_manager_to_clients(now, &mut flow_manager, &mut clients)? > 0;
        for lab_client in &mut clients {
            made_progress |= receive_lab_client_response(lab_client)? > 0;
        }
        made_progress |= prune_closed_flows(
            &mut flow_manager,
            &mut bridges,
            &mut remote_backlogs,
            &mut removable_flows,
        )? > 0;

        let completed = clients
            .iter()
            .filter(|client| bridge_lab_client_complete(client))
            .count();
        if completed >= min_completed {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let sent = clients.iter().filter(|client| client.sent_request).count();
            let closed = clients
                .iter()
                .filter(|client| client.saw_bridge_close)
                .count();
            let response_bytes: usize = clients.iter().map(|client| client.response.len()).sum();
            bail!(
                "bridge lab timed out; completed={completed}/{min_completed}, sent_requests={sent}/{}, closed={closed}/{}, response_bytes={response_bytes}",
                clients.len(),
                clients.len()
            );
        }

        if !made_progress {
            tokio::time::sleep(Duration::from_millis(5)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    let elapsed = started_at.elapsed();
    let response_bytes: usize = clients.iter().map(|client| client.response.len()).sum();
    if args.summary {
        let completed = clients
            .iter()
            .filter(|client| bridge_lab_client_complete(client))
            .count();
        println!(
            "bridge_lab_summary connections={} completed={} response_bytes={} elapsed_ms={}",
            clients.len(),
            completed,
            response_bytes,
            elapsed.as_millis()
        );
    } else {
        let mut response = Vec::with_capacity(response_bytes);
        for client in &clients {
            response.extend_from_slice(&client.response);
        }
        io::stdout()
            .write_all(&response)
            .await
            .context("failed to write bridge lab response to stdout")?;
    }
    Ok(())
}

async fn capture_packets(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    exit_after_packets: Option<u64>,
) -> Result<()> {
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let started_at = StdInstant::now();
    let mut captured_packets = 0_u64;
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                eprintln!("signal: {} received", signal?);
                return Ok(());
            }
            result = dev.recv(&mut buf) => {
                let len = result.context("failed to read packet from TUN device")?;
                captured_packets = captured_packets.saturating_add(1);
                match parse_ipv4_metadata(&buf[..len]) {
                    Ok(packet) => {
                        eprintln!(
                            "packet: len={} total_len={} proto={} src={} dst={}",
                            len,
                            packet.total_len,
                            packet.protocol,
                            packet.src,
                            packet.dst
                        );
                        match tcp_core::parse_ipv4_tcp_segment(&buf[..len]) {
                            Ok(Some(segment)) => {
                                eprintln!(
                                    "tcp: {}:{} -> {}:{} syn={} ack={} fin={} rst={} opening_syn={} payload_len={}",
                                    segment.flow.src_ip,
                                    segment.flow.src_port,
                                    segment.flow.dst_ip,
                                    segment.flow.dst_port,
                                    segment.flags.syn,
                                    segment.flags.ack,
                                    segment.flags.fin,
                                    segment.flags.rst,
                                    segment.flags.is_opening_syn(),
                                    segment.payload_len
                                );
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!("tcp: parse_error={err}");
                            }
                        }

                        flow_manager
                            .ingest_packet_into(
                                smol_now(started_at),
                                &buf[..len],
                                &mut outbound_packets,
                            )
                            .context("failed to feed packet into userspace TCP engine")?;
                        let _ = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                        for snapshot in flow_manager.snapshots() {
                            eprintln!(
                                "flow: {:?} state={:?} buffered_rx={}",
                                snapshot.key,
                                snapshot.state,
                                snapshot.buffered_rx
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("packet: len={len} parse_error={err}");
                    }
                }
                if exit_after_packets
                    .is_some_and(|limit| captured_packets >= limit)
                {
                    eprintln!("capture: exit-after-packets reached ({captured_packets})");
                    return Ok(());
                }
            }
        }
    }
}

async fn shutdown_signal() -> Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?;
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl+C")?;
                Ok("interrupt")
            }
            received = sigterm.recv() => {
                received.context("SIGTERM stream closed")?;
                Ok("terminate")
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to listen for Ctrl+C")?;
        Ok("interrupt")
    }
}

fn smol_now(started_at: StdInstant) -> SmolInstant {
    let millis = started_at.elapsed().as_millis().min(i64::MAX as u128) as i64;
    SmolInstant::from_millis(millis)
}

fn validate_tun_args(args: &TunCaptureArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
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
    Ok(())
}

fn validate_tunnel_args(args: &TunnelArgs) -> Result<()> {
    let _ = expand_target_routes(&args.targets)?;
    let Some(remote) = args.ssh.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    let _ = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto | BridgeTransportKind::DirectTcpip
    ) {
        validate_ssh_session_count(args.ssh_sessions)?;
    }
    if matches!(
        args.bridge_transport,
        BridgeTransportKind::Auto | BridgeTransportKind::Agent
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

fn parse_target_cidr(input: &str) -> std::result::Result<Ipv4Net, String> {
    if let Ok(cidr) = input.parse::<Ipv4Net>() {
        return Ok(cidr);
    }

    let (addr, prefix) = input
        .split_once('/')
        .ok_or_else(|| format!("target CIDR must be IPv4/prefix, got {input}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("target CIDR prefix must be 0..=32, got {input}"))?;
    if prefix > 32 {
        return Err(format!("target CIDR prefix must be <= 32, got {input}"));
    }

    let parts = parse_abbreviated_ipv4_octets(addr, input)?;
    let ip = Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]);
    Ipv4Net::new(ip, prefix).map_err(|err| format!("invalid target CIDR {input}: {err}"))
}

fn parse_abbreviated_ipv4_octets(
    addr: &str,
    original: &str,
) -> std::result::Result<[u8; 4], String> {
    let raw_parts = addr.split('.').collect::<Vec<_>>();
    if raw_parts.is_empty() || raw_parts.len() > 4 {
        return Err(format!(
            "invalid abbreviated IPv4 address in target CIDR {original}"
        ));
    }

    let mut octets = [0_u8; 4];
    for (index, part) in raw_parts.iter().enumerate() {
        if part.is_empty() {
            return Err(format!(
                "invalid abbreviated IPv4 address in target CIDR {original}"
            ));
        }
        octets[index] = part
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 octet {part:?} in target CIDR {original}"))?;
    }
    Ok(octets)
}

fn expand_target_routes(targets: &[Ipv4Net]) -> Result<Vec<Ipv4Net>> {
    if targets.is_empty() {
        bail!("at least one target CIDR is required");
    }
    let mut expanded = Vec::with_capacity(targets.len().saturating_add(1));
    for target in targets {
        if target.prefix_len() == 0 {
            expanded.push("0.0.0.0/1".parse().expect("valid split default route"));
            expanded.push("128.0.0.0/1".parse().expect("valid split default route"));
        } else if !expanded.contains(target) {
            expanded.push(*target);
        }
    }

    if expanded.len() > smoltcp::config::IFACE_MAX_ROUTE_COUNT {
        bail!(
            "too many target CIDRs: {} requested, maximum is {}",
            expanded.len(),
            smoltcp::config::IFACE_MAX_ROUTE_COUNT
        );
    }
    Ok(expanded)
}

fn ssh_control_ip_to_protect(ssh_server: &str, targets: &[Ipv4Net]) -> Result<Option<Ipv4Addr>> {
    let ssh_addr = parse_ssh_target(ssh_server, None)?.addr;
    let addrs = ssh_addr
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SSH server address {ssh_addr}"))?;

    for addr in addrs {
        if let IpAddr::V4(ip) = addr.ip() {
            for target in targets {
                if target.contains(&ip) {
                    return Ok(Some(ip));
                }
            }
        }
    }

    Ok(None)
}

fn target_route_parts(targets: &[Ipv4Net]) -> Vec<tcp_core::Ipv4NetParts> {
    targets
        .iter()
        .map(|target| tcp_core::Ipv4NetParts::new(target.network(), target.prefix_len()))
        .collect()
}

async fn run_tunnel_loop(
    dev: tun_rs::AsyncDevice,
    mut flow_manager: tcp_core::FlowManager,
    bridge_runtime: BridgeRuntime,
    dns_transport: DnsTransport,
    dns_remote: Destination,
    udp_association_idle_timeout: Duration,
) -> Result<()> {
    let mut buf = vec![0_u8; PACKET_BUF_SIZE];
    let mut outbound_packets = Vec::with_capacity(tcp_core::PACKET_QUEUE_CAPACITY);
    let mut ready_flow_ids = Vec::new();
    let mut flow_keys = Vec::new();
    let mut backlog_flow_ids = Vec::new();
    let mut backlog_closed_flows = Vec::new();
    let mut bridge_event_closed_flows = Vec::new();
    let mut expired_flows = Vec::new();
    let mut removable_flows = Vec::new();
    let started_at = StdInstant::now();
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let (dns_tx, mut dns_rx) = mpsc::channel(DNS_EVENT_CHANNEL_DEPTH);
    let (udp_response_tx, mut udp_response_rx) = mpsc::channel(UDP_RESPONSE_EVENT_CHANNEL_DEPTH);
    let (udp_close_tx, mut udp_close_rx) = mpsc::channel(UDP_CLOSE_EVENT_CHANNEL_DEPTH);
    let udp_events = UdpAssociationEvents {
        response_tx: udp_response_tx,
        close_tx: udp_close_tx,
    };
    let mut bridges = HashMap::<tcp_core::FlowKey, ssh_bridge::FlowBridge>::new();
    let mut udp_associations = HashMap::<UdpFlowKey, UdpAssociation>::new();
    let mut remote_backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
    let mut dns_inflight = DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES);
    let mut udp_inflight = DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS);
    let mut stats = TunnelStats::new();
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    let mut stats_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + STATS_LOG_INTERVAL,
        STATS_LOG_INTERVAL,
    );
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            signal = &mut shutdown => {
                eprintln!("signal: {} received", signal?);
                eprintln!(
                    "stats: final {}",
                    stats.status_line(
                        flow_manager.active_flow_count(),
                        bridges.len(),
                        &remote_backlogs,
                        &dns_inflight,
                        &udp_inflight,
                        bridge_runtime.agent_snapshot().await,
                    )
                );
                return Ok(());
            }
            result = dev.recv(&mut buf) => {
                let len = result.context("failed to read packet from TUN device")?;
                stats.record_tun_rx(len);
                if let Some(request) = parse_dns_request_for_tunnel(&buf[..len]) {
                    stats.dns_forwarded = stats.dns_forwarded.saturating_add(1);
                    eprintln!(
                        "dns: forwarding UDP query {}:{} -> {}:{} over SSH to {}:{}",
                        request.src_ip,
                        request.src_port,
                        request.dst_ip,
                        request.dst_port,
                        dns_remote.host,
                        dns_remote.port
                    );
                    if dns_inflight.try_admit() {
                        spawn_dns_query(
                            dns_transport.clone(),
                            dns_remote.clone(),
                            request,
                            dns_tx.clone(),
                        );
                    } else {
                        eprintln!(
                            "dns: dropping query because {} DNS queries are already in flight",
                            dns_inflight.max()
                        );
                        stats.dns_dropped = stats.dns_dropped.saturating_add(1);
                        stats.record_dns_response(false);
                        let tun_write = write_dns_event_to_tun(
                            &dev,
                            DnsResponseEvent {
                                request,
                                result: Err("DNS in-flight limit reached".to_owned()),
                            },
                        )
                        .await?;
                        stats.record_tun_write(tun_write);
                    }
                    continue;
                }
                if let Some(request) = parse_udp_request_for_agent_tunnel(&buf[..len]) {
                    if let Some(agent) = dns_transport.agent_transport() {
                        admit_udp_datagram(
                            agent,
                            request,
                            &mut udp_associations,
                            &mut udp_inflight,
                            udp_events.clone(),
                            udp_association_idle_timeout,
                            &mut stats,
                        );
                    } else {
                        drop_unsupported_direct_udp(&request, &mut stats);
                    }
                    continue;
                }

                let now = smol_now(started_at);
                flow_manager
                    .ingest_packet_into(now, &buf[..len], &mut outbound_packets)
                    .context("failed to feed packet into userspace TCP engine")?;
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                let admission_stats = ensure_bridges(
                    &mut flow_manager,
                    &mut bridges,
                    &bridge_runtime,
                    event_tx.clone(),
                    &mut ready_flow_ids,
                )?;
                stats.record_bridge_admission(admission_stats);
                let drain_stats =
                    drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
                stats.record_local_drain(drain_stats);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    smol_now(started_at),
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                stats.expired_flows = stats.expired_flows.saturating_add(expire_stale_flows(
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    smol_now(started_at),
                    &mut expired_flows,
                ) as u64);
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
            event = dns_rx.recv() => {
                if let Some(event) = event {
                    dns_inflight.complete();
                    let remote_ok = event.result.is_ok();
                    let tun_write = write_dns_event_to_tun(&dev, event).await?;
                    stats.record_dns_delivery(remote_ok, tun_write);
                }
            }
            event = udp_response_rx.recv() => {
                if let Some(event) = event {
                    let tun_write = write_udp_response_to_tun(&dev, event.key, event.payload).await?;
                    stats.record_udp_delivery(tun_write);
                }
            }
            event = udp_close_rx.recv() => {
                if let Some(event) = event {
                    udp_associations.remove(&event.key);
                    udp_inflight.complete();
                    if let Some(error) = event.error {
                        eprintln!(
                            "udp: association {}:{} -> {}:{} closed with error: {error}",
                            event.key.src_ip,
                            event.key.src_port,
                            event.key.dst_ip,
                            event.key.dst_port,
                        );
                        stats.record_udp_response(false);
                    }
                }
            }
            event = event_rx.recv(), if !remote_backlogs.should_pause_bridge_events() => {
                let Some(event) = event else {
                    bail!("SSH bridge event channel closed");
                };
                stats.record_bridge_event(&event);
                let now = smol_now(started_at);
                let outcome = handle_bridge_event_into(
                    event,
                    &mut flow_manager,
                    &mut remote_backlogs,
                    now,
                    &mut bridge_event_closed_flows,
                )?;
                stats.remote_backlog_overflows = stats
                    .remote_backlog_overflows
                    .saturating_add(outcome.remote_backlog_overflows);
                stats.stale_bridge_events = stats
                    .stale_bridge_events
                    .saturating_add(outcome.stale_bridge_events);
                for flow in bridge_event_closed_flows.drain(..) {
                    bridges.remove(&flow);
                }
                flow_manager.poll_into(now, &mut outbound_packets);
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    now,
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                stats.expired_flows = stats.expired_flows.saturating_add(
                    expire_stale_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        now,
                        &mut expired_flows,
                    ) as u64
                );
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
            _ = stats_tick.tick() => {
                eprintln!(
                    "stats: {}",
                    stats.status_line(
                        flow_manager.active_flow_count(),
                        bridges.len(),
                        &remote_backlogs,
                        &dns_inflight,
                        &udp_inflight,
                        bridge_runtime.agent_snapshot().await,
                    )
                );
            }
            _ = tick.tick() => {
                let now = smol_now(started_at);
                flow_manager.poll_into(now, &mut outbound_packets);
                let tun_write = write_packets_to_tun(&dev, &mut outbound_packets).await?;
                stats.record_tun_write(tun_write);
                flush_remote_backlogs_to_tun(
                    &dev,
                    &mut flow_manager,
                    &mut bridges,
                    &mut remote_backlogs,
                    now,
                    RemoteFlushScratch {
                        backlog_flow_ids: &mut backlog_flow_ids,
                        closed_flows: &mut backlog_closed_flows,
                        packets: &mut outbound_packets,
                    },
                    &mut stats,
                ).await?;
                let admission_stats = ensure_bridges(
                    &mut flow_manager,
                    &mut bridges,
                    &bridge_runtime,
                    event_tx.clone(),
                    &mut ready_flow_ids,
                )?;
                stats.record_bridge_admission(admission_stats);
                let drain_stats =
                    drain_local_bytes_to_bridges(&mut flow_manager, &mut bridges, &mut flow_keys)?;
                stats.record_local_drain(drain_stats);
                stats.expired_flows = stats.expired_flows.saturating_add(
                    expire_stale_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        now,
                        &mut expired_flows,
                    ) as u64
                );
                stats.pruned_flows = stats.pruned_flows.saturating_add(
                    prune_closed_flows(
                        &mut flow_manager,
                        &mut bridges,
                        &mut remote_backlogs,
                        &mut removable_flows,
                    )? as u64
                );
            }
        }
    }
}

fn parse_dns_request_for_tunnel(packet: &[u8]) -> Option<dns::UdpDnsRequest> {
    match dns::parse_udp_dns_request(packet) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("dns: packet parse failed: {err}");
            None
        }
    }
}

fn parse_udp_request_for_agent_tunnel(packet: &[u8]) -> Option<dns::UdpPacket> {
    match dns::parse_ipv4_udp_packet(packet) {
        Ok(Some(request)) if request.dst_port != dns::DNS_PORT => Some(request),
        Ok(_) => None,
        Err(err) => {
            eprintln!("udp: packet parse failed: {err}");
            None
        }
    }
}

#[derive(Debug)]
struct DnsResponseEvent {
    request: dns::UdpDnsRequest,
    result: std::result::Result<Bytes, String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

impl UdpFlowKey {
    fn from_packet(packet: &dns::UdpPacket) -> Self {
        Self {
            src_ip: packet.src_ip,
            src_port: packet.src_port,
            dst_ip: packet.dst_ip,
            dst_port: packet.dst_port,
        }
    }

    fn response_template(self) -> dns::UdpPacket {
        dns::UdpPacket {
            src_ip: self.src_ip,
            src_port: self.src_port,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port,
            payload: Bytes::new(),
        }
    }
}

#[derive(Debug)]
struct UdpAssociation {
    to_remote: mpsc::Sender<Bytes>,
}

#[derive(Clone)]
struct UdpAssociationEvents {
    response_tx: mpsc::Sender<UdpResponseEvent>,
    close_tx: mpsc::Sender<UdpClosedEvent>,
}

impl UdpAssociationEvents {
    fn try_send_response(&self, key: UdpFlowKey, payload: Bytes) -> bool {
        match self.response_tx.try_send(UdpResponseEvent { key, payload }) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    fn try_send_closed(&self, key: UdpFlowKey, error: Option<String>) -> bool {
        match self.close_tx.try_send(UdpClosedEvent { key, error }) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => false,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

#[derive(Debug)]
struct UdpResponseEvent {
    key: UdpFlowKey,
    payload: Bytes,
}

#[derive(Debug)]
struct UdpClosedEvent {
    key: UdpFlowKey,
    error: Option<String>,
}

#[derive(Debug)]
struct TunnelStats {
    started_at: StdInstant,
    tun_rx_packets: u64,
    tun_rx_bytes: u64,
    tun_tx_packets: u64,
    tun_tx_bytes: u64,
    tun_tx_dropped_packets: u64,
    tun_tx_dropped_bytes: u64,
    local_to_remote_bytes: u64,
    remote_to_local_bytes: u64,
    ssh_opened: u64,
    ssh_failed: u64,
    ssh_closed: u64,
    ssh_remote_eof: u64,
    ssh_open_latency_total_ms: u64,
    ssh_open_latency_max_ms: u64,
    ssh_open_deferred_active_limit: u64,
    ssh_open_deferred_open_limit: u64,
    dns_forwarded: u64,
    dns_ok: u64,
    dns_failed: u64,
    dns_dropped: u64,
    udp_forwarded: u64,
    udp_ok: u64,
    udp_failed: u64,
    udp_dropped: u64,
    expired_flows: u64,
    pruned_flows: u64,
    bridge_backpressure_events: u64,
    bridge_send_failures: u64,
    remote_backlog_overflows: u64,
    stale_bridge_events: u64,
}

impl TunnelStats {
    fn new() -> Self {
        Self {
            started_at: StdInstant::now(),
            tun_rx_packets: 0,
            tun_rx_bytes: 0,
            tun_tx_packets: 0,
            tun_tx_bytes: 0,
            tun_tx_dropped_packets: 0,
            tun_tx_dropped_bytes: 0,
            local_to_remote_bytes: 0,
            remote_to_local_bytes: 0,
            ssh_opened: 0,
            ssh_failed: 0,
            ssh_closed: 0,
            ssh_remote_eof: 0,
            ssh_open_latency_total_ms: 0,
            ssh_open_latency_max_ms: 0,
            ssh_open_deferred_active_limit: 0,
            ssh_open_deferred_open_limit: 0,
            dns_forwarded: 0,
            dns_ok: 0,
            dns_failed: 0,
            dns_dropped: 0,
            udp_forwarded: 0,
            udp_ok: 0,
            udp_failed: 0,
            udp_dropped: 0,
            expired_flows: 0,
            pruned_flows: 0,
            bridge_backpressure_events: 0,
            bridge_send_failures: 0,
            remote_backlog_overflows: 0,
            stale_bridge_events: 0,
        }
    }

    fn record_tun_rx(&mut self, len: usize) {
        self.tun_rx_packets = self.tun_rx_packets.saturating_add(1);
        self.tun_rx_bytes = self.tun_rx_bytes.saturating_add(len as u64);
    }

    fn record_tun_write(&mut self, write: TunWriteStats) {
        self.tun_tx_packets = self.tun_tx_packets.saturating_add(write.packets);
        self.tun_tx_bytes = self.tun_tx_bytes.saturating_add(write.bytes);
        self.tun_tx_dropped_packets = self
            .tun_tx_dropped_packets
            .saturating_add(write.dropped_packets);
        self.tun_tx_dropped_bytes = self
            .tun_tx_dropped_bytes
            .saturating_add(write.dropped_bytes);
    }

    fn record_dns_delivery(&mut self, remote_ok: bool, write: TunWriteStats) {
        let delivered = write.delivered_at_least_one_packet_without_drop();
        self.record_tun_write(write);
        self.record_dns_response(remote_ok && delivered);
    }

    fn record_udp_delivery(&mut self, write: TunWriteStats) {
        let delivered = write.delivered_at_least_one_packet_without_drop();
        self.record_tun_write(write);
        self.record_udp_response(delivered);
    }

    fn record_bridge_event(&mut self, event: &ssh_bridge::BridgeEvent) {
        match event {
            ssh_bridge::BridgeEvent::Opened { open_ms, .. } => {
                self.ssh_opened = self.ssh_opened.saturating_add(1);
                self.ssh_open_latency_total_ms =
                    self.ssh_open_latency_total_ms.saturating_add(*open_ms);
                self.ssh_open_latency_max_ms = self.ssh_open_latency_max_ms.max(*open_ms);
            }
            ssh_bridge::BridgeEvent::RemoteData { bytes, .. } => {
                self.remote_to_local_bytes = self
                    .remote_to_local_bytes
                    .saturating_add(bytes.len() as u64);
            }
            ssh_bridge::BridgeEvent::RemoteEof { .. } => {
                self.ssh_remote_eof = self.ssh_remote_eof.saturating_add(1);
            }
            ssh_bridge::BridgeEvent::Closed { .. } => {
                self.ssh_closed = self.ssh_closed.saturating_add(1);
            }
            ssh_bridge::BridgeEvent::Failed { .. } => {
                self.ssh_failed = self.ssh_failed.saturating_add(1);
            }
        }
    }

    fn record_local_drain(&mut self, stats: LocalDrainStats) {
        self.local_to_remote_bytes = self
            .local_to_remote_bytes
            .saturating_add(stats.bytes_to_bridge);
        self.bridge_backpressure_events = self
            .bridge_backpressure_events
            .saturating_add(stats.bridge_backpressure_events);
        self.bridge_send_failures = self
            .bridge_send_failures
            .saturating_add(stats.bridge_send_failures);
    }

    fn record_bridge_admission(&mut self, stats: BridgeAdmissionStats) {
        self.ssh_open_deferred_active_limit = self
            .ssh_open_deferred_active_limit
            .saturating_add(stats.deferred_active_limit);
        self.ssh_open_deferred_open_limit = self
            .ssh_open_deferred_open_limit
            .saturating_add(stats.deferred_open_limit);
    }

    fn record_dns_response(&mut self, remote_ok: bool) {
        if remote_ok {
            self.dns_ok = self.dns_ok.saturating_add(1);
        } else {
            self.dns_failed = self.dns_failed.saturating_add(1);
        }
    }

    fn record_udp_response(&mut self, remote_ok: bool) {
        if remote_ok {
            self.udp_ok = self.udp_ok.saturating_add(1);
        } else {
            self.udp_failed = self.udp_failed.saturating_add(1);
        }
    }

    fn status_line(
        &self,
        active_flows: usize,
        ssh_channels: usize,
        remote_backlogs: &RemoteBacklogs,
        dns_inflight: &DnsInflight,
        udp_inflight: &DnsInflight,
        agent: AgentBridgeSnapshot,
    ) -> String {
        let avg_open_ms = if self.ssh_opened == 0 {
            0
        } else {
            self.ssh_open_latency_total_ms / self.ssh_opened
        };

        format!(
            "uptime={} active_flows={} ssh_channels={} backlog_flows={} backlog_bytes={} tun_rx={}/{} tun_tx={}/{} tun_drop={}/{} tcp_l2r={} tcp_r2l={} dns=fwd:{} ok:{} fail:{} drop:{} inflight:{} udp=fwd:{} ok:{} fail:{} drop:{} active:{} ssh=open:{} fail:{} eof:{} close:{} open_ms=avg:{} max:{} defer=active:{} open:{} agent_reconnect=attempt:{} ok:{} fail:{} agent_lanes=total:{} desired:{} ok:{} fail:{} missing:{} quarantine:{} repairing:{} active:{} max_load:{} max_quarantine_ms:{} flow=expired:{} pruned:{} bridge_backpressure:{} bridge_send_fail:{} backlog_overflow:{} stale_bridge:{}",
            format_duration(self.started_at.elapsed()),
            active_flows,
            ssh_channels,
            remote_backlogs.active_flow_count(),
            format_bytes(remote_backlogs.total_bytes()),
            self.tun_rx_packets,
            format_bytes(self.tun_rx_bytes),
            self.tun_tx_packets,
            format_bytes(self.tun_tx_bytes),
            self.tun_tx_dropped_packets,
            format_bytes(self.tun_tx_dropped_bytes),
            format_bytes(self.local_to_remote_bytes),
            format_bytes(self.remote_to_local_bytes),
            self.dns_forwarded,
            self.dns_ok,
            self.dns_failed,
            self.dns_dropped,
            dns_inflight.current(),
            self.udp_forwarded,
            self.udp_ok,
            self.udp_failed,
            self.udp_dropped,
            udp_inflight.current(),
            self.ssh_opened,
            self.ssh_failed,
            self.ssh_remote_eof,
            self.ssh_closed,
            avg_open_ms,
            self.ssh_open_latency_max_ms,
            self.ssh_open_deferred_active_limit,
            self.ssh_open_deferred_open_limit,
            agent.reconnects.attempts,
            agent.reconnects.successes,
            agent.reconnects.failures,
            agent.lanes_total,
            agent.lanes_desired,
            agent.lanes_available,
            agent.lanes_failed,
            agent.lanes_missing,
            agent.lanes_quarantined,
            agent.lanes_repairing,
            agent.active_streams,
            agent.max_lane_load,
            agent.max_quarantine_ms,
            self.expired_flows,
            self.pruned_flows,
            self.bridge_backpressure_events,
            self.bridge_send_failures,
            self.remote_backlog_overflows,
            self.stale_bridge_events,
        )
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
struct BridgeAdmissionStats {
    deferred_active_limit: u64,
    deferred_open_limit: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
struct LocalDrainStats {
    bytes_to_bridge: u64,
    bridge_backpressure_events: u64,
    bridge_send_failures: u64,
}

#[cfg(test)]
#[derive(Debug, Default, Eq, PartialEq)]
struct BridgeEventOutcome {
    closed_flows: Vec<tcp_core::FlowKey>,
    remote_backlog_overflows: u64,
    stale_bridge_events: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
struct BridgeEventStats {
    remote_backlog_overflows: u64,
    stale_bridge_events: u64,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
struct TunWriteStats {
    packets: u64,
    bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
}

impl TunWriteStats {
    fn record_written(&mut self, len: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
    }

    fn record_dropped(&mut self, len: usize) {
        self.dropped_packets = self.dropped_packets.saturating_add(1);
        self.dropped_bytes = self.dropped_bytes.saturating_add(len as u64);
    }

    fn combine(&mut self, other: Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.dropped_packets = self.dropped_packets.saturating_add(other.dropped_packets);
        self.dropped_bytes = self.dropped_bytes.saturating_add(other.dropped_bytes);
    }

    fn delivered_at_least_one_packet_without_drop(&self) -> bool {
        self.packets > 0 && self.dropped_packets == 0
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let millis = duration.subsec_millis();
    format!("{seconds}.{millis:03}s")
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

#[derive(Debug)]
struct DnsInflight {
    max: usize,
    current: usize,
    dropped: u64,
    completed: u64,
}

impl DnsInflight {
    fn new(max: usize) -> Self {
        assert!(max > 0, "in-flight limit must be greater than zero");
        Self {
            max,
            current: 0,
            dropped: 0,
            completed: 0,
        }
    }

    fn max(&self) -> usize {
        self.max
    }

    fn current(&self) -> usize {
        self.current
    }

    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.dropped
    }

    #[cfg(test)]
    fn completed(&self) -> u64 {
        self.completed
    }

    fn try_admit(&mut self) -> bool {
        if self.current >= self.max {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }

        self.current += 1;
        true
    }

    fn complete(&mut self) {
        if self.current > 0 {
            self.current -= 1;
            self.completed = self.completed.saturating_add(1);
        }
    }
}

struct LocalDnsProxy {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalDnsProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_local_dns_proxy(
    bind_ip: Ipv4Addr,
    transport: DnsTransport,
    remote: Destination,
) -> Result<LocalDnsProxy> {
    let socket = Arc::new(
        UdpSocket::bind((bind_ip, dns::DNS_PORT))
            .await
            .with_context(|| format!("failed to bind local DNS proxy on {bind_ip}:53"))?,
    );
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_DNS_QUERIES));
    eprintln!("dns: local resolver proxy listening on {bind_ip}:53");

    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 4096];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(err) => {
                    eprintln!("dns: local resolver proxy receive failed: {err:#}");
                    break;
                }
            };
            let query = Bytes::copy_from_slice(&buf[..len]);
            let permit = match Arc::clone(&permits).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    eprintln!(
                        "dns: local resolver proxy dropping query from {peer} because the in-flight cap is reached"
                    );
                    if let Some(response) = dns::build_dns_servfail_response(query.as_ref()) {
                        let _ = socket.send_to(&response, peer).await;
                    }
                    continue;
                }
            };

            let socket = Arc::clone(&socket);
            let transport = transport.clone();
            let remote = remote.clone();
            tokio::spawn(async move {
                let _permit = permit;
                eprintln!(
                    "dns: forwarding local resolver query from {peer} over SSH to {}:{}",
                    remote.host, remote.port
                );
                let response =
                    match query_dns_over_transport(transport, &remote, query.as_ref()).await {
                        Ok(response) => response,
                        Err(err) => {
                            eprintln!("dns: local resolver proxy query failed for {peer}: {err:#}");
                            match dns::build_dns_servfail_response(query.as_ref()) {
                                Some(response) => Bytes::from(response),
                                None => return,
                            }
                        }
                    };
                if let Err(err) = socket.send_to(response.as_ref(), peer).await {
                    eprintln!("dns: local resolver proxy response to {peer} failed: {err:#}");
                }
            });
        }
    });

    Ok(LocalDnsProxy { task })
}

#[derive(Clone)]
enum DnsTransport {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
}

impl DnsTransport {
    fn agent_transport(&self) -> Option<ReconnectingAgentBridge> {
        match self {
            Self::Agent(agent) => Some(agent.clone()),
            Self::DirectTcpip(_) => None,
        }
    }
}

enum AgentIoStream {
    Bridge(AgentBridgeStream),
    #[cfg(test)]
    Raw(agent_transport::AgentStream),
}

impl AgentIoStream {
    async fn send_data(&self, bytes: impl Into<Bytes>) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_data(bytes).await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_data(bytes).await,
        }
    }

    async fn send_eof(&self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.send_eof().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.send_eof().await,
        }
    }

    async fn recv(&mut self) -> Option<agent_proto::AgentFrame> {
        match self {
            Self::Bridge(stream) => stream.recv().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.recv().await,
        }
    }

    async fn close(self) -> Result<()> {
        match self {
            Self::Bridge(stream) => stream.close().await,
            #[cfg(test)]
            Self::Raw(stream) => stream.close().await,
        }
    }
}

fn spawn_dns_query(
    transport: DnsTransport,
    remote: Destination,
    request: dns::UdpDnsRequest,
    event_tx: mpsc::Sender<DnsResponseEvent>,
) {
    tokio::spawn(async move {
        let result = query_dns_over_transport(transport, &remote, request.payload.as_ref())
            .await
            .map_err(|err| err.to_string());
        send_dns_response_event(&event_tx, DnsResponseEvent { request, result });
    });
}

fn send_dns_response_event(
    event_tx: &mpsc::Sender<DnsResponseEvent>,
    event: DnsResponseEvent,
) -> bool {
    match event_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            eprintln!("dns: response event queue is full despite the in-flight cap");
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn admit_udp_datagram(
    agent: ReconnectingAgentBridge,
    request: dns::UdpPacket,
    associations: &mut HashMap<UdpFlowKey, UdpAssociation>,
    association_limit: &mut DnsInflight,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
    stats: &mut TunnelStats,
) {
    let key = UdpFlowKey::from_packet(&request);
    let association = match associations.entry(key) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            if !association_limit.try_admit() {
                eprintln!(
                    "udp: dropping datagram because {} UDP associations are already active",
                    association_limit.max()
                );
                stats.udp_dropped = stats.udp_dropped.saturating_add(1);
                stats.record_udp_response(false);
                return;
            }

            let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
            spawn_udp_association_with_idle_timeout(
                agent,
                key,
                from_local,
                events.clone(),
                idle_timeout,
            );
            entry.insert(UdpAssociation { to_remote })
        }
    };

    match association.to_remote.try_send(request.payload) {
        Ok(()) => {
            stats.udp_forwarded = stats.udp_forwarded.saturating_add(1);
            eprintln!(
                "udp: forwarding datagram {}:{} -> {}:{} over agent",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            eprintln!(
                "udp: dropping datagram {}:{} -> {}:{} because the association queue is full",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
            stats.udp_dropped = stats.udp_dropped.saturating_add(1);
            stats.record_udp_response(false);
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            associations.remove(&key);
            association_limit.complete();
            eprintln!(
                "udp: dropping datagram {}:{} -> {}:{} because the association is closed",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
            );
            stats.udp_dropped = stats.udp_dropped.saturating_add(1);
            stats.record_udp_response(false);
        }
    }
}

fn drop_unsupported_direct_udp(request: &dns::UdpPacket, stats: &mut TunnelStats) {
    eprintln!(
        "udp: dropping datagram {}:{} -> {}:{} because direct-tcpip transport does not support generic UDP",
        request.src_ip, request.src_port, request.dst_ip, request.dst_port,
    );
    stats.udp_dropped = stats.udp_dropped.saturating_add(1);
    stats.record_udp_response(false);
}

fn spawn_udp_association_with_idle_timeout(
    agent: ReconnectingAgentBridge,
    key: UdpFlowKey,
    from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) {
    tokio::spawn(async move {
        let error = run_udp_association(agent, key, from_local, events.clone(), idle_timeout)
            .await
            .err()
            .map(|err| err.to_string());
        if !events.try_send_closed(key, error) {
            eprintln!(
                "udp: failed to enqueue close event for association {}:{} -> {}:{}",
                key.src_ip, key.src_port, key.dst_ip, key.dst_port
            );
        }
    });
}

async fn query_dns_over_transport(
    transport: DnsTransport,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    match transport {
        DnsTransport::DirectTcpip(ssh) => query_dns_over_ssh(ssh, remote, query).await,
        DnsTransport::Agent(agent) => query_dns_over_reconnecting_agent(agent, remote, query).await,
    }
}

async fn query_dns_over_ssh(
    ssh: SshSessionPool,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    if query.len() > usize::from(u16::MAX) {
        bail!("DNS query exceeds TCP DNS length limit");
    }

    let mut channel = tokio::time::timeout(
        ssh_bridge::BRIDGE_OPEN_TIMEOUT,
        ssh.open_background_direct_tcpip(
            remote.host.clone(),
            u32::from(remote.port),
            "127.0.0.1".to_owned(),
            0,
        ),
    )
    .await
    .context("timed out opening SSH direct-tcpip channel to DNS resolver")?
    .with_context(|| {
        format!(
            "failed to open SSH direct-tcpip channel to DNS resolver {}:{}",
            remote.host, remote.port
        )
    })?;

    let mut frame = BytesMut::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    channel
        .data_bytes(frame.freeze())
        .await
        .context("failed to write DNS TCP query over SSH")?;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        let mut received = BytesMut::with_capacity(512);
        let mut expected_len = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    received.extend_from_slice(data.as_ref());
                    if expected_len.is_none() && received.len() >= 2 {
                        expected_len =
                            Some(usize::from(u16::from_be_bytes([received[0], received[1]])));
                    }
                    if let Some(len) = expected_len {
                        if received.len() >= len + 2 {
                            let frame = received.split_to(len + 2).freeze();
                            return Ok(frame.slice(2..));
                        }
                    }
                }
                russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a complete TCP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS TCP response")??;

    let _ = channel.close().await;
    Ok(response)
}

async fn query_dns_over_reconnecting_agent(
    agent: ReconnectingAgentBridge,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        let stream = agent
            .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent UDP DNS association to {}:{}",
                    remote.host, remote.port
                )
            })?;
        query_dns_over_agent_udp_stream(AgentIoStream::Bridge(stream), query).await
    } else {
        let stream = open_dns_agent_stream(agent, remote).await?;
        query_dns_over_agent_tcp_stream(stream, query).await
    }
}

#[cfg(test)]
async fn query_dns_over_agent(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    let stream = open_dns_agent_transport_stream(agent, remote).await?;
    query_dns_over_agent_tcp_stream(stream, query).await
}

#[cfg(test)]
async fn query_dns_over_agent_udp(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
    query: &[u8],
) -> Result<Bytes> {
    let remote_ip = remote
        .host
        .parse::<Ipv4Addr>()
        .with_context(|| format!("test UDP DNS remote must be IPv4, got {}", remote.host))?;
    let stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: remote_ip,
            destination_port: remote.port,
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 0,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP DNS association to {}:{}",
                remote.host, remote.port
            )
        })?;
    query_dns_over_agent_udp_stream(AgentIoStream::Raw(stream), query).await
}

async fn open_dns_agent_stream(
    agent: ReconnectingAgentBridge,
    remote: &Destination,
) -> Result<AgentIoStream> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        agent
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Bridge)
    } else {
        agent
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: remote.host.clone(),
                destination_port: remote.port,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent hostname stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Bridge)
    }
}

#[cfg(test)]
async fn open_dns_agent_transport_stream(
    agent: agent_transport::AgentTransport,
    remote: &Destination,
) -> Result<AgentIoStream> {
    if let Ok(remote_ip) = remote.host.parse::<Ipv4Addr>() {
        agent
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: remote_ip,
                destination_port: remote.port,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Raw)
    } else {
        agent
            .open_tcp_host(agent_proto::AgentOpenHost {
                destination_host: remote.host.clone(),
                destination_port: remote.port,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 0,
            })
            .await
            .with_context(|| {
                format!(
                    "failed to open agent hostname stream to DNS resolver {}:{}",
                    remote.host, remote.port
                )
            })
            .map(AgentIoStream::Raw)
    }
}

async fn query_dns_over_agent_tcp_stream(mut stream: AgentIoStream, query: &[u8]) -> Result<Bytes> {
    if query.len() > usize::from(u16::MAX) {
        bail!("DNS query exceeds TCP DNS length limit");
    }
    let mut frame = BytesMut::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    stream
        .send_data(frame.freeze())
        .await
        .context("failed to write DNS TCP query over agent")?;
    let _ = stream.send_eof().await;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        let mut received = BytesMut::with_capacity(512);
        let mut expected_len = None;

        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => {
                    received.extend_from_slice(frame.payload.as_ref());
                    if expected_len.is_none() && received.len() >= 2 {
                        expected_len =
                            Some(usize::from(u16::from_be_bytes([received[0], received[1]])));
                    }
                    if let Some(len) = expected_len {
                        if received.len() >= len + 2 {
                            let frame = received.split_to(len + 2).freeze();
                            return Ok(frame.slice(2..));
                        }
                    }
                }
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent DNS stream reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a complete TCP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS TCP response over agent")??;

    let _ = stream.close().await;
    Ok(response)
}

async fn query_dns_over_agent_udp_stream(mut stream: AgentIoStream, query: &[u8]) -> Result<Bytes> {
    stream
        .send_data(Bytes::copy_from_slice(query))
        .await
        .context("failed to write DNS UDP query over agent")?;

    let response = tokio::time::timeout(DNS_QUERY_TIMEOUT, async {
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => return Ok(frame.payload),
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent DNS UDP association reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote DNS resolver closed before sending a UDP DNS response")
    })
    .await
    .context("timed out waiting for remote DNS UDP response over agent")??;

    let _ = stream.close().await;
    Ok(response)
}

async fn run_udp_association(
    agent: ReconnectingAgentBridge,
    key: UdpFlowKey,
    mut from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: key.dst_ip,
            destination_port: key.dst_port,
            originator_ip: key.src_ip,
            originator_port: key.src_port,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP association to {}:{}",
                key.dst_ip, key.dst_port
            )
        })?;

    run_udp_association_stream(
        AgentIoStream::Bridge(stream),
        key,
        &mut from_local,
        events,
        idle_timeout,
    )
    .await
}

#[cfg(test)]
async fn run_udp_association_transport(
    agent: agent_transport::AgentTransport,
    key: UdpFlowKey,
    mut from_local: mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: key.dst_ip,
            destination_port: key.dst_port,
            originator_ip: key.src_ip,
            originator_port: key.src_port,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP association to {}:{}",
                key.dst_ip, key.dst_port
            )
        })?;

    run_udp_association_stream(
        AgentIoStream::Raw(stream),
        key,
        &mut from_local,
        events,
        idle_timeout,
    )
    .await
}

async fn run_udp_association_stream(
    mut stream: AgentIoStream,
    key: UdpFlowKey,
    from_local: &mut mpsc::Receiver<Bytes>,
    events: UdpAssociationEvents,
    idle_timeout: Duration,
) -> Result<()> {
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            maybe_payload = from_local.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                stream
                    .send_data(payload)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to write UDP datagram over agent to {}:{}",
                            key.dst_ip, key.dst_port
                        )
                    })?;
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            maybe_frame = stream.recv() => {
                let Some(frame) = maybe_frame else {
                    break;
                };
                match frame.kind {
                    agent_proto::AgentFrameKind::Data => {
                        if !events.try_send_response(key, frame.payload) {
                            eprintln!(
                                "udp: dropping response datagram for {}:{} -> {}:{} because the response event queue is full or closed",
                                key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                            );
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                    agent_proto::AgentFrameKind::Reset => {
                        let message = String::from_utf8_lossy(&frame.payload);
                        bail!("agent UDP association reset: {message}");
                    }
                    _ => {}
                }
            }
            _ = &mut idle => {
                break;
            }
        }
    }

    let _ = stream.close().await;
    Ok(())
}

#[cfg(test)]
async fn query_udp_over_agent(
    agent: agent_transport::AgentTransport,
    request: &dns::UdpPacket,
) -> Result<Vec<u8>> {
    let mut stream = agent
        .open_udp_ipv4(agent_proto::AgentOpenIpv4 {
            destination_ip: request.dst_ip,
            destination_port: request.dst_port,
            originator_ip: request.src_ip,
            originator_port: request.src_port,
        })
        .await
        .with_context(|| {
            format!(
                "failed to open agent UDP stream to {}:{}",
                request.dst_ip, request.dst_port
            )
        })?;

    stream
        .send_data(request.payload.clone())
        .await
        .with_context(|| {
            format!(
                "failed to write UDP datagram over agent to {}:{}",
                request.dst_ip, request.dst_port
            )
        })?;

    let response = tokio::time::timeout(UDP_DATAGRAM_TIMEOUT, async {
        while let Some(frame) = stream.recv().await {
            match frame.kind {
                agent_proto::AgentFrameKind::Data => return Ok(frame.payload.to_vec()),
                agent_proto::AgentFrameKind::Eof | agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    let message = String::from_utf8_lossy(&frame.payload);
                    bail!("agent UDP stream reset: {message}");
                }
                _ => {}
            }
        }

        bail!("remote UDP socket closed before sending a response datagram")
    })
    .await;

    let _ = stream.close().await;
    response.with_context(|| {
        format!(
            "timed out waiting for UDP response over agent from {}:{}",
            request.dst_ip, request.dst_port
        )
    })?
}

async fn write_dns_event_to_tun(
    dev: &tun_rs::AsyncDevice,
    event: DnsResponseEvent,
) -> Result<TunWriteStats> {
    let payload = match event.result {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("dns: remote query failed: {err}");
            let Some(payload) = dns::build_dns_servfail_response(event.request.payload.as_ref())
            else {
                return Ok(TunWriteStats::default());
            };
            Bytes::from(payload)
        }
    };

    let packet = dns::build_udp_dns_response(&event.request, &payload)
        .context("failed to synthesize DNS UDP response packet")?;
    write_packet_to_tun(dev, &packet, "DNS response").await
}

async fn write_udp_response_to_tun(
    dev: &tun_rs::AsyncDevice,
    key: UdpFlowKey,
    payload: Bytes,
) -> Result<TunWriteStats> {
    let request = key.response_template();
    let packet = dns::build_udp_response(&request, &payload)
        .context("failed to synthesize UDP response packet")?;
    write_packet_to_tun(dev, &packet, "UDP response").await
}

enum BridgeRuntime {
    DirectTcpip(SshSessionPool),
    Agent(ReconnectingAgentBridge),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BridgeAdmissionLimits {
    active: usize,
    opening: usize,
}

impl BridgeAdmissionLimits {
    const fn direct_tcpip() -> Self {
        Self {
            active: MAX_DIRECT_ACTIVE_CHANNELS,
            opening: MAX_DIRECT_OPENING_CHANNELS,
        }
    }

    const fn agent() -> Self {
        Self {
            active: MAX_AGENT_ACTIVE_STREAMS,
            opening: MAX_AGENT_OPENING_STREAMS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BridgeAdmissionDecision {
    Admit,
    DeferActive,
    DeferOpening,
}

fn bridge_admission_decision(
    active: usize,
    opening: usize,
    limits: BridgeAdmissionLimits,
) -> BridgeAdmissionDecision {
    if active >= limits.active {
        BridgeAdmissionDecision::DeferActive
    } else if opening >= limits.opening {
        BridgeAdmissionDecision::DeferOpening
    } else {
        BridgeAdmissionDecision::Admit
    }
}

impl BridgeRuntime {
    fn admission_limits(&self) -> BridgeAdmissionLimits {
        match self {
            Self::DirectTcpip(_) => BridgeAdmissionLimits::direct_tcpip(),
            Self::Agent(_) => BridgeAdmissionLimits::agent(),
        }
    }

    async fn agent_snapshot(&self) -> AgentBridgeSnapshot {
        match self {
            Self::DirectTcpip(_) => AgentBridgeSnapshot::default(),
            Self::Agent(agent) => agent.snapshot().await,
        }
    }
}

enum AgentBridgeCarrier {
    Ssh(Handle<Client>),
    #[allow(dead_code)]
    Detached,
}

impl AgentBridgeCarrier {
    async fn disconnect(&self, reason: &str) -> Result<()> {
        match self {
            Self::Ssh(handle) => handle
                .disconnect(russh::Disconnect::ByApplication, reason, "en")
                .await
                .with_context(|| format!("failed to disconnect agent carrier: {reason}")),
            Self::Detached => Ok(()),
        }
    }
}

struct AgentBridgeTransport {
    carrier: AgentBridgeCarrier,
    transport: agent_transport::AgentTransport,
    agent_command: String,
}

impl AgentBridgeTransport {
    async fn disconnect(&self, reason: &str) -> Result<()> {
        self.carrier.disconnect(reason).await
    }
}

struct AgentBridgeLane {
    index: usize,
    agent_command: Mutex<String>,
    inner: Mutex<Option<AgentBridgeTransport>>,
    health: Mutex<AgentLaneHealth>,
    load: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct AgentLaneHealth {
    consecutive_reconnect_failures: u32,
    quarantine_until: Option<StdInstant>,
    background_repair_in_progress: bool,
}

#[derive(Debug, Default)]
struct AgentReconnectCounters {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AgentReconnectSnapshot {
    attempts: u64,
    successes: u64,
    failures: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AgentBridgeSnapshot {
    reconnects: AgentReconnectSnapshot,
    lanes_total: usize,
    lanes_desired: usize,
    lanes_available: usize,
    lanes_failed: usize,
    lanes_missing: usize,
    lanes_quarantined: usize,
    lanes_repairing: usize,
    max_quarantine_ms: u64,
    active_streams: usize,
    max_lane_load: usize,
}

struct AgentLaneLease {
    bridge: ReconnectingAgentBridge,
    lane_index: usize,
    load: Option<Arc<AtomicUsize>>,
}

impl AgentLaneLease {
    fn new(bridge: ReconnectingAgentBridge, lane_index: usize, load: Arc<AtomicUsize>) -> Self {
        load.fetch_add(1, Ordering::AcqRel);
        Self {
            bridge,
            lane_index,
            load: Some(load),
        }
    }

    fn into_stream(mut self, inner: agent_transport::AgentStream) -> AgentBridgeStream {
        AgentBridgeStream {
            bridge: self.bridge.clone(),
            lane_index: self.lane_index,
            inner: Some(inner),
            load: self.load.take(),
        }
    }
}

impl Drop for AgentLaneLease {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct AgentBridgeStream {
    bridge: ReconnectingAgentBridge,
    lane_index: usize,
    inner: Option<agent_transport::AgentStream>,
    load: Option<Arc<AtomicUsize>>,
}

impl AgentBridgeStream {
    async fn send_data(&self, bytes: impl Into<Bytes>) -> Result<()> {
        let result = self
            .inner
            .as_ref()
            .context("agent bridge stream is already closed")?
            .send_data(bytes)
            .await;
        if result.is_err() {
            self.schedule_repair_if_transport_failed().await;
        }
        result
    }

    async fn send_eof(&self) -> Result<()> {
        let result = self
            .inner
            .as_ref()
            .context("agent bridge stream is already closed")?
            .send_eof()
            .await;
        if result.is_err() {
            self.schedule_repair_if_transport_failed().await;
        }
        result
    }

    async fn recv(&mut self) -> Option<agent_proto::AgentFrame> {
        let frame = self.inner.as_mut()?.recv().await;
        if matches!(
            frame.as_ref().map(|frame| frame.kind),
            None | Some(agent_proto::AgentFrameKind::Reset)
        ) {
            self.schedule_repair_if_transport_failed().await;
        }
        frame
    }

    async fn close(mut self) -> Result<()> {
        match self.inner.take() {
            Some(stream) => {
                let result = stream.close().await;
                if let Err(err) = &result {
                    self.bridge
                        .spawn_lane_repair(self.lane_index, err.to_string());
                }
                result
            }
            None => Ok(()),
        }
    }

    async fn schedule_repair_if_transport_failed(&self) {
        let Some(stream) = self.inner.as_ref() else {
            return;
        };
        if let Some(failure) = stream.transport_failure_message().await {
            self.bridge.spawn_lane_repair(self.lane_index, failure);
        }
    }
}

impl Drop for AgentBridgeStream {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AgentLaneSelectionStatus {
    Available { load: usize },
    Failed { failure: String },
    Missing,
    Repairing,
    Quarantined,
}

#[derive(Clone)]
struct ReconnectingAgentBridge {
    connector: Arc<dyn AgentBridgeConnector>,
    lanes: Arc<Vec<AgentBridgeLane>>,
    desired_lanes: usize,
    reconnects: Arc<AgentReconnectCounters>,
}

impl ReconnectingAgentBridge {
    #[cfg(test)]
    fn new(connector: Arc<dyn AgentBridgeConnector>, initial: Vec<AgentBridgeTransport>) -> Self {
        let desired_lanes = initial.len();
        Self::new_with_desired_lanes(connector, initial, desired_lanes)
    }

    fn new_with_desired_lanes(
        connector: Arc<dyn AgentBridgeConnector>,
        initial: Vec<AgentBridgeTransport>,
        desired_lanes: usize,
    ) -> Self {
        Self::new_with_desired_lanes_and_missing_repair_delay(
            connector,
            initial,
            desired_lanes,
            None,
        )
    }

    fn new_with_desired_lanes_and_missing_repair_delay(
        connector: Arc<dyn AgentBridgeConnector>,
        initial: Vec<AgentBridgeTransport>,
        desired_lanes: usize,
        missing_repair_delay: Option<Duration>,
    ) -> Self {
        assert!(
            !initial.is_empty(),
            "agent bridge requires at least one transport"
        );
        let desired_lanes = desired_lanes.max(initial.len());
        let first_effective_command = initial[0].agent_command.clone();
        let initial_len = initial.len();
        let mut lanes = initial
            .into_iter()
            .enumerate()
            .map(|(index, transport)| {
                let agent_command = transport.agent_command.clone();
                AgentBridgeLane {
                    index,
                    agent_command: Mutex::new(agent_command),
                    inner: Mutex::new(Some(transport)),
                    health: Mutex::new(AgentLaneHealth::default()),
                    load: Arc::new(AtomicUsize::new(0)),
                }
            })
            .collect::<Vec<_>>();
        for index in initial_len..desired_lanes {
            lanes.push(AgentBridgeLane {
                index,
                agent_command: Mutex::new(first_effective_command.clone()),
                inner: Mutex::new(None),
                health: Mutex::new(AgentLaneHealth::default()),
                load: Arc::new(AtomicUsize::new(0)),
            });
        }
        let bridge = Self {
            connector,
            lanes: Arc::new(lanes),
            desired_lanes,
            reconnects: Arc::new(AgentReconnectCounters::default()),
        };
        for index in initial_len..desired_lanes {
            bridge.spawn_lane_repair_with_delay(
                index,
                "missing startup exec transport".to_owned(),
                missing_repair_delay,
            );
        }
        bridge
    }

    async fn open_tcp_ipv4(&self, open: agent_proto::AgentOpenIpv4) -> Result<AgentBridgeStream> {
        let (primary, secondary) =
            agent_lane_candidates(agent_ipv4_lane_hash(&open, 6), self.lanes.len());
        let lane_index = self.choose_lane_index(primary, secondary).await;
        let lane = &self.lanes[lane_index];
        if let Some(err) = self.quarantined_lane_error(lane).await {
            return self
                .open_tcp_ipv4_on_alternate_lane(open, lane_index, err)
                .await;
        }
        let lease = self.reserve_lane(lane);
        let transport = match self.current_transport(lane).await {
            Some(transport) => transport,
            None => match self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
            {
                Ok(replacement) => replacement,
                Err(reconnect_err) => {
                    drop(lease);
                    return self
                        .open_tcp_ipv4_on_alternate_lane(open, lane_index, reconnect_err)
                        .await;
                }
            },
        };
        match transport.open_tcp_ipv4(open).await {
            Ok(stream) => {
                self.mark_lane_open_success(lane).await;
                Ok(lease.into_stream(stream))
            }
            Err(err) => {
                let Some(failure) = transport.failure_message().await else {
                    return Err(err);
                };
                let replacement = match self.reconnect_failed_lane(lane, failure).await {
                    Ok(replacement) => replacement,
                    Err(reconnect_err) => {
                        drop(lease);
                        return self
                            .open_tcp_ipv4_on_alternate_lane(open, lane_index, reconnect_err)
                            .await;
                    }
                };
                match replacement.open_tcp_ipv4(open).await {
                    Ok(stream) => {
                        self.mark_lane_open_success(lane).await;
                        Ok(lease.into_stream(stream))
                    }
                    Err(err) => {
                        if replacement.failure_message().await.is_some() {
                            drop(lease);
                            self.open_tcp_ipv4_on_alternate_lane(open, lane_index, err)
                                .await
                        } else {
                            Err(err).context("failed to open agent TCP stream on repaired lane")
                        }
                    }
                }
            }
        }
    }

    async fn open_tcp_host(&self, open: agent_proto::AgentOpenHost) -> Result<AgentBridgeStream> {
        let (primary, secondary) =
            agent_lane_candidates(agent_host_lane_hash(&open, 6), self.lanes.len());
        let lane_index = self.choose_lane_index(primary, secondary).await;
        let lane = &self.lanes[lane_index];
        if let Some(err) = self.quarantined_lane_error(lane).await {
            return self
                .open_tcp_host_on_alternate_lane(open, lane_index, err)
                .await;
        }
        let lease = self.reserve_lane(lane);
        let transport = match self.current_transport(lane).await {
            Some(transport) => transport,
            None => match self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
            {
                Ok(replacement) => replacement,
                Err(reconnect_err) => {
                    drop(lease);
                    return self
                        .open_tcp_host_on_alternate_lane(open, lane_index, reconnect_err)
                        .await;
                }
            },
        };
        match transport.open_tcp_host(open.clone()).await {
            Ok(stream) => {
                self.mark_lane_open_success(lane).await;
                Ok(lease.into_stream(stream))
            }
            Err(err) => {
                let Some(failure) = transport.failure_message().await else {
                    return Err(err);
                };
                let replacement = match self.reconnect_failed_lane(lane, failure).await {
                    Ok(replacement) => replacement,
                    Err(reconnect_err) => {
                        drop(lease);
                        return self
                            .open_tcp_host_on_alternate_lane(open, lane_index, reconnect_err)
                            .await;
                    }
                };
                match replacement.open_tcp_host(open.clone()).await {
                    Ok(stream) => {
                        self.mark_lane_open_success(lane).await;
                        Ok(lease.into_stream(stream))
                    }
                    Err(err) => {
                        if replacement.failure_message().await.is_some() {
                            drop(lease);
                            self.open_tcp_host_on_alternate_lane(open, lane_index, err)
                                .await
                        } else {
                            Err(err).context(
                                "failed to open agent hostname TCP stream on repaired lane",
                            )
                        }
                    }
                }
            }
        }
    }

    async fn open_udp_ipv4(&self, open: agent_proto::AgentOpenIpv4) -> Result<AgentBridgeStream> {
        let (primary, secondary) =
            agent_lane_candidates(agent_ipv4_lane_hash(&open, 17), self.lanes.len());
        let lane_index = self.choose_lane_index(primary, secondary).await;
        let lane = &self.lanes[lane_index];
        if let Some(err) = self.quarantined_lane_error(lane).await {
            return self
                .open_udp_ipv4_on_alternate_lane(open, lane_index, err)
                .await;
        }
        let lease = self.reserve_lane(lane);
        let transport = match self.current_transport(lane).await {
            Some(transport) => transport,
            None => match self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
            {
                Ok(replacement) => replacement,
                Err(reconnect_err) => {
                    drop(lease);
                    return self
                        .open_udp_ipv4_on_alternate_lane(open, lane_index, reconnect_err)
                        .await;
                }
            },
        };
        match transport.open_udp_ipv4(open).await {
            Ok(stream) => {
                self.mark_lane_open_success(lane).await;
                Ok(lease.into_stream(stream))
            }
            Err(err) => {
                let Some(failure) = transport.failure_message().await else {
                    return Err(err);
                };
                let replacement = match self.reconnect_failed_lane(lane, failure).await {
                    Ok(replacement) => replacement,
                    Err(reconnect_err) => {
                        drop(lease);
                        return self
                            .open_udp_ipv4_on_alternate_lane(open, lane_index, reconnect_err)
                            .await;
                    }
                };
                match replacement.open_udp_ipv4(open).await {
                    Ok(stream) => {
                        self.mark_lane_open_success(lane).await;
                        Ok(lease.into_stream(stream))
                    }
                    Err(err) => {
                        if replacement.failure_message().await.is_some() {
                            drop(lease);
                            self.open_udp_ipv4_on_alternate_lane(open, lane_index, err)
                                .await
                        } else {
                            Err(err).context("failed to open agent UDP stream on repaired lane")
                        }
                    }
                }
            }
        }
    }

    async fn open_tcp_ipv4_on_alternate_lane(
        &self,
        open: agent_proto::AgentOpenIpv4,
        skipped_index: usize,
        original_err: anyhow::Error,
    ) -> Result<AgentBridgeStream> {
        let mut last_err = original_err;
        let mut tried_lanes = 0_u64;
        while let Some(lane) = self.next_alternate_lane_by_load(skipped_index, tried_lanes) {
            tried_lanes |= agent_lane_bit(lane.index);
            let transport = match self.alternate_transport_or_repair(lane).await {
                Ok(Some(transport)) => transport,
                Ok(None) => continue,
                Err(err) => {
                    last_err = err;
                    continue;
                }
            };
            let lease = self.reserve_lane(lane);
            match transport.open_tcp_ipv4(open).await {
                Ok(stream) => {
                    self.mark_lane_open_success(lane).await;
                    eprintln!(
                        "agent: opened TCP stream on alternate lane {} after lane {} failed",
                        lane.index, skipped_index
                    );
                    return Ok(lease.into_stream(stream));
                }
                Err(err) => {
                    let Some(failure) = transport.failure_message().await else {
                        return Err(err).with_context(|| {
                            format!(
                                "failed to open agent TCP stream on alternate lane {}",
                                lane.index
                            )
                        });
                    };
                    drop(lease);
                    let repaired = match self.reconnect_failed_lane(lane, failure).await {
                        Ok(repaired) => repaired,
                        Err(reconnect_err) => {
                            last_err = reconnect_err;
                            continue;
                        }
                    };
                    let lease = self.reserve_lane(lane);
                    match repaired.open_tcp_ipv4(open).await {
                        Ok(stream) => {
                            self.mark_lane_open_success(lane).await;
                            eprintln!(
                                "agent: opened TCP stream on repaired alternate lane {} after lane {} failed",
                                lane.index, skipped_index
                            );
                            return Ok(lease.into_stream(stream));
                        }
                        Err(err) => {
                            if repaired.failure_message().await.is_some() {
                                drop(lease);
                                last_err = err;
                                continue;
                            }
                            return Err(err).with_context(|| {
                                format!(
                                    "failed to open agent TCP stream on repaired alternate lane {}",
                                    lane.index
                                )
                            });
                        }
                    }
                }
            }
        }
        Err(last_err).context(
            "failed to open agent TCP stream on preferred lane and no alternate agent lane succeeded",
        )
    }

    async fn open_tcp_host_on_alternate_lane(
        &self,
        open: agent_proto::AgentOpenHost,
        skipped_index: usize,
        original_err: anyhow::Error,
    ) -> Result<AgentBridgeStream> {
        let mut last_err = original_err;
        let mut tried_lanes = 0_u64;
        while let Some(lane) = self.next_alternate_lane_by_load(skipped_index, tried_lanes) {
            tried_lanes |= agent_lane_bit(lane.index);
            let transport = match self.alternate_transport_or_repair(lane).await {
                Ok(Some(transport)) => transport,
                Ok(None) => continue,
                Err(err) => {
                    last_err = err;
                    continue;
                }
            };
            let lease = self.reserve_lane(lane);
            match transport.open_tcp_host(open.clone()).await {
                Ok(stream) => {
                    self.mark_lane_open_success(lane).await;
                    eprintln!(
                        "agent: opened hostname TCP stream on alternate lane {} after lane {} failed",
                        lane.index, skipped_index
                    );
                    return Ok(lease.into_stream(stream));
                }
                Err(err) => {
                    let Some(failure) = transport.failure_message().await else {
                        return Err(err).with_context(|| {
                            format!(
                                "failed to open agent hostname TCP stream on alternate lane {}",
                                lane.index
                            )
                        });
                    };
                    drop(lease);
                    let repaired = match self.reconnect_failed_lane(lane, failure).await {
                        Ok(repaired) => repaired,
                        Err(reconnect_err) => {
                            last_err = reconnect_err;
                            continue;
                        }
                    };
                    let lease = self.reserve_lane(lane);
                    match repaired.open_tcp_host(open.clone()).await {
                        Ok(stream) => {
                            self.mark_lane_open_success(lane).await;
                            eprintln!(
                                "agent: opened hostname TCP stream on repaired alternate lane {} after lane {} failed",
                                lane.index, skipped_index
                            );
                            return Ok(lease.into_stream(stream));
                        }
                        Err(err) => {
                            if repaired.failure_message().await.is_some() {
                                drop(lease);
                                last_err = err;
                                continue;
                            }
                            return Err(err).with_context(|| {
                                format!(
                                    "failed to open agent hostname TCP stream on repaired alternate lane {}",
                                    lane.index
                                )
                            });
                        }
                    }
                }
            }
        }
        Err(last_err).context(
            "failed to open agent hostname TCP stream on preferred lane and no alternate agent lane succeeded",
        )
    }

    async fn open_udp_ipv4_on_alternate_lane(
        &self,
        open: agent_proto::AgentOpenIpv4,
        skipped_index: usize,
        original_err: anyhow::Error,
    ) -> Result<AgentBridgeStream> {
        let mut last_err = original_err;
        let mut tried_lanes = 0_u64;
        while let Some(lane) = self.next_alternate_lane_by_load(skipped_index, tried_lanes) {
            tried_lanes |= agent_lane_bit(lane.index);
            let transport = match self.alternate_transport_or_repair(lane).await {
                Ok(Some(transport)) => transport,
                Ok(None) => continue,
                Err(err) => {
                    last_err = err;
                    continue;
                }
            };
            let lease = self.reserve_lane(lane);
            match transport.open_udp_ipv4(open).await {
                Ok(stream) => {
                    self.mark_lane_open_success(lane).await;
                    eprintln!(
                        "agent: opened UDP stream on alternate lane {} after lane {} failed",
                        lane.index, skipped_index
                    );
                    return Ok(lease.into_stream(stream));
                }
                Err(err) => {
                    let Some(failure) = transport.failure_message().await else {
                        return Err(err).with_context(|| {
                            format!(
                                "failed to open agent UDP stream on alternate lane {}",
                                lane.index
                            )
                        });
                    };
                    drop(lease);
                    let repaired = match self.reconnect_failed_lane(lane, failure).await {
                        Ok(repaired) => repaired,
                        Err(reconnect_err) => {
                            last_err = reconnect_err;
                            continue;
                        }
                    };
                    let lease = self.reserve_lane(lane);
                    match repaired.open_udp_ipv4(open).await {
                        Ok(stream) => {
                            self.mark_lane_open_success(lane).await;
                            eprintln!(
                                "agent: opened UDP stream on repaired alternate lane {} after lane {} failed",
                                lane.index, skipped_index
                            );
                            return Ok(lease.into_stream(stream));
                        }
                        Err(err) => {
                            if repaired.failure_message().await.is_some() {
                                drop(lease);
                                last_err = err;
                                continue;
                            }
                            return Err(err).with_context(|| {
                                format!(
                                    "failed to open agent UDP stream on repaired alternate lane {}",
                                    lane.index
                                )
                            });
                        }
                    }
                }
            }
        }
        Err(last_err).context(
            "failed to open agent UDP stream on preferred lane and no alternate agent lane succeeded",
        )
    }

    fn next_alternate_lane_by_load(
        &self,
        skipped_index: usize,
        tried_lanes: u64,
    ) -> Option<&AgentBridgeLane> {
        let mut best = None;
        for lane in self.lanes.iter() {
            if lane.index == skipped_index || tried_lanes & agent_lane_bit(lane.index) != 0 {
                continue;
            }
            let candidate = (lane.load.load(Ordering::Acquire), lane.index);
            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
        best.and_then(|(_, index)| self.lanes.get(index))
    }

    async fn alternate_transport_or_repair(
        &self,
        lane: &AgentBridgeLane,
    ) -> Result<Option<agent_transport::AgentTransport>> {
        if self.lane_quarantine_remaining(lane).await.is_some() {
            return Ok(None);
        }

        let Some(transport) = self.current_transport(lane).await else {
            return self
                .reconnect_failed_lane(lane, "missing startup exec transport".to_owned())
                .await
                .map(Some);
        };

        match transport.failure_message().await {
            Some(failure) => self.reconnect_failed_lane(lane, failure).await.map(Some),
            None => Ok(Some(transport)),
        }
    }

    async fn current_transport(
        &self,
        lane: &AgentBridgeLane,
    ) -> Option<agent_transport::AgentTransport> {
        lane.inner
            .lock()
            .await
            .as_ref()
            .map(|inner| inner.transport.clone())
    }

    fn reserve_lane(&self, lane: &AgentBridgeLane) -> AgentLaneLease {
        AgentLaneLease::new(self.clone(), lane.index, Arc::clone(&lane.load))
    }

    async fn choose_lane_index(&self, primary: usize, secondary: usize) -> usize {
        if primary == secondary || self.lanes.len() == 1 {
            return primary;
        }

        let primary_lane = &self.lanes[primary];
        let primary_status = self.lane_selection_status(primary_lane).await;

        let secondary_lane = &self.lanes[secondary];
        let secondary_status = self.lane_selection_status(secondary_lane).await;
        match (primary_status, secondary_status) {
            (
                AgentLaneSelectionStatus::Available { load: primary_load },
                AgentLaneSelectionStatus::Available {
                    load: secondary_load,
                },
            ) if secondary_load < primary_load => secondary,
            (AgentLaneSelectionStatus::Available { .. }, secondary_status) => {
                self.spawn_lane_repair_for_status(secondary, &secondary_status);
                primary
            }
            (primary_status, AgentLaneSelectionStatus::Available { .. }) => {
                self.spawn_lane_repair_for_status(primary, &primary_status);
                secondary
            }
            (primary_status, secondary_status) => {
                if let Some(index) = self
                    .best_available_lane_index_except(primary, secondary)
                    .await
                {
                    self.spawn_lane_repair_for_status(primary, &primary_status);
                    self.spawn_lane_repair_for_status(secondary, &secondary_status);
                    index
                } else {
                    primary
                }
            }
        }
    }

    async fn best_available_lane_index_except(
        &self,
        first_skipped: usize,
        second_skipped: usize,
    ) -> Option<usize> {
        let mut best = None;
        for lane in self
            .lanes
            .iter()
            .filter(|lane| lane.index != first_skipped && lane.index != second_skipped)
        {
            if let AgentLaneSelectionStatus::Available { load } =
                self.lane_selection_status(lane).await
            {
                let candidate = (load, lane.index);
                if best.is_none_or(|current| candidate < current) {
                    best = Some(candidate);
                }
            }
        }
        best.map(|(_, index)| index)
    }

    fn spawn_lane_repair_for_status(&self, lane_index: usize, status: &AgentLaneSelectionStatus) {
        match status {
            AgentLaneSelectionStatus::Failed { failure } => {
                self.spawn_lane_repair(lane_index, failure.clone());
            }
            AgentLaneSelectionStatus::Missing => {
                self.spawn_lane_repair(lane_index, "missing startup exec transport".to_owned());
            }
            AgentLaneSelectionStatus::Available { .. }
            | AgentLaneSelectionStatus::Repairing
            | AgentLaneSelectionStatus::Quarantined => {}
        }
    }

    async fn lane_selection_status(&self, lane: &AgentBridgeLane) -> AgentLaneSelectionStatus {
        if self.lane_quarantine_remaining(lane).await.is_some() {
            return AgentLaneSelectionStatus::Quarantined;
        }
        if self.lane_is_repairing(lane).await {
            return AgentLaneSelectionStatus::Repairing;
        }
        match self.current_transport(lane).await {
            Some(transport) => {
                if let Some(failure) = transport.failure_message().await {
                    AgentLaneSelectionStatus::Failed { failure }
                } else {
                    AgentLaneSelectionStatus::Available {
                        load: lane.load.load(Ordering::Acquire),
                    }
                }
            }
            None => AgentLaneSelectionStatus::Missing,
        }
    }

    async fn lane_is_repairing(&self, lane: &AgentBridgeLane) -> bool {
        lane.health.lock().await.background_repair_in_progress
    }

    fn spawn_lane_repair(&self, lane_index: usize, failure: String) {
        self.spawn_lane_repair_with_delay(lane_index, failure, None);
    }

    fn spawn_lane_repair_with_delay(
        &self,
        lane_index: usize,
        failure: String,
        delay: Option<Duration>,
    ) {
        let lane = &self.lanes[lane_index];
        if !self.try_start_background_lane_repair(lane) {
            return;
        }

        let lanes = Arc::downgrade(&self.lanes);
        let reconnects = Arc::downgrade(&self.reconnects);
        let connector = Arc::clone(&self.connector);
        tokio::spawn(async move {
            if let Some(delay) = delay.filter(|delay| !delay.is_zero()) {
                tokio::time::sleep(delay).await;
            }

            let mut last_failure = failure;
            let mut attempts = 0_usize;

            loop {
                let Some(lanes_for_wait) = lanes.upgrade() else {
                    return;
                };
                let remaining = {
                    let lane = &lanes_for_wait[lane_index];
                    ReconnectingAgentBridge::lane_quarantine_remaining_for(lane).await
                };
                drop(lanes_for_wait);
                if let Some(remaining) = remaining {
                    tokio::time::sleep(remaining).await;
                    continue;
                }

                if attempts >= AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS {
                    let Some(lanes_for_finish) = lanes.upgrade() else {
                        return;
                    };
                    let lane = &lanes_for_finish[lane_index];
                    ReconnectingAgentBridge::finish_background_lane_repair_for(lane).await;
                    eprintln!(
                        "agent: background repair of lane {} stopped after {} failed attempt(s)",
                        lane.index, attempts
                    );
                    return;
                }
                attempts = attempts.saturating_add(1);

                let Some(lanes_for_repair) = lanes.upgrade() else {
                    return;
                };
                let Some(reconnects) = reconnects.upgrade() else {
                    return;
                };
                let lane = &lanes_for_repair[lane_index];
                match ReconnectingAgentBridge::reconnect_failed_lane_with(
                    &connector,
                    &reconnects,
                    lane,
                    last_failure.clone(),
                )
                .await
                {
                    Ok(_) => {
                        ReconnectingAgentBridge::finish_background_lane_repair_for(lane).await;
                        return;
                    }
                    Err(err) => {
                        last_failure = err.to_string();
                        eprintln!(
                            "agent: background repair attempt {}/{} of lane {} failed: {err:#}",
                            attempts, AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS, lane.index
                        );
                    }
                }
            }
        });
    }

    fn try_start_background_lane_repair(&self, lane: &AgentBridgeLane) -> bool {
        let Ok(mut health) = lane.health.try_lock() else {
            return false;
        };
        if health.background_repair_in_progress || health.quarantine_until.is_some() {
            return false;
        }
        health.background_repair_in_progress = true;
        true
    }

    #[cfg(test)]
    async fn finish_background_lane_repair(&self, lane: &AgentBridgeLane) {
        Self::finish_background_lane_repair_for(lane).await;
    }

    async fn finish_background_lane_repair_for(lane: &AgentBridgeLane) {
        let mut health = lane.health.lock().await;
        health.background_repair_in_progress = false;
    }

    fn reconnect_snapshot(&self) -> AgentReconnectSnapshot {
        AgentReconnectSnapshot {
            attempts: self.reconnects.attempts.load(Ordering::Acquire),
            successes: self.reconnects.successes.load(Ordering::Acquire),
            failures: self.reconnects.failures.load(Ordering::Acquire),
        }
    }

    async fn snapshot(&self) -> AgentBridgeSnapshot {
        let mut snapshot = AgentBridgeSnapshot {
            reconnects: self.reconnect_snapshot(),
            lanes_total: self.lanes.len(),
            lanes_desired: self.desired_lanes,
            ..AgentBridgeSnapshot::default()
        };

        for lane in self.lanes.iter() {
            let lane_load = lane.load.load(Ordering::Acquire);
            snapshot.active_streams = snapshot.active_streams.saturating_add(lane_load);
            snapshot.max_lane_load = snapshot.max_lane_load.max(lane_load);
            let (quarantine_ms, repairing) = self.lane_snapshot_health(lane).await;
            if let Some(quarantine_ms) = quarantine_ms {
                snapshot.lanes_quarantined = snapshot.lanes_quarantined.saturating_add(1);
                snapshot.max_quarantine_ms = snapshot.max_quarantine_ms.max(quarantine_ms);
            }
            if repairing {
                snapshot.lanes_repairing = snapshot.lanes_repairing.saturating_add(1);
            }

            match self.current_transport(lane).await {
                Some(transport) => {
                    if transport.failure_message().await.is_some() {
                        snapshot.lanes_failed = snapshot.lanes_failed.saturating_add(1);
                    } else if quarantine_ms.is_none() {
                        snapshot.lanes_available = snapshot.lanes_available.saturating_add(1);
                    }
                }
                None => {
                    snapshot.lanes_missing = snapshot.lanes_missing.saturating_add(1);
                }
            }
        }

        snapshot
    }

    async fn lane_snapshot_health(&self, lane: &AgentBridgeLane) -> (Option<u64>, bool) {
        let mut health = lane.health.lock().await;
        let quarantine_ms = match health.quarantine_until {
            Some(until) => match until.checked_duration_since(StdInstant::now()) {
                Some(remaining) if remaining.as_nanos() > 0 => {
                    Some(remaining.as_millis().try_into().unwrap_or(u64::MAX))
                }
                _ => {
                    health.quarantine_until = None;
                    None
                }
            },
            None => None,
        };
        (quarantine_ms, health.background_repair_in_progress)
    }

    async fn quarantined_lane_error(&self, lane: &AgentBridgeLane) -> Option<anyhow::Error> {
        Self::quarantined_lane_error_for(lane).await
    }

    async fn quarantined_lane_error_for(lane: &AgentBridgeLane) -> Option<anyhow::Error> {
        Self::lane_quarantine_remaining_for(lane)
            .await
            .map(|remaining| {
                anyhow!(
                    "agent lane {} is quarantined for {}ms after reconnect failures",
                    lane.index,
                    remaining.as_millis()
                )
            })
    }

    async fn lane_quarantine_remaining(&self, lane: &AgentBridgeLane) -> Option<Duration> {
        Self::lane_quarantine_remaining_for(lane).await
    }

    async fn lane_quarantine_remaining_for(lane: &AgentBridgeLane) -> Option<Duration> {
        let mut health = lane.health.lock().await;
        let until = health.quarantine_until?;
        match until.checked_duration_since(StdInstant::now()) {
            Some(remaining) if remaining.as_nanos() > 0 => Some(remaining),
            _ => {
                health.quarantine_until = None;
                None
            }
        }
    }

    async fn mark_lane_open_success(&self, lane: &AgentBridgeLane) {
        Self::mark_lane_open_success_for(lane).await;
    }

    async fn mark_lane_open_success_for(lane: &AgentBridgeLane) {
        let mut health = lane.health.lock().await;
        health.consecutive_reconnect_failures = 0;
        health.quarantine_until = None;
        health.background_repair_in_progress = false;
    }

    async fn mark_lane_reconnect_failure_for(lane: &AgentBridgeLane) -> Duration {
        let mut health = lane.health.lock().await;
        health.consecutive_reconnect_failures =
            health.consecutive_reconnect_failures.saturating_add(1);
        let backoff =
            agent_lane_backoff_duration(lane.index, health.consecutive_reconnect_failures);
        health.quarantine_until = Some(StdInstant::now() + backoff);
        backoff
    }

    async fn reconnect_failed_lane(
        &self,
        lane: &AgentBridgeLane,
        failure: String,
    ) -> Result<agent_transport::AgentTransport> {
        Self::reconnect_failed_lane_with(&self.connector, &self.reconnects, lane, failure).await
    }

    async fn reconnect_failed_lane_with(
        connector: &Arc<dyn AgentBridgeConnector>,
        reconnects: &AgentReconnectCounters,
        lane: &AgentBridgeLane,
        failure: String,
    ) -> Result<agent_transport::AgentTransport> {
        if let Some(err) = Self::quarantined_lane_error_for(lane).await {
            return Err(err);
        }
        let mut inner = lane.inner.lock().await;
        let reconnect_command = match inner.as_ref() {
            Some(transport) => {
                if transport.transport.failure_message().await.is_none() {
                    return Ok(transport.transport.clone());
                }
                transport.agent_command.clone()
            }
            None => lane.agent_command.lock().await.clone(),
        };

        if inner.is_some() {
            eprintln!(
                "agent: reconnecting after transport failure on lane {}: {failure}",
                lane.index
            );
        } else {
            eprintln!(
                "agent: connecting missing exec transport on lane {}: {failure}",
                lane.index
            );
        }
        reconnects.attempts.fetch_add(1, Ordering::AcqRel);
        let replacement = match Self::reconnect_agent_lane_transport_with(
            connector,
            lane.index,
            &reconnect_command,
            &failure,
        )
        .await
        {
            Ok(replacement) => replacement,
            Err(err) => {
                reconnects.failures.fetch_add(1, Ordering::AcqRel);
                let backoff = Self::mark_lane_reconnect_failure_for(lane).await;
                eprintln!(
                    "agent: quarantined lane {} for {}ms after reconnect failure",
                    lane.index,
                    backoff.as_millis()
                );
                return Err(err);
            }
        };
        let replacement_command = replacement.agent_command.clone();
        let transport = replacement.transport.clone();
        *inner = Some(replacement);
        *lane.agent_command.lock().await = replacement_command;
        Self::mark_lane_open_success_for(lane).await;
        reconnects.successes.fetch_add(1, Ordering::AcqRel);
        Ok(transport)
    }

    async fn reconnect_agent_lane_transport_with(
        connector: &Arc<dyn AgentBridgeConnector>,
        lane_index: usize,
        reconnect_command: &str,
        failure: &str,
    ) -> Result<AgentBridgeTransport> {
        if reconnect_command == connector.primary_command() {
            return connector.connect_primary().await.with_context(|| {
                format!("failed to reconnect Rustle agent after transport failure: {failure}")
            });
        }

        match connector.connect_command(reconnect_command).await {
            Ok(replacement) => Ok(replacement),
            Err(reconnect_err) => {
                eprintln!(
                    "agent: lane {lane_index} effective reconnect command failed ({reconnect_err:#}); trying primary/bootstrap"
                );
                connector.connect_primary().await.with_context(|| {
                    format!(
                        "failed to reconnect Rustle agent after lane command failure ({reconnect_err:#}) and transport failure: {failure}"
                    )
                })
            }
        }
    }
}

#[cfg(test)]
fn agent_lane_index(open: &agent_proto::AgentOpenIpv4, protocol: u8, lanes: usize) -> usize {
    let (primary, _) = agent_lane_candidates(agent_ipv4_lane_hash(open, protocol), lanes);
    primary
}

fn agent_ipv4_lane_hash(open: &agent_proto::AgentOpenIpv4, protocol: u8) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in open.originator_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in open.originator_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in open.destination_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in open.destination_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash = fnv1a_mix(hash, protocol);
    hash
}

fn agent_lane_backoff_duration(lane_index: usize, consecutive_failures: u32) -> Duration {
    let failures = consecutive_failures.max(1);
    let shift = failures.saturating_sub(1).min(7);
    let base_ms = (AGENT_LANE_BACKOFF_BASE.as_millis() as u64)
        .saturating_mul(1_u64 << shift)
        .min(AGENT_LANE_BACKOFF_MAX.as_millis() as u64);
    let jitter_ms = ((lane_index as u64).saturating_mul(37) + u64::from(failures) * 11) % 100;
    Duration::from_millis((base_ms + jitter_ms).min(AGENT_LANE_BACKOFF_MAX.as_millis() as u64))
}

#[cfg(test)]
fn agent_host_lane_index(open: &agent_proto::AgentOpenHost, protocol: u8, lanes: usize) -> usize {
    let (primary, _) = agent_lane_candidates(agent_host_lane_hash(open, protocol), lanes);
    primary
}

fn agent_host_lane_hash(open: &agent_proto::AgentOpenHost, protocol: u8) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in open.originator_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in open.originator_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in open.destination_host.as_bytes() {
        hash = fnv1a_mix(hash, byte.to_ascii_lowercase());
    }
    for byte in open.destination_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash = fnv1a_mix(hash, protocol);
    hash
}

fn agent_lane_candidates(hash: u64, lanes: usize) -> (usize, usize) {
    assert!(lanes > 0, "agent lane count must be non-zero");
    let primary = (finalize_flow_hash(hash) % lanes as u64) as usize;
    if lanes == 1 {
        return (primary, primary);
    }

    let secondary_hash = hash ^ 0x9e37_79b9_7f4a_7c15_u64;
    let mut secondary = (finalize_flow_hash(secondary_hash) % lanes as u64) as usize;
    if secondary == primary {
        secondary = (secondary + 1) % lanes;
    }
    (primary, secondary)
}

fn agent_lane_bit(index: usize) -> u64 {
    assert!(
        index < u64::BITS as usize,
        "agent lane bitset supports at most 64 lanes"
    );
    1_u64 << index
}

fn ensure_bridges(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    runtime: &BridgeRuntime,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    ready_flow_ids: &mut Vec<tcp_core::FlowId>,
) -> Result<BridgeAdmissionStats> {
    let mut stats = BridgeAdmissionStats::default();
    let limits = runtime.admission_limits();
    let mut active_channels = bridges.len();
    let mut opening_channels = flow_manager.opening_flow_count();

    flow_manager.ready_to_bridge_flow_ids_into(ready_flow_ids);
    for id in ready_flow_ids.drain(..) {
        let flow = id.key;
        if bridges.contains_key(&flow) {
            continue;
        }
        match bridge_admission_decision(active_channels, opening_channels, limits) {
            BridgeAdmissionDecision::Admit => {}
            BridgeAdmissionDecision::DeferActive => {
                stats.deferred_active_limit = stats.deferred_active_limit.saturating_add(1);
                continue;
            }
            BridgeAdmissionDecision::DeferOpening => {
                stats.deferred_open_limit = stats.deferred_open_limit.saturating_add(1);
                continue;
            }
        }

        flow_manager.mark_flow_state(flow, tcp_core::FlowState::SshOpening)?;
        let bridge = match runtime {
            BridgeRuntime::DirectTcpip(ssh) => {
                let ssh = ssh.clone();
                eprintln!(
                    "ssh: opening direct-tcpip {}:{} for local {}:{} generation={}",
                    flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
                );
                ssh_bridge::spawn_direct_tcpip_bridge_with_opener(id, event_tx.clone(), move |id| {
                    let ssh = ssh.clone();
                    async move { ssh.open_direct_tcpip_for_flow(id).await }
                })
            }
            BridgeRuntime::Agent(agent) => {
                let agent = agent.clone();
                eprintln!(
                    "agent: opening stream {}:{} for local {}:{} generation={}",
                    flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port, id.generation
                );
                spawn_agent_tcp_bridge(id, event_tx.clone(), agent)
            }
        };
        bridges.insert(bridge.id.key, bridge);
        active_channels += 1;
        opening_channels += 1;
    }
    Ok(stats)
}

fn spawn_agent_tcp_bridge(
    id: tcp_core::FlowId,
    event_tx: mpsc::Sender<ssh_bridge::BridgeEvent>,
    agent: ReconnectingAgentBridge,
) -> ssh_bridge::FlowBridge {
    ssh_bridge::spawn_bridge_task(id, event_tx, move |id, mut local_rx, event_tx| async move {
        let open_started_at = StdInstant::now();
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: id.key.dst_ip,
            destination_port: id.key.dst_port,
            originator_ip: id.key.src_ip,
            originator_port: id.key.src_port,
        };
        let mut stream = match agent.open_tcp_ipv4(open).await {
            Ok(stream) => stream,
            Err(err) => {
                let _ = ssh_bridge::send_bridge_event(
                    &event_tx,
                    ssh_bridge::BridgeEvent::Failed {
                        id,
                        phase: ssh_bridge::BridgeFailurePhase::Open,
                        message: format!("failed to open agent stream: {err:#}"),
                    },
                )
                .await;
                return;
            }
        };

        let open_ms = open_started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        if !ssh_bridge::send_bridge_event(
            &event_tx,
            ssh_bridge::BridgeEvent::Opened { id, open_ms },
        )
        .await
        {
            let _ = stream.close().await;
            return;
        }

        loop {
            tokio::select! {
                local = local_rx.recv() => {
                    match local {
                        Some(bytes) => {
                            match tokio::time::timeout(
                                ssh_bridge::BRIDGE_WRITE_TIMEOUT,
                                stream.send_data(bytes),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => {
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: ssh_bridge::BridgeFailurePhase::Write,
                                            message: format!("failed to write to agent stream: {err:#}"),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                                Err(_) => {
                                    let _ = ssh_bridge::send_bridge_event(
                                        &event_tx,
                                        ssh_bridge::BridgeEvent::Failed {
                                            id,
                                            phase: ssh_bridge::BridgeFailurePhase::Write,
                                            message: format!(
                                                "timed out after {}ms writing to agent stream",
                                                ssh_bridge::BRIDGE_WRITE_TIMEOUT.as_millis()
                                            ),
                                        },
                                    )
                                    .await;
                                    break;
                                }
                            }
                        }
                        None => {
                            let _ = stream.send_eof().await;
                            break;
                        }
                    }
                }
                remote = stream.recv() => {
                    match remote {
                        Some(frame) => match frame.kind {
                            agent_proto::AgentFrameKind::Data => {
                                if !ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::RemoteData {
                                        id,
                                        bytes: frame.payload,
                                    },
                                )
                                .await
                                {
                                    break;
                                }
                            }
                            agent_proto::AgentFrameKind::Eof => {
                                let _ = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::RemoteEof { id },
                                )
                                .await;
                                break;
                            }
                            agent_proto::AgentFrameKind::Close => break,
                            agent_proto::AgentFrameKind::Reset => {
                                let message = String::from_utf8_lossy(&frame.payload).to_string();
                                let _ = ssh_bridge::send_bridge_event(
                                    &event_tx,
                                    ssh_bridge::BridgeEvent::Failed {
                                        id,
                                        phase: ssh_bridge::BridgeFailurePhase::Write,
                                        message: format!("agent stream reset: {message}"),
                                    },
                                )
                                .await;
                                break;
                            }
                            _ => {}
                        },
                        None => break,
                    }
                }
            }
        }

        let _ = stream.close().await;
        let _ =
            ssh_bridge::send_bridge_event(&event_tx, ssh_bridge::BridgeEvent::Closed { id }).await;
    })
}

fn drain_local_bytes_to_bridges(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    flow_keys: &mut Vec<tcp_core::FlowKey>,
) -> Result<LocalDrainStats> {
    let mut stats = LocalDrainStats::default();
    flow_manager.flow_keys_into(flow_keys);
    for flow in flow_keys.drain(..) {
        if flow_manager.recv_queue_len(flow)? == 0 {
            continue;
        }

        let Some(bridge) = bridges.get(&flow) else {
            if matches!(
                flow_manager.flow_state(flow)?,
                tcp_core::FlowState::TcpEstablished | tcp_core::FlowState::SshOpening
            ) {
                stats.bridge_backpressure_events =
                    stats.bridge_backpressure_events.saturating_add(1);
                continue;
            }
            eprintln!(
                "ssh: missing bridge while draining local bytes for {flow:?}; resetting flow"
            );
            flow_manager.abort_flow(flow)?;
            stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            continue;
        };

        let remaining_bridge_bytes = bridge.local_queue_remaining_bytes();
        if bridge.local_queue_capacity() == 0 || remaining_bridge_bytes == 0 {
            stats.bridge_backpressure_events = stats.bridge_backpressure_events.saturating_add(1);
            continue;
        }

        let bytes = flow_manager.recv_flow_bytes(flow, remaining_bridge_bytes.min(16 * 1024))?;
        if bytes.is_empty() {
            continue;
        }

        let len = bytes.len() as u64;
        match bridge.try_send_local_data(bytes) {
            Ok(true) => {
                stats.bytes_to_bridge = stats.bytes_to_bridge.saturating_add(len);
            }
            Ok(false) => {
                eprintln!(
                    "ssh: bridge queue filled while draining local bytes for {flow:?}; resetting flow"
                );
                bridges.remove(&flow);
                flow_manager.abort_flow(flow)?;
                stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            }
            Err(err) => {
                eprintln!("ssh: bridge task closed while sending local bytes for {flow:?}: {err}");
                bridges.remove(&flow);
                flow_manager.abort_flow(flow)?;
                stats.bridge_send_failures = stats.bridge_send_failures.saturating_add(1);
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
fn handle_bridge_event(
    event: ssh_bridge::BridgeEvent,
    flow_manager: &mut tcp_core::FlowManager,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
) -> Result<BridgeEventOutcome> {
    let mut closed_flows = Vec::new();
    let stats =
        handle_bridge_event_into(event, flow_manager, remote_backlogs, now, &mut closed_flows)?;
    Ok(BridgeEventOutcome {
        closed_flows,
        remote_backlog_overflows: stats.remote_backlog_overflows,
        stale_bridge_events: stats.stale_bridge_events,
    })
}

fn handle_bridge_event_into(
    event: ssh_bridge::BridgeEvent,
    flow_manager: &mut tcp_core::FlowManager,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
    closed_flows: &mut Vec<tcp_core::FlowKey>,
) -> Result<BridgeEventStats> {
    closed_flows.clear();
    let id = bridge_event_id(&event);
    let flow = id.key;
    if !flow_manager.contains_flow(flow) {
        if should_log_stale_bridge_event(&event) {
            eprintln!(
                "ssh: ignoring stale {} event for removed {flow:?}",
                bridge_event_name(&event)
            );
        }
        remote_backlogs.remove_id(id);
        return Ok(BridgeEventStats {
            stale_bridge_events: 1,
            ..BridgeEventStats::default()
        });
    }
    if !flow_manager.contains_flow_id(id) {
        if should_log_stale_bridge_event(&event) {
            eprintln!(
                "ssh: ignoring stale {} event for reused {flow:?} generation={}",
                bridge_event_name(&event),
                id.generation
            );
        }
        remote_backlogs.remove_id(id);
        return Ok(BridgeEventStats {
            stale_bridge_events: 1,
            ..BridgeEventStats::default()
        });
    }

    match event {
        ssh_bridge::BridgeEvent::Opened { id, open_ms } => {
            let flow = id.key;
            flow_manager.mark_flow_state(flow, tcp_core::FlowState::Relaying)?;
            eprintln!(
                "bridge: open for {flow:?} generation={} in {open_ms}ms",
                id.generation
            );
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::RemoteData { id, bytes } => {
            let flow = id.key;
            match remote_backlogs.push(id, bytes) {
                RemoteBacklogPush::Accepted => {}
                RemoteBacklogPush::FlowLimit => {
                    eprintln!(
                        "tcp: remote backlog exceeded {} bytes for {flow:?}; resetting flow",
                        remote_backlogs.max_bytes_per_flow()
                    );
                    remote_backlogs.remove_id(id);
                    flow_manager.abort_flow(flow)?;
                    closed_flows.push(flow);
                    return Ok(BridgeEventStats {
                        remote_backlog_overflows: 1,
                        ..BridgeEventStats::default()
                    });
                }
                RemoteBacklogPush::TotalLimit => {
                    eprintln!(
                        "tcp: total remote backlog exceeded {} bytes; resetting {flow:?}",
                        remote_backlogs.max_total_bytes()
                    );
                    remote_backlogs.remove_id(id);
                    flow_manager.abort_flow(flow)?;
                    closed_flows.push(flow);
                    return Ok(BridgeEventStats {
                        remote_backlog_overflows: 1,
                        ..BridgeEventStats::default()
                    });
                }
            }
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::RemoteEof { id } => {
            remote_backlogs.close_after_flush(id);
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::Closed { id } => {
            let flow = id.key;
            remote_backlogs.close_after_flush(id);
            remote_backlogs.flush_flow_into(flow_manager, id, now, closed_flows)?;
            if !closed_flows.contains(&flow) {
                closed_flows.push(flow);
            }
            Ok(BridgeEventStats::default())
        }
        ssh_bridge::BridgeEvent::Failed { id, phase, message } => {
            let flow = id.key;
            eprintln!("bridge: {phase:?} failed for {flow:?}: {message}");
            remote_backlogs.remove_id(id);
            flow_manager.abort_flow(flow)?;
            closed_flows.push(flow);
            Ok(BridgeEventStats::default())
        }
    }
}

fn should_log_stale_bridge_event(event: &ssh_bridge::BridgeEvent) -> bool {
    !matches!(event, ssh_bridge::BridgeEvent::RemoteData { .. })
}

fn bridge_event_id(event: &ssh_bridge::BridgeEvent) -> tcp_core::FlowId {
    match event {
        ssh_bridge::BridgeEvent::Opened { id, .. }
        | ssh_bridge::BridgeEvent::RemoteData { id, .. }
        | ssh_bridge::BridgeEvent::RemoteEof { id }
        | ssh_bridge::BridgeEvent::Closed { id }
        | ssh_bridge::BridgeEvent::Failed { id, .. } => *id,
    }
}

fn bridge_event_name(event: &ssh_bridge::BridgeEvent) -> &'static str {
    match event {
        ssh_bridge::BridgeEvent::Opened { .. } => "opened",
        ssh_bridge::BridgeEvent::RemoteData { .. } => "remote-data",
        ssh_bridge::BridgeEvent::RemoteEof { .. } => "remote-eof",
        ssh_bridge::BridgeEvent::Closed { .. } => "closed",
        ssh_bridge::BridgeEvent::Failed { .. } => "failed",
    }
}

struct RemoteFlushScratch<'a> {
    backlog_flow_ids: &'a mut Vec<tcp_core::FlowId>,
    closed_flows: &'a mut Vec<tcp_core::FlowKey>,
    packets: &'a mut Vec<tcp_core::PacketBuf>,
}

async fn flush_remote_backlogs_to_tun(
    dev: &tun_rs::AsyncDevice,
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
    scratch: RemoteFlushScratch<'_>,
    stats: &mut TunnelStats,
) -> Result<()> {
    remote_backlogs.flush_all_into(
        flow_manager,
        now,
        scratch.backlog_flow_ids,
        scratch.closed_flows,
    )?;
    for closed_flow in scratch.closed_flows.drain(..) {
        bridges.remove(&closed_flow);
    }
    flow_manager.poll_into(now, scratch.packets);
    let tun_write = write_packets_to_tun(dev, scratch.packets).await?;
    stats.record_tun_write(tun_write);
    Ok(())
}

#[derive(Debug)]
struct RemoteBacklogs {
    max_bytes_per_flow: usize,
    max_total_bytes: usize,
    total_bytes: usize,
    flows: HashMap<tcp_core::FlowId, RemoteBacklog>,
}

#[derive(Debug, Default)]
struct RemoteBacklog {
    chunks: VecDeque<Bytes>,
    front_offset: usize,
    bytes: usize,
    close_after_flush: bool,
    close_defer_flushes: u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RemoteBacklogPush {
    Accepted,
    FlowLimit,
    TotalLimit,
}

impl RemoteBacklogs {
    fn new(max_bytes_per_flow: usize) -> Self {
        Self::with_limits(max_bytes_per_flow, REMOTE_BACKLOG_BYTES_TOTAL)
    }

    fn with_limits(max_bytes_per_flow: usize, max_total_bytes: usize) -> Self {
        Self {
            max_bytes_per_flow,
            max_total_bytes,
            total_bytes: 0,
            flows: HashMap::new(),
        }
    }

    fn max_bytes_per_flow(&self) -> usize {
        self.max_bytes_per_flow
    }

    fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    fn total_bytes(&self) -> u64 {
        self.total_bytes as u64
    }

    fn should_pause_bridge_events(&self) -> bool {
        self.total_bytes >= self.bridge_event_pause_threshold()
    }

    fn bridge_event_pause_threshold(&self) -> usize {
        self.max_total_bytes
            .saturating_sub(self.max_total_bytes / 4)
    }

    fn push(&mut self, id: tcp_core::FlowId, bytes: impl Into<Bytes>) -> RemoteBacklogPush {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return RemoteBacklogPush::Accepted;
        }
        if self.total_bytes.saturating_add(bytes.len()) > self.max_total_bytes {
            return RemoteBacklogPush::TotalLimit;
        }
        let backlog = self.flows.entry(id).or_default();
        if backlog.bytes.saturating_add(bytes.len()) > self.max_bytes_per_flow {
            return RemoteBacklogPush::FlowLimit;
        }
        backlog.bytes += bytes.len();
        self.total_bytes += bytes.len();
        backlog.chunks.push_back(bytes);
        if backlog.close_after_flush {
            backlog.close_defer_flushes = REMOTE_CLOSE_DEFER_FLUSHES;
        }
        RemoteBacklogPush::Accepted
    }

    fn close_after_flush(&mut self, id: tcp_core::FlowId) {
        let backlog = self.flows.entry(id).or_default();
        backlog.close_after_flush = true;
        backlog.close_defer_flushes = REMOTE_CLOSE_DEFER_FLUSHES;
    }

    fn remove_id(&mut self, id: tcp_core::FlowId) {
        if let Some(backlog) = self.flows.remove(&id) {
            self.total_bytes = self.total_bytes.saturating_sub(backlog.bytes);
        }
    }

    fn remove_flow(&mut self, flow: tcp_core::FlowKey) {
        let mut removed_bytes = 0_usize;
        self.flows.retain(|id, backlog| {
            if id.key == flow {
                removed_bytes = removed_bytes.saturating_add(backlog.bytes);
                false
            } else {
                true
            }
        });
        self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
    }

    fn flush_all_into(
        &mut self,
        flow_manager: &mut tcp_core::FlowManager,
        now: SmolInstant,
        flows: &mut Vec<tcp_core::FlowId>,
        closed: &mut Vec<tcp_core::FlowKey>,
    ) -> Result<()> {
        flows.clear();
        flows.reserve(self.flows.len());
        flows.extend(self.flows.keys().copied());
        closed.clear();
        closed.reserve(flows.len());
        for id in flows.drain(..) {
            self.flush_flow_into(flow_manager, id, now, closed)?;
        }
        Ok(())
    }

    fn flush_flow_into(
        &mut self,
        flow_manager: &mut tcp_core::FlowManager,
        id: tcp_core::FlowId,
        now: SmolInstant,
        closed: &mut Vec<tcp_core::FlowKey>,
    ) -> Result<()> {
        let flow = id.key;
        if !flow_manager.contains_flow_id(id) {
            eprintln!(
                "tcp: dropping stale remote backlog for {flow:?} generation={}",
                id.generation
            );
            self.remove_id(id);
            return Ok(());
        }

        let Some(backlog) = self.flows.get_mut(&id) else {
            return Ok(());
        };

        let mut abort_flow = false;
        while let Some(chunk) = backlog.chunks.front() {
            let pending = &chunk[backlog.front_offset..];
            let Some(sent) = flow_manager.try_send_flow_bytes_at(flow, pending, now)? else {
                eprintln!(
                    "tcp: remote backlog cannot flush because local flow closed for {flow:?}; resetting flow"
                );
                abort_flow = true;
                break;
            };

            if sent == 0 {
                return Ok(());
            }

            backlog.front_offset += sent;
            backlog.bytes = backlog.bytes.saturating_sub(sent);
            self.total_bytes = self.total_bytes.saturating_sub(sent);
            if backlog.front_offset == chunk.len() {
                backlog.chunks.pop_front();
                backlog.front_offset = 0;
            }
        }

        if abort_flow {
            self.remove_id(id);
            flow_manager.abort_flow(flow)?;
            closed.push(flow);
            return Ok(());
        }

        if backlog.close_after_flush {
            if backlog.close_defer_flushes > 0 {
                backlog.close_defer_flushes -= 1;
                return Ok(());
            }
            self.flows.remove(&id);
            flow_manager.close_flow(flow, tcp_core::FlowState::HalfClosedRemote)?;
        } else if backlog.bytes == 0 {
            self.flows.remove(&id);
        }

        Ok(())
    }
}

fn expire_stale_flows(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    now: SmolInstant,
    expired: &mut Vec<tcp_core::FlowKey>,
) -> usize {
    flow_manager.expire_stale_flows_into(now, expired);
    let count = expired.len();
    for flow in expired.drain(..) {
        eprintln!("tcp: expiring stale flow {flow:?}");
        bridges.remove(&flow);
        remote_backlogs.remove_flow(flow);
    }
    count
}

fn prune_closed_flows(
    flow_manager: &mut tcp_core::FlowManager,
    bridges: &mut HashMap<tcp_core::FlowKey, ssh_bridge::FlowBridge>,
    remote_backlogs: &mut RemoteBacklogs,
    removable: &mut Vec<tcp_core::FlowKey>,
) -> Result<usize> {
    flow_manager.removable_flows_into(removable);
    let count = removable.len();
    for flow in removable.drain(..) {
        bridges.remove(&flow);
        remote_backlogs.remove_flow(flow);
        flow_manager.remove_flow(flow)?;
    }
    Ok(count)
}

async fn write_packets_to_tun(
    dev: &tun_rs::AsyncDevice,
    packets: &mut Vec<tcp_core::PacketBuf>,
) -> Result<TunWriteStats> {
    let mut stats = TunWriteStats::default();
    for packet in packets.drain(..) {
        stats.combine(write_packet_to_tun(dev, packet.as_ref(), "userspace TCP packet").await?);
    }
    Ok(stats)
}

async fn write_packet_to_tun(
    dev: &tun_rs::AsyncDevice,
    packet: &[u8],
    description: &'static str,
) -> Result<TunWriteStats> {
    let len = packet.len();
    let mut stats = TunWriteStats::default();
    match tokio::time::timeout(TUN_WRITE_TIMEOUT, dev.send(packet)).await {
        Ok(Ok(_)) => {
            stats.record_written(len);
        }
        Ok(Err(err)) => {
            return Err(err)
                .with_context(|| format!("failed to write {description} to TUN device"));
        }
        Err(_) => {
            eprintln!(
                "tun: dropping {len}-byte {description} after {}ms waiting for TUN write",
                TUN_WRITE_TIMEOUT.as_millis()
            );
            stats.record_dropped(len);
        }
    }
    Ok(stats)
}

fn synthetic_lab_client(
    client_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    client_port: u16,
) -> Result<(
    Interface,
    tcp_core::PacketQueueDevice,
    SocketSet<'static>,
    smoltcp::iface::SocketHandle,
)> {
    let mut device = tcp_core::PacketQueueDevice::new(usize::from(DEFAULT_MTU));
    let mut config = SmolConfig::new(HardwareAddress::Ip);
    config.random_seed = 0x4252_4c41_4221;

    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::from(client_ip), DEFAULT_TUN_PREFIX))
            .expect("smoltcp default IP address storage must fit lab client address");
    });
    iface.routes_mut().update(|routes| {
        routes
            .push(Route {
                cidr: IpCidr::Ipv4(Ipv4Cidr::new(destination_ip, 32)),
                via_router: IpAddress::from(gateway),
                preferred_until: None,
                expires_at: None,
            })
            .expect("smoltcp default route storage must fit lab destination route");
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut client_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; tcp_core::TCP_SEND_BUFFER_BYTES]),
        tcp::SocketBuffer::new(vec![0; tcp_core::TCP_RECV_BUFFER_BYTES]),
    );
    client_socket.set_ack_delay(None);
    client_socket.set_nagle_enabled(false);
    let client_handle = sockets.add(client_socket);
    sockets
        .get_mut::<tcp::Socket>(client_handle)
        .connect(
            iface.context(),
            (IpAddress::from(destination_ip), destination_port),
            client_port,
        )
        .context("failed to connect synthetic lab client socket")?;

    Ok((iface, device, sockets, client_handle))
}

fn drain_lab_client_to_manager(
    now: SmolInstant,
    client: &mut BridgeLabClient,
    flow_manager: &mut tcp_core::FlowManager,
) -> Result<Vec<tcp_core::PacketBuf>> {
    let mut outbound = Vec::new();
    for packet in client.device.drain_tx() {
        let response_packets = flow_manager
            .ingest_packet(now, packet.as_ref())
            .context("failed to feed lab client packet into FlowManager")?;
        outbound.extend(response_packets);
    }
    Ok(outbound)
}

fn pump_lab_manager_to_clients(
    now: SmolInstant,
    flow_manager: &mut tcp_core::FlowManager,
    clients: &mut [BridgeLabClient],
) -> Result<usize> {
    let packets = flow_manager.poll(now);
    route_lab_packets_to_clients(packets, clients)
}

fn route_lab_packets_to_clients(
    packets: Vec<tcp_core::PacketBuf>,
    clients: &mut [BridgeLabClient],
) -> Result<usize> {
    let mut routed = 0_usize;
    for packet in packets {
        let Some(segment) = tcp_core::parse_ipv4_tcp_segment(packet.as_ref())
            .context("failed to inspect lab TCP packet")?
        else {
            continue;
        };

        let Some(client) = clients.iter_mut().find(|client| {
            client.client_ip == segment.flow.dst_ip && client.client_port == segment.flow.dst_port
        }) else {
            bail!(
                "lab packet has no synthetic client: {}:{} -> {}:{}",
                segment.flow.src_ip,
                segment.flow.src_port,
                segment.flow.dst_ip,
                segment.flow.dst_port
            );
        };
        client.device.inject(packet.as_ref())?;
        routed = routed.saturating_add(1);
    }
    Ok(routed)
}

#[derive(Debug)]
struct Ipv4PacketMetadata {
    total_len: u16,
    protocol: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

fn parse_ipv4_metadata(packet: &[u8]) -> Result<Ipv4PacketMetadata> {
    if packet.len() < 20 {
        bail!("short IPv4 packet");
    }

    let version = packet[0] >> 4;
    if version != 4 {
        bail!("not IPv4 version {version}");
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 {
        bail!("invalid IPv4 header length {header_len}");
    }
    if packet.len() < header_len {
        bail!("truncated IPv4 header");
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if usize::from(total_len) > packet.len() {
        bail!("truncated IPv4 payload");
    }

    Ok(Ipv4PacketMetadata {
        total_len,
        protocol: packet[9],
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExistingRoute {
    gateway: Option<Ipv4Addr>,
    if_name: Option<String>,
    if_index: Option<u32>,
}

trait ControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute>;
    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
struct SystemControlRouteCommandExecutor;

impl ControlRouteCommandExecutor for SystemControlRouteCommandExecutor {
    fn lookup_route_to(&self, target: Ipv4Addr) -> Result<ExistingRoute> {
        lookup_existing_route_to(target)
    }

    fn run_control_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Addr,
        route: &ExistingRoute,
    ) -> Result<()> {
        run_control_route_command(action, target, route)
    }
}

struct ControlRouteGuard<E: ControlRouteCommandExecutor = SystemControlRouteCommandExecutor> {
    target: Ipv4Addr,
    route: ExistingRoute,
    executor: E,
}

impl<E: ControlRouteCommandExecutor> ControlRouteGuard<E> {
    fn add(target: Ipv4Addr, route: ExistingRoute, executor: E) -> Result<Self> {
        executor.run_control_route_command(RouteAction::Add, target, &route)?;
        Ok(Self {
            target,
            route,
            executor,
        })
    }
}

impl<E: ControlRouteCommandExecutor> Drop for ControlRouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) =
            self.executor
                .run_control_route_command(RouteAction::Delete, self.target, &self.route)
        {
            eprintln!(
                "route: failed to delete SSH control host route {}: {err:#}",
                self.target
            );
        } else {
            eprintln!("route: deleted SSH control host route {}", self.target);
        }
    }
}

fn add_ssh_control_route(target: Ipv4Addr) -> Result<Option<ControlRouteGuard>> {
    add_ssh_control_route_with(target, SystemControlRouteCommandExecutor)
}

fn add_ssh_control_route_with<E: ControlRouteCommandExecutor + Clone>(
    target: Ipv4Addr,
    executor: E,
) -> Result<Option<ControlRouteGuard<E>>> {
    let route = executor
        .lookup_route_to(target)
        .with_context(|| format!("failed to inspect existing route to SSH server {target}"))?;
    if !route_requires_control_host_route(&route) {
        eprintln!(
            "route: existing route to SSH control connection {target} is already direct via {route:?}"
        );
        return Ok(None);
    }
    let guard = ControlRouteGuard::add(target, route.clone(), executor)
        .with_context(|| format!("failed to add SSH control host route for {target}"))?;
    eprintln!("route: protected SSH control connection to {target} via {route:?}");
    Ok(Some(guard))
}

fn route_requires_control_host_route(route: &ExistingRoute) -> bool {
    route
        .gateway
        .is_some_and(|gateway| !gateway.is_unspecified())
}

trait RouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()>;
}

#[derive(Clone, Copy)]
struct SystemRouteCommandExecutor;

impl RouteCommandExecutor for SystemRouteCommandExecutor {
    fn run_route_command(
        &self,
        action: RouteAction,
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
    ) -> Result<()> {
        run_route_command(action, target, if_name, if_index, gateway)
    }
}

struct RouteGuard<E: RouteCommandExecutor = SystemRouteCommandExecutor> {
    target: Ipv4Net,
    if_name: String,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
}

impl<E: RouteCommandExecutor> RouteGuard<E> {
    fn add(
        target: Ipv4Net,
        if_name: &str,
        if_index: u32,
        gateway: Ipv4Addr,
        executor: E,
    ) -> Result<Self> {
        executor.run_route_command(RouteAction::Add, target, if_name, if_index, gateway)?;
        Ok(Self {
            target,
            if_name: if_name.to_owned(),
            if_index,
            gateway,
            executor,
        })
    }
}

fn add_target_routes(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<Vec<RouteGuard>> {
    add_target_routes_with(
        targets,
        if_name,
        if_index,
        gateway,
        SystemRouteCommandExecutor,
    )
}

fn add_target_routes_with<E: RouteCommandExecutor + Clone>(
    targets: &[Ipv4Net],
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
    executor: E,
) -> Result<Vec<RouteGuard<E>>> {
    let mut routes = Vec::with_capacity(targets.len());
    for target in targets {
        let route = RouteGuard::add(*target, if_name, if_index, gateway, executor.clone())
            .with_context(|| format!("failed to add target route {target}"))?;
        eprintln!("route: added {target} via {if_name}");
        routes.push(route);
    }
    Ok(routes)
}

impl<E: RouteCommandExecutor> Drop for RouteGuard<E> {
    fn drop(&mut self) {
        if let Err(err) = self.executor.run_route_command(
            RouteAction::Delete,
            self.target,
            &self.if_name,
            self.if_index,
            self.gateway,
        ) {
            eprintln!("route: failed to delete {}: {err:#}", self.target);
        } else {
            eprintln!("route: deleted {}", self.target);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteAction {
    Add,
    Delete,
}

fn run_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<()> {
    let (program, args) = route_command(action, target, if_name, if_index, gateway)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

fn run_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<()> {
    let (program, args) = control_route_command(action, target, route)?;
    let output = Command::new(&program)
        .args(&args)
        .output()
        .with_context(|| format!("failed to execute control route command {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "control route command failed: {} {}\nstdout: {}\nstderr: {}",
            program,
            args.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("route")
        .args(["-n", "get", &target.to_string()])
        .output()
        .context("failed to execute route -n get")?;
    if !output.status.success() {
        bail!(
            "route -n get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_macos_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "linux")]
fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let output = Command::new("ip")
        .args(["-4", "route", "get", &target.to_string()])
        .output()
        .context("failed to execute ip route get")?;
    if !output.status.success() {
        bail!(
            "ip route get {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_linux_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "windows")]
fn lookup_existing_route_to(target: Ipv4Addr) -> Result<ExistingRoute> {
    let script = format!(
        "$r = Find-NetRoute -RemoteIPAddress '{}' | Select-Object -First 1; if ($null -eq $r) {{ exit 1 }}; '{{0}} {{1}}' -f $r.InterfaceIndex, $r.NextHop",
        target
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("failed to execute Find-NetRoute")?;
    if !output.status.success() {
        bail!(
            "Find-NetRoute {} failed: {}",
            target,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_windows_find_net_route(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn lookup_existing_route_to(_target: Ipv4Addr) -> Result<ExistingRoute> {
    bail!(
        "SSH control route protection is not implemented for {}",
        env::consts::OS
    );
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_macos_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => {
                gateway = value.trim().parse::<Ipv4Addr>().ok();
            }
            "interface" => {
                let value = value.trim();
                if !value.is_empty() {
                    if_name = Some(value.to_owned());
                }
            }
            _ => {}
        }
    }

    if gateway.is_none() && if_name.is_none() {
        bail!("route output did not include a gateway or interface");
    }
    Ok(ExistingRoute {
        gateway,
        if_name,
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_linux_route_get(output: &str) -> Result<ExistingRoute> {
    let mut gateway = None;
    let mut if_name = None;
    let tokens: Vec<_> = output.split_whitespace().collect();
    for pair in tokens.windows(2) {
        match pair[0] {
            "via" => gateway = pair[1].parse::<Ipv4Addr>().ok(),
            "dev" => if_name = Some(pair[1].to_owned()),
            _ => {}
        }
    }

    let Some(if_name) = if_name else {
        bail!("ip route output did not include a dev field");
    };
    Ok(ExistingRoute {
        gateway,
        if_name: Some(if_name),
        if_index: None,
    })
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_windows_find_net_route(output: &str) -> Result<ExistingRoute> {
    let mut fields = output.split_whitespace();
    let if_index = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include InterfaceIndex"))?
        .parse::<u32>()
        .context("failed to parse Find-NetRoute InterfaceIndex")?;
    let gateway = fields
        .next()
        .ok_or_else(|| anyhow!("Find-NetRoute output did not include NextHop"))?
        .parse::<Ipv4Addr>()
        .context("failed to parse Find-NetRoute NextHop")?;

    Ok(ExistingRoute {
        gateway: Some(gateway),
        if_name: None,
        if_index: Some(if_index),
    })
}

#[cfg(target_os = "linux")]
fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(linux_route_command(action, target, if_name))
}

#[cfg(target_os = "linux")]
fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    linux_control_route_command(action, target, route)
}

#[cfg(target_os = "macos")]
fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(macos_route_command(action, target, if_name))
}

#[cfg(target_os = "macos")]
fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    macos_control_route_command(action, target, route)
}

#[cfg(target_os = "windows")]
fn route_command(
    action: RouteAction,
    target: Ipv4Net,
    _if_name: &str,
    if_index: u32,
    gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    Ok(windows_route_command(action, target, if_index, gateway))
}

#[cfg(target_os = "windows")]
fn control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    windows_control_route_command(action, target, route)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    (
        "ip".to_owned(),
        vec![
            "route".to_owned(),
            verb.to_owned(),
            target.to_string(),
            "dev".to_owned(),
            if_name.to_owned(),
        ],
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "del",
    };
    let mut args = vec!["route".to_owned(), verb.to_owned(), format!("{target}/32")];
    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway.filter(|gateway| !gateway.is_unspecified()) {
            args.extend(["via".to_owned(), gateway.to_string()]);
        }
        let if_name = route
            .if_name
            .as_deref()
            .ok_or_else(|| anyhow!("Linux control route requires an interface name"))?;
        args.extend(["dev".to_owned(), if_name.to_owned()]);
    }

    Ok(("ip".to_owned(), args))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_name: &str,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };

    let mut args = if target.prefix_len() == 32 {
        vec![
            verb.to_owned(),
            "-host".to_owned(),
            target.addr().to_string(),
        ]
    } else {
        vec![
            verb.to_owned(),
            "-net".to_owned(),
            target.network().to_string(),
            "-netmask".to_owned(),
            prefix_to_mask(target.prefix_len()).to_string(),
        ]
    };

    if matches!(action, RouteAction::Add) {
        args.extend(["-interface".to_owned(), if_name.to_owned()]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn macos_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let verb = match action {
        RouteAction::Add => "add",
        RouteAction::Delete => "delete",
    };
    let mut args = vec![verb.to_owned(), "-host".to_owned(), target.to_string()];

    if matches!(action, RouteAction::Add) {
        if let Some(gateway) = route.gateway {
            args.push(gateway.to_string());
        } else {
            let if_name = route
                .if_name
                .as_deref()
                .ok_or_else(|| anyhow!("macOS control route requires a gateway or interface"))?;
            args.extend(["-interface".to_owned(), if_name.to_owned()]);
        }
    }

    Ok(("route".to_owned(), args))
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_route_command(
    action: RouteAction,
    target: Ipv4Net,
    if_index: u32,
    gateway: Ipv4Addr,
) -> (String, Vec<String>) {
    let verb = match action {
        RouteAction::Add => "ADD",
        RouteAction::Delete => "DELETE",
    };
    let mut args = vec![
        verb.to_owned(),
        target.network().to_string(),
        "MASK".to_owned(),
        prefix_to_mask(target.prefix_len()).to_string(),
        gateway.to_string(),
    ];
    if matches!(action, RouteAction::Add) {
        args.extend([
            "METRIC".to_owned(),
            "1".to_owned(),
            "IF".to_owned(),
            if_index.to_string(),
        ]);
    }

    ("route".to_owned(), args)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_control_route_command(
    action: RouteAction,
    target: Ipv4Addr,
    route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    let if_index = route
        .if_index
        .ok_or_else(|| anyhow!("Windows control route requires an interface index"))?;
    let gateway = route
        .gateway
        .ok_or_else(|| anyhow!("Windows control route requires a next hop"))?;
    Ok(windows_route_command(
        action,
        Ipv4Net::new(target, 32).expect("host route prefix is valid"),
        if_index,
        gateway,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn route_command(
    _action: RouteAction,
    _target: Ipv4Net,
    _if_name: &str,
    _if_index: u32,
    _gateway: Ipv4Addr,
) -> Result<(String, Vec<String>)> {
    bail!("route management is not implemented for this operating system")
}

fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ipv4Addr::from(bits)
}

fn virtual_dns_ip(tun_ip: Ipv4Addr, tun_prefix: u8) -> Result<Ipv4Addr> {
    if tun_prefix > 32 {
        bail!("tun-prefix must be <= 32");
    }
    if tun_prefix > 30 {
        bail!("--dns requires a TUN prefix of /30 or wider so Rustle can reserve a virtual DNS IP");
    }

    let mask = u32::from(prefix_to_mask(tun_prefix));
    let network = u32::from(tun_ip) & mask;
    let broadcast = network | !mask;
    let first = network + 1;
    let last = broadcast - 1;
    let tun = u32::from(tun_ip);
    let preferred = (network + 53).clamp(first, last);

    for candidate in [preferred, first, first.saturating_add(1), last] {
        if candidate >= first && candidate <= last && candidate != tun {
            return Ok(Ipv4Addr::from(candidate));
        }
    }

    bail!("could not reserve a virtual DNS IP inside {tun_ip}/{tun_prefix}")
}

#[derive(Clone)]
struct SshSessionPool {
    slots: Arc<Vec<Arc<SshSessionSlot>>>,
    next_background: Arc<AtomicUsize>,
}

impl SshSessionPool {
    fn new(slots: Vec<Arc<SshSessionSlot>>) -> Result<Self> {
        if slots.is_empty() {
            bail!("SSH session pool must contain at least one session");
        }
        Ok(Self {
            slots: Arc::new(slots),
            next_background: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn slot_for_flow(&self, id: tcp_core::FlowId) -> Arc<SshSessionSlot> {
        Arc::clone(&self.slots[ssh_session_index_for_flow(id, self.slots.len())])
    }

    fn slot_for_background(&self) -> Arc<SshSessionSlot> {
        let index = self.next_background.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        Arc::clone(&self.slots[index])
    }

    async fn open_direct_tcpip_for_flow(
        &self,
        id: tcp_core::FlowId,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let flow = id.key;
        self.slot_for_flow(id)
            .open_direct_tcpip(
                flow.dst_ip.to_string(),
                u32::from(flow.dst_port),
                flow.src_ip.to_string(),
                u32::from(flow.src_port),
            )
            .await
    }

    async fn open_background_direct_tcpip(
        &self,
        host: String,
        port: u32,
        originator_address: String,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        self.slot_for_background()
            .open_direct_tcpip(host, port, originator_address, originator_port)
            .await
    }
}

struct SshSessionSlot {
    index: usize,
    handle: Mutex<Handle<Client>>,
    reconnect_lock: Mutex<()>,
    prepared: Arc<PreparedSshConnection>,
    reconnects: AtomicUsize,
}

impl SshSessionSlot {
    fn new(index: usize, handle: Handle<Client>, prepared: Arc<PreparedSshConnection>) -> Self {
        Self {
            index,
            handle: Mutex::new(handle),
            reconnect_lock: Mutex::new(()),
            prepared,
            reconnects: AtomicUsize::new(0),
        }
    }

    async fn open_direct_tcpip(
        &self,
        host: String,
        port: u32,
        originator_address: String,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let observed_reconnects = self.reconnects.load(Ordering::Acquire);
        match self
            .try_open_direct_tcpip(&host, port, &originator_address, originator_port)
            .await
        {
            Ok(channel) => Ok(channel),
            Err(first_err) => {
                eprintln!(
                    "ssh: session {} direct-tcpip open failed: {first_err:#}; reconnecting",
                    self.index
                );
                self.reconnect_if_unchanged(observed_reconnects).await?;
                self.try_open_direct_tcpip(&host, port, &originator_address, originator_port)
                    .await
                    .with_context(|| {
                        format!(
                            "direct-tcpip open still failed after reconnecting SSH session {}",
                            self.index
                        )
                    })
            }
        }
    }

    async fn try_open_direct_tcpip(
        &self,
        host: &str,
        port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ssh_bridge::DirectTcpipChannel> {
        let handle = self.handle.lock().await;
        handle
            .channel_open_direct_tcpip(
                host.to_owned(),
                port,
                originator_address.to_owned(),
                originator_port,
            )
            .await
            .with_context(|| {
                format!(
                    "failed to open SSH direct-tcpip channel on session {}",
                    self.index
                )
            })
    }

    async fn reconnect_if_unchanged(&self, observed_reconnects: usize) -> Result<()> {
        let _guard = self.reconnect_lock.lock().await;
        if self.reconnects.load(Ordering::Acquire) != observed_reconnects {
            eprintln!(
                "ssh: session {} was already reconnected by another flow",
                self.index
            );
            return Ok(());
        }

        let new_handle = connect_prepared_ssh(&self.prepared)
            .await
            .with_context(|| format!("failed to reconnect SSH session {}", self.index))?;
        let mut handle = self.handle.lock().await;
        *handle = new_handle;
        let reconnect_count = self.reconnects.fetch_add(1, Ordering::AcqRel) + 1;
        eprintln!(
            "ssh: session {} reconnected count={reconnect_count}",
            self.index
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PreparedSshConnection {
    target: SshTarget,
    identity: Option<PathBuf>,
    password: Option<String>,
    known_hosts: Option<PathBuf>,
    insecure_accept_host_key: bool,
    accept_new_host_key: bool,
    connect_timeout: Duration,
}

async fn connect_ssh_pool(args: &SshArgs, desired_sessions: usize) -> Result<SshSessionPool> {
    validate_ssh_session_count(desired_sessions)?;
    let prepared = Arc::new(prepare_ssh_connection(args)?);
    let mut slots = Vec::with_capacity(desired_sessions);
    slots.push(Arc::new(SshSessionSlot::new(
        0,
        connect_prepared_ssh(&prepared).await?,
        Arc::clone(&prepared),
    )));

    for index in 1..desired_sessions {
        match connect_prepared_ssh(&prepared).await {
            Ok(handle) => slots.push(Arc::new(SshSessionSlot::new(
                index,
                handle,
                Arc::clone(&prepared),
            ))),
            Err(err) => {
                eprintln!(
                    "ssh: additional session {}/{} failed: {err:#}; continuing with {} session(s)",
                    index + 1,
                    desired_sessions,
                    slots.len()
                );
                break;
            }
        }
    }

    let pool = SshSessionPool::new(slots)?;
    eprintln!("ssh: established {} session(s)", pool.len());
    Ok(pool)
}

fn validate_ssh_session_count(sessions: usize) -> Result<()> {
    if sessions == 0 {
        bail!("--ssh-sessions must be greater than zero");
    }
    if sessions > MAX_SSH_SESSIONS {
        bail!("--ssh-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

fn validate_agent_session_count(sessions: usize) -> Result<()> {
    if sessions == 0 {
        bail!("--agent-sessions must be greater than zero");
    }
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

fn validate_agent_session_request_count(sessions: usize) -> Result<()> {
    if sessions > MAX_SSH_SESSIONS {
        bail!("--agent-sessions must be <= {MAX_SSH_SESSIONS}");
    }
    Ok(())
}

fn resolve_agent_session_count(requested: usize) -> usize {
    if requested == AUTO_AGENT_SESSIONS {
        recommended_agent_session_count()
    } else {
        requested
    }
}

fn recommended_agent_session_count() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2);
    recommended_agent_session_count_for_parallelism(parallelism)
}

fn recommended_agent_session_count_for_parallelism(parallelism: usize) -> usize {
    let cap = MAX_AUTO_AGENT_SESSIONS.min(MAX_SSH_SESSIONS);
    let parallelism = parallelism.max(1);
    for lanes in 1..=cap {
        if parallelism <= lanes.saturating_mul(lanes) {
            return lanes;
        }
    }
    cap
}

fn ssh_session_index_for_flow(id: tcp_core::FlowId, sessions: usize) -> usize {
    assert!(sessions > 0, "session count must be non-zero");
    (finalize_flow_hash(flow_hash(id)) % sessions as u64) as usize
}

fn flow_hash(id: tcp_core::FlowId) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in id.key.src_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.src_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.dst_ip.octets() {
        hash = fnv1a_mix(hash, byte);
    }
    for byte in id.key.dst_port.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash = fnv1a_mix(hash, 6);
    for byte in id.generation.to_be_bytes() {
        hash = fnv1a_mix(hash, byte);
    }
    hash
}

fn fnv1a_mix(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
}

fn finalize_flow_hash(mut hash: u64) -> u64 {
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

async fn connect_ssh(args: &SshArgs) -> Result<Handle<Client>> {
    let prepared = prepare_ssh_connection(args)?;
    connect_prepared_ssh(&prepared).await
}

fn prepare_ssh_connection(args: &SshArgs) -> Result<PreparedSshConnection> {
    let Some(remote) = args.ssh_server.as_deref() else {
        bail!("missing SSH remote; use -r user@host");
    };
    if args.insecure_accept_host_key && args.accept_new_host_key {
        bail!("--accept-new-host-key cannot be combined with --insecure-accept-host-key");
    }
    let target = parse_ssh_target(remote, args.ssh_user.as_deref())?;
    let password = resolve_ssh_password(args)?;

    Ok(PreparedSshConnection {
        target,
        identity: args.identity.clone(),
        password,
        known_hosts: args.known_hosts.clone(),
        insecure_accept_host_key: args.insecure_accept_host_key,
        accept_new_host_key: args.accept_new_host_key,
        connect_timeout: ssh_connect_timeout(args.ssh_connect_timeout_secs)?,
    })
}

fn resolve_ssh_password(args: &SshArgs) -> Result<Option<String>> {
    if args.password.is_some() && args.password_file.is_some() {
        bail!("--password-file cannot be combined with --password");
    }
    match (&args.password, &args.password_file) {
        (_, Some(path)) => read_password_file(path).map(Some),
        (Some(Some(value)), None) => {
            eprintln!(
                "ssh: warning: inline --password values may be visible to other local users; prefer --password-file or an interactive prompt"
            );
            Ok(Some(value.clone()))
        }
        (Some(None), None) => {
            let password = match read_password_file_from_env()? {
                Some(value) => value,
                None => rpassword::prompt_password("SSH password: ")
                    .context("failed to read password from terminal")?,
            };
            Ok(Some(password))
        }
        (None, None) => Ok(None),
    }
}

async fn connect_prepared_ssh(prepared: &PreparedSshConnection) -> Result<Handle<Client>> {
    let target = &prepared.target;
    let verifier = HostKeyVerifier::new(
        target.host.clone(),
        target.port,
        prepared.known_hosts.clone(),
        prepared.insecure_accept_host_key,
        prepared.accept_new_host_key,
    );
    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 3,
        nodelay: true,
        ..Config::default()
    });

    eprintln!(
        "ssh: connecting to {} with timeout {}s",
        target.addr,
        prepared.connect_timeout.as_secs()
    );
    let mut handle = tokio::time::timeout(
        prepared.connect_timeout,
        client::connect(config, target.addr.as_str(), Client { verifier }),
    )
    .await
    .with_context(|| {
        format!(
            "timed out after {}s connecting to SSH server {}",
            prepared.connect_timeout.as_secs(),
            target.addr
        )
    })?
    .with_context(|| format!("failed to connect to SSH server {}", target.addr))?;
    eprintln!(
        "ssh: connected to {}; authenticating as {}",
        target.addr, target.user
    );
    authenticate(&mut handle, &target.user, prepared).await?;
    eprintln!("ssh: authenticated to {}", target.addr);
    Ok(handle)
}

fn ssh_connect_timeout(seconds: u64) -> Result<Duration> {
    if seconds == 0 {
        bail!("--ssh-connect-timeout must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

async fn authenticate(
    handle: &mut Handle<Client>,
    user: &str,
    prepared: &PreparedSshConnection,
) -> Result<()> {
    if let Some(identity) = &prepared.identity {
        let key = load_private_key(identity)?;
        let result = handle
            .authenticate_publickey(user.to_owned(), key)
            .await
            .context("public-key authentication failed")?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    if let Some(password) = &prepared.password {
        let result = handle
            .authenticate_password(user.to_owned(), password.clone())
            .await
            .context("password authentication failed")?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    bail!("authentication failed; provide --identity, --password, or both")
}

fn read_password_file_from_env() -> Result<Option<String>> {
    let Some(path) = env::var_os(SSH_PASSWORD_FILE_ENV) else {
        return Ok(None);
    };
    read_password_file(Path::new(&path)).map(Some)
}

fn read_password_file(path: &Path) -> Result<String> {
    let mut password = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SSH password file {}", path.display()))?;
    while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    Ok(password)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyWithHashAlg> {
    let key_data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    let key = PrivateKey::from_openssh(&key_data)
        .with_context(|| format!("failed to parse private key {}", path.display()))?;
    let hash_alg = match key.algorithm() {
        Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
        _ => None,
    };

    Ok(PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SshTarget {
    user: String,
    addr: String,
    host: String,
    port: u16,
}

fn parse_ssh_target(remote: &str, user_override: Option<&str>) -> Result<SshTarget> {
    let (remote_user, host) = match remote.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() && !host.is_empty() => (Some(user), host),
        Some(_) => bail!("invalid SSH remote {remote}; expected user@host"),
        None => (None, remote),
    };

    let user = user_override
        .or(remote_user)
        .map(str::to_owned)
        .or_else(default_username)
        .ok_or_else(|| anyhow!("missing SSH user; use -r user@host or --user"))?;

    let endpoint = parse_ssh_endpoint(host)?;

    Ok(SshTarget {
        user,
        addr: endpoint.addr,
        host: endpoint.host,
        port: endpoint.port,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct SshEndpoint {
    host: String,
    port: u16,
    addr: String,
}

fn parse_ssh_endpoint(input: &str) -> Result<SshEndpoint> {
    if input.is_empty() {
        bail!("missing SSH host");
    }

    let (host, port) = if let Some(rest) = input.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            bail!("invalid SSH remote host {input}; missing closing ]");
        };
        if host.is_empty() {
            bail!("invalid SSH remote host {input}; empty bracketed host");
        }
        let port = match suffix.strip_prefix(':') {
            Some(port) if !port.is_empty() => parse_port(port, input)?,
            Some(_) => bail!("invalid SSH remote host {input}; empty port"),
            None if suffix.is_empty() => 22,
            None => bail!("invalid SSH remote host {input}; expected [host]:port"),
        };
        (host.to_owned(), port)
    } else if let Some((host, port)) = input.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            bail!("invalid SSH remote host {input}; expected host[:port]");
        }
        (host.to_owned(), parse_port(port, input)?)
    } else {
        (input.to_owned(), 22)
    };

    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    Ok(SshEndpoint { host, port, addr })
}

fn parse_port(port: &str, input: &str) -> Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("invalid SSH remote port in {input}"))
}

fn default_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|value| !value.is_empty())
        })
}

#[derive(Clone, Debug)]
struct Destination {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct Ipv4Destination {
    host: String,
    ip: Ipv4Addr,
    port: u16,
}

fn parse_destination(input: &str) -> Result<Destination> {
    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("destination must be in host:port form"))?;
    if host.is_empty() {
        bail!("destination host must not be empty");
    }

    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid destination port in {input}"))?;
    Ok(Destination {
        host: host.to_owned(),
        port,
    })
}

fn parse_ipv4_destination(input: &str) -> Result<Ipv4Destination> {
    let destination = parse_destination(input)?;
    let ip = destination
        .host
        .parse::<Ipv4Addr>()
        .with_context(|| format!("destination must use an IPv4 address for the MVP: {input}"))?;
    Ok(Ipv4Destination {
        host: destination.host,
        ip,
        port: destination.port,
    })
}

fn default_http_request(host: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[derive(Clone, Debug)]
struct HostKeyVerifier {
    host: String,
    port: u16,
    known_hosts: Option<PathBuf>,
    insecure_accept: bool,
    accept_new: bool,
}

impl HostKeyVerifier {
    fn new(
        host: String,
        port: u16,
        known_hosts: Option<PathBuf>,
        insecure_accept: bool,
        accept_new: bool,
    ) -> Self {
        Self {
            host,
            port,
            known_hosts,
            insecure_accept,
            accept_new,
        }
    }

    fn verify(&self, server_public_key: &PublicKey) -> Result<bool> {
        if self.insecure_accept {
            eprintln!(
                "ssh: insecurely accepting host key for {} ({})",
                self.known_hosts_hostport(),
                server_public_key.fingerprint(Default::default())
            );
            return Ok(true);
        }

        let path = self.known_hosts_path()?;
        let input = match std::fs::read_to_string(&path) {
            Ok(input) => input,
            Err(err) if self.accept_new && err.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read known_hosts file {}", path.display()))
            }
        };
        let candidates = self.host_match_candidates();
        let mut host_matched = false;
        let mut key_mismatch = false;

        for entry in KnownHosts::new(&input) {
            let entry = entry.with_context(|| format!("failed to parse {}", path.display()))?;
            if !known_hosts_entry_matches(entry.host_patterns(), &candidates) {
                continue;
            }

            host_matched = true;
            let key_matches = entry.public_key().key_data() == server_public_key.key_data();
            if matches!(entry.marker(), Some(Marker::Revoked)) && key_matches {
                bail!(
                    "SSH host key for {} is marked revoked in {}",
                    self.known_hosts_hostport(),
                    path.display()
                );
            }

            if key_matches && entry.marker().is_none() {
                return Ok(true);
            }
            if key_matches && matches!(entry.marker(), Some(Marker::CertAuthority)) {
                continue;
            }
            key_mismatch = true;
        }

        let fingerprint = server_public_key.fingerprint(Default::default());
        if key_mismatch {
            bail!(
                "SSH host key mismatch for {}; presented fingerprint {}; update {} only if the server key changed intentionally",
                self.known_hosts_hostport(),
                fingerprint,
                path.display()
            );
        }
        if host_matched {
            bail!(
                "SSH host entry for {} exists in {}, but no usable plain host-key entry matched fingerprint {}",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
        }

        if self.accept_new {
            self.append_known_host(&path, server_public_key)?;
            eprintln!(
                "ssh: recorded new host key for {} in {} ({})",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
            return Ok(true);
        }

        bail!(
            "SSH host {} is not in {}; verify the fingerprint {}, then add it with ssh-keyscan, use --accept-new-host-key to trust and record this first key, or use --insecure-accept-host-key only for a controlled lab",
            self.known_hosts_hostport(),
            path.display(),
            fingerprint
        )
    }

    fn append_known_host(&self, path: &Path, server_public_key: &PublicKey) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_known_hosts_parent_dir(parent)?;
            }
        }

        let key = server_public_key
            .to_openssh()
            .context("failed to encode SSH server public key")?;
        let entry = format!("{} {}\n", self.known_hosts_hostport(), key);
        append_known_hosts_entry(path, &entry)
            .with_context(|| format!("failed to append host key to {}", path.display()))
    }

    fn known_hosts_path(&self) -> Result<PathBuf> {
        if let Some(path) = &self.known_hosts {
            return Ok(path.clone());
        }
        default_known_hosts_path()
            .ok_or_else(|| anyhow!("could not locate home directory for ~/.ssh/known_hosts"))
    }

    fn known_hosts_hostport(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }

    fn host_match_candidates(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        candidates.push(self.known_hosts_hostport());
        if self.port == 22 {
            candidates.push(self.host.clone());
        }
        let lowercase_host = self.host.to_ascii_lowercase();
        if lowercase_host != self.host {
            if self.port == 22 {
                candidates.push(lowercase_host.clone());
            } else {
                candidates.push(format!("[{lowercase_host}]:{}", self.port));
            }
        }
        dedupe_strings(candidates)
    }
}

fn default_known_hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .map(|home| home.join(".ssh").join("known_hosts"))
}

fn create_known_hosts_parent_dir(path: &Path) -> Result<()> {
    let existed = path.exists();
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create known_hosts directory {}", path.display()))?;
    if existed {
        Ok(())
    } else {
        set_known_hosts_parent_permissions(path)
    }
}

#[cfg(unix)]
fn set_known_hosts_parent_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_parent_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn append_known_hosts_entry(path: &Path, entry: &str) -> Result<()> {
    let needs_separator = known_hosts_needs_leading_newline(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    if needs_separator {
        file.write_all(b"\n")?;
    }
    file.write_all(entry.as_bytes())?;
    file.sync_all()?;
    set_known_hosts_file_permissions(path)
}

fn known_hosts_needs_leading_newline(path: &Path) -> Result<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(false);
    }
    use std::io::{Read, Seek};
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    Ok(byte[0] != b'\n')
}

#[cfg(unix)]
fn set_known_hosts_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn known_hosts_entry_matches(patterns: &HostPatterns, candidates: &[String]) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => patterns_match(patterns, candidates),
        HostPatterns::HashedName { salt, hash } => candidates.iter().any(|candidate| {
            hashed_known_host_matches(salt, hash, candidate)
                || hashed_known_host_matches(salt, hash, &candidate.to_ascii_lowercase())
        }),
    }
}

fn patterns_match(patterns: &[String], candidates: &[String]) -> bool {
    let mut matched_positive = false;
    for pattern in patterns {
        let (negated, pattern) = if let Some(pattern) = pattern.strip_prefix('!') {
            (true, pattern)
        } else {
            (false, pattern.as_str())
        };
        let matched = candidates
            .iter()
            .any(|candidate| glob_match_case_insensitive(pattern, candidate));
        if matched && negated {
            return false;
        }
        matched_positive |= matched;
    }
    matched_positive
}

fn glob_match_case_insensitive(pattern: &str, candidate: &str) -> bool {
    glob_match(
        pattern.to_ascii_lowercase().as_bytes(),
        candidate.to_ascii_lowercase().as_bytes(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn control_route_command(
    _action: RouteAction,
    _target: Ipv4Addr,
    _route: &ExistingRoute,
) -> Result<(String, Vec<String>)> {
    bail!(
        "SSH control route protection is not implemented for {}",
        env::consts::OS
    );
}

fn glob_match(pattern: &[u8], candidate: &[u8]) -> bool {
    let (mut p, mut c) = (0, 0);
    let mut star = None;
    let mut star_candidate = 0;

    while c < candidate.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == candidate[c]) {
            p += 1;
            c += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_candidate = c;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_candidate += 1;
            c = star_candidate;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn hashed_known_host_matches(salt: &[u8], expected_hash: &[u8; 20], candidate: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let tag = hmac::sign(&key, candidate.as_bytes());
    tag.as_ref() == expected_hash
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.iter().any(|existing| existing == &value) {
            unique.push(value);
        }
    }
    unique
}

#[derive(Clone)]
struct Client {
    verifier: HostKeyVerifier,
}

impl Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool> {
        self.verifier.verify(server_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    const TEST_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const OTHER_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";

    #[test]
    fn prefix_masks_are_big_endian_ipv4_masks() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn virtual_dns_ip_uses_stable_host_inside_tun_subnet() {
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 255, 255, 1), 24).unwrap(),
            Ipv4Addr::new(10, 255, 255, 53)
        );
        assert_eq!(
            virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 30).unwrap(),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert!(virtual_dns_ip(Ipv4Addr::new(10, 0, 0, 1), 31).is_err());
    }

    #[test]
    fn dns_inflight_caps_queries_and_tracks_releases() {
        let mut inflight = DnsInflight::new(2);

        assert_eq!(inflight.current(), 0);
        assert!(inflight.try_admit());
        assert!(inflight.try_admit());
        assert!(!inflight.try_admit());
        assert_eq!(inflight.current(), 2);
        assert_eq!(inflight.dropped(), 1);

        inflight.complete();
        assert_eq!(inflight.current(), 1);
        assert_eq!(inflight.completed(), 1);

        assert!(inflight.try_admit());
        assert_eq!(inflight.current(), 2);

        inflight.complete();
        inflight.complete();
        inflight.complete();
        assert_eq!(inflight.current(), 0);
        assert_eq!(inflight.completed(), 3);
    }

    #[test]
    fn udp_response_backpressure_cannot_block_close_accounting() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };

        assert!(events.try_send_response(key, Bytes::from_static(b"first")));
        assert!(!events.try_send_response(key, Bytes::from_static(b"second")));
        assert!(events.try_send_closed(key, None));

        let response = response_rx.try_recv().expect("queued UDP response");
        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"first");
        assert!(response_rx.try_recv().is_err());

        let closed = close_rx.try_recv().expect("queued UDP close");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
    }

    #[test]
    fn udp_response_event_keeps_agent_payload_as_bytes() {
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let payload = Bytes::from_static(b"agent-response");
        let ptr = payload.as_ptr();

        assert!(events.try_send_response(key, payload));
        let response = response_rx.try_recv().expect("queued UDP response");

        assert_eq!(response.key, key);
        assert_eq!(response.payload.as_ref(), b"agent-response");
        assert_eq!(response.payload.as_ptr(), ptr);
    }

    #[tokio::test]
    async fn udp_admission_moves_parsed_payload_bytes_into_association_queue() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
        };
        let payload = Bytes::from_static(b"client-datagram");
        let payload_ptr = payload.as_ptr();
        let (to_remote, mut from_local) = mpsc::channel(1);
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let (response_tx, _response_rx) = mpsc::channel(1);
        let (close_tx, _close_rx) = mpsc::channel(1);
        let mut association_limit = DnsInflight::new(1);
        let mut stats = TunnelStats::new();

        admit_udp_datagram(
            bridge.clone(),
            dns::UdpPacket {
                src_ip: key.src_ip,
                src_port: key.src_port,
                dst_ip: key.dst_ip,
                dst_port: key.dst_port,
                payload,
            },
            &mut associations,
            &mut association_limit,
            UdpAssociationEvents {
                response_tx,
                close_tx,
            },
            UDP_ASSOCIATION_IDLE_TIMEOUT,
            &mut stats,
        );

        let queued = from_local.try_recv().expect("queued UDP payload");
        assert_eq!(queued.as_ref(), b"client-datagram");
        assert_eq!(queued.as_ptr(), payload_ptr);
        assert_eq!(stats.udp_forwarded, 1);
        assert_eq!(stats.udp_dropped, 0);

        drop(associations);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[test]
    fn direct_tcpip_generic_udp_drop_is_counted_without_admission() {
        let mut stats = TunnelStats::new();
        let request = dns::UdpPacket {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(192, 168, 1, 10),
            dst_port: 53,
            payload: Bytes::from_static(b"generic-udp"),
        };

        drop_unsupported_direct_udp(&request, &mut stats);

        assert_eq!(stats.udp_forwarded, 0);
        assert_eq!(stats.udp_dropped, 1);
        assert_eq!(stats.udp_ok, 0);
        assert_eq!(stats.udp_failed, 1);
    }

    #[test]
    fn dns_response_event_keeps_remote_payload_as_bytes() {
        let request = dns::UdpDnsRequest {
            src_ip: Ipv4Addr::new(10, 255, 255, 2),
            dst_ip: virtual_dns_ip(DEFAULT_TUN_IP, DEFAULT_TUN_PREFIX).unwrap(),
            src_port: 49152,
            dst_port: dns::DNS_PORT,
            payload: Bytes::from_static(b"\x12\x34query"),
        };
        let payload = Bytes::from_static(b"\x12\x34answer");
        let ptr = payload.as_ptr();
        let (event_tx, mut event_rx) = mpsc::channel(1);

        assert!(send_dns_response_event(
            &event_tx,
            DnsResponseEvent {
                request: request.clone(),
                result: Ok(payload),
            },
        ));
        let event = event_rx.try_recv().expect("queued DNS response");

        assert_eq!(event.request, request);
        let response = event.result.expect("DNS response payload");
        assert_eq!(response.as_ref(), b"\x12\x34answer");
        assert_eq!(response.as_ptr(), ptr);
    }

    #[test]
    fn password_file_reader_strips_shell_newlines_only() {
        let path = env::temp_dir().join(format!(
            "rustle-password-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, " secret value \r\n").unwrap();

        let password = read_password_file(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(password, " secret value ");
    }

    #[test]
    fn ssh_password_file_option_reads_password_without_argv_secret() {
        let path = env::temp_dir().join(format!(
            "rustle-password-file-option-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, "file secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password-file",
            path.to_str().expect("password path is UTF-8"),
            "10.0.0.0/8",
        ])
        .expect("compact CLI with password file");

        assert_eq!(cli.compact.ssh.password, None);
        assert_eq!(
            cli.compact.ssh.password_file.as_deref(),
            Some(path.as_path())
        );
        assert_eq!(
            resolve_ssh_password(&cli.compact.ssh).expect("read password file"),
            Some("file secret".to_owned())
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn stats_formatting_uses_stable_units() {
        assert_eq!(format_bytes(999), "999B");
        assert_eq!(format_bytes(1024), "1.0KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MiB");
        assert_eq!(format_duration(Duration::from_millis(1234)), "1.234s");
    }

    #[test]
    fn stats_report_bridge_pressure_and_open_latency() {
        let mut stats = TunnelStats::new();
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 21 });
        stats.record_bridge_event(&ssh_bridge::BridgeEvent::Opened { id, open_ms: 43 });
        stats.record_bridge_admission(BridgeAdmissionStats {
            deferred_active_limit: 2,
            deferred_open_limit: 3,
        });
        stats.record_local_drain(LocalDrainStats {
            bytes_to_bridge: 1024,
            bridge_backpressure_events: 4,
            bridge_send_failures: 0,
        });
        stats.record_tun_write(TunWriteStats {
            packets: 2,
            bytes: 2048,
            dropped_packets: 1,
            dropped_bytes: 512,
        });

        let line = stats.status_line(
            1,
            1,
            &RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW),
            &DnsInflight::new(MAX_IN_FLIGHT_DNS_QUERIES),
            &DnsInflight::new(MAX_ACTIVE_UDP_ASSOCIATIONS),
            AgentBridgeSnapshot {
                reconnects: AgentReconnectSnapshot {
                    attempts: 5,
                    successes: 4,
                    failures: 1,
                },
                lanes_total: 4,
                lanes_desired: 4,
                lanes_available: 1,
                lanes_failed: 1,
                lanes_missing: 1,
                lanes_quarantined: 1,
                lanes_repairing: 1,
                active_streams: 7,
                max_lane_load: 4,
                max_quarantine_ms: 250,
            },
        );

        assert!(line.contains("tun_tx=2/2.0KiB"));
        assert!(line.contains("tun_drop=1/512B"));
        assert!(line.contains("ssh=open:2 fail:0 eof:0 close:0"));
        assert!(line.contains("open_ms=avg:32 max:43"));
        assert!(line.contains("defer=active:2 open:3"));
        assert!(line.contains("agent_reconnect=attempt:5 ok:4 fail:1"));
        assert!(line.contains(
            "agent_lanes=total:4 desired:4 ok:1 fail:1 missing:1 quarantine:1 repairing:1 active:7 max_load:4 max_quarantine_ms:250"
        ));
        assert!(line.contains("bridge_backpressure:4"));
    }

    #[test]
    fn dns_and_udp_success_require_local_tun_delivery() {
        let mut stats = TunnelStats::new();

        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );
        stats.record_dns_delivery(
            true,
            TunWriteStats {
                packets: 0,
                bytes: 0,
                dropped_packets: 1,
                dropped_bytes: 96,
            },
        );
        stats.record_dns_delivery(
            false,
            TunWriteStats {
                packets: 1,
                bytes: 96,
                dropped_packets: 0,
                dropped_bytes: 0,
            },
        );

        stats.record_udp_delivery(TunWriteStats {
            packets: 1,
            bytes: 128,
            dropped_packets: 0,
            dropped_bytes: 0,
        });
        stats.record_udp_delivery(TunWriteStats {
            packets: 0,
            bytes: 0,
            dropped_packets: 1,
            dropped_bytes: 128,
        });

        assert_eq!(stats.dns_ok, 1);
        assert_eq!(stats.dns_failed, 2);
        assert_eq!(stats.udp_ok, 1);
        assert_eq!(stats.udp_failed, 1);
        assert_eq!(stats.tun_tx_packets, 3);
        assert_eq!(stats.tun_tx_dropped_packets, 2);
    }

    #[test]
    fn macos_route_delete_omits_interface_operand() {
        let target = "192.168.0.0/16".parse().unwrap();

        let (_, add_args) = macos_route_command(RouteAction::Add, target, "utun7");
        assert_eq!(
            add_args,
            vec![
                "add",
                "-net",
                "192.168.0.0",
                "-netmask",
                "255.255.0.0",
                "-interface",
                "utun7"
            ]
        );

        let (_, delete_args) = macos_route_command(RouteAction::Delete, target, "utun7");
        assert_eq!(
            delete_args,
            vec!["delete", "-net", "192.168.0.0", "-netmask", "255.255.0.0"]
        );
    }

    #[test]
    fn linux_route_commands_use_ip_route_dev_form() {
        let target = "192.168.0.0/16".parse().unwrap();

        assert_eq!(
            linux_route_command(RouteAction::Add, target, "tun0"),
            (
                "ip".to_owned(),
                vec!["route", "add", "192.168.0.0/16", "dev", "tun0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            linux_route_command(RouteAction::Delete, target, "tun0"),
            (
                "ip".to_owned(),
                vec!["route", "del", "192.168.0.0/16", "dev", "tun0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
    }

    #[test]
    fn windows_route_commands_use_interface_index_on_add() {
        let target = "192.168.0.0/16".parse().unwrap();
        let gateway = Ipv4Addr::new(10, 255, 255, 1);

        assert_eq!(
            windows_route_command(RouteAction::Add, target, 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "192.168.0.0",
                    "MASK",
                    "255.255.0.0",
                    "10.255.255.1",
                    "METRIC",
                    "1",
                    "IF",
                    "42"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
        assert_eq!(
            windows_route_command(RouteAction::Delete, target, 42, gateway),
            (
                "route".to_owned(),
                vec![
                    "DELETE",
                    "192.168.0.0",
                    "MASK",
                    "255.255.0.0",
                    "10.255.255.1"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
    }

    #[test]
    fn control_route_commands_protect_ssh_host_via_existing_route() {
        let target = Ipv4Addr::new(203, 0, 113, 10);
        let route = ExistingRoute {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
            if_name: Some("en0".to_owned()),
            if_index: Some(42),
        };

        assert_eq!(
            macos_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec!["add", "-host", "203.0.113.10", "192.168.1.254"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            macos_control_route_command(RouteAction::Delete, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec!["delete", "-host", "203.0.113.10"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            linux_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "ip".to_owned(),
                vec![
                    "route",
                    "add",
                    "203.0.113.10/32",
                    "via",
                    "192.168.1.254",
                    "dev",
                    "en0"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
        assert_eq!(
            linux_control_route_command(RouteAction::Delete, target, &route).unwrap(),
            (
                "ip".to_owned(),
                vec!["route", "del", "203.0.113.10/32"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            )
        );
        assert_eq!(
            windows_control_route_command(RouteAction::Add, target, &route).unwrap(),
            (
                "route".to_owned(),
                vec![
                    "ADD",
                    "203.0.113.10",
                    "MASK",
                    "255.255.255.255",
                    "192.168.1.254",
                    "METRIC",
                    "1",
                    "IF",
                    "42"
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            )
        );
    }

    #[test]
    fn route_setup_rolls_back_added_routes_when_later_add_fails() {
        #[derive(Clone)]
        struct RecordingRouteExecutor {
            calls: std::sync::Arc<std::sync::Mutex<Vec<(RouteAction, Ipv4Net)>>>,
            fail_add: Ipv4Net,
        }

        impl RouteCommandExecutor for RecordingRouteExecutor {
            fn run_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Net,
                _if_name: &str,
                _if_index: u32,
                _gateway: Ipv4Addr,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                if action == RouteAction::Add && target == self.fail_add {
                    bail!("injected route add failure");
                }
                Ok(())
            }
        }

        let first = "192.168.0.0/24".parse().unwrap();
        let second = "192.168.1.0/24".parse().unwrap();
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let executor = RecordingRouteExecutor {
            calls: calls.clone(),
            fail_add: second,
        };

        let result = add_target_routes_with(
            &[first, second],
            "tun-test",
            7,
            Ipv4Addr::new(10, 255, 255, 1),
            executor,
        );
        let err = match result {
            Ok(_) => panic!("second route add must fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to add target route"));
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                (RouteAction::Add, first),
                (RouteAction::Add, second),
                (RouteAction::Delete, first),
            ]
        );
    }

    #[test]
    fn control_route_setup_deletes_added_host_route_on_drop() {
        #[derive(Clone)]
        struct RecordingControlRouteExecutor {
            calls: std::sync::Arc<std::sync::Mutex<Vec<(RouteAction, Ipv4Addr)>>>,
            route: ExistingRoute,
        }

        impl ControlRouteCommandExecutor for RecordingControlRouteExecutor {
            fn lookup_route_to(&self, _target: Ipv4Addr) -> Result<ExistingRoute> {
                Ok(self.route.clone())
            }

            fn run_control_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Addr,
                _route: &ExistingRoute,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                Ok(())
            }
        }

        let target = Ipv4Addr::new(203, 0, 113, 10);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let executor = RecordingControlRouteExecutor {
            calls: calls.clone(),
            route: ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: Some("en0".to_owned()),
                if_index: Some(7),
            },
        };

        let guard = add_ssh_control_route_with(target, executor)
            .expect("control route guard")
            .expect("gateway route should require a guard");
        assert_eq!(*calls.lock().unwrap(), vec![(RouteAction::Add, target)]);
        drop(guard);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(RouteAction::Add, target), (RouteAction::Delete, target)]
        );
    }

    #[test]
    fn control_route_setup_skips_direct_existing_routes() {
        #[derive(Clone)]
        struct DirectControlRouteExecutor {
            calls: std::sync::Arc<std::sync::Mutex<Vec<(RouteAction, Ipv4Addr)>>>,
        }

        impl ControlRouteCommandExecutor for DirectControlRouteExecutor {
            fn lookup_route_to(&self, _target: Ipv4Addr) -> Result<ExistingRoute> {
                Ok(ExistingRoute {
                    gateway: None,
                    if_name: Some("en0".to_owned()),
                    if_index: Some(7),
                })
            }

            fn run_control_route_command(
                &self,
                action: RouteAction,
                target: Ipv4Addr,
                _route: &ExistingRoute,
            ) -> Result<()> {
                self.calls.lock().unwrap().push((action, target));
                Ok(())
            }
        }

        let target = Ipv4Addr::new(192, 168, 1, 47);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let guard = add_ssh_control_route_with(
            target,
            DirectControlRouteExecutor {
                calls: calls.clone(),
            },
        )
        .expect("direct control route lookup should succeed");

        assert!(guard.is_none());
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn parse_ipv4_metadata_accepts_minimal_header() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 10, 10,
            0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let metadata = parse_ipv4_metadata(&packet).expect("valid packet");
        assert_eq!(metadata.total_len, 40);
        assert_eq!(metadata.protocol, 6);
        assert_eq!(metadata.src, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(metadata.dst, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn parse_ipv4_metadata_rejects_non_ipv4() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x60;
        let err = parse_ipv4_metadata(&packet).expect_err("IPv6 must not parse as IPv4");
        assert!(err.to_string().contains("not IPv4"));
    }

    #[test]
    fn target_cidr_parser_accepts_sshuttle_abbreviations() {
        let full = parse_target_cidr("0/0").expect("parse full-tunnel shorthand");
        assert_eq!(full.network(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(full.prefix_len(), 0);

        let private = parse_target_cidr("10/8").expect("parse class-A shorthand");
        assert_eq!(private.network(), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(private.prefix_len(), 8);

        let partial = parse_target_cidr("172.16/12").expect("parse partial IPv4 shorthand");
        assert_eq!(partial.network(), Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(partial.prefix_len(), 12);

        let canonical = parse_target_cidr("192.168.1.0/24").expect("parse canonical CIDR");
        assert_eq!(canonical.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(canonical.prefix_len(), 24);
    }

    #[test]
    fn target_cidr_parser_rejects_invalid_abbreviations() {
        for input in ["10/33", "300/8", "10..0/8", "10/-1", "example/8"] {
            assert!(
                parse_target_cidr(input).is_err(),
                "{input} should be rejected"
            );
        }
    }

    #[test]
    fn full_tunnel_expands_to_split_default_routes() {
        assert_eq!(
            expand_target_routes(&[parse_target_cidr("0/0").unwrap()]).unwrap(),
            vec![
                "0.0.0.0/1".parse::<Ipv4Net>().unwrap(),
                "128.0.0.0/1".parse::<Ipv4Net>().unwrap()
            ]
        );
    }

    #[test]
    fn validate_tun_args_accepts_full_tunnel_route() {
        let args = TunCaptureArgs {
            targets: vec!["0.0.0.0/0".parse().unwrap()],
            tun_ip: DEFAULT_TUN_IP,
            tun_prefix: DEFAULT_TUN_PREFIX,
            mtu: DEFAULT_MTU,
            name: None,
            exit_after_packets: None,
        };

        validate_tun_args(&args).expect("full tunnel should expand to split routes");
    }

    #[test]
    fn ssh_control_ip_to_protect_detects_captured_server() {
        let targets = expand_target_routes(&["0.0.0.0/0".parse().unwrap()]).unwrap();
        assert_eq!(
            ssh_control_ip_to_protect("127.0.0.1:22", &targets).unwrap(),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn route_get_parsers_extract_existing_routes() {
        assert_eq!(
            parse_macos_route_get(
                "   route to: 1.1.1.1\n\
                 destination: default\n\
                    gateway: 192.168.1.254\n\
                  interface: en0\n"
            )
            .unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 254)),
                if_name: Some("en0".to_owned()),
                if_index: None,
            }
        );
        assert_eq!(
            parse_linux_route_get("1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.10\n").unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: Some("eth0".to_owned()),
                if_index: None,
            }
        );
        assert_eq!(
            parse_windows_find_net_route("42 192.168.1.1\n").unwrap(),
            ExistingRoute {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                if_name: None,
                if_index: Some(42),
            }
        );
    }

    #[test]
    fn ssh_session_index_is_stable_for_same_flow_id() {
        let id = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(10, 255, 255, 2),
                49152,
                Ipv4Addr::new(192, 168, 1, 10),
                443,
            ),
            7,
        );

        let first = ssh_session_index_for_flow(id, 4);
        for _ in 0..16 {
            assert_eq!(ssh_session_index_for_flow(id, 4), first);
        }
    }

    #[test]
    fn ssh_session_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            let id = tcp_core::FlowId::new(
                tcp_core::FlowKey::tcp(
                    Ipv4Addr::new(10, 255, 255, 2),
                    49152 + offset,
                    Ipv4Addr::new(192, 168, 1, 10),
                    443,
                ),
                u64::from(offset) + 1,
            );
            seen.insert(ssh_session_index_for_flow(id, 4));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn agent_lane_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            seen.insert(agent_lane_index(
                &agent_proto::AgentOpenIpv4 {
                    destination_ip: Ipv4Addr::new(192, 168, 1, 10),
                    destination_port: 443,
                    originator_ip: Ipv4Addr::new(10, 255, 255, 2),
                    originator_port: 49152 + offset,
                },
                6,
                4,
            ));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn agent_host_lane_index_spreads_many_flows_across_pool() {
        let mut seen = std::collections::BTreeSet::new();
        for offset in 0..256_u16 {
            seen.insert(agent_host_lane_index(
                &agent_proto::AgentOpenHost {
                    destination_host: "resolver.internal".to_owned(),
                    destination_port: 53,
                    originator_ip: Ipv4Addr::new(10, 255, 255, 2),
                    originator_port: 49152 + offset,
                },
                6,
                4,
            ));
        }

        assert_eq!(seen, [0_usize, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn agent_lane_backoff_is_bounded_and_progressive() {
        let first = agent_lane_backoff_duration(0, 1);
        let second = agent_lane_backoff_duration(0, 2);
        let later = agent_lane_backoff_duration(0, 32);
        let shifted_lane = agent_lane_backoff_duration(1, 1);

        assert!(first >= AGENT_LANE_BACKOFF_BASE);
        assert!(second > first);
        assert_eq!(later, AGENT_LANE_BACKOFF_MAX);
        assert!(shifted_lane > first);
        assert!(shifted_lane <= AGENT_LANE_BACKOFF_MAX);
    }

    #[test]
    fn ssh_session_count_validation_bounds_pool_size() {
        assert!(validate_ssh_session_count(1).is_ok());
        assert!(validate_ssh_session_count(DEFAULT_SSH_SESSIONS).is_ok());
        assert!(validate_ssh_session_count(0).is_err());
        assert!(validate_ssh_session_count(MAX_SSH_SESSIONS + 1).is_err());
    }

    #[test]
    fn agent_session_count_validation_bounds_pool_size() {
        assert!(validate_agent_session_count(1).is_ok());
        assert!(validate_agent_session_count(MAX_AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_count(0).is_err());
        assert!(validate_agent_session_count(MAX_SSH_SESSIONS + 1).is_err());
        assert!(validate_agent_session_request_count(AUTO_AGENT_SESSIONS).is_ok());
        assert!(validate_agent_session_request_count(MAX_SSH_SESSIONS + 1).is_err());
    }

    #[test]
    fn auto_agent_session_count_is_conservative_and_nonzero() {
        assert_eq!(resolve_agent_session_count(3), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(0), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(1), 1);
        assert_eq!(recommended_agent_session_count_for_parallelism(2), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(4), 2);
        assert_eq!(recommended_agent_session_count_for_parallelism(5), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(9), 3);
        assert_eq!(recommended_agent_session_count_for_parallelism(10), 4);
        assert_eq!(
            recommended_agent_session_count_for_parallelism(usize::MAX),
            MAX_AUTO_AGENT_SESSIONS
        );
        let resolved = resolve_agent_session_count(AUTO_AGENT_SESSIONS);
        assert!((1..=MAX_AUTO_AGENT_SESSIONS).contains(&resolved));
    }

    #[test]
    fn auto_agent_sessions_fast_start_when_multiple_lanes_are_recommended() {
        assert!(!should_fast_start_agent_lanes(true, AUTO_AGENT_SESSIONS, 1));
        assert!(should_fast_start_agent_lanes(true, AUTO_AGENT_SESSIONS, 2));
        assert!(
            !should_fast_start_agent_lanes(false, AUTO_AGENT_SESSIONS, 2),
            "bridge-lab and other steady-state harnesses can opt out"
        );
        assert!(
            !should_fast_start_agent_lanes(true, 2, 2),
            "explicit --agent-sessions must keep full startup gating"
        );
        assert_eq!(
            format_agent_fast_start_message(1, 4),
            "agent: established 1/4 exec transport(s); warming 3 remaining exec transport(s) in background"
        );
        assert_eq!(
            format_agent_fast_start_message(1, 1),
            "agent: established 1/1 exec transport(s)"
        );
    }

    #[test]
    fn agent_established_message_reports_degraded_lane_pool() {
        assert_eq!(
            format_agent_established_message(3, 4),
            "agent: established 3/4 exec transport(s)"
        );
    }

    #[test]
    fn shell_quote_uses_single_quote_safe_form() {
        assert_eq!(shell_quote("/tmp/rustle-agent"), "'/tmp/rustle-agent'");
        assert_eq!(shell_quote("/tmp/rustle'agent"), "'/tmp/rustle'\\''agent'");
    }

    #[test]
    fn effective_agent_command_quotes_literal_agent_path() {
        assert_eq!(
            effective_agent_command(None, None).expect("default agent command"),
            DEFAULT_AGENT_COMMAND
        );
        assert_eq!(
            effective_agent_command(Some("/tmp/rustle agent"), None)
                .expect("raw command stays raw"),
            "/tmp/rustle agent"
        );
        assert_eq!(
            effective_agent_command(None, Some("/tmp/rustle dir/rustle'bin"))
                .expect("path command is quoted"),
            "'/tmp/rustle dir/rustle'\\''bin' agent"
        );
        assert!(effective_agent_command(Some(" "), None).is_err());
        assert!(effective_agent_command(None, Some(" ")).is_err());
        assert!(effective_agent_command(Some("rustle agent"), Some("/tmp/rustle")).is_err());
    }

    #[test]
    fn powershell_quote_uses_single_quote_safe_form() {
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle.exe"),
            "'C:\\Temp\\rustle.exe'"
        );
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle'agent.exe"),
            "'C:\\Temp\\rustle''agent.exe'"
        );
    }

    #[test]
    fn uploaded_agent_command_quotes_path_and_cleans_up() {
        let command = uploaded_agent_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );

        assert!(command.contains("tmp='/tmp/rustle'\\''agent'"));
        assert!(command.contains("refdir=\"$tmp.refs\""));
        assert!(command.contains("marker=\"$refdir/$$\""));
        assert!(command.contains("owner=$$"));
        assert!(command.contains("mkdir -p \"$refdir\""));
        assert!(command.contains(": > \"$marker\""));
        assert!(command.contains("trap cleanup EXIT HUP INT TERM"));
        assert!(command.contains("\"$tmp\" agent"));
        assert!(command.contains("rm -f \"$marker\""));
        assert!(command.contains("for stale in \"$refdir\"/*"));
        assert!(command.contains("kill -0 \"$pid\" 2>/dev/null || rm -f \"$stale\""));
        assert!(command.contains("while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup"));
        assert!(command.contains("cleanup_parent()"));
        assert!(command.contains("case \"$base\" in rustle-agent.*)"));
        assert!(command
            .contains("if rmdir \"$refdir\" 2>/dev/null; then rm -f \"$tmp\"; cleanup_parent; fi"));
    }

    #[test]
    fn windows_uploaded_agent_command_uses_powershell_and_cleans_up() {
        let platform = RemotePlatform {
            os: "windows",
            arch: "x86_64",
        };
        let command = uploaded_agent_command("C:\\Temp\\rustle'agent.exe", platform);

        assert!(command.starts_with("powershell.exe -NoProfile -NonInteractive"));
        assert!(command.contains("$tmp='C:\\Temp\\rustle''agent.exe'"));
        assert!(command.contains("$refdir=$tmp+'.refs'"));
        assert!(command.contains("$marker=Join-Path -Path $refdir -ChildPath $PID"));
        assert!(command.contains("New-Item -ItemType Directory -Force -LiteralPath $refdir"));
        assert!(command.contains("function CleanupParent"));
        assert!(command.contains("[IO.Path]::GetDirectoryName($tmp)"));
        assert!(command.contains("[IO.Path]::GetFileName($parent) -like 'rustle-agent-*'"));
        assert!(command.contains("Remove-Item -LiteralPath $marker -Force"));
        assert!(command.contains("Get-Process -Id $id -ErrorAction SilentlyContinue"));
        assert!(command.contains("Remove-Item -LiteralPath $refdir -Force"));
        assert!(command.contains("Remove-Item -LiteralPath $tmp -Force"));
        assert!(command.contains("CleanupParent"));
        assert!(command.contains("& $tmp agent"));
        assert_eq!(
            remote_agent_upload_command(platform),
            WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND
        );
    }

    #[test]
    fn posix_remote_agent_upload_command_is_used_for_unix_platforms() {
        assert_eq!(
            remote_agent_upload_command(RemotePlatform {
                os: "macos",
                arch: "aarch64",
            }),
            POSIX_REMOTE_AGENT_UPLOAD_COMMAND
        );
    }

    #[test]
    fn remote_agent_upload_commands_stage_in_private_temp_dirs() {
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("umask 077"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("mktemp -d"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("rustle-agent.XXXXXX"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("chmod 700 \"$dir\""));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("p=\"$dir/rustle-agent\""));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("trap cleanup EXIT HUP INT TERM"));

        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("[Guid]::NewGuid()"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("New-Item -ItemType Directory"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("'rustle-agent.exe'"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("[IO.FileMode]::CreateNew"));
        assert!(
            WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("Remove-Item -LiteralPath $dir -Recurse")
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_remote_agent_upload_command_creates_private_executable_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = env::temp_dir().join(format!(
            "rustle-upload-temp-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        std::fs::create_dir(&root).expect("create upload temp root");
        let temp = TempTree { path: root };
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(POSIX_REMOTE_AGENT_UPLOAD_COMMAND)
            .env("TMPDIR", &temp.path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn POSIX upload command");
        child
            .stdin
            .as_mut()
            .expect("upload command stdin")
            .write_all(b"agent")
            .expect("write upload command stdin");
        let output = child.wait_with_output().expect("wait for upload command");
        assert!(
            output.status.success(),
            "upload command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let remote_path = PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("upload path is UTF-8")
                .trim(),
        );
        assert_eq!(remote_path.file_name().unwrap(), "rustle-agent");
        assert!(remote_path.starts_with(&temp.path));
        let parent = remote_path.parent().expect("uploaded file has parent");
        assert!(parent
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("rustle-agent."));
        assert_eq!(
            std::fs::metadata(parent)
                .expect("private upload dir exists")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&remote_path)
                .expect("uploaded helper exists")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read(&remote_path).expect("read uploaded helper"),
            b"agent"
        );

        let cleanup = Command::new("sh")
            .arg("-c")
            .arg(uploaded_posix_agent_cleanup_command(
                remote_path.to_str().expect("upload path is UTF-8"),
            ))
            .status()
            .expect("run cleanup command");
        assert!(cleanup.success(), "cleanup command failed");
        assert!(!parent.exists(), "private upload dir should be removed");
    }

    #[test]
    fn uploaded_agent_sha256_command_uses_remote_hash_tools() {
        let command = uploaded_agent_sha256_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );

        assert!(command.contains("p='/tmp/rustle'\\''agent'"));
        assert!(command.contains("command -v sha256sum"));
        assert!(command.contains("sha256sum \"$p\" | awk '{print $1}'"));
        assert!(command.contains("command -v shasum"));
        assert!(command.contains("shasum -a 256 \"$p\" | awk '{print $1}'"));
        assert!(command.contains("command -v openssl"));
        assert!(command.contains("openssl dgst -sha256 -r \"$p\" | awk '{print $1}'"));
        assert!(command.contains("no remote SHA-256 command found"));
    }

    #[test]
    fn windows_uploaded_agent_sha256_command_uses_get_file_hash() {
        let command = uploaded_agent_sha256_command(
            "C:\\Temp\\rustle'agent.exe",
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            },
        );

        assert!(command.starts_with("powershell.exe -NoProfile -NonInteractive"));
        assert!(command.contains("$p='C:\\Temp\\rustle''agent.exe'"));
        assert!(command.contains("Get-FileHash -Algorithm SHA256 -LiteralPath $p"));
        assert!(command.contains(".Hash.ToLowerInvariant()"));
    }

    #[test]
    fn uploaded_agent_cleanup_command_quotes_path_and_refs() {
        let posix = uploaded_agent_cleanup_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );
        assert_eq!(
            posix,
            "p='/tmp/rustle'\\''agent'; rm -f \"$p\"; rm -rf \"$p.refs\"; parent=${p%/*}; base=${parent##*/}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac"
        );

        let windows = uploaded_agent_cleanup_command(
            "C:\\Temp\\rustle'agent.exe",
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            },
        );
        assert!(windows.contains("$p='C:\\Temp\\rustle''agent.exe'"));
        assert!(windows.contains("Remove-Item -LiteralPath $p -Force"));
        assert!(windows.contains("Remove-Item -LiteralPath ($p+'.refs') -Recurse -Force"));
        assert!(windows.contains("[IO.Path]::GetDirectoryName($p)"));
        assert!(windows.contains("[IO.Path]::GetFileName($parent) -like 'rustle-agent-*'"));
        assert!(windows.contains("Remove-Item -LiteralPath $parent -Recurse -Force"));
    }

    #[cfg(unix)]
    #[test]
    fn uploaded_agent_cleanup_removes_unverified_posix_staging_tree() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let parent = env::temp_dir().join(format!(
            "rustle-agent.cleanup-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree {
            path: parent.clone(),
        };
        std::fs::create_dir(&temp.path).expect("create private staging dir");

        let agent_path = temp.path.join("rustle-agent");
        let refdir = PathBuf::from(format!("{}.refs", agent_path.display()));
        std::fs::write(&agent_path, b"unverified").expect("write unverified helper");
        std::fs::create_dir(&refdir).expect("create refs dir");
        std::fs::write(refdir.join("12345"), b"stale lane marker").expect("write refs marker");

        let cleanup = Command::new("sh")
            .arg("-c")
            .arg(uploaded_posix_agent_cleanup_command(
                agent_path.to_str().expect("staging path is UTF-8"),
            ))
            .status()
            .expect("run POSIX cleanup command");
        assert!(cleanup.success(), "cleanup command failed");

        assert!(!agent_path.exists(), "unverified helper should be removed");
        assert!(!refdir.exists(), "refs directory should be removed");
        assert!(!parent.exists(), "private staging dir should be removed");
    }

    #[test]
    fn sha256_hex_validation_accepts_only_complete_digests() {
        assert!(is_sha256_hex(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ));
        assert!(is_sha256_hex(
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
        ));
        assert!(!is_sha256_hex("9f86d081"));
        assert!(!is_sha256_hex(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0z"
        ));
    }

    #[tokio::test]
    async fn sha256_file_hex_hashes_local_file() {
        struct TempFile {
            path: PathBuf,
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        let path = env::temp_dir().join(format!(
            "rustle-sha256-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempFile { path };
        tokio::fs::write(&temp.path, b"test")
            .await
            .expect("write test file");

        assert_eq!(
            sha256_file_hex(&temp.path).await.expect("hash test file"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn local_agent_selection_uses_current_binary_for_matching_platform() {
        let current_exe = PathBuf::from(if cfg!(windows) {
            "C:\\rustle\\rustle.exe"
        } else {
            "/tmp/rustle"
        });
        let local = RemotePlatform::local().expect("local platform is supported");

        assert_eq!(
            local_agent_binary_for_platform(&current_exe, local)
                .expect("current binary works for matching platform"),
            current_exe
        );
    }

    #[test]
    fn cross_platform_agent_candidates_include_release_package_shapes() {
        let dir = PathBuf::from("/opt/rustle");
        let linux = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let linux_candidates = agent_binary_candidates_in_dirs(linux, std::slice::from_ref(&dir));

        assert_eq!(
            linux_candidates.first(),
            Some(&dir.join("rustle-agent-linux-x86_64"))
        );
        let musl = dir.join("rustle-x86_64-unknown-linux-musl").join("rustle");
        let gnu = dir.join("rustle-x86_64-unknown-linux-gnu").join("rustle");
        let musl_index = linux_candidates
            .iter()
            .position(|candidate| candidate == &musl)
            .expect("Linux musl release package shape is a candidate");
        let gnu_index = linux_candidates
            .iter()
            .position(|candidate| candidate == &gnu)
            .expect("Linux gnu release package shape is a candidate");
        assert!(musl_index < gnu_index, "static Linux sidecar is preferred");

        let windows = RemotePlatform {
            os: "windows",
            arch: "aarch64",
        };
        let windows_candidates =
            agent_binary_candidates_in_dirs(windows, std::slice::from_ref(&dir));
        assert!(windows_candidates.contains(
            &dir.join("rustle-aarch64-pc-windows-msvc")
                .join("rustle.exe")
        ));
    }

    #[test]
    fn cross_platform_release_package_shape_is_a_sidecar_candidate() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        fn nonlocal_platform() -> RemotePlatform {
            let local = RemotePlatform::local().expect("local platform is supported");
            [
                RemotePlatform {
                    os: "linux",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "linux",
                    arch: "aarch64",
                },
                RemotePlatform {
                    os: "macos",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "macos",
                    arch: "aarch64",
                },
                RemotePlatform {
                    os: "windows",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "windows",
                    arch: "aarch64",
                },
            ]
            .into_iter()
            .find(|platform| *platform != local)
            .expect("at least one nonlocal supported platform")
        }

        let root = env::temp_dir().join(format!(
            "rustle-agent-sidecar-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let bin_dir = temp.path.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create sidecar test bin dir");

        let current_exe = bin_dir.join(if cfg!(windows) {
            "rustle-current.exe"
        } else {
            "rustle-current"
        });
        std::fs::write(&current_exe, "local").expect("write fake current binary");

        let remote = nonlocal_platform();
        let triple = remote_platform_target_triples(remote)
            .first()
            .expect("remote platform has a release target");
        let package_dir = bin_dir.join(format!("rustle-{triple}"));
        std::fs::create_dir(&package_dir).expect("create sidecar package dir");
        let sidecar = package_dir.join(if remote.is_windows() {
            "rustle.exe"
        } else {
            "rustle"
        });
        std::fs::write(&sidecar, "agent").expect("write fake sidecar");

        let candidates = agent_binary_candidates_in_dirs(remote, std::slice::from_ref(&bin_dir));
        let selected = candidates
            .iter()
            .find(|path| path.is_file())
            .expect("matching sidecar should be a selectable candidate");
        assert_eq!(selected, &sidecar);
    }

    #[test]
    fn local_agent_search_dirs_include_release_package_parent() {
        let current_exe = PathBuf::from("/opt/rustle/rustle-aarch64-apple-darwin/rustle");
        let dirs = local_agent_search_dirs(&current_exe);

        assert!(dirs.contains(&PathBuf::from("/opt/rustle/rustle-aarch64-apple-darwin")));
        assert!(dirs.contains(&PathBuf::from("/opt/rustle")));
    }

    #[test]
    fn cross_platform_agent_candidates_support_env_style_agent_dirs() {
        let agent_dir = PathBuf::from("/var/lib/rustle-agents");
        let linux = RemotePlatform {
            os: "linux",
            arch: "aarch64",
        };
        let candidates = agent_binary_candidates_in_dirs(linux, std::slice::from_ref(&agent_dir));

        assert!(candidates.contains(
            &agent_dir
                .join("rustle-aarch64-unknown-linux-musl")
                .join("rustle")
        ));
        assert!(candidates.contains(&agent_dir.join("rustle-agent-linux-aarch64")));
    }

    #[cfg(unix)]
    #[test]
    fn uploaded_agent_command_keeps_staged_binary_until_last_lane_exits() {
        use std::os::unix::fs::PermissionsExt;

        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        struct ChildGuard {
            children: Vec<std::process::Child>,
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                for child in &mut self.children {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        fn wait_for_files(dir: &Path, wanted: usize) -> Vec<PathBuf> {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                let mut files = std::fs::read_dir(dir)
                    .expect("read wait directory")
                    .map(|entry| entry.expect("read wait entry").path())
                    .collect::<Vec<_>>();
                files.sort();
                if files.len() >= wanted {
                    return files;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for {wanted} files in {}",
                    dir.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_any_child_exit(children: &mut [std::process::Child]) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if children
                    .iter_mut()
                    .any(|child| child.try_wait().expect("poll child").is_some())
                {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for one uploaded-agent wrapper to exit"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_all_children_exit(children: &mut [std::process::Child]) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if children
                    .iter_mut()
                    .all(|child| child.try_wait().expect("poll child").is_some())
                {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for uploaded-agent wrappers to exit"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_absent(path: &Path) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if !path.exists() {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for {} to be removed",
                    path.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn dir_entry_count(path: &Path) -> usize {
            std::fs::read_dir(path)
                .map(|entries| entries.filter_map(Result::ok).count())
                .unwrap_or(0)
        }

        let root = env::temp_dir().join(format!(
            "rustle-uploaded-agent-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        std::fs::create_dir_all(&temp.path).expect("create temp tree");
        let ready_dir = temp.path.join("ready");
        let release_dir = temp.path.join("release");
        std::fs::create_dir(&ready_dir).expect("create ready dir");
        std::fs::create_dir(&release_dir).expect("create release dir");

        let agent_path = temp.path.join("rustle-agent");
        std::fs::write(
            &agent_path,
            "#!/bin/sh\n\
             set -eu\n\
             if [ \"${1:-}\" != \"agent\" ]; then exit 64; fi\n\
             : > \"$RUSTLE_FAKE_AGENT_READY_DIR/$$\"\n\
             while [ ! -f \"$RUSTLE_FAKE_AGENT_RELEASE_DIR/$$\" ]; do sleep 0.05; done\n",
        )
        .expect("write fake uploaded agent");
        let mut perms = std::fs::metadata(&agent_path)
            .expect("fake agent metadata")
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&agent_path, perms).expect("chmod fake agent");

        let command = uploaded_agent_command(
            agent_path.to_str().expect("utf-8 temp path"),
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );
        let mut children = ChildGuard {
            children: (0..2)
                .map(|_| {
                    Command::new("sh")
                        .arg("-c")
                        .arg(&command)
                        .env("RUSTLE_FAKE_AGENT_READY_DIR", &ready_dir)
                        .env("RUSTLE_FAKE_AGENT_RELEASE_DIR", &release_dir)
                        .spawn()
                        .expect("spawn uploaded-agent wrapper")
                })
                .collect(),
        };
        let refdir = PathBuf::from(format!("{}.refs", agent_path.display()));

        let ready = wait_for_files(&ready_dir, 2);
        assert!(agent_path.exists(), "staged helper disappeared early");
        assert!(refdir.exists(), "refdir should exist while lanes run");
        assert_eq!(dir_entry_count(&refdir), 2);

        let first_release = release_dir.join(ready[0].file_name().expect("ready file name"));
        std::fs::write(first_release, b"").expect("release one fake agent");
        wait_for_any_child_exit(&mut children.children);
        assert!(
            agent_path.exists(),
            "staged helper should remain while another lane is active"
        );
        assert_eq!(dir_entry_count(&refdir), 1);

        for ready_file in &ready[1..] {
            std::fs::write(
                release_dir.join(ready_file.file_name().expect("ready file name")),
                b"",
            )
            .expect("release remaining fake agent");
        }
        wait_for_all_children_exit(&mut children.children);
        wait_for_absent(&agent_path);
        wait_for_absent(&refdir);
    }

    #[test]
    fn platform_probe_normalizes_common_uname_values() {
        assert_eq!(normalize_remote_os("Linux"), Some("linux"));
        assert_eq!(normalize_remote_os("Darwin"), Some("macos"));
        assert_eq!(normalize_remote_os("Windows"), Some("windows"));
        assert_eq!(normalize_remote_os("MINGW64_NT-10.0"), Some("windows"));
        assert_eq!(normalize_remote_arch("x86_64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("amd64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("AMD64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("arm64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("ARM64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("aarch64"), Some("aarch64"));
        assert_eq!(normalize_remote_os("Plan9"), None);
        assert_eq!(normalize_remote_arch("riscv64"), None);
    }

    #[test]
    fn platform_probe_parser_accepts_unix_and_windows_outputs() {
        assert_eq!(
            parse_remote_platform_probe(b"Linux\nx86_64\n").unwrap(),
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            }
        );
        assert_eq!(
            parse_remote_platform_probe(b"Windows\r\nAMD64\r\n").unwrap(),
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            }
        );
    }

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
        assert_eq!(cli.compact.agent_sessions, AUTO_AGENT_SESSIONS);
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
        .expect("tunnel CLI with zero UDP idle timeout");

        let Some(CommandKind::Tunnel(args)) = cli.command else {
            panic!("expected tunnel subcommand");
        };
        let err = validate_tunnel_args(&args).expect_err("zero UDP timeout must be rejected");
        assert!(err.to_string().contains("udp-idle-timeout-ms"));
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

    #[test]
    fn ssh_endpoint_parses_host_and_port_for_known_hosts() {
        assert_eq!(
            parse_ssh_endpoint("example.com").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 22,
                addr: "example.com:22".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("example.com:2222").unwrap(),
            SshEndpoint {
                host: "example.com".to_owned(),
                port: 2222,
                addr: "example.com:2222".to_owned(),
            }
        );
        assert_eq!(
            parse_ssh_endpoint("[2001:db8::1]:2222").unwrap(),
            SshEndpoint {
                host: "2001:db8::1".to_owned(),
                port: 2222,
                addr: "[2001:db8::1]:2222".to_owned(),
            }
        );
    }

    #[test]
    fn known_hosts_patterns_support_wildcards_ports_and_negation() {
        assert!(patterns_match(
            &["*.example.com".to_owned()],
            &["api.example.com".to_owned()]
        ));
        assert!(patterns_match(
            &["[*.example.com]:2222".to_owned()],
            &["[api.example.com]:2222".to_owned()]
        ));
        assert!(!patterns_match(
            &["*.example.com".to_owned(), "!bad.example.com".to_owned()],
            &["bad.example.com".to_owned()]
        ));
    }

    #[test]
    fn known_hosts_hashed_name_matches_hmac_sha1_candidate() {
        let salt = b"01234567890123456789";
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&key, b"example.com");
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(tag.as_ref());

        assert!(known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["example.com".to_owned()]
        ));
        assert!(!known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["other.example.com".to_owned()]
        ));
    }

    #[test]
    fn host_key_verifier_accepts_matching_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_mismatched_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("mismatch must fail");
        assert!(err.to_string().contains("mismatch"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accepts_bracketed_non_default_port() {
        let path = write_temp_known_hosts(&format!("[test.example.com]:2222 {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            2222,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_revoked_key() {
        let path =
            write_temp_known_hosts(&format!("@revoked test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("revoked key must fail");
        assert!(err.to_string().contains("revoked"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_records_missing_host_key() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = env::temp_dir().join(format!(
            "rustle-known-hosts-accept-new-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let path = temp.path.join(".ssh").join("known_hosts");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was created");
        assert_eq!(recorded, format!("test.example.com {TEST_ED25519_KEY}\n"));

        let strict = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        assert!(strict.verify(&key).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .expect("known_hosts parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("known_hosts metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn host_key_verifier_accept_new_preserves_existing_line_without_newline() {
        let path = write_temp_known_hosts(&format!("other.example.com {OTHER_ED25519_KEY}"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was updated");
        assert_eq!(
            recorded,
            format!("other.example.com {OTHER_ED25519_KEY}\ntest.example.com {TEST_ED25519_KEY}\n")
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_rejects_changed_known_host() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("accept-new must reject changed keys");
        assert!(err.to_string().contains("mismatch"));
        let recorded = std::fs::read_to_string(&path).expect("known_hosts still readable");
        assert!(!recorded.contains(OTHER_ED25519_KEY));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_unknown_host_error_mentions_accept_new() {
        let path = write_temp_known_hosts("");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("unknown host must fail in strict mode");
        let message = err.to_string();
        assert!(message.contains("--accept-new-host-key"));
        assert!(message.contains("--insecure-accept-host-key"));
        assert!(message.contains("SHA256:"));
        std::fs::remove_file(path).ok();
    }

    fn write_temp_known_hosts(contents: &str) -> PathBuf {
        static NEXT_KNOWN_HOSTS_FILE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT_KNOWN_HOSTS_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustle-known-hosts-{}-{}-{}.tmp",
            std::process::id(),
            sequence,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn remote_backlog_is_bounded_per_flow() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 1);
        let mut backlogs = RemoteBacklogs::new(8);

        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"world")),
            RemoteBacklogPush::FlowLimit
        );
        assert_eq!(backlogs.active_flow_count(), 1);
        assert_eq!(backlogs.total_bytes(), 5);
        assert_eq!(
            backlogs.flows.get(&id).map(|backlog| backlog.bytes),
            Some(5)
        );

        backlogs.close_after_flush(id);
        assert_eq!(
            backlogs
                .flows
                .get(&id)
                .map(|backlog| backlog.close_after_flush),
            Some(true)
        );

        backlogs.remove_flow(flow);
        assert!(!backlogs.flows.contains_key(&id));
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_is_bounded_globally() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::TotalLimit
        );
        assert_eq!(backlogs.total_bytes(), 5);

        backlogs.remove_flow(first);
        assert_eq!(backlogs.total_bytes(), 0);
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"world")),
            RemoteBacklogPush::Accepted
        );
    }

    #[test]
    fn remote_backlog_pauses_bridge_events_at_high_watermark() {
        let first = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let second = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 3),
            49153,
            Ipv4Addr::new(192, 168, 1, 11),
            443,
        );
        let first_id = tcp_core::FlowId::new(first, 1);
        let second_id = tcp_core::FlowId::new(second, 2);
        let mut backlogs = RemoteBacklogs::with_limits(16, 8);

        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(first_id, Bytes::from_static(b"hello")),
            RemoteBacklogPush::Accepted
        );
        assert!(!backlogs.should_pause_bridge_events());
        assert_eq!(
            backlogs.push(second_id, Bytes::from_static(b"!")),
            RemoteBacklogPush::Accepted
        );
        assert_eq!(backlogs.total_bytes(), 6);
        assert!(backlogs.should_pause_bridge_events());

        backlogs.remove_flow(first);
        assert!(!backlogs.should_pause_bridge_events());
    }

    #[test]
    fn remote_backlogs_flush_all_into_reuses_scratch_vectors() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let stale = tcp_core::FlowId::new(
            tcp_core::FlowKey::tcp(
                Ipv4Addr::new(192, 0, 2, 1),
                1,
                Ipv4Addr::new(192, 0, 2, 2),
                2,
            ),
            99,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"remote bytes")),
            RemoteBacklogPush::Accepted
        );

        let mut flow_keys = Vec::with_capacity(8);
        flow_keys.push(stale);
        let flow_keys_capacity = flow_keys.capacity();
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale.key);
        let closed_flows_capacity = closed_flows.capacity();

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("flush backlogs");

        assert!(flow_keys.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(flow_keys.capacity(), flow_keys_capacity);
        assert_eq!(closed_flows.capacity(), closed_flows_capacity);
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn bridge_lab_response_completion_uses_http_content_length() {
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let incomplete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";

        assert!(bridge_lab_response_complete(complete));
        assert!(!bridge_lab_response_complete(incomplete));
        assert!(!bridge_lab_response_complete(b"raw bytes"));
    }

    #[test]
    fn bridge_lab_synthetic_client_models_proxy_response_window() {
        let (_iface, _device, sockets, handle) = synthetic_lab_client(
            Ipv4Addr::new(10, 255, 255, 2),
            DEFAULT_TUN_IP,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
            49152,
        )
        .expect("synthetic client");
        let socket = sockets.get::<tcp::Socket>(handle);

        assert_eq!(socket.recv_capacity(), tcp_core::TCP_SEND_BUFFER_BYTES);
        assert_eq!(socket.send_capacity(), tcp_core::TCP_RECV_BUFFER_BYTES);
        assert_eq!(socket.ack_delay(), None);
        assert!(!socket.nagle_enabled());
    }

    #[test]
    fn agent_bridge_admission_budget_exceeds_direct_tcpip_channel_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(direct.active, MAX_DIRECT_ACTIVE_CHANNELS);
        assert_eq!(direct.opening, MAX_DIRECT_OPENING_CHANNELS);
        assert_eq!(agent.active, tcp_core::DEFAULT_MAX_ACTIVE_FLOWS);
        assert!(agent.active > direct.active);
        assert!(agent.opening > direct.opening);
    }

    #[test]
    fn bridge_admission_decision_uses_transport_specific_opening_budget() {
        let direct = BridgeAdmissionLimits::direct_tcpip();
        let agent = BridgeAdmissionLimits::agent();

        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS - 1, direct),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, direct),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_DIRECT_OPENING_CHANNELS, agent),
            BridgeAdmissionDecision::Admit
        );
        assert_eq!(
            bridge_admission_decision(0, MAX_AGENT_OPENING_STREAMS, agent),
            BridgeAdmissionDecision::DeferOpening
        );
        assert_eq!(
            bridge_admission_decision(MAX_AGENT_ACTIVE_STREAMS, 0, agent),
            BridgeAdmissionDecision::DeferActive
        );
    }

    #[test]
    fn stale_bridge_event_for_removed_flow_is_not_fatal() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(
                Ipv4Addr::new(192, 168, 1, 10),
                32,
            )],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed {
                id: tcp_core::FlowId::new(flow, 1),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale bridge event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
    }

    #[test]
    fn stale_remote_data_storm_after_flow_removal_is_bounded() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager
            .remove_flow(flow)
            .expect("remove flow before stale storm");

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        let closed_capacity = closed_flows.capacity();
        let payload = Bytes::from(vec![0x5a; 16 * 1024]);
        let mut stale_events = 0_u64;
        let mut overflows = 0_u64;

        for tick in 0..2048 {
            let stats = handle_bridge_event_into(
                ssh_bridge::BridgeEvent::RemoteData {
                    id,
                    bytes: payload.clone(),
                },
                &mut manager,
                &mut backlogs,
                SmolInstant::from_millis(tick),
                &mut closed_flows,
            )
            .expect("stale remote-data event should not fail");
            stale_events = stale_events.saturating_add(stats.stale_bridge_events);
            overflows = overflows.saturating_add(stats.remote_backlog_overflows);

            assert!(closed_flows.is_empty());
            assert_eq!(closed_flows.capacity(), closed_capacity);
            assert_eq!(backlogs.active_flow_count(), 0);
            assert_eq!(backlogs.total_bytes(), 0);
        }

        assert_eq!(stale_events, 2048);
        assert_eq!(overflows, 0);
    }

    #[test]
    fn stale_remote_data_events_are_counted_without_per_chunk_log() {
        let flow = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(10, 255, 255, 2),
            49152,
            Ipv4Addr::new(192, 168, 1, 10),
            443,
        );
        let id = tcp_core::FlowId::new(flow, 7);

        assert!(!should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"stale")
            }
        ));
        assert!(should_log_stale_bridge_event(
            &ssh_bridge::BridgeEvent::Closed { id }
        ));
    }

    #[test]
    fn stale_bridge_event_for_reused_tuple_does_not_touch_new_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");

        let old_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        manager.remove_flow(flow).expect("remove old flow");
        let new_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(old_id.key, new_id.key);
        assert_ne!(old_id.generation, new_id.generation);

        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(new_id, b"new-flow-data".to_vec()),
            RemoteBacklogPush::Accepted
        );
        let outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id: old_id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(0),
        )
        .expect("stale generation event should not fail");

        assert!(outcome.closed_flows.is_empty());
        assert_eq!(outcome.remote_backlog_overflows, 0);
        assert_eq!(outcome.stale_bridge_events, 1);
        assert!(manager.contains_flow_id(new_id));
        assert_eq!(backlogs.total_bytes(), b"new-flow-data".len() as u64);
    }

    #[test]
    fn remote_backlog_for_removed_flow_is_dropped_without_failing() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(id, Bytes::from_static(b"stale remote bytes")),
            RemoteBacklogPush::Accepted
        );
        manager.remove_flow(flow).expect("remove flow before flush");

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("stale queued backlog should not fail");

        assert!(flow_ids.is_empty());
        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    #[test]
    fn remote_backlog_for_old_generation_does_not_touch_reused_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let old_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        assert_eq!(
            backlogs.push(old_id, Bytes::from_static(b"old-generation bytes")),
            RemoteBacklogPush::Accepted
        );
        manager.remove_flow(flow).expect("remove old flow");
        let new_id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(old_id.key, new_id.key);
        assert_ne!(old_id.generation, new_id.generation);

        let mut flow_ids = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(1),
                &mut flow_ids,
                &mut closed_flows,
            )
            .expect("old queued backlog should be dropped");

        assert!(closed_flows.is_empty());
        assert_eq!(backlogs.active_flow_count(), 0);
        assert_eq!(backlogs.total_bytes(), 0);
        assert!(manager.contains_flow_id(new_id));
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("new flow snapshot");
        assert_eq!(snapshot.generation, new_id.generation);
        assert_eq!(snapshot.remote_to_local_bytes, 0);
    }

    #[test]
    fn remote_close_defers_flow_close_for_late_remote_data() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);

        let close_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::Closed { id },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
        )
        .expect("remote close event");
        assert_eq!(close_outcome.closed_flows, vec![flow]);
        assert_eq!(close_outcome.stale_bridge_events, 0);
        assert!(manager.contains_flow_id(id));
        assert_eq!(backlogs.active_flow_count(), 1);

        let late_bytes = Bytes::from_static(b"late remote bytes after close marker");
        let expected_len = late_bytes.len() as u64;
        let data_outcome = handle_bridge_event(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: late_bytes,
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(2),
        )
        .expect("late remote data event");
        assert!(data_outcome.closed_flows.is_empty());
        assert_eq!(data_outcome.stale_bridge_events, 0);
        assert_eq!(backlogs.total_bytes(), 0);

        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.key == flow)
            .expect("flow snapshot");
        assert_eq!(snapshot.remote_to_local_bytes, expected_len);
        assert_eq!(snapshot.state, tcp_core::FlowState::TcpEstablished);

        let mut flow_keys = Vec::new();
        let mut closed_flows = Vec::new();
        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(3),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("first deferred flush");
        assert!(manager.contains_flow_id(id));
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::TcpEstablished
        );

        backlogs
            .flush_all_into(
                &mut manager,
                SmolInstant::from_millis(4),
                &mut flow_keys,
                &mut closed_flows,
            )
            .expect("second deferred flush");
        assert_eq!(
            manager.flow_state(flow).expect("flow state"),
            tcp_core::FlowState::HalfClosedRemote
        );
        assert_eq!(backlogs.active_flow_count(), 0);
    }

    #[test]
    fn bridge_event_handler_into_reuses_closed_flow_scratch_vector() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let stale = tcp_core::FlowKey::tcp(
            Ipv4Addr::new(192, 0, 2, 1),
            1,
            Ipv4Addr::new(192, 0, 2, 2),
            2,
        );
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let id = establish_lab_flow(
            &mut manager,
            client_ip,
            destination_ip,
            destination_port,
            client_port,
        );
        assert_eq!(id.key, flow);
        let mut backlogs = RemoteBacklogs::new(REMOTE_BACKLOG_BYTES_PER_FLOW);
        let mut closed_flows = Vec::with_capacity(8);
        closed_flows.push(stale);
        let capacity = closed_flows.capacity();

        let stats = handle_bridge_event_into(
            ssh_bridge::BridgeEvent::RemoteData {
                id,
                bytes: Bytes::from_static(b"remote bytes"),
            },
            &mut manager,
            &mut backlogs,
            SmolInstant::from_millis(1),
            &mut closed_flows,
        )
        .expect("remote data event");

        assert_eq!(stats, BridgeEventStats::default());
        assert!(closed_flows.is_empty());
        assert_eq!(closed_flows.capacity(), capacity);
        assert_eq!(backlogs.total_bytes(), 0);
    }

    fn establish_lab_flow(
        manager: &mut tcp_core::FlowManager,
        client_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        destination_port: u16,
        client_port: u16,
    ) -> tcp_core::FlowId {
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, manager).expect("drain client")
            };
            route_lab_packets_to_clients(packets, &mut clients).expect("route packets");
            pump_lab_manager_to_clients(now, manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                return manager.flow_id(flow).expect("flow id");
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        panic!("synthetic flow did not reach TcpEstablished");
    }

    #[tokio::test]
    async fn missing_bridge_during_local_drain_resets_flow() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(packets, &mut clients).expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET / HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(packets, &mut clients).expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 1);
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Reset
        }));
    }

    #[tokio::test]
    async fn dns_over_agent_round_trips_tcp_dns_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\x12\x34query");

            let response = b"\x12\x34answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response = query_dns_over_agent(transport.clone(), &remote, b"\x12\x34query")
            .await
            .expect("query DNS over agent");
        assert_eq!(response.as_ref(), b"\x12\x34answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    #[tokio::test]
    async fn dns_over_agent_prefers_udp_for_ipv4_remote() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP DNS socket");
        let destination = socket.local_addr().expect("UDP DNS socket address");
        let dns_server = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            let (len, peer) = socket
                .recv_from(&mut buf)
                .await
                .expect("recv UDP DNS query");
            assert_eq!(&buf[..len], b"\x12\x34udp-query");
            socket
                .send_to(b"\x12\x34udp-answer", peer)
                .await
                .expect("send UDP DNS response");
        });

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let remote = Destination {
            host: destination.ip().to_string(),
            port: destination.port(),
        };

        let response = query_dns_over_agent_udp(transport.clone(), &remote, b"\x12\x34udp-query")
            .await
            .expect("query DNS over agent UDP");
        assert_eq!(response.as_ref(), b"\x12\x34udp-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS UDP server join");
    }

    #[tokio::test]
    async fn dns_over_agent_accepts_hostname_remote() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP DNS listener");
        let destination = listener.local_addr().expect("TCP DNS listener address");
        let dns_server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP DNS query");
            let mut len = [0_u8; 2];
            socket
                .read_exact(&mut len)
                .await
                .expect("read TCP DNS query length");
            let query_len = usize::from(u16::from_be_bytes(len));
            let mut query = vec![0_u8; query_len];
            socket
                .read_exact(&mut query)
                .await
                .expect("read TCP DNS query");
            assert_eq!(query, b"\xab\xcdname-query");

            let response = b"\xab\xcdname-answer";
            socket
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .expect("write TCP DNS response length");
            socket
                .write_all(response)
                .await
                .expect("write TCP DNS response");
            socket.shutdown().await.expect("shutdown TCP DNS socket");
        });

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect agent transport");
        let remote = Destination {
            host: "localhost".to_owned(),
            port: destination.port(),
        };

        let response = query_dns_over_agent(transport.clone(), &remote, b"\xab\xcdname-query")
            .await
            .expect("query DNS over agent hostname");
        assert_eq!(response.as_ref(), b"\xab\xcdname-answer");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        dns_server.await.expect("DNS server join");
    }

    async fn test_agent_transport() -> (
        agent_transport::AgentTransport,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect test agent transport");
        (transport, agent)
    }

    async fn test_agent_transport_closes_after_first_open(
    ) -> (agent_transport::AgentTransport, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

        async fn read_test_agent_frame<R: AsyncRead + Unpin>(
            reader: &mut R,
            inbound: &mut BytesMut,
        ) -> agent_proto::AgentFrame {
            loop {
                if let Some(frame) =
                    agent_proto::try_decode_frame(inbound).expect("decode test agent frame")
                {
                    return frame;
                }

                let mut buf = [0_u8; 8192];
                let read = reader.read(&mut buf).await.expect("read test agent frame");
                assert_ne!(read, 0, "test agent stream closed before next frame");
                inbound.extend_from_slice(&buf[..read]);
            }
        }

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let agent = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(agent_io);
            let mut inbound = BytesMut::new();

            let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
            let hello = agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("test hello frame");
            let encoded = agent_proto::encode_frame(&hello).expect("encode test hello");
            writer.write_all(&encoded).await.expect("write test hello");
            writer.flush().await.expect("flush test hello");

            let open = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert!(
                matches!(
                    open.kind,
                    agent_proto::AgentFrameKind::OpenTcp
                        | agent_proto::AgentFrameKind::OpenTcpHost
                        | agent_proto::AgentFrameKind::OpenUdp
                ),
                "expected first stream open frame, got {:?}",
                open.kind
            );
        });

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect closing test agent transport");
        (transport, agent)
    }

    async fn test_agent_transport_closes_after_opened() -> (
        agent_transport::AgentTransport,
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

        async fn read_test_agent_frame<R: AsyncRead + Unpin>(
            reader: &mut R,
            inbound: &mut BytesMut,
        ) -> agent_proto::AgentFrame {
            loop {
                if let Some(frame) =
                    agent_proto::try_decode_frame(inbound).expect("decode test agent frame")
                {
                    return frame;
                }

                let mut buf = [0_u8; 8192];
                let read = reader.read(&mut buf).await.expect("read test agent frame");
                assert_ne!(read, 0, "test agent stream closed before next frame");
                inbound.extend_from_slice(&buf[..read]);
            }
        }

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let agent = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(agent_io);
            let mut inbound = BytesMut::new();

            let hello = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert_eq!(hello.kind, agent_proto::AgentFrameKind::Hello);
            let hello = agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Hello,
                0,
                agent_proto::AgentHello::current(DEFAULT_MTU).encode(),
            )
            .expect("test hello frame");
            let encoded = agent_proto::encode_frame(&hello).expect("encode test hello");
            writer.write_all(&encoded).await.expect("write test hello");
            writer.flush().await.expect("flush test hello");

            let open = read_test_agent_frame(&mut reader, &mut inbound).await;
            assert!(
                matches!(
                    open.kind,
                    agent_proto::AgentFrameKind::OpenTcp
                        | agent_proto::AgentFrameKind::OpenTcpHost
                        | agent_proto::AgentFrameKind::OpenUdp
                ),
                "expected first stream open frame, got {:?}",
                open.kind
            );
            let opened = agent_proto::AgentFrame::new(
                agent_proto::AgentFrameKind::Opened,
                open.stream_id,
                Bytes::new(),
            )
            .expect("test opened frame")
            .with_credit(1024);
            let encoded = agent_proto::encode_frame(&opened).expect("encode test opened");
            writer.write_all(&encoded).await.expect("write test opened");
            writer.flush().await.expect("flush test opened");
            let _ = close_rx.await;
        });

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect closing test agent transport");
        (transport, agent, close_tx)
    }

    struct QueuedAgentConnector {
        primary_command: String,
        forced_primary_failures: std::sync::Mutex<usize>,
        forced_command_failures: std::sync::Mutex<usize>,
        primary_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
        command_transports: std::sync::Mutex<VecDeque<AgentBridgeTransport>>,
        command_requests: std::sync::Mutex<Vec<String>>,
    }

    impl QueuedAgentConnector {
        fn new(
            primary_command: &str,
            primary_transports: Vec<AgentBridgeTransport>,
            command_transports: Vec<AgentBridgeTransport>,
        ) -> Arc<Self> {
            Self::new_with_failures(
                primary_command,
                primary_transports,
                command_transports,
                0,
                0,
            )
        }

        fn new_with_primary_failures(
            primary_command: &str,
            primary_transports: Vec<AgentBridgeTransport>,
            command_transports: Vec<AgentBridgeTransport>,
            forced_primary_failures: usize,
        ) -> Arc<Self> {
            Self::new_with_failures(
                primary_command,
                primary_transports,
                command_transports,
                forced_primary_failures,
                0,
            )
        }

        fn new_with_failures(
            primary_command: &str,
            primary_transports: Vec<AgentBridgeTransport>,
            command_transports: Vec<AgentBridgeTransport>,
            forced_primary_failures: usize,
            forced_command_failures: usize,
        ) -> Arc<Self> {
            Arc::new(Self {
                primary_command: primary_command.to_owned(),
                forced_primary_failures: std::sync::Mutex::new(forced_primary_failures),
                forced_command_failures: std::sync::Mutex::new(forced_command_failures),
                primary_transports: std::sync::Mutex::new(VecDeque::from(primary_transports)),
                command_transports: std::sync::Mutex::new(VecDeque::from(command_transports)),
                command_requests: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn command_requests(&self) -> Vec<String> {
            self.command_requests
                .lock()
                .expect("command request lock")
                .clone()
        }
    }

    impl AgentBridgeConnector for QueuedAgentConnector {
        fn primary_command(&self) -> &str {
            &self.primary_command
        }

        fn connect_initial(&self, desired_sessions: usize) -> AgentBridgeConnectManyFuture<'_> {
            Box::pin(async move {
                connect_agent_bridge_transports_from_connector(self, desired_sessions).await
            })
        }

        fn connect_primary(&self) -> AgentBridgeConnectFuture<'_> {
            Box::pin(async move {
                {
                    let mut forced_failures = self
                        .forced_primary_failures
                        .lock()
                        .expect("primary failure counter lock");
                    if *forced_failures > 0 {
                        *forced_failures -= 1;
                        return Err(anyhow!("test connector forced primary reconnect failure"));
                    }
                }
                self.primary_transports
                    .lock()
                    .expect("primary transport queue lock")
                    .pop_front()
                    .ok_or_else(|| anyhow!("test connector has no primary transport"))
            })
        }

        fn connect_command<'a>(&'a self, agent_command: &'a str) -> AgentBridgeConnectFuture<'a> {
            Box::pin(async move {
                self.command_requests
                    .lock()
                    .expect("command request lock")
                    .push(agent_command.to_owned());
                {
                    let mut forced_failures = self
                        .forced_command_failures
                        .lock()
                        .expect("command failure counter lock");
                    if *forced_failures > 0 {
                        *forced_failures -= 1;
                        return Err(anyhow!("test connector forced command lane failure"));
                    }
                }
                self.command_transports
                    .lock()
                    .expect("command transport queue lock")
                    .pop_front()
                    .ok_or_else(|| {
                        anyhow!("test connector has no command transport for {agent_command}")
                    })
            })
        }
    }

    async fn wait_for_transport_failure(transport: &agent_transport::AgentTransport) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if transport.failure_message().await.is_some() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("test agent transport reports failure");
    }

    async fn wait_for_reconnect_snapshot(
        bridge: &ReconnectingAgentBridge,
        expected: AgentReconnectSnapshot,
    ) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if bridge.reconnect_snapshot() == expected {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("test agent bridge reaches reconnect snapshot");
    }

    fn detached_bridge_transport(
        transport: agent_transport::AgentTransport,
    ) -> AgentBridgeTransport {
        AgentBridgeTransport {
            carrier: AgentBridgeCarrier::Detached,
            transport,
            agent_command: "rustle agent".to_owned(),
        }
    }

    #[tokio::test]
    async fn detached_agent_carrier_disconnect_is_noop() {
        AgentBridgeCarrier::Detached
            .disconnect("detached test done")
            .await
            .expect("detached carrier disconnect");
    }

    #[tokio::test]
    async fn agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![detached_bridge_transport(replacement_transport)],
                Vec::new(),
            ),
            vec![
                detached_bridge_transport(first_transport.clone()),
                detached_bridge_transport(second_transport),
            ],
        );

        bridge.lanes[0].load.store(5, Ordering::Release);
        assert_eq!(bridge.choose_lane_index(0, 1).await, 1);

        bridge.lanes[1].load.store(8, Ordering::Release);
        assert_eq!(bridge.choose_lane_index(0, 1).await, 0);

        first_agent.abort();
        let _ = first_agent.await;
        wait_for_transport_failure(&first_transport).await;
        assert_eq!(bridge.choose_lane_index(0, 1).await, 1);
        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 2);
        assert_eq!(snapshot.lanes_failed, 0);

        drop(bridge);
        for agent in [second_agent, replacement_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy() {
        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        let (failed_secondary_transport, failed_secondary_agent) = test_agent_transport().await;
        let (busy_transport, busy_agent) = test_agent_transport().await;
        let (idle_transport, idle_agent) = test_agent_transport().await;
        let (primary_replacement_transport, primary_replacement_agent) =
            test_agent_transport().await;
        let (secondary_replacement_transport, secondary_replacement_agent) =
            test_agent_transport().await;

        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;
        failed_secondary_agent.abort();
        let _ = failed_secondary_agent.await;
        wait_for_transport_failure(&failed_secondary_transport).await;

        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![
                    detached_bridge_transport(primary_replacement_transport),
                    detached_bridge_transport(secondary_replacement_transport),
                ],
                Vec::new(),
            ),
            vec![
                detached_bridge_transport(failed_primary_transport),
                detached_bridge_transport(failed_secondary_transport),
                detached_bridge_transport(busy_transport),
                detached_bridge_transport(idle_transport),
            ],
        );

        bridge.lanes[2].load.store(7, Ordering::Release);
        bridge.lanes[3].load.store(1, Ordering::Release);
        assert_eq!(bridge.choose_lane_index(0, 1).await, 3);

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 2,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_available, 4);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_repairing, 0);

        drop(bridge);
        for agent in [
            busy_agent,
            idle_agent,
            primary_replacement_agent,
            secondary_replacement_agent,
        ] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn alternate_lane_selection_scans_by_load_without_snapshot_vector() {
        let (skipped_transport, skipped_agent) = test_agent_transport().await;
        let (busy_transport, busy_agent) = test_agent_transport().await;
        let (idle_transport, idle_agent) = test_agent_transport().await;
        let (middle_transport, middle_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![
                detached_bridge_transport(skipped_transport),
                detached_bridge_transport(busy_transport),
                detached_bridge_transport(idle_transport),
                detached_bridge_transport(middle_transport),
            ],
        );

        bridge.lanes[1].load.store(9, Ordering::Release);
        bridge.lanes[2].load.store(1, Ordering::Release);
        bridge.lanes[3].load.store(4, Ordering::Release);

        let first = bridge
            .next_alternate_lane_by_load(0, 0)
            .expect("first alternate lane");
        assert_eq!(first.index, 2);

        let second = bridge
            .next_alternate_lane_by_load(0, agent_lane_bit(first.index))
            .expect("second alternate lane");
        assert_eq!(second.index, 3);

        let tried = agent_lane_bit(first.index) | agent_lane_bit(second.index);
        let third = bridge
            .next_alternate_lane_by_load(0, tried)
            .expect("third alternate lane");
        assert_eq!(third.index, 1);

        let tried = tried | agent_lane_bit(third.index);
        assert!(bridge.next_alternate_lane_by_load(0, tried).is_none());

        drop(bridge);
        for agent in [skipped_agent, busy_agent, idle_agent, middle_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn background_lane_repair_requests_are_coalesced() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );

        let lane = &bridge.lanes[0];
        assert!(bridge.try_start_background_lane_repair(lane));
        assert!(
            !bridge.try_start_background_lane_repair(lane),
            "duplicate background repair request should be coalesced"
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_repairing, 1);

        bridge.finish_background_lane_repair(lane).await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_repairing, 0);
        assert!(bridge.try_start_background_lane_repair(lane));
        bridge.finish_background_lane_repair(lane).await;

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn agent_bridge_stream_load_is_released_on_close() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            use tokio::io::AsyncReadExt;
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert!(request.is_empty());
        });

        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };

        let stream = bridge
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: *destination.ip(),
                destination_port: destination.port(),
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 49152,
            })
            .await
            .expect("open tracked agent stream");
        assert_eq!(bridge.lanes[0].load.load(Ordering::Acquire), 1);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.active_streams, 1);
        assert_eq!(snapshot.max_lane_load, 1);

        stream.close().await.expect("close tracked stream");
        assert_eq!(bridge.lanes[0].load.load(Ordering::Acquire), 0);

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn agent_bridge_repairs_lane_after_active_stream_transport_failure() {
        let (dying_transport, dying_agent, close_dying_transport) =
            test_agent_transport_closes_after_opened().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new(
                "rustle agent",
                vec![detached_bridge_transport(replacement_transport)],
                Vec::new(),
            ),
            vec![detached_bridge_transport(dying_transport)],
        );

        let mut stream = bridge
            .open_tcp_ipv4(agent_proto::AgentOpenIpv4 {
                destination_ip: Ipv4Addr::new(127, 0, 0, 1),
                destination_port: 443,
                originator_ip: DEFAULT_TUN_IP,
                originator_port: 49152,
            })
            .await
            .expect("open tracked agent stream");
        assert_eq!(bridge.lanes[0].load.load(Ordering::Acquire), 1);

        close_dying_transport
            .send(())
            .expect("signal fake agent transport close");
        dying_agent.await.expect("dying fake agent join");
        let reset = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
            .await
            .expect("receive active stream reset after transport failure")
            .expect("stream reset frame");
        assert_eq!(reset.kind, agent_proto::AgentFrameKind::Reset);
        assert!(
            String::from_utf8_lossy(&reset.payload).contains("agent"),
            "reset payload should explain the agent transport failure"
        );

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 1);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(snapshot.active_streams, 1);

        drop(stream);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.active_streams, 0);

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
    }

    #[tokio::test]
    async fn agent_initial_startup_reuses_first_effective_command_for_extra_lanes() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: first_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: second_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: third_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
            ],
        );

        let transports = connector
            .connect_initial(3)
            .await
            .expect("connect initial lanes");
        assert_eq!(transports.len(), 3);
        assert_eq!(
            transports
                .iter()
                .map(|transport| transport.agent_command.as_str())
                .collect::<Vec<_>>(),
            vec![
                "/tmp/rustle-uploaded agent",
                "/tmp/rustle-uploaded agent",
                "/tmp/rustle-uploaded agent",
            ]
        );
        assert_eq!(
            connector.command_requests(),
            vec![
                "/tmp/rustle-uploaded agent".to_owned(),
                "/tmp/rustle-uploaded agent".to_owned(),
            ]
        );

        drop(transports);
        for agent in [first_agent, second_agent, third_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn auto_agent_startup_returns_after_primary_and_warms_extra_lanes() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: first_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: second_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: third_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
            ],
        );

        let transports = connect_auto_agent_bridge_transports_from_connector(connector.as_ref(), 3)
            .await
            .expect("auto startup connects primary lane");
        assert_eq!(transports.len(), 1);
        assert!(
            connector.command_requests().is_empty(),
            "auto startup must not wait for extra lane commands before returning"
        );

        let bridge =
            ReconnectingAgentBridge::new_with_desired_lanes(connector.clone(), transports, 3);
        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 2,
                failures: 0,
            },
        )
        .await;
        assert_eq!(
            connector.command_requests(),
            vec![
                "/tmp/rustle-uploaded agent".to_owned(),
                "/tmp/rustle-uploaded agent".to_owned(),
            ]
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 3);
        assert_eq!(snapshot.lanes_desired, 3);
        assert_eq!(snapshot.lanes_available, 3);
        assert_eq!(snapshot.lanes_missing, 0);
        assert_eq!(snapshot.lanes_repairing, 0);

        drop(bridge);
        for agent in [first_agent, second_agent, third_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn fast_start_missing_lane_warmup_can_be_deferred() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: first_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: second_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
        );

        let transports = connect_auto_agent_bridge_transports_from_connector(connector.as_ref(), 2)
            .await
            .expect("auto startup connects primary lane");
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes_and_missing_repair_delay(
            connector.clone(),
            transports,
            2,
            Some(Duration::from_millis(100)),
        );

        tokio::task::yield_now().await;
        assert!(
            connector.command_requests().is_empty(),
            "deferred warmup should not compete with the first scheduler turn"
        );
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_missing, 1);
        assert_eq!(snapshot.lanes_repairing, 1);

        wait_for_reconnect_snapshot(
            &bridge,
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            },
        )
        .await;
        assert_eq!(
            connector.command_requests(),
            vec!["/tmp/rustle-uploaded agent".to_owned()]
        );

        drop(bridge);
        for agent in [first_agent, second_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_failures(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: first_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: second_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: third_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
            ],
            0,
            1,
        );

        let transports = connector
            .connect_initial(4)
            .await
            .expect("connect initial lanes despite one extra-lane failure");
        assert_eq!(transports.len(), 3);
        let command_requests = connector.command_requests();
        assert_eq!(command_requests.len(), 4);
        assert!(command_requests
            .iter()
            .all(|command| command == "/tmp/rustle-uploaded agent"));

        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(connector, transports, 4);
        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_desired, 4);

        drop(bridge);
        for agent in [first_agent, second_agent, third_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_bridge_repairs_missing_startup_lane_in_background() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let (fourth_transport, fourth_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![detached_bridge_transport(fourth_transport)],
            Vec::new(),
        );
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(
            connector.clone(),
            vec![
                detached_bridge_transport(first_transport),
                detached_bridge_transport(second_transport),
                detached_bridge_transport(third_transport),
            ],
            4,
        );

        let snapshot = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let snapshot = bridge.snapshot().await;
                if snapshot.lanes_available == 4 && snapshot.lanes_missing == 0 {
                    return snapshot;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("missing startup lane is repaired");
        assert_eq!(snapshot.lanes_total, 4);
        assert_eq!(snapshot.lanes_desired, 4);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_quarantined, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            }
        );
        assert_eq!(connector.command_requests(), Vec::<String>::new());

        drop(bridge);
        for agent in [first_agent, second_agent, third_agent, fourth_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn background_repair_retries_missing_lane_after_quarantine() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![detached_bridge_transport(replacement_transport)],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new_with_desired_lanes(
            connector.clone(),
            vec![detached_bridge_transport(first_transport)],
            2,
        );

        let snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let snapshot = bridge.snapshot().await;
                if snapshot.lanes_available == 2 && snapshot.lanes_missing == 0 {
                    return snapshot;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("missing lane is retried after quarantine");
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_desired, 2);
        assert_eq!(snapshot.lanes_failed, 0);
        assert_eq!(snapshot.lanes_quarantined, 0);
        assert_eq!(snapshot.lanes_repairing, 0);
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );
        assert_eq!(connector.command_requests(), Vec::<String>::new());

        drop(bridge);
        for agent in [first_agent, replacement_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn agent_initial_startup_retries_missing_extra_lanes_after_transient_failure() {
        let (first_transport, first_agent) = test_agent_transport().await;
        let (second_transport, second_agent) = test_agent_transport().await;
        let (third_transport, third_agent) = test_agent_transport().await;
        let (fourth_transport, fourth_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_failures(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: first_transport,
                agent_command: "/tmp/rustle-uploaded agent".to_owned(),
            }],
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: second_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: third_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: fourth_transport,
                    agent_command: "/tmp/rustle-uploaded agent".to_owned(),
                },
            ],
            0,
            1,
        );

        let transports = connector
            .connect_initial(4)
            .await
            .expect("retry missing startup lane after transient failure");
        assert_eq!(transports.len(), 4);
        let command_requests = connector.command_requests();
        assert_eq!(command_requests.len(), 4);
        assert!(command_requests
            .iter()
            .all(|command| command == "/tmp/rustle-uploaded agent"));

        drop(transports);
        for agent in [first_agent, second_agent, third_agent, fourth_agent] {
            tokio::time::timeout(std::time::Duration::from_secs(1), agent)
                .await
                .expect("agent exits")
                .expect("agent join")
                .expect("agent run");
        }
    }

    #[tokio::test]
    async fn reconnecting_agent_repairs_failed_lane_through_connector() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair");
            socket
                .write_all(b"connector:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: replacement_transport,
                agent_command: "rustle agent".to_owned(),
            }],
            Vec::new(),
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: failed_transport,
                agent_command: "rustle agent".to_owned(),
            }],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("open stream through repaired lane");
        stream
            .send_data(Bytes::from_static(b"repair"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"connector:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 1,
                failures: 0,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_uses_alternate_lane_when_preferred_lane_reconnect_fails() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"ping");
            socket.write_all(b"alt:pong").await.expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (healthy_transport, healthy_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: failed_transport,
                    agent_command: "rustle agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: healthy_transport,
                    agent_command: "rustle agent".to_owned(),
                },
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("open stream through alternate lane");
        stream
            .send_data(Bytes::from_static(b"ping"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "alternate lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"alt:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 0,
                failures: 1,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), healthy_agent)
            .await
            .expect("healthy agent exits")
            .expect("healthy agent join")
            .expect("healthy agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair-alt");
            socket
                .write_all(b"repaired-alt:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;

        let (failed_alternate_transport, failed_alternate_agent) = test_agent_transport().await;
        failed_alternate_agent.abort();
        let _ = failed_alternate_agent.await;
        wait_for_transport_failure(&failed_alternate_transport).await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: replacement_transport,
                agent_command: "rustle agent".to_owned(),
            }],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: failed_primary_transport,
                    agent_command: "rustle agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: failed_alternate_transport,
                    agent_command: "rustle agent".to_owned(),
                },
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("repair failed alternate lane after primary reconnect failure");
        stream
            .send_data(Bytes::from_static(b"repair-alt"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired alternate lane stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"repaired-alt:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );

        let snapshot = bridge.snapshot().await;
        assert_eq!(snapshot.lanes_total, 2);
        assert_eq!(snapshot.lanes_available, 1);
        assert_eq!(snapshot.lanes_failed, 1);
        assert_eq!(snapshot.lanes_quarantined, 1);

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_repairs_alternate_lane_that_fails_during_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
            let mut request = Vec::new();
            socket
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"repair-during-open");
            socket
                .write_all(b"repaired-open:pong")
                .await
                .expect("write response");
            socket.shutdown().await.expect("shutdown TCP stream");
        });

        let (failed_primary_transport, failed_primary_agent) = test_agent_transport().await;
        failed_primary_agent.abort();
        let _ = failed_primary_agent.await;
        wait_for_transport_failure(&failed_primary_transport).await;

        let (dying_alternate_transport, dying_alternate_agent) =
            test_agent_transport_closes_after_first_open().await;

        let (replacement_transport, replacement_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new_with_primary_failures(
            "rustle agent",
            vec![AgentBridgeTransport {
                carrier: AgentBridgeCarrier::Detached,
                transport: replacement_transport,
                agent_command: "rustle agent".to_owned(),
            }],
            Vec::new(),
            1,
        );
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: failed_primary_transport,
                    agent_command: "rustle agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: dying_alternate_transport,
                    agent_command: "rustle agent".to_owned(),
                },
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        let mut stream = bridge
            .open_tcp_ipv4(open)
            .await
            .expect("repair alternate lane that fails during open");
        stream
            .send_data(Bytes::from_static(b"repair-during-open"))
            .await
            .expect("send request");
        stream.send_eof().await.expect("send EOF");

        let mut response = Vec::new();
        let mut saw_eof = false;
        loop {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                .await
                .expect("receive agent frame")
                .expect("agent stream frame");
            match frame.kind {
                agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                agent_proto::AgentFrameKind::Eof => saw_eof = true,
                agent_proto::AgentFrameKind::Close => break,
                agent_proto::AgentFrameKind::Reset => {
                    panic!(
                        "repaired alternate-open stream reset: {}",
                        String::from_utf8_lossy(&frame.payload)
                    );
                }
                other => panic!("unexpected agent frame {other:?}"),
            }
        }
        assert!(saw_eof);
        assert_eq!(response, b"repaired-open:pong");
        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 2,
                successes: 1,
                failures: 1,
            }
        );

        drop(stream);
        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement_agent)
            .await
            .expect("replacement agent exits")
            .expect("replacement agent join")
            .expect("replacement agent run");
        dying_alternate_agent
            .await
            .expect("dying alternate agent join");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn reconnecting_agent_quarantines_failed_lane_after_reconnect_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind TCP target");
        let destination = listener.local_addr().expect("TCP target address");
        let server = tokio::spawn(async move {
            for (request, response) in [
                (&b"first"[..], &b"alt:first"[..]),
                (&b"second"[..], &b"alt:second"[..]),
            ] {
                let (mut socket, _) = listener.accept().await.expect("accept TCP stream");
                let mut received = Vec::new();
                socket
                    .read_to_end(&mut received)
                    .await
                    .expect("read request");
                assert_eq!(received, request);
                socket.write_all(response).await.expect("write response");
                socket.shutdown().await.expect("shutdown TCP stream");
            }
        });

        let (failed_transport, failed_agent) = test_agent_transport().await;
        failed_agent.abort();
        let _ = failed_agent.await;
        wait_for_transport_failure(&failed_transport).await;

        let (healthy_transport, healthy_agent) = test_agent_transport().await;
        let connector = QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new());
        let bridge = ReconnectingAgentBridge::new(
            connector,
            vec![
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: failed_transport,
                    agent_command: "rustle agent".to_owned(),
                },
                AgentBridgeTransport {
                    carrier: AgentBridgeCarrier::Detached,
                    transport: healthy_transport,
                    agent_command: "rustle agent".to_owned(),
                },
            ],
        );

        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let mut open = agent_proto::AgentOpenIpv4 {
            destination_ip: *destination.ip(),
            destination_port: destination.port(),
            originator_ip: DEFAULT_TUN_IP,
            originator_port: 49152,
        };
        while agent_lane_index(&open, 6, 2) != 0 {
            open.originator_port = open.originator_port.saturating_add(1);
        }

        for (index, (request, expected)) in [
            (&b"first"[..], &b"alt:first"[..]),
            (&b"second"[..], &b"alt:second"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let mut stream = bridge
                .open_tcp_ipv4(open)
                .await
                .expect("open stream through alternate lane");
            if index == 0 {
                let snapshot = bridge.snapshot().await;
                assert_eq!(snapshot.reconnects.attempts, 1);
                assert_eq!(snapshot.reconnects.successes, 0);
                assert_eq!(snapshot.reconnects.failures, 1);
                assert_eq!(snapshot.lanes_total, 2);
                assert_eq!(snapshot.lanes_available, 1);
                assert_eq!(snapshot.lanes_failed, 1);
                assert_eq!(snapshot.lanes_quarantined, 1);
                assert!(snapshot.max_quarantine_ms > 0);
                assert!(snapshot.max_quarantine_ms <= AGENT_LANE_BACKOFF_MAX.as_millis() as u64);
            }
            stream
                .send_data(Bytes::copy_from_slice(request))
                .await
                .expect("send request");
            stream.send_eof().await.expect("send EOF");

            let mut response = Vec::new();
            let mut saw_eof = false;
            loop {
                let frame = tokio::time::timeout(std::time::Duration::from_secs(1), stream.recv())
                    .await
                    .expect("receive agent frame")
                    .expect("agent stream frame");
                match frame.kind {
                    agent_proto::AgentFrameKind::Data => response.extend_from_slice(&frame.payload),
                    agent_proto::AgentFrameKind::Eof => saw_eof = true,
                    agent_proto::AgentFrameKind::Close => break,
                    agent_proto::AgentFrameKind::Reset => {
                        panic!(
                            "alternate lane stream reset: {}",
                            String::from_utf8_lossy(&frame.payload)
                        );
                    }
                    other => panic!("unexpected agent frame {other:?}"),
                }
            }
            assert!(saw_eof);
            assert_eq!(response, expected);
        }

        assert_eq!(
            bridge.reconnect_snapshot(),
            AgentReconnectSnapshot {
                attempts: 1,
                successes: 0,
                failures: 1,
            }
        );

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), healthy_agent)
            .await
            .expect("healthy agent exits")
            .expect("healthy agent join")
            .expect("healthy agent run");
        server.await.expect("TCP server join");
    }

    #[tokio::test]
    async fn udp_over_agent_round_trips_datagram() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
            assert_eq!(&buf[..len], b"ping");
            socket
                .send_to(b"pong", peer)
                .await
                .expect("write UDP response");
        });

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };

        let response = query_udp_over_agent(
            transport.clone(),
            &dns::UdpPacket {
                src_ip: Ipv4Addr::new(10, 255, 255, 1),
                dst_ip: *destination.ip(),
                src_port: 49152,
                dst_port: destination.port(),
                payload: Bytes::from_static(b"ping"),
            },
        )
        .await
        .expect("query UDP over agent");
        assert_eq!(response, b"pong");

        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_reuses_agent_stream_for_multiple_datagrams() {
        let socket = tokio::net::UdpSocket::bind(("127.0.0.1", 0))
            .await
            .expect("bind UDP target");
        let destination = socket.local_addr().expect("UDP target address");
        let udp_server = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            for _ in 0..2 {
                let (len, peer) = socket.recv_from(&mut buf).await.expect("read UDP query");
                let mut response = b"echo:".to_vec();
                response.extend_from_slice(&buf[..len]);
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("write UDP response");
            }
        });

        let (client_io, agent_io) = tokio::io::duplex(256 * 1024);
        let (agent_reader, agent_writer) = tokio::io::split(agent_io);
        let agent = tokio::spawn(agent_runtime::run(
            agent_reader,
            agent_writer,
            agent_runtime::AgentRuntimeConfig::new(DEFAULT_MTU),
        ));

        let (client_reader, client_writer) = tokio::io::split(client_io);
        let transport =
            agent_transport::AgentTransport::connect(client_reader, client_writer, DEFAULT_MTU)
                .await
                .expect("connect agent transport");
        let destination = match destination {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => panic!("test listener should be IPv4"),
        };
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: *destination.ip(),
            dst_port: destination.port(),
        };

        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(8);
        let (close_tx, mut close_rx) = mpsc::channel(8);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let association = tokio::spawn(run_udp_association_transport(
            transport.clone(),
            key,
            from_local,
            events,
            UDP_ASSOCIATION_IDLE_TIMEOUT,
        ));

        to_remote
            .send(Bytes::from_static(b"one"))
            .await
            .expect("send first datagram");
        to_remote
            .send(Bytes::from_static(b"two"))
            .await
            .expect("send second datagram");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            tokio::select! {
                event = response_rx.recv() => {
                    let event = event.expect("association response channel closed");
                    let event_key = event.key;
                    let payload = event.payload;
                    assert_eq!(event_key, key);
                    responses.push(payload);
                }
                event = close_rx.recv() => {
                    let event = event.expect("association close channel closed");
                    panic!("UDP association closed before responses: {:?}", event.error);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timed out waiting for UDP association event");
                }
            }
        }
        assert_eq!(
            responses,
            vec![
                Bytes::from_static(b"echo:one"),
                Bytes::from_static(b"echo:two")
            ]
        );

        drop(to_remote);
        tokio::time::timeout(std::time::Duration::from_secs(1), association)
            .await
            .expect("association exits")
            .expect("association join")
            .expect("association run");
        drop(transport);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
        udp_server.await.expect("UDP server join");
    }

    #[tokio::test]
    async fn udp_association_idle_timeout_emits_close_for_accounting() {
        let (transport, agent) = test_agent_transport().await;
        let bridge = ReconnectingAgentBridge::new(
            QueuedAgentConnector::new("rustle agent", Vec::new(), Vec::new()),
            vec![detached_bridge_transport(transport)],
        );
        let key = UdpFlowKey {
            src_ip: Ipv4Addr::new(10, 255, 255, 1),
            src_port: 49152,
            dst_ip: Ipv4Addr::new(127, 0, 0, 1),
            dst_port: 5353,
        };
        let (to_remote, from_local) = mpsc::channel(UDP_DATAGRAMS_PER_ASSOCIATION);
        let (response_tx, mut response_rx) = mpsc::channel(1);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let events = UdpAssociationEvents {
            response_tx,
            close_tx,
        };
        let mut associations = HashMap::new();
        associations.insert(key, UdpAssociation { to_remote });
        let mut association_limit = DnsInflight::new(1);
        assert!(association_limit.try_admit());

        spawn_udp_association_with_idle_timeout(
            bridge.clone(),
            key,
            from_local,
            events,
            std::time::Duration::from_millis(10),
        );

        let closed = tokio::time::timeout(std::time::Duration::from_secs(1), close_rx.recv())
            .await
            .expect("idle association closes")
            .expect("close event");
        assert_eq!(closed.key, key);
        assert!(closed.error.is_none());
        assert!(response_rx.try_recv().is_err());

        associations.remove(&closed.key);
        association_limit.complete();
        assert_eq!(association_limit.current(), 0);
        assert_eq!(association_limit.completed(), 1);
        assert!(associations.is_empty());

        drop(bridge);
        tokio::time::timeout(std::time::Duration::from_secs(1), agent)
            .await
            .expect("agent exits")
            .expect("agent join")
            .expect("agent run");
    }

    #[tokio::test]
    async fn deferred_bridge_admission_leaves_local_bytes_buffered() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(packets, &mut clients).expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /deferred HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(packets, &mut clients).expect("route request packets");

        let mut bridges = HashMap::new();
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain local bytes");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(stats.bridge_backpressure_events, 1);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
        }));
    }

    #[tokio::test]
    async fn saturated_bridge_queue_leaves_local_bytes_buffered() {
        let client_ip = Ipv4Addr::new(10, 255, 255, 2);
        let destination_ip = Ipv4Addr::new(192, 168, 1, 10);
        let destination_port = 443;
        let client_port = 49152;
        let flow = tcp_core::FlowKey::tcp(client_ip, client_port, destination_ip, destination_port);
        let mut manager = tcp_core::FlowManager::new(
            DEFAULT_TUN_IP,
            DEFAULT_TUN_PREFIX,
            &[tcp_core::Ipv4NetParts::new(destination_ip, 32)],
            usize::from(DEFAULT_MTU),
        )
        .expect("flow manager");
        let (iface, device, sockets, handle) = synthetic_lab_client(
            client_ip,
            DEFAULT_TUN_IP,
            destination_ip,
            destination_port,
            client_port,
        )
        .expect("synthetic client");
        let mut clients = vec![BridgeLabClient {
            flow,
            client_ip,
            client_port,
            iface,
            device,
            sockets,
            handle,
            sent_request: false,
            saw_bridge_close: false,
            response: Vec::new(),
        }];
        let mut now = SmolInstant::from_millis(0);

        for _ in 0..256 {
            let packets = {
                let client = &mut clients[0];
                client
                    .iface
                    .poll(now, &mut client.device, &mut client.sockets);
                drain_lab_client_to_manager(now, client, &mut manager).expect("drain client")
            };
            route_lab_packets_to_clients(packets, &mut clients).expect("route packets");
            pump_lab_manager_to_clients(now, &mut manager, &mut clients).expect("pump manager");

            if manager.snapshots().iter().any(|snapshot| {
                snapshot.key == flow && snapshot.state == tcp_core::FlowState::TcpEstablished
            }) {
                break;
            }
            now += smoltcp::time::Duration::from_millis(1);
        }

        manager
            .mark_flow_state(flow, tcp_core::FlowState::Relaying)
            .expect("mark relaying");
        {
            let client = &mut clients[0];
            let socket = client.sockets.get_mut::<tcp::Socket>(client.handle);
            socket
                .send_slice(b"GET /slow HTTP/1.1\r\n\r\n")
                .expect("client send");
        }
        let packets = {
            let client = &mut clients[0];
            client
                .iface
                .poll(now, &mut client.device, &mut client.sockets);
            drain_lab_client_to_manager(now, client, &mut manager).expect("drain request")
        };
        route_lab_packets_to_clients(packets, &mut clients).expect("route request packets");

        let (event_tx, _event_rx) = mpsc::channel(1);
        let id = manager.flow_id(flow).expect("flow id");
        let bridge =
            ssh_bridge::spawn_bridge_task(id, event_tx, |_id, local_rx, _event_tx| async {
                let _local_rx = local_rx;
                std::future::pending::<()>().await;
            });
        for index in 0..ssh_bridge::FLOW_CHANNEL_DEPTH {
            assert!(
                bridge
                    .try_send_local_data(vec![index as u8])
                    .expect("pre-fill bridge queue"),
                "bridge queue should accept pre-fill item {index}"
            );
        }
        assert_eq!(bridge.local_queue_capacity(), 0);

        let mut bridges = HashMap::from([(flow, bridge)]);
        let mut flow_keys = Vec::new();
        let before = manager.recv_queue_len(flow).expect("queued local bytes");
        assert!(before > 0);

        let stats = drain_local_bytes_to_bridges(&mut manager, &mut bridges, &mut flow_keys)
            .expect("drain should not block or fail");

        assert_eq!(stats.bytes_to_bridge, 0);
        assert_eq!(stats.bridge_send_failures, 0);
        assert_eq!(
            manager.recv_queue_len(flow).expect("queued local bytes"),
            before
        );
        assert!(manager.snapshots().iter().any(|snapshot| {
            snapshot.key == flow && snapshot.state == tcp_core::FlowState::Relaying
        }));
    }

    #[test]
    fn ssh_target_parses_user_at_host_like_sshuttle() {
        assert_eq!(
            parse_ssh_target("alice@example.com:2222", None).unwrap(),
            SshTarget {
                user: "alice".to_owned(),
                addr: "example.com:2222".to_owned(),
                host: "example.com".to_owned(),
                port: 2222,
            }
        );
    }

    #[test]
    fn ssh_target_user_flag_overrides_remote_user() {
        assert_eq!(
            parse_ssh_target("alice@example.com", Some("bob")).unwrap(),
            SshTarget {
                user: "bob".to_owned(),
                addr: "example.com:22".to_owned(),
                host: "example.com".to_owned(),
                port: 22,
            }
        );
    }
}
