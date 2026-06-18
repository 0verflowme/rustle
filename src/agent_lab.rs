use std::time::{Duration, Instant as StdInstant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use tokio::io::{self, AsyncWriteExt};

use crate::agent_bridge::AgentBridgeConnector;
use crate::agent_proto;
use crate::cli::{AgentDnsLabArgs, AgentLabArgs, AgentUdpLabArgs};
use crate::control_plane::{
    bridge_runtime_command_plan, connect_tunnel_runtime, SshAgentBridgeConnector,
};
use crate::data_plane::query_dns_on_data_plane;
use crate::defaults::{DEFAULT_SSH_SESSIONS, DEFAULT_TUN_IP};
use crate::lab_support::{
    build_dns_a_query, default_http_request, parse_ipv4_destination, percentile_nearest_rank,
    validate_dns_response,
};
use crate::remote_helper::agent_command_plan;
use crate::transport_model::{parse_destination, TunnelRuntimeOptions};

const MAX_AGENT_UDP_LAB_MESSAGES: usize = 1_000_000;

pub(crate) async fn run_agent_lab(args: AgentLabArgs) -> Result<()> {
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

    let helper_plan =
        agent_command_plan(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let connector = SshAgentBridgeConnector::new(args.ssh.clone(), helper_plan, args.mtu)?;
    let agent_runtime = connector.connect_primary().await?;
    let mut stream = agent_runtime
        .transport()
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

pub(crate) async fn run_agent_udp_lab(args: AgentUdpLabArgs) -> Result<()> {
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
    let helper_plan =
        agent_command_plan(args.agent_command.as_deref(), args.agent_path.as_deref())?;
    let connector = SshAgentBridgeConnector::new(args.ssh.clone(), helper_plan, args.mtu)?;
    let agent_runtime = connector.connect_primary().await?;
    let mut stream = agent_runtime
        .transport()
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

pub(crate) async fn run_agent_dns_lab(args: AgentDnsLabArgs) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), run_agent_dns_lab_inner(args))
        .await
        .context("agent DNS lab timed out")?
}

async fn run_agent_dns_lab_inner(args: AgentDnsLabArgs) -> Result<()> {
    if args.queries == 0 {
        bail!("agent-dns-lab --queries must be greater than zero");
    }
    if args.queries > MAX_AGENT_UDP_LAB_MESSAGES {
        bail!(
            "agent-dns-lab --queries must not exceed {}",
            MAX_AGENT_UDP_LAB_MESSAGES
        );
    }

    let dns_remote = parse_destination(&args.dns_remote)
        .with_context(|| format!("invalid --dns-remote {}", args.dns_remote))?;
    let helper_plan = bridge_runtime_command_plan(
        args.bridge_transport,
        args.agent_command.as_deref(),
        args.agent_path.as_deref(),
    )?;
    let runtime = connect_tunnel_runtime(
        &args.ssh,
        args.bridge_transport,
        helper_plan,
        args.mtu,
        Some(&dns_remote),
        TunnelRuntimeOptions {
            ssh_sessions: DEFAULT_SSH_SESSIONS,
            agent_sessions: args.agent_sessions,
            fast_start_auto_agent_lanes: false,
        },
    )
    .await?;
    let data_plane = runtime.data_plane();

    let mut latencies_us = Vec::with_capacity(args.queries);
    let mut response_bytes = 0_usize;
    let started_at = StdInstant::now();
    for index in 0..args.queries {
        let id = 0x5200_u16.wrapping_add(index as u16);
        let query = build_dns_a_query(id, &args.name)?;
        let query_started = StdInstant::now();
        let response = query_dns_on_data_plane(
            data_plane.as_ref(),
            &dns_remote,
            query.as_ref(),
            DEFAULT_TUN_IP,
        )
        .await
        .with_context(|| format!("DNS query {} through Rustle transport failed", index + 1))?;
        let elapsed = query_started.elapsed().as_micros();
        validate_dns_response(&query, response.as_ref())
            .with_context(|| format!("invalid DNS response for query {}", index + 1))?;
        response_bytes = response_bytes.saturating_add(response.len());
        latencies_us.push(elapsed);
    }

    let elapsed = started_at.elapsed();
    latencies_us.sort_unstable();
    let p50_us = percentile_nearest_rank(&latencies_us, 50);
    let p95_us = percentile_nearest_rank(&latencies_us, 95);
    let max_us = *latencies_us.last().unwrap_or(&0);
    println!(
        "agent_dns_lab_summary transport={:?} queries={} response_bytes={} elapsed_ms={} p50_us={} p95_us={} max_us={}",
        args.bridge_transport,
        args.queries,
        response_bytes,
        elapsed.as_millis(),
        p50_us,
        p95_us,
        max_us,
    );

    Ok(())
}
