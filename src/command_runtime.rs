use anyhow::{bail, Context, Result};
use tokio::io::{self, AsyncWriteExt};

use crate::cli::{CompactTunnelArgs, DirectTcpipArgs};
use crate::lab_support::default_http_request;
use crate::ssh_control::connect_ssh;
use crate::supervisor::run_tunnel;
use crate::transport_model::parse_destination;
use crate::TunnelArgs;

pub(crate) async fn run_direct_tcpip(args: DirectTcpipArgs) -> Result<()> {
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

pub(crate) async fn run_compact_tunnel(args: CompactTunnelArgs) -> Result<()> {
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
