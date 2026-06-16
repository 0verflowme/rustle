use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BridgeTransportKind {
    Auto,
    DirectTcpip,
    Agent,
    QuicAgent,
    QuicNative,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct BridgeRuntimeOptions {
    pub(crate) ssh_sessions: usize,
    pub(crate) agent_sessions: usize,
    pub(crate) fast_start_auto_agent_lanes: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Destination {
    pub(crate) host: String,
    pub(crate) port: u16,
}

pub(crate) fn parse_destination(input: &str) -> Result<Destination> {
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
