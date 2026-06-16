use anyhow::{Context, Result};

use crate::cli::{AgentArgs, QuicAgentArgs, QuicBridgeAgentArgs};
use crate::{agent_runtime, quic_agent, quic_agent_runtime};

pub(crate) async fn run_agent(args: AgentArgs) -> Result<()> {
    agent_runtime::run_stdio(agent_runtime::AgentRuntimeConfig::new(args.mtu)).await
}

pub(crate) async fn run_quic_agent(args: QuicAgentArgs) -> Result<()> {
    let server = quic_agent::start_quic_agent_server(args.bind)?;
    {
        use std::io::Write;

        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", server.bootstrap().encode_line())
            .context("failed to write QUIC agent bootstrap line")?;
        stdout
            .flush()
            .context("failed to flush QUIC agent bootstrap line")?;
    }
    eprintln!("quic-agent: listening on {}", server.local_addr()?);
    quic_agent_runtime::run_one(server, agent_runtime::AgentRuntimeConfig::new(args.mtu)).await
}

pub(crate) async fn run_quic_bridge_agent(args: QuicBridgeAgentArgs) -> Result<()> {
    let server = quic_agent::start_quic_bridge_server(args.bind)?;
    {
        use std::io::Write;

        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", server.bootstrap().encode_bridge_line())
            .context("failed to write native QUIC bridge bootstrap line")?;
        stdout
            .flush()
            .context("failed to flush native QUIC bridge bootstrap line")?;
    }
    eprintln!("quic-bridge-agent: listening on {}", server.local_addr()?);
    server.run().await
}
