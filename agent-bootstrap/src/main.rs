use std::env;

use anyhow::{anyhow, bail, Context, Result};

#[allow(dead_code)]
#[path = "../../src/agent_proto.rs"]
mod agent_proto;
#[allow(dead_code)]
#[path = "../../src/agent_io.rs"]
mod agent_io;
#[path = "../../src/agent_runtime.rs"]
mod agent_runtime;
#[path = "../../src/agent_window.rs"]
mod agent_window;

const DEFAULT_MTU: u16 = 1300;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| anyhow!("expected `agent` subcommand"))?;
    if command != "agent" {
        bail!("expected `agent` subcommand, got `{command}`");
    }

    let mut mtu = DEFAULT_MTU;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mtu" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--mtu requires a value"))?;
                mtu = value
                    .parse::<u16>()
                    .with_context(|| format!("invalid --mtu value `{value}`"))?;
            }
            other => bail!("unexpected agent argument `{other}`"),
        }
    }

    agent_runtime::run_stdio(agent_runtime::AgentRuntimeConfig::new(mtu)).await
}
