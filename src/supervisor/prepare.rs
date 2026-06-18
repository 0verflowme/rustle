use anyhow::Result;

mod config;
mod prepared;

pub(crate) use config::validate_tunnel_args;

use self::prepared::PreparedTunnel;
use crate::TunnelArgs;

use super::lifecycle::{shutdown_signal, ShutdownSignal};

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

pub(super) async fn await_startup_or_shutdown<T, Fut>(
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
