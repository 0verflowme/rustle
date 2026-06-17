use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const QUIC_DATA_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) async fn connect_quic_data_plane_any<T, F, Connect>(
    label: &'static str,
    remote_addrs: &[SocketAddr],
    connect: Connect,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    Connect: FnMut(SocketAddr) -> F,
{
    connect_quic_data_plane_any_with_timeout(
        label,
        remote_addrs,
        QUIC_DATA_PLANE_CONNECT_TIMEOUT,
        connect,
    )
    .await
}

async fn connect_quic_data_plane_any_with_timeout<T, F, Connect>(
    label: &'static str,
    remote_addrs: &[SocketAddr],
    timeout: Duration,
    mut connect: Connect,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    Connect: FnMut(SocketAddr) -> F,
{
    if remote_addrs.is_empty() {
        bail!("{label}: no resolved UDP data-plane addresses after SSH bootstrap");
    }

    let attempt_timeout = quic_data_plane_attempt_timeout(timeout, remote_addrs.len());
    let mut failures = Vec::new();
    let attempt_count = remote_addrs.len();
    for (index, remote_addr) in remote_addrs.iter().copied().enumerate() {
        let attempt_started = Instant::now();
        eprintln!(
            "{label}: UDP data plane attempt {}/{} remote={} attempt_timeout_ms={}",
            index + 1,
            attempt_count,
            remote_addr,
            attempt_timeout.as_millis()
        );
        match connect_quic_data_plane_with_timeout(
            label,
            remote_addr,
            attempt_timeout,
            connect(remote_addr),
        )
        .await
        {
            Ok(connected) => {
                eprintln!(
                    "{label}: UDP data plane connected to {remote_addr} on attempt {}/{} after {}ms",
                    index + 1,
                    attempt_count,
                    attempt_started.elapsed().as_millis()
                );
                return Ok(connected);
            }
            Err(err) => failures.push(format!(
                "attempt {}/{} {remote_addr} after {}ms: {err:#}",
                index + 1,
                attempt_count,
                attempt_started.elapsed().as_millis()
            )),
        }
    }

    bail!(
        "{}",
        quic_data_plane_all_addrs_failed_context(label, remote_addrs, &failures)
    )
}

async fn connect_quic_data_plane_with_timeout<T, F>(
    label: &'static str,
    remote_addr: SocketAddr,
    timeout: Duration,
    future: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result.with_context(|| quic_data_plane_error_context(label, remote_addr)),
        Err(_) => bail!(
            "{}",
            quic_data_plane_timeout_context(label, remote_addr, timeout)
        ),
    }
}

fn quic_data_plane_attempt_timeout(total_timeout: Duration, attempts: usize) -> Duration {
    // Do not split this budget across resolved addresses: QUIC connect plus
    // token auth has its own stage timeouts, and too-small outer attempts hide
    // useful stage context on dual-stack or multi-address hosts.
    if attempts == 0 || total_timeout < Duration::from_millis(1) {
        Duration::from_millis(1)
    } else {
        total_timeout
    }
}

fn quic_data_plane_error_context(label: &str, remote_addr: SocketAddr) -> String {
    format!(
        "{label}: failed to establish UDP data plane to {remote_addr} after SSH bootstrap; inbound UDP to the helper port may be blocked, or the advertised address may be unreachable"
    )
}

fn quic_data_plane_timeout_context(
    label: &str,
    remote_addr: SocketAddr,
    timeout: Duration,
) -> String {
    format!(
        "{label}: timed out after {}ms establishing UDP data plane to {remote_addr} after SSH bootstrap; inbound UDP to the helper port may be blocked, or the advertised address may be unreachable",
        timeout.as_millis()
    )
}

fn quic_data_plane_all_addrs_failed_context(
    label: &str,
    remote_addrs: &[SocketAddr],
    failures: &[String],
) -> String {
    format!(
        "{label}: failed to establish UDP data plane to any resolved address after SSH bootstrap; tried=[{}]; failures=[{}]",
        format_socket_addrs(remote_addrs),
        failures.join(" | ")
    )
}

pub(super) fn resolve_quic_helper_addrs(
    label: &'static str,
    remote_host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = (remote_host, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {label} address for {remote_host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no socket addresses found for {label} {remote_host}:{port}");
    }
    Ok(addrs)
}

pub(super) fn format_socket_addrs(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::{anyhow, Result};

    use super::{
        connect_quic_data_plane_any_with_timeout, connect_quic_data_plane_with_timeout,
        quic_data_plane_attempt_timeout, resolve_quic_helper_addrs,
    };

    #[test]
    fn resolve_quic_helper_addrs_preserves_loopback_port() {
        let addrs = resolve_quic_helper_addrs("quic-native", "127.0.0.1", 4433)
            .expect("loopback should resolve");

        assert_eq!(
            addrs,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4433
            )]
        );
    }

    #[tokio::test]
    async fn quic_data_plane_any_tries_later_resolved_address() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 4433);
        let attempts = Arc::new(Mutex::new(Vec::new()));

        let connected = connect_quic_data_plane_any_with_timeout(
            "quic-native",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().expect("attempts lock").push(remote_addr);
                    if remote_addr == first {
                        Err(anyhow!("first address failed"))
                    } else {
                        Ok(remote_addr)
                    }
                }
            },
        )
        .await
        .expect("second address should connect");

        assert_eq!(connected, second);
        assert_eq!(
            *attempts.lock().expect("attempts lock"),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn quic_data_plane_any_reports_all_resolved_addresses() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 4434);

        let err = connect_quic_data_plane_any_with_timeout(
            "quic-agent",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| async move { Err::<(), _>(anyhow!("failed {remote_addr}")) },
        )
        .await
        .expect_err("all addresses should fail");
        let detail = format!("{err:#}");

        assert!(detail
            .contains("quic-agent: failed to establish UDP data plane to any resolved address"));
        assert!(detail.contains("tried=[203.0.113.1:4433,203.0.113.2:4434]"));
        assert!(detail.contains("attempt 1/2 203.0.113.1:4433 after "));
        assert!(detail.contains("attempt 2/2 203.0.113.2:4434 after "));
        assert!(detail.contains("failed 203.0.113.1:4433"));
        assert!(detail.contains("failed 203.0.113.2:4434"));
    }

    #[test]
    fn quic_data_plane_attempt_timeout_keeps_full_budget_per_address() {
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_secs(8), 1),
            Duration::from_secs(8)
        );
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_secs(8), 2),
            Duration::from_secs(8)
        );
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_millis(1), 4),
            Duration::from_millis(1)
        );
        assert_eq!(
            quic_data_plane_attempt_timeout(Duration::from_secs(8), 0),
            Duration::from_millis(1)
        );
    }

    #[tokio::test]
    async fn quic_data_plane_success_stops_fallback_before_protocol_negotiation() {
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 4433);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 4433);
        let attempts = Arc::new(Mutex::new(Vec::new()));

        let connected = connect_quic_data_plane_any_with_timeout(
            "quic-agent",
            &[first, second],
            Duration::from_secs(1),
            |remote_addr| {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.lock().expect("attempts lock").push(remote_addr);
                    Ok(remote_addr)
                }
            },
        )
        .await
        .expect("first authenticated address should stop fallback");

        assert_eq!(connected, first);
        assert_eq!(*attempts.lock().expect("attempts lock"), vec![first]);
    }

    #[tokio::test]
    async fn quic_data_plane_error_context_explains_udp_reachability() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4433);
        let err = connect_quic_data_plane_with_timeout(
            "quic-native",
            remote,
            Duration::from_secs(1),
            async { Err::<(), _>(anyhow!("handshake failed")) },
        )
        .await
        .expect_err("expected wrapped QUIC data-plane error");
        let detail = format!("{err:#}");

        assert!(detail.contains("quic-native: failed to establish UDP data plane"));
        assert!(detail.contains("203.0.113.7:4433"));
        assert!(detail.contains("after SSH bootstrap"));
        assert!(detail.contains("inbound UDP to the helper port may be blocked"));
        assert!(detail.contains("handshake failed"));
    }

    #[tokio::test]
    async fn quic_data_plane_timeout_context_explains_udp_reachability() {
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 4444);
        let err = connect_quic_data_plane_with_timeout(
            "quic-agent",
            remote,
            Duration::from_millis(1),
            future::pending::<Result<()>>(),
        )
        .await
        .expect_err("expected QUIC data-plane timeout");
        let detail = format!("{err:#}");

        assert!(detail.contains("quic-agent: timed out after 1ms"));
        assert!(detail.contains("198.51.100.9:4444"));
        assert!(detail.contains("after SSH bootstrap"));
        assert!(detail.contains("advertised address may be unreachable"));
    }
}
