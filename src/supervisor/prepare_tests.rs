use anyhow::Result;
use clap::Parser;

use super::prepare::{await_startup_or_shutdown, validate_tunnel_args};
use crate::cli::{Cli, CommandKind};
use crate::transport_model::BridgeTransportKind;
use crate::tunnel_lifecycle::ShutdownSignal;

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
    .expect("tunnel CLI with zero UDP timeout");

    let Some(CommandKind::Tunnel(args)) = cli.command else {
        panic!("expected tunnel subcommand");
    };
    let err = validate_tunnel_args(&args).expect_err("zero UDP timeout must be rejected");
    assert!(err.to_string().contains("udp-idle-timeout-ms"));
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
    let err =
        validate_tunnel_args(&args).expect_err("explicit auto fallback needs valid ssh sessions");
    assert!(err.to_string().contains("--ssh-sessions"));
}

#[test]
fn explicit_auto_quic_tunnel_validates_agent_fallback_session_count() {
    let cli = Cli::try_parse_from([
        "rustle",
        "tunnel",
        "-r",
        "alice@example.com",
        "--target",
        "10.0.0.0/8",
        "--bridge-transport",
        "auto-quic",
        "--agent-sessions",
        "9999",
    ])
    .expect("tunnel CLI with out-of-range agent sessions");

    let Some(CommandKind::Tunnel(args)) = cli.command else {
        panic!("expected tunnel subcommand");
    };
    assert_eq!(args.bridge_transport, BridgeTransportKind::AutoQuic);
    let err = validate_tunnel_args(&args)
        .expect_err("explicit auto-quic fallback needs valid agent sessions");
    assert!(err.to_string().contains("--agent-sessions"));
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
    validate_tunnel_args(&args).expect("agent supports hostname DNS remote through OpenTcpHost");
}

#[test]
fn quic_native_tunnel_accepts_hostname_dns_remote() {
    let cli = Cli::try_parse_from([
        "rustle",
        "tunnel",
        "-r",
        "alice@example.com",
        "--target",
        "10.0.0.0/8",
        "--bridge-transport",
        "quic-native",
        "--dns-remote",
        "localhost:53",
    ])
    .expect("tunnel CLI with native QUIC hostname DNS remote");

    let Some(CommandKind::Tunnel(args)) = cli.command else {
        panic!("expected tunnel subcommand");
    };
    validate_tunnel_args(&args)
        .expect("native QUIC supports hostname DNS remote through TCP host open");
}

#[tokio::test]
async fn startup_shutdown_wins_over_pending_startup() {
    let mut shutdown = ShutdownSignal::triggered_for_test("interrupt");
    let startup = std::future::pending::<Result<&'static str>>();

    let result = await_startup_or_shutdown(&mut shutdown, startup)
        .await
        .expect("shutdown should be clean");

    assert!(result.is_none());
}

#[tokio::test]
async fn ready_startup_wins_when_shutdown_is_pending() {
    let mut shutdown = ShutdownSignal::pending_for_test();

    let result =
        await_startup_or_shutdown(&mut shutdown, async { Ok::<_, anyhow::Error>("prepared") })
            .await
            .expect("startup should complete");

    assert_eq!(result, Some("prepared"));
}
