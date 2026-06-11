#!/usr/bin/env python3
"""Verify that the release target matrix and docs stay in sync."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = REPO / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
BUILD_SCRIPT = REPO / "build.rs"
MAIN_SOURCE = REPO / "src" / "main.rs"
RELEASE_NOTES = REPO / "docs" / "release.md"
ARCHITECTURE_NOTES = REPO / "docs" / "architecture.md"
PERFORMANCE_NOTES = REPO / "docs" / "performance.md"
LIVE_SMOKE = REPO / "scripts" / "smoke-live-tunnel.sh"
LIVE_UDP_SMOKE = REPO / "scripts" / "smoke-live-udp.sh"
LIVE_BENCH = REPO / "scripts" / "bench-live-compare.sh"
LIVE_FIXTURE = REPO / "scripts" / "bench-live-fixture.sh"
LIVE_FIXTURE_ROWS = REPO / "scripts" / "verify-live-fixture-rows.py"
BRIDGE_BENCH = REPO / "scripts" / "bench-bridge-lab.sh"
AGENT_UDP_BENCH = REPO / "scripts" / "bench-agent-udp-lab.sh"
VERIFY_LOCAL = REPO / "scripts" / "verify-local.sh"
SMOKE_LIB = REPO / "scripts" / "smoke-lib.sh"
TUN_DNS_SMOKE = REPO / "scripts" / "smoke-tun-dns.sh"
NETNS_UDP_SMOKE = REPO / "scripts" / "smoke-linux-netns-udp.sh"
WINDOWS_TUN_SMOKE_VERIFIER = REPO / "scripts" / "verify-windows-tun-smoke.py"
AGENT_SIDECARS = REPO / "scripts" / "prepare-agent-sidecars.sh"
AGENT_SIDECAR_BUILD = REPO / "scripts" / "build-agent-sidecars.sh"
AGENT_SIDECAR_SMOKE = REPO / "scripts" / "smoke-agent-sidecars.sh"


def rust_source_text() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((REPO / "src").glob("*.rs"))
    )

EXPECTED = [
    {
        "os": "ubuntu-latest",
        "target": "x86_64-unknown-linux-gnu",
        "package": "rustle-x86_64-unknown-linux-gnu",
        "archive": "rustle-x86_64-unknown-linux-gnu.tar.gz",
    },
    {
        "os": "ubuntu-latest",
        "target": "x86_64-unknown-linux-musl",
        "package": "rustle-x86_64-unknown-linux-musl",
        "archive": "rustle-x86_64-unknown-linux-musl.tar.gz",
    },
    {
        "os": "ubuntu-24.04-arm",
        "target": "aarch64-unknown-linux-gnu",
        "package": "rustle-aarch64-unknown-linux-gnu",
        "archive": "rustle-aarch64-unknown-linux-gnu.tar.gz",
    },
    {
        "os": "ubuntu-24.04-arm",
        "target": "aarch64-unknown-linux-musl",
        "package": "rustle-aarch64-unknown-linux-musl",
        "archive": "rustle-aarch64-unknown-linux-musl.tar.gz",
    },
    {
        "os": "macos-15-intel",
        "target": "x86_64-apple-darwin",
        "package": "rustle-x86_64-apple-darwin",
        "archive": "rustle-x86_64-apple-darwin.tar.gz",
    },
    {
        "os": "macos-14",
        "target": "aarch64-apple-darwin",
        "package": "rustle-aarch64-apple-darwin",
        "archive": "rustle-aarch64-apple-darwin.tar.gz",
    },
    {
        "os": "windows-latest",
        "target": "x86_64-pc-windows-msvc",
        "package": "rustle-x86_64-pc-windows-msvc",
        "archive": "rustle-x86_64-pc-windows-msvc.zip",
    },
    {
        "os": "windows-11-arm",
        "target": "aarch64-pc-windows-msvc",
        "package": "rustle-aarch64-pc-windows-msvc",
        "archive": "rustle-aarch64-pc-windows-msvc.zip",
    },
]

EXPECTED_CI_OS = [
    "ubuntu-latest",
    "ubuntu-24.04-arm",
    "macos-15-intel",
    "macos-14",
    "windows-latest",
    "windows-11-arm",
]

REQUIRED_WORKFLOW_SNIPPETS = [
    "cargo build --locked --release --target ${{ matrix.target }}",
    "cp README.md",
    "cp docs/architecture.md",
    "cp docs/release.md",
    "Copy-Item \"README.md\"",
    "Copy-Item \"docs/architecture.md\"",
    "Copy-Item \"docs/release.md\"",
    "$secretName is required for release Windows archives",
    "unexpected Windows archive contents",
    "Windows release archive must not ship wintun.dll beside rustle.exe",
    "\"verify/${{ matrix.package }}/rustle\" --help >/dev/null",
    "& \"$package/rustle.exe\" --help | Out-Null",
    "Native Windows TUN smoke",
    "RUSTLE_WINDOWS_SMOKE_TIMEOUT_SECONDS: 30",
    ".\\scripts\\smoke-windows-tun.ps1 -RustleBin $rustle",
    "musl release binary appears dynamically linked",
    "sha256sum > SHA256SUMS",
    "name: rustle-checksums",
    "Verify agent sidecar store",
    "scripts/prepare-agent-sidecars.sh",
    "RUSTLE_AGENT_REQUIRE_ALL=1",
    "rustle-agent-linux-x86_64",
    "rustle-agent-linux-aarch64",
    "rustle-agent-macos-x86_64",
    "rustle-agent-macos-aarch64",
    "rustle-agent-windows-x86_64.exe",
    "rustle-agent-windows-aarch64.exe",
]

REQUIRED_BUILD_SCRIPT_SNIPPETS = [
    "RUSTLE_EMBED_WINTUN_DLL architecture mismatch",
    "expected_windows_pe_machine",
    "pe_machine_from_bytes",
]

REQUIRED_MAIN_SOURCE_SNIPPETS = [
    'default_value = "agent"',
    "BridgeTransportKind::DirectTcpip",
    "BridgeTransportKind::Auto",
    "spawn_lane_repair",
    "background_repair_in_progress",
    "lanes_repairing",
    "lanes_missing",
    "missing:{}",
    "repairing:{}",
    "desired:{}",
    "lanes_desired",
    "lanes.saturating_mul(lanes)",
    "AGENT_INITIAL_CONNECT_BATCH",
    "AGENT_INITIAL_CONNECT_RETRY_ROUNDS",
    "AGENT_BACKGROUND_REPAIR_RETRY_ROUNDS",
    "retrying {missing} missing exec transport",
    "connect_auto_agent_bridge_transports_from_connector",
    "should_fast_start_agent_lanes",
    "fast_start_auto_agent_lanes",
    "format_agent_fast_start_message",
    "auto_agent_startup_returns_after_primary_and_warms_extra_lanes",
    "auto_agent_sessions_fast_start_when_multiple_lanes_are_recommended",
    "connect_agent_bridge_transport_fresh_ssh_command",
    "fresh SSH connection with one exec",
    "connect_additional_agent_bridge_transport_batch",
    "format_agent_established_message",
    "AgentLaneSelectionStatus::Failed { failure }",
    "AgentLaneSelectionStatus::Missing",
    "alternate_transport_or_repair",
    "next_alternate_lane_by_load",
    "agent_lane_bit",
    "best_available_lane_index_except",
    "spawn_lane_repair_for_status",
    "background_lane_repair_requests_are_coalesced",
    "background_repair_retries_missing_lane_after_quarantine",
    "assert_eq!(snapshot.lanes_repairing, 1)",
    "agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure",
    "agent_initial_startup_retries_missing_extra_lanes_after_transient_failure",
    "agent_bridge_repairs_missing_startup_lane_in_background",
    "assert_eq!(snapshot.lanes_desired, 4)",
    "agent_established_message_reports_degraded_lane_pool",
    "agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary",
    "agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy",
    "alternate_lane_selection_scans_by_load_without_snapshot_vector",
    "reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails",
    "reconnecting_agent_repairs_alternate_lane_that_fails_during_open",
    "agent_bridge_repairs_lane_after_active_stream_transport_failure",
    "agent_writer_clears_reused_buffers_between_bursts",
    "transport_writer_clears_reused_buffers_between_bursts",
    "accept_new_host_key",
    "--accept-new-host-key",
    "append_known_host",
    "known_hosts_needs_leading_newline",
    "host_key_verifier_accept_new_records_missing_host_key",
    "host_key_verifier_accept_new_rejects_changed_known_host",
    "host_key_verifier_accept_new_preserves_existing_line_without_newline",
    "compact_cli_rejects_conflicting_host_key_modes",
    "password_file: Option<PathBuf>",
    "--password-file",
    "resolve_ssh_password",
    "ssh_password_file_option_reads_password_without_argv_secret",
    "compact_cli_rejects_conflicting_password_sources",
    "inline --password values may be visible",
    "DEFAULT_AGENT_COMMAND",
    "effective_agent_command",
    "--agent-path",
    "effective_agent_command_quotes_literal_agent_path",
    "compact_cli_accepts_hidden_agent_path_switch",
    "compact_cli_rejects_conflicting_agent_command_modes",
    "tunnel_subcommand_accepts_hidden_agent_path_switch",
    "verify_uploaded_agent_binary",
    "cleanup_uploaded_agent_binary",
    "uploaded_agent_sha256_command",
    "uploaded_posix_agent_sha256_command",
    "uploaded_windows_agent_sha256_command",
    "POSIX_REMOTE_AGENT_UPLOAD_COMMAND",
    "WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND",
    "mktemp -d",
    "umask 077",
    "rustle-agent.XXXXXX",
    "remote_agent_upload_commands_stage_in_private_temp_dirs",
    "posix_remote_agent_upload_command_creates_private_executable_file",
    "sha256_file_hex",
    "uploaded_agent_sha256_command_uses_remote_hash_tools",
    "windows_uploaded_agent_sha256_command_uses_get_file_hash",
    "uploaded_agent_cleanup_command_quotes_path_and_refs",
    "uploaded_agent_cleanup_removes_unverified_posix_staging_tree",
    "sha256_file_hex_hashes_local_file",
    "embedded_wintun_path_is_content_and_arch_addressed",
    "sha256_hex(bytes)",
    "ingest_packet_into",
    "poll_into",
    "drain_tx_into",
    "packet_queue_device_drain_tx_into_reuses_output_vector",
    "TCP_SEND_BUFFER_BYTES",
    "socket.set_ack_delay(None)",
    "socket.set_nagle_enabled(false)",
    "new_flow_socket_uses_proxy_response_window_and_latency_settings",
    "bridge_lab_synthetic_client_models_proxy_response_window",
    "flow_keys_into",
    "ready_to_bridge_flow_ids_into",
    "opening_flow_count",
    "removable_flows_into",
    "expire_stale_flows_into",
    "flush_all_into",
    "handle_bridge_event_into",
    "query_dns_over_agent_udp_stream",
    "query_dns_over_agent_udp",
    "result: std::result::Result<Bytes, String>",
    "return Ok(frame.slice(2..))",
    "AgentFrameKind::Data => return Ok(frame.payload)",
    "dns_response_event_keeps_remote_payload_as_bytes",
    "flow_manager_flow_keys_into_reuses_output_vector",
    "flow_manager_ready_flow_ids_into_reuses_output_vector",
    "flow_manager_counts_opening_flows_without_snapshot_allocation",
    "flow_manager_cleanup_enumeration_into_reuses_output_vectors",
    "remote_backlogs_flush_all_into_reuses_scratch_vectors",
    "bridge_event_handler_into_reuses_closed_flow_scratch_vector",
    "should_log_stale_bridge_event",
    "stale_remote_data_storm_after_flow_removal_is_bounded",
    "high_fanout_stale_remote_data_after_removal_is_bounded",
    "stale_remote_data_events_are_counted_without_per_chunk_log",
    "remote_close_defers_flow_close_for_late_remote_data",
    "remote_backlog_pauses_bridge_events_at_high_watermark",
    "pub payload: Bytes",
    "association.to_remote.try_send(request.payload)",
    "udp_admission_moves_parsed_payload_bytes_into_association_queue",
    "drop_unsupported_direct_udp",
    "direct_tcpip_generic_udp_drop_is_counted_without_admission",
    "fn try_send_response(&self, key: UdpFlowKey, payload: Bytes)",
    "payload: Bytes",
    "events.try_send_response(key, frame.payload)",
    "udp_response_event_keeps_agent_payload_as_bytes",
    "spawn_udp_association_with_idle_timeout",
    "DEFAULT_UDP_ASSOCIATION_IDLE_TIMEOUT_MS",
    "udp_idle_timeout_ms",
    "udp_association_idle_timeout_emits_close_for_accounting",
    "dns_over_agent_prefers_udp_for_ipv4_remote",
]

REQUIRED_CI_SNIPPETS = [
    "python3 scripts/verify-release-matrix.py",
    "python3 scripts/verify-windows-tun-smoke.py",
    "cargo fmt --check",
    "cargo test",
    "cargo clippy --all-targets -- -D warnings",
    "cargo build --locked",
    "scripts/smoke-windows-tun.ps1",
    "bash scripts/smoke-bridge-lab.sh",
    "bash scripts/smoke-agent-lab.sh",
    "bash scripts/smoke-agent-sidecars.sh",
    "bash scripts/smoke-agent-udp-lab.sh",
    "bash scripts/smoke-agent-bridge-lab.sh",
    "bash scripts/smoke-agent-reconnect-lab.sh",
    "bash scripts/smoke-agent-active-failure-lab.sh",
    "bash scripts/stress-bridge-lab.sh",
    "bash scripts/smoke-tun-dns.sh",
    "Linux TUN DNS smoke over direct-tcpip",
    "Linux TUN DNS smoke over agent",
    "macOS TUN DNS smoke over direct-tcpip",
    "macOS TUN DNS smoke over agent",
    "RUSTLE_SMOKE_BRIDGE_TRANSPORT: direct-tcpip",
    "RUSTLE_SMOKE_BRIDGE_TRANSPORT: agent",
    "bash scripts/smoke-linux-netns-tcp.sh",
    "RUSTLE_NETNS_BRIDGE_TRANSPORT: agent",
    "bash scripts/smoke-linux-netns-udp.sh",
    'if [[ "$status" -eq 77 ]]',
]

REQUIRED_RELEASE_NOTE_SNIPPETS = [
    "automatic remote-agent bootstrap",
    "rustle-x86_64-unknown-linux-musl/rustle",
    "scripts/prepare-agent-sidecars.sh",
    "scripts/build-agent-sidecars.sh",
    "scripts/smoke-agent-sidecars.sh",
    "RUSTLE_AGENT_RELEASE_TAG",
    "RUSTLE_AGENT_ARCHIVE_DIR",
    "RUSTLE_AGENT_BUILD_TARGETS",
    "RUSTLE_AGENT_BUILD_ZIG",
    "RUSTLE_AGENT_REQUIRE_ALL=1",
    "rustle-agent-linux-x86_64",
    "rustle-agent-macos-aarch64",
    "rustle-agent-windows-x86_64.exe",
    "RUSTLE_AGENT_DIR",
    "cross-platform sidecar candidate selection",
    "CI operating-system matrix",
    "primary `agent` first",
    "SSH host-key UX checks",
    "host_key_verifier_accept_new_records_missing_host_key",
    "host_key_verifier_accept_new_rejects_changed_known_host",
    "compact_cli_rejects_conflicting_host_key_modes",
    "`--accept-new-host-key` records only unknown hosts",
    "SSH password handling checks",
    "ssh_password_file_option_reads_password_without_argv_secret",
    "compact_cli_rejects_conflicting_password_sources",
    "`--password-file` without putting secrets in argv",
    "Remote agent command handling checks",
    "effective_agent_command_quotes_literal_agent_path",
    "compact_cli_accepts_hidden_agent_path_switch",
    "compact_cli_rejects_conflicting_agent_command_modes",
    "`--agent-path` quotes a literal remote",
    "background_lane_repair_requests_are_coalesced",
    "agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure",
    "agent_initial_startup_retries_missing_extra_lanes_after_transient_failure",
    "agent_bridge_repairs_missing_startup_lane_in_background",
    "auto_agent_startup_returns_after_primary_and_warms_extra_lanes",
    "background_repair_retries_missing_lane_after_quarantine",
    "agent_writer_clears_reused_buffers_between_bursts",
    "transport_writer_clears_reused_buffers_between_bursts",
    "agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary",
    "agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy",
    "alternate_lane_selection_scans_by_load_without_snapshot_vector",
    "reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails",
    "reconnecting_agent_repairs_alternate_lane_that_fails_during_open",
    "agent_bridge_repairs_lane_after_active_stream_transport_failure",
    "connect_agent_bridge_transport_fresh_ssh_command",
    "fresh SSH connection for each exec lane",
    "packet_queue_device_drain_tx_into_reuses_output_vector",
    "flow_manager_flow_keys_into_reuses_output_vector",
    "flow_manager_ready_flow_ids_into_reuses_output_vector",
    "flow_manager_counts_opening_flows_without_snapshot_allocation",
    "flow_manager_cleanup_enumeration_into_reuses_output_vectors",
    "remote_backlogs_flush_all_into_reuses_scratch_vectors",
    "bridge_event_handler_into_reuses_closed_flow_scratch_vector",
    "target/release/rustle",
    "RUSTLE_BENCH_PROFILE=debug",
    "used as throughput evidence",
    "RUSTLE_BENCH_MAX_ELAPSED_MS=2000",
    "RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5",
    "low-concurrency path",
    "udp_admission_moves_parsed_payload_bytes_into_association_queue",
    "direct_tcpip_generic_udp_drop_is_counted_without_admission",
    "udp_association_idle_timeout_emits_close_for_accounting",
    "dns_over_agent_prefers_udp_for_ipv4_remote",
    "scripts/smoke-live-udp.sh",
    "real remote `sshd` and UDP",
    "RUSTLE_SMOKE_CONFIGURE_DNS=1",
    "resolver takeover points the OS at the Rustle virtual DNS",
    "normal system resolver lookup succeeds",
    "original resolver settings are restored",
    "content-addressed path under the user",
    "DLL SHA-256",
    "identical already-materialized DLLs are reused",
    "scripts/verify-windows-tun-smoke.py",
    "fallback route cleanup",
    "replacement for this elevated native run",
    "preserve `RUSTLE_AGENT_DIR` through",
    "sidecar store that automatic upload bootstrap uses",
    "Uploaded-agent temp staging checks",
    "remote_agent_upload_commands_stage_in_private_temp_dirs",
    "posix_remote_agent_upload_command_creates_private_executable_file",
    "Uploaded-agent integrity checks",
    "uploaded_agent_sha256_command_uses_remote_hash_tools",
    "uploaded_agent_cleanup_removes_unverified_posix_staging_tree",
    "sha256_file_hex_hashes_local_file",
]

REQUIRED_AGENT_SIDECAR_SNIPPETS = [
    "RUSTLE_AGENT_RELEASE_TAG",
    "RUSTLE_AGENT_RELEASE_REPO",
    "RUSTLE_AGENT_ARCHIVE_DIR",
    "RUSTLE_AGENT_TARGETS",
    "RUSTLE_AGENT_REQUIRE_ALL",
    "RUSTLE_AGENT_SKIP_CHECKSUMS",
    'ARCHIVE_DIR="$(cd -- "$ARCHIVE_DIR" && pwd -P)"',
    'OUT_DIR="$(cd -- "$OUT_DIR" && pwd -P)"',
    'if [[ -e "$alias_path" ]]; then',
    'if [[ -L "$alias_path" && "$FORCE" != "1" ]]; then',
    "SHA256SUMS",
    "create_alias_if_missing",
    "rustle-agent-${platform}",
    "x86_64-unknown-linux-musl",
    "aarch64-pc-windows-msvc",
]

REQUIRED_AGENT_SIDECAR_BUILD_SNIPPETS = [
    "RUSTLE_AGENT_BUILD_TARGETS",
    "RUSTLE_AGENT_ARCHIVE_DIR",
    "RUSTLE_AGENT_DIR",
    "RUSTLE_AGENT_BUILD_USE_ZIG",
    "RUSTLE_AGENT_BUILD_PROFILE",
    "RUSTLE_AGENT_BUILD_ZIG",
    "cargo zigbuild --locked --release --target \"$target\"",
    "cargo build --locked --release --target \"$target\"",
    "rustle-%s.tar.gz",
    "rustle-%s.zip",
    "README.md",
    "ARCHITECTURE.md",
    "RELEASE.md",
    "SHA256SUMS",
    "RUSTLE_AGENT_REQUIRE_ALL=1",
    "RUSTLE_AGENT_FORCE=1",
    "prepare-agent-sidecars.sh",
]

REQUIRED_AGENT_SIDECAR_SMOKE_SNIPPETS = [
    "RUSTLE_AGENT_FORCE=1",
    "relative-work",
    "missing-sidecar",
    "prepare-force.out",
    'RUSTLE_AGENT_ARCHIVE_DIR="../archives"',
    'RUSTLE_AGENT_DIR="agents"',
    "linux-x64-musl-sidecar",
    "linux-arm64-musl-sidecar",
    "macos-x64-sidecar",
    "macos-arm64-sidecar",
    "windows-x64-sidecar",
    "windows-arm-sidecar",
    "rustle-agent-linux-x86_64",
    "rustle-agent-linux-aarch64",
    "rustle-agent-macos-x86_64",
    "rustle-agent-macos-aarch64",
    "rustle-agent-windows-x86_64.exe",
    "rustle-agent-windows-aarch64.exe",
    "SHA256SUMS",
]

REQUIRED_ARCHITECTURE_NOTE_SNIPPETS = [
    "deterministic two-candidate choice",
    "ceil(sqrt(local CPU parallelism))",
    "bounded concurrent batches",
    "bounded retry",
    "fresh SSH connection with one exec channel",
    "established/desired",
    "desired/availability/missing/quarantine/repair/load state",
    "compact auto-lane path starts after the primary",
    "explicit lane counts keep the full initial startup gate",
    "failed primary is repaired in the background",
    "coalesced per lane",
    "retries after the lane's quarantine backoff",
    "availability/missing/quarantine/repair/load state",
    "reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails",
    "reconnecting_agent_repairs_alternate_lane_that_fails_during_open",
    "agent_bridge_repairs_lane_after_active_stream_transport_failure",
    "caller-owned scratch vector",
    "fresh `Vec<PacketBuf>`",
    "ready `FlowId` and active `FlowKey` enumeration",
    "does not allocate snapshots or",
    "backlog, expiry, and cleanup scans",
    "Bridge event handling writes closed-flow results into caller-owned scratch",
    "Agent mode keeps default IPv4 DNS as UDP datagrams over `OpenUdp`",
    "drop without admitting UDP association state",
    "drops generic UDP without admitting association state",
    "udp_association_idle_timeout_emits_close_for_accounting",
    "active UDP association budget",
    "close-event path that frees the association",
    "RUSTLE_SMOKE_CONFIGURE_DNS=1",
    "snapshots resolver settings",
    "resolves through the system resolver",
    "requires exact resolver restoration",
    "zero active UDP associations",
    "`--accept-new-host-key` for OpenSSH-style trust-on-first-use",
    "Accept-new mode",
    "records unknown hosts without accepting changed keys",
    "`--agent-command` is the explicit raw SSH exec command",
    "`--agent-path` shell-quotes a literal remote executable path",
    "quotes one literal executable path",
    "comparing the local SHA-256 digest with a remote hash",
    "Rustle removes the staged",
    "helper and refuses to execute it",
    "PowerShell `Get-FileHash`",
    "scripts/verify-windows-tun-smoke.py",
    "statically guards those required smoke",
    "assertions on every local verifier run",
    "private Rustle-owned temporary directories",
    "`mktemp -d` under",
    "`umask 077` and `chmod 700`",
    "GUID-suffixed",
    "Rustle-owned parent directory",
]

REQUIRED_LIVE_BENCH_SNIPPETS = [
    'RUSTLE_TRANSPORTS="agent direct-tcpip"',
    "RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO",
    "RUSTLE_BENCH_EXPECT_BYTES",
    "smoke_wait_for_rustle_target_route_logs",
    "rustle-agent",
    "sshuttle",
    "agent/sshuttle",
    "--password-file",
    "smoke_resolve_rustle_bench_bin",
    '"${#cmd_env[@]}" -gt 0',
    'cmd_env+=(RUSTLE_AGENT_DIR="$RUSTLE_AGENT_DIR")',
    "RUSTLE_BENCH_READY_METHOD",
    "probe_args+=(--head)",
]

REQUIRED_AGENT_PRIMARY_SCRIPT_SNIPPETS = [
    (
        BRIDGE_BENCH,
        'TRANSPORTS="${RUSTLE_BENCH_BRIDGE_TRANSPORTS:-agent direct-tcpip}"',
    ),
    (
        BRIDGE_BENCH,
        "smoke_resolve_rustle_bench_bin",
    ),
    (
        BRIDGE_BENCH,
        "RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S",
    ),
    (
        BRIDGE_BENCH,
        "RUSTLE_BENCH_MAX_ELAPSED_MS",
    ),
    (
        AGENT_UDP_BENCH,
        "smoke_resolve_rustle_bench_bin",
    ),
    (
        REPO / "scripts" / "stress-bridge-lab.sh",
        'TRANSPORTS="${RUSTLE_STRESS_BRIDGE_TRANSPORTS:-agent direct-tcpip}"',
    ),
    (
        REPO / "scripts" / "stress-bridge-lab.sh",
        'CONNECTIONS="${RUSTLE_STRESS_BRIDGE_CONNECTIONS:-256}"',
    ),
    (
        REPO / "scripts" / "stress-bridge-lab.sh",
        'BODY_BYTES="${RUSTLE_STRESS_BRIDGE_BODY_BYTES:-1048576}"',
    ),
    (
        REPO / "scripts" / "stress-bridge-lab.sh",
        "RUSTLE_STRESS_BRIDGE_PROFILE:-debug",
    ),
    (
        VERIFY_LOCAL,
        'LIVE_TRANSPORTS="${RUSTLE_VERIFY_LIVE_TRANSPORTS:-${RUSTLE_LIVE_BRIDGE_TRANSPORT:-agent direct-tcpip}}"',
    ),
    (
        VERIFY_LOCAL,
        'RUN_LIVE_FIXTURE="${RUSTLE_VERIFY_LIVE_FIXTURE:-0}"',
    ),
    (
        VERIFY_LOCAL,
        'RUN_LIVE_UDP="${RUSTLE_VERIFY_LIVE_UDP:-0}"',
    ),
    (
        VERIFY_LOCAL,
        "cargo build --locked --release",
    ),
    (
        VERIFY_LOCAL,
        "RUSTLE_BENCH_MAX_ELAPSED_MS=2000",
    ),
    (
        VERIFY_LOCAL,
        "RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5",
    ),
    (
        VERIFY_LOCAL,
        "verify-live-fixture-rows.py",
    ),
    (
        VERIFY_LOCAL,
        "smoke-live-udp.sh",
    ),
    (
        VERIFY_LOCAL,
        "verify-windows-tun-smoke.py",
    ),
    (
        VERIFY_LOCAL,
        'RUN_DNS_TAKEOVER="${RUSTLE_VERIFY_DNS_TAKEOVER:-0}"',
    ),
    (
        VERIFY_LOCAL,
        "RUSTLE_SMOKE_CONFIGURE_DNS=1 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent",
    ),
    (
        VERIFY_LOCAL,
        'RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent direct-tcpip"',
    ),
    (
        VERIFY_LOCAL,
        '"${SCRIPT_DIR}/stress-bridge-lab.sh"',
    ),
]

REQUIRED_LIVE_FIXTURE_SNIPPETS = [
    "RUSTLE_FIXTURE_BODY_BYTES",
    "1048576 10485760 104857600",
    "BENCH_ENV",
    "RUSTLE_BENCH_PASSWORD_VALUE",
    "RUSTLE_BENCH_SSHUTTLE_PASSWORD_VALUE",
    "RUSTLE_FIXTURE_IDENTITY",
    "RUSTLE_FIXTURE_INSECURE_HOST_KEY",
    "RUSTLE_FIXTURE_KNOWN_HOSTS",
    'sys.stdout.write("READY %d\\n"',
    'is_head = data[:5].upper() == b"HEAD "',
    "RUSTLE_BENCH_READY_METHOD=HEAD",
    "verify_fixture_benchmark_rows",
    "verify-live-fixture-rows.py",
    "$fixture_results",
    "thread.daemon = True",
    "conn.close()",
    "sock.close()",
    "RUSTLE_BENCH_EXPECT=rustle-live-fixture",
    "RUSTLE_BENCH_EXPECT_BYTES",
    "bench-live-compare.sh",
]

REQUIRED_LIVE_FIXTURE_ROW_SNIPPETS = [
    "verify(path: pathlib.Path, body_bytes: int)",
    "body_bytes * success",
    "invalid live fixture benchmark row",
    "produced no benchmark rows",
    "produced invalid benchmark rows",
    "--self-test",
    "assert_rejects",
]

REQUIRED_LIVE_SMOKE_SNIPPETS = [
    "smoke_wait_for_rustle_target_route_logs",
    "--password-file",
    'CMD_ENV+=(RUSTLE_AGENT_DIR="$RUSTLE_AGENT_DIR")',
]

REQUIRED_LIVE_UDP_SMOKE_SNIPPETS = [
    "RUSTLE_LIVE_UDP_HOST",
    "RUSTLE_LIVE_UDP_MESSAGES",
    "RUSTLE_LIVE_UDP_IDLE_TIMEOUT_MS",
    "RUSTLE_LIVE_UDP_IDLE_GRACE_MS",
    "--udp-idle-timeout-ms",
    "rustle-live-udp-pong:",
    "smoke_wait_for_rustle_target_route_logs",
    'CMD_ENV+=(RUSTLE_AGENT_DIR="$RUSTLE_AGENT_DIR")',
    "--password-file",
    "udp: forwarding datagram .* -> ${FIXTURE_HOST}:${ACTUAL_PORT} over agent",
    "waiting for UDP association idle cleanup",
    'smoke_require_stat_at_least "UDP forwarded"',
    'smoke_require_stat_at_least "UDP successes"',
    'smoke_require_stat_zero "UDP active associations"',
    "live UDP target route table did not return to its original state",
]

REQUIRED_SMOKE_LIB_SNIPPETS = [
    "smoke_resolve_rustle_bench_bin",
    "RUSTLE_BENCH_PROFILE",
    "target/${profile}/rustle",
    "smoke_wait_for_log_fixed_or_exit",
    "smoke_wait_for_rustle_target_route_logs",
    "route: added 0.0.0.0/1",
    "route: added 128.0.0.0/1",
]

REQUIRED_TUN_DNS_SMOKE_SNIPPETS = [
    "RUSTLE_SMOKE_CONFIGURE_DNS",
    "dns_snapshot",
    "dns_settings_use_expected_resolver",
    "runtime_dns_uses_expected_resolver",
    "diagnose_runtime_dns_conflict",
    "wait_for_runtime_dns",
    "verify_dns_restored",
    "DNS_RESTORE_CHECKED",
    "scutil --dns",
    "global_config",
    "macOS runtime DNS is still using a global resolver",
    "dscacheutil -flushcache",
    "RUSTLE_SMOKE_SYSTEM_DNS_IP",
    "RUSTLE_SMOKE_DNS_NAME",
    "198.18.255.1",
    "198.18.255.53",
    "rustle-smoke.example.com",
    "add_virtual_dns_route",
    "delete_virtual_dns_route_best_effort",
    "dns: configured host resolver to use DNS",
    "dns: forwarding UDP query",
    "Rustle did not log the TUN DNS query",
    "system DNS settings did not point at the expected Rustle resolver",
    "runtime DNS resolver did not pick up the expected Rustle resolver",
    "system DNS settings did not return to their original state",
    "socket.gethostbyname",
    "system resolver DNS smoke response ok",
    "resolvectl status",
    "networksetup -getdnsservers",
]

REQUIRED_NETNS_UDP_SMOKE_SNIPPETS = [
    "RUSTLE_NETNS_UDP_IDLE_TIMEOUT_MS",
    "RUSTLE_NETNS_UDP_IDLE_GRACE_MS",
    "--udp-idle-timeout-ms",
    "waiting for UDP association idle cleanup",
    'smoke_require_stat_zero "UDP active associations"',
]

REQUIRED_WINDOWS_TUN_SMOKE_VERIFIER_SNIPPETS = [
    "REQUIRED_SNIPPETS",
    "[Security.Principal.WindowsBuiltInRole]::Administrator",
    "Get-RouteSnapshot",
    "$routeBefore = @(Get-RouteSnapshot $TargetCidr)",
    "$routeAfter = @(Get-RouteSnapshot $TargetCidr)",
    "route.exe DELETE $targetIp MASK 255.255.255.255 $TunIp",
    '"tun-capture"',
    '"--exit-after-packets", "1"',
    "[System.Net.Sockets.TcpClient]::new()",
    "capture: exit-after-packets reached",
    "target route table did not return to its original state",
    "ORDERED_SNIPPETS",
]

REQUIRED_PERFORMANCE_NOTE_SNIPPETS = [
    "RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO",
    "cargo build --release",
    "target/release/rustle",
    "RUSTLE_BENCH_PROFILE=debug",
    "RUSTLE_BENCH_MAX_ELAPSED_MS",
    "tiny-response 1-flow latency gate",
    "RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S",
    "1 MiB / 1-flow gate",
    "hard gate",
    "256 x 1 MiB",
    "lifecycle gate",
    "not throughput evidence",
    "rustle-agent",
    "primary `agent` transport",
    "agent` first and `direct-tcpip` second",
    "same SSH server, target URL, request",
    "bench-live-fixture.sh",
    "scripts/build-agent-sidecars.sh",
    "1 MiB / 10 MiB / 100 MiB",
    'RUSTLE_AGENT_DIR="$HOME/.cache/rustle/agents"',
    "preserve that variable through `sudo`",
    "published archives are not",
    "split default routes",
    "intercepted DNS in agent mode keeps IPv4 resolver traffic on `OpenUdp`",
    "RUSTLE_SMOKE_CONFIGURE_DNS=1",
    "RUSTLE_VERIFY_DNS_TAKEOVER=1",
    "DNS resolver takeover, normal system resolver delivery through Rustle",
    "global `scutil --dns` resolver",
    "--udp-idle-timeout-ms",
    "zero active associations",
    "RUSTLE_VERIFY_LIVE_FIXTURE=1",
    "RUSTLE_VERIFY_LIVE_UDP=1",
    "scripts/smoke-live-udp.sh",
    "generic UDP live fixture",
    "captures the nested benchmark TSV output",
    "body_bytes * success",
    "compact command already defaults to the framed agent transport",
    "compact auto-lane path starts after the primary agent lane",
    "short first-flow defer",
    "explicit `--agent-sessions`",
    "bridge-lab` disables the compact tunnel's auto-lane fast-start",
    "rootless `bridge-lab` keeps full lane warmup",
    "fresh SSH connection with one exec channel",
    "caller-owned scratch vectors",
    "fresh `Vec<PacketBuf>`",
    "opening-flow counts are computed directly",
    "per-tick cleanup scans",
    "high-rate remote-data events do not allocate temporary closed-flow vectors",
    "generic UDP request payloads are parsed into `Bytes` once",
    "direct-tcpip compatibility mode drops generic UDP intentionally",
    "generic UDP response events keep agent `Data` frame payloads as `Bytes`",
    "idle generic UDP associations emit close events",
    "DNS response events keep remote resolver payloads as `Bytes`",
    "loopback DNS proxy",
    "Rustle receives the password through its `--password-file` option",
    "Bare `--password` still supports the legacy",
    "known-failed primary lanes must not add reconnect latency",
    "least-loaded healthy lane elsewhere in the pool",
    "fallback alternate scans do not allocate sorted lane snapshots",
    "background repair requests must coalesce per lane",
    "background repair must retry after bounded quarantine backoff",
    "fallback opens must repair failed alternate agent lanes",
    "fallback alternate-lane scans must not allocate sorted lane snapshots",
    "active stream transport failures must trigger lane repair",
    "bounded retry",
    "explicit initial extra agent lanes must start in bounded batches and preserve",
    "missing desired lane slots must remain repairable",
    "reuse per-task burst frame and encoded-byte buffers",
]


def fail(message: str) -> None:
    print(f"release matrix verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_matrix(workflow: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in workflow.splitlines():
        os_match = re.match(r"\s*-\s+os:\s+([^\s]+)\s*$", line)
        if os_match:
            if current is not None:
                entries.append(current)
            current = {"os": os_match.group(1)}
            continue

        if current is None:
            continue

        field_match = re.match(r"\s+(target|package|archive):\s+([^\s]+)\s*$", line)
        if field_match:
            current[field_match.group(1)] = field_match.group(2)

    if current is not None:
        entries.append(current)

    return entries


def parse_ci_os_matrix(workflow: str) -> list[str]:
    match = re.search(r"(?ms)^\s+os:\s*\n((?:\s+-\s+[^\n]+\n)+)", workflow)
    if not match:
        fail(".github/workflows/ci.yml is missing the test OS matrix")
    return [entry.strip() for entry in re.findall(r"^\s+-\s+([^\s]+)\s*$", match.group(1), re.M)]


def docs_targets(notes: str) -> list[str]:
    marker = "The release workflow builds native archives for:"
    try:
        start = notes.index(marker)
    except ValueError:
        fail("docs/release.md is missing the binary target marker")

    targets: list[str] = []
    for line in notes[start + len(marker) :].splitlines():
        if not line.strip():
            if targets:
                break
            continue
        match = re.match(r"- `([^`]+)`", line.strip())
        if match:
            targets.append(match.group(1))
    return targets


def main() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    main_source = MAIN_SOURCE.read_text(encoding="utf-8")
    rust_sources = rust_source_text()
    notes = RELEASE_NOTES.read_text(encoding="utf-8")
    architecture_notes = ARCHITECTURE_NOTES.read_text(encoding="utf-8")
    performance_notes = PERFORMANCE_NOTES.read_text(encoding="utf-8")
    live_smoke = LIVE_SMOKE.read_text(encoding="utf-8")
    live_udp_smoke = LIVE_UDP_SMOKE.read_text(encoding="utf-8")
    live_bench = LIVE_BENCH.read_text(encoding="utf-8")
    live_fixture = LIVE_FIXTURE.read_text(encoding="utf-8")
    live_fixture_rows = LIVE_FIXTURE_ROWS.read_text(encoding="utf-8")
    smoke_lib = SMOKE_LIB.read_text(encoding="utf-8")
    tun_dns_smoke = TUN_DNS_SMOKE.read_text(encoding="utf-8")
    netns_udp_smoke = NETNS_UDP_SMOKE.read_text(encoding="utf-8")
    windows_tun_smoke_verifier = WINDOWS_TUN_SMOKE_VERIFIER.read_text(encoding="utf-8")
    agent_sidecars = AGENT_SIDECARS.read_text(encoding="utf-8")
    agent_sidecar_build = AGENT_SIDECAR_BUILD.read_text(encoding="utf-8")
    agent_sidecar_smoke = AGENT_SIDECAR_SMOKE.read_text(encoding="utf-8")

    matrix = parse_matrix(workflow)
    if matrix != EXPECTED:
        fail(f"release.yml matrix does not match expected target set:\nactual={matrix!r}")

    expected_targets = [entry["target"] for entry in EXPECTED]
    if docs_targets(notes) != expected_targets:
        fail("docs/release.md binary target list does not match release.yml matrix")

    for entry in EXPECTED:
        target = entry["target"]
        package = entry["package"]
        archive = entry["archive"]
        if package != f"rustle-{target}":
            fail(f"unexpected package name for {target}: {package}")
        expected_archive = f"{package}.zip" if "windows" in target else f"{package}.tar.gz"
        if archive != expected_archive:
            fail(f"unexpected archive name for {target}: {archive}")

    archive_counts = [int(value) for value in re.findall(r"expected_archives=(\d+)", workflow)]
    if not archive_counts:
        fail("release.yml does not check the number of release archives")
    if any(count != len(EXPECTED) for count in archive_counts):
        fail(f"release.yml archive count checks are not {len(EXPECTED)}: {archive_counts}")

    missing = [snippet for snippet in REQUIRED_WORKFLOW_SNIPPETS if snippet not in workflow]
    if missing:
        fail(f"release.yml is missing required verification snippets: {missing!r}")

    missing_build = [
        snippet for snippet in REQUIRED_BUILD_SCRIPT_SNIPPETS if snippet not in build_script
    ]
    if missing_build:
        fail(f"build.rs is missing required Wintun validation snippets: {missing_build!r}")

    missing_main = [
        snippet for snippet in REQUIRED_MAIN_SOURCE_SNIPPETS if snippet not in rust_sources
    ]
    if missing_main:
        fail(f"src/*.rs is missing required transport snippets: {missing_main!r}")
    if main_source.count('default_value = "agent"') < 3:
        fail("src/main.rs must keep compact, tunnel, and bridge-lab defaulting to agent")

    ci_os = parse_ci_os_matrix(ci_workflow)
    if ci_os != EXPECTED_CI_OS:
        fail(f"ci.yml OS matrix does not match expected platform set:\nactual={ci_os!r}")

    missing_ci = [snippet for snippet in REQUIRED_CI_SNIPPETS if snippet not in ci_workflow]
    if missing_ci:
        fail(f"ci.yml is missing required verification snippets: {missing_ci!r}")

    missing_notes = [
        snippet for snippet in REQUIRED_RELEASE_NOTE_SNIPPETS if snippet not in notes
    ]
    if missing_notes:
        fail(f"docs/release.md is missing required snippets: {missing_notes!r}")

    missing_architecture_notes = [
        snippet
        for snippet in REQUIRED_ARCHITECTURE_NOTE_SNIPPETS
        if snippet not in architecture_notes
    ]
    if missing_architecture_notes:
        fail(
            "docs/architecture.md is missing required snippets: "
            f"{missing_architecture_notes!r}"
        )

    missing_live_bench = [
        snippet for snippet in REQUIRED_LIVE_BENCH_SNIPPETS if snippet not in live_bench
    ]
    if missing_live_bench:
        fail(
            "scripts/bench-live-compare.sh is missing required snippets: "
            f"{missing_live_bench!r}"
        )

    missing_agent_primary_scripts = [
        (path, snippet)
        for path, snippet in REQUIRED_AGENT_PRIMARY_SCRIPT_SNIPPETS
        if snippet not in path.read_text(encoding="utf-8")
    ]
    if missing_agent_primary_scripts:
        details = [
            f"{path.relative_to(REPO)} missing {snippet!r}"
            for path, snippet in missing_agent_primary_scripts
        ]
        fail("agent-primary script defaults drifted: " + "; ".join(details))

    missing_live_fixture = [
        snippet
        for snippet in REQUIRED_LIVE_FIXTURE_SNIPPETS
        if snippet not in live_fixture
    ]
    if missing_live_fixture:
        fail(
            "scripts/bench-live-fixture.sh is missing required snippets: "
            f"{missing_live_fixture!r}"
        )

    missing_live_fixture_rows = [
        snippet
        for snippet in REQUIRED_LIVE_FIXTURE_ROW_SNIPPETS
        if snippet not in live_fixture_rows
    ]
    if missing_live_fixture_rows:
        fail(
            "scripts/verify-live-fixture-rows.py is missing required snippets: "
            f"{missing_live_fixture_rows!r}"
        )

    missing_live_smoke = [
        snippet for snippet in REQUIRED_LIVE_SMOKE_SNIPPETS if snippet not in live_smoke
    ]
    if missing_live_smoke:
        fail(
            "scripts/smoke-live-tunnel.sh is missing required snippets: "
            f"{missing_live_smoke!r}"
        )

    missing_live_udp_smoke = [
        snippet
        for snippet in REQUIRED_LIVE_UDP_SMOKE_SNIPPETS
        if snippet not in live_udp_smoke
    ]
    if missing_live_udp_smoke:
        fail(
            "scripts/smoke-live-udp.sh is missing required snippets: "
            f"{missing_live_udp_smoke!r}"
        )

    missing_smoke_lib = [
        snippet for snippet in REQUIRED_SMOKE_LIB_SNIPPETS if snippet not in smoke_lib
    ]
    if missing_smoke_lib:
        fail(f"scripts/smoke-lib.sh is missing required snippets: {missing_smoke_lib!r}")

    missing_tun_dns_smoke = [
        snippet
        for snippet in REQUIRED_TUN_DNS_SMOKE_SNIPPETS
        if snippet not in tun_dns_smoke
    ]
    if missing_tun_dns_smoke:
        fail(
            "scripts/smoke-tun-dns.sh is missing required snippets: "
            f"{missing_tun_dns_smoke!r}"
        )

    missing_netns_udp_smoke = [
        snippet
        for snippet in REQUIRED_NETNS_UDP_SMOKE_SNIPPETS
        if snippet not in netns_udp_smoke
    ]
    if missing_netns_udp_smoke:
        fail(
            "scripts/smoke-linux-netns-udp.sh is missing required snippets: "
            f"{missing_netns_udp_smoke!r}"
        )

    missing_windows_tun_smoke_verifier = [
        snippet
        for snippet in REQUIRED_WINDOWS_TUN_SMOKE_VERIFIER_SNIPPETS
        if snippet not in windows_tun_smoke_verifier
    ]
    if missing_windows_tun_smoke_verifier:
        fail(
            "scripts/verify-windows-tun-smoke.py is missing required snippets: "
            f"{missing_windows_tun_smoke_verifier!r}"
        )

    missing_agent_sidecars = [
        snippet
        for snippet in REQUIRED_AGENT_SIDECAR_SNIPPETS
        if snippet not in agent_sidecars
    ]
    if missing_agent_sidecars:
        fail(
            "scripts/prepare-agent-sidecars.sh is missing required snippets: "
            f"{missing_agent_sidecars!r}"
        )

    missing_agent_sidecar_build = [
        snippet
        for snippet in REQUIRED_AGENT_SIDECAR_BUILD_SNIPPETS
        if snippet not in agent_sidecar_build
    ]
    if missing_agent_sidecar_build:
        fail(
            "scripts/build-agent-sidecars.sh is missing required snippets: "
            f"{missing_agent_sidecar_build!r}"
        )

    missing_agent_sidecar_smoke = [
        snippet
        for snippet in REQUIRED_AGENT_SIDECAR_SMOKE_SNIPPETS
        if snippet not in agent_sidecar_smoke
    ]
    if missing_agent_sidecar_smoke:
        fail(
            "scripts/smoke-agent-sidecars.sh is missing required snippets: "
            f"{missing_agent_sidecar_smoke!r}"
        )

    missing_performance_notes = [
        snippet
        for snippet in REQUIRED_PERFORMANCE_NOTE_SNIPPETS
        if snippet not in performance_notes
    ]
    if missing_performance_notes:
        fail(
            "docs/performance.md is missing required snippets: "
            f"{missing_performance_notes!r}"
        )

    print(f"release matrix ok: {len(EXPECTED)} targets; CI ok: {len(EXPECTED_CI_OS)} OSes")


if __name__ == "__main__":
    main()
