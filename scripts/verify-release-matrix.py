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
LIVE_BENCH = REPO / "scripts" / "bench-live-compare.sh"
LIVE_FIXTURE = REPO / "scripts" / "bench-live-fixture.sh"
SMOKE_LIB = REPO / "scripts" / "smoke-lib.sh"
AGENT_SIDECARS = REPO / "scripts" / "prepare-agent-sidecars.sh"
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
    "musl release binary appears dynamically linked",
    "sha256sum > SHA256SUMS",
    "name: rustle-checksums",
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
    "embedded_wintun_path_is_content_and_arch_addressed",
    "sha256_hex(bytes)",
    "ingest_packet_into",
    "poll_into",
    "drain_tx_into",
    "packet_queue_device_drain_tx_into_reuses_output_vector",
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
    "remote_close_defers_flow_close_for_late_remote_data",
    "remote_backlog_pauses_bridge_events_at_high_watermark",
    "pub payload: Bytes",
    "association.to_remote.try_send(request.payload)",
    "udp_admission_moves_parsed_payload_bytes_into_association_queue",
    "fn try_send_response(&self, key: UdpFlowKey, payload: Bytes)",
    "payload: Bytes",
    "events.try_send_response(key, frame.payload)",
    "udp_response_event_keeps_agent_payload_as_bytes",
    "dns_over_agent_prefers_udp_for_ipv4_remote",
]

REQUIRED_CI_SNIPPETS = [
    "python3 scripts/verify-release-matrix.py",
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
    "scripts/smoke-agent-sidecars.sh",
    "RUSTLE_AGENT_RELEASE_TAG",
    "RUSTLE_AGENT_ARCHIVE_DIR",
    "rustle-agent-linux-x86_64",
    "RUSTLE_AGENT_DIR",
    "cross-platform sidecar candidate selection",
    "CI operating-system matrix",
    "background_lane_repair_requests_are_coalesced",
    "agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure",
    "agent_initial_startup_retries_missing_extra_lanes_after_transient_failure",
    "agent_bridge_repairs_missing_startup_lane_in_background",
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
    "udp_admission_moves_parsed_payload_bytes_into_association_queue",
    "dns_over_agent_prefers_udp_for_ipv4_remote",
    "content-addressed path under the user",
    "DLL SHA-256",
    "identical already-materialized DLLs are reused",
]

REQUIRED_AGENT_SIDECAR_SNIPPETS = [
    "RUSTLE_AGENT_RELEASE_TAG",
    "RUSTLE_AGENT_RELEASE_REPO",
    "RUSTLE_AGENT_ARCHIVE_DIR",
    "RUSTLE_AGENT_TARGETS",
    "RUSTLE_AGENT_REQUIRE_ALL",
    "RUSTLE_AGENT_SKIP_CHECKSUMS",
    "SHA256SUMS",
    "create_alias_if_missing",
    "rustle-agent-${platform}",
    "x86_64-unknown-linux-musl",
    "aarch64-pc-windows-msvc",
]

REQUIRED_AGENT_SIDECAR_SMOKE_SNIPPETS = [
    "RUSTLE_AGENT_FORCE=1",
    "grep -q 'musl-sidecar'",
    "rustle-agent-linux-x86_64",
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
]

REQUIRED_LIVE_BENCH_SNIPPETS = [
    "RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO",
    "RUSTLE_BENCH_EXPECT_BYTES",
    "smoke_wait_for_rustle_target_route_logs",
    "rustle-agent",
    "sshuttle",
    "agent/sshuttle",
]

REQUIRED_LIVE_FIXTURE_SNIPPETS = [
    "RUSTLE_FIXTURE_BODY_BYTES",
    "1048576 10485760 104857600",
    "RUSTLE_BENCH_EXPECT_BYTES",
    "bench-live-compare.sh",
]

REQUIRED_LIVE_SMOKE_SNIPPETS = [
    "smoke_wait_for_rustle_target_route_logs",
]

REQUIRED_SMOKE_LIB_SNIPPETS = [
    "smoke_wait_for_log_fixed_or_exit",
    "smoke_wait_for_rustle_target_route_logs",
    "route: added 0.0.0.0/1",
    "route: added 128.0.0.0/1",
]

REQUIRED_PERFORMANCE_NOTE_SNIPPETS = [
    "RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO",
    "hard gate",
    "rustle-agent",
    "same SSH server, target URL, request",
    "bench-live-fixture.sh",
    "1 MiB / 10 MiB / 100 MiB",
    "split default routes",
    "intercepted DNS in agent mode keeps IPv4 resolver traffic on `OpenUdp`",
    "compact command already defaults to the framed agent transport",
    "fresh SSH connection with one exec channel",
    "caller-owned scratch vectors",
    "fresh `Vec<PacketBuf>`",
    "opening-flow counts are computed directly",
    "per-tick cleanup scans",
    "high-rate remote-data events do not allocate temporary closed-flow vectors",
    "generic UDP request payloads are parsed into `Bytes` once",
    "generic UDP response events keep agent `Data` frame payloads as `Bytes`",
    "DNS response events keep remote resolver payloads as `Bytes`",
    "known-failed primary lanes must not add reconnect latency",
    "least-loaded healthy lane elsewhere in the pool",
    "fallback alternate scans do not allocate sorted lane snapshots",
    "background repair requests must coalesce per lane",
    "background repair must retry after bounded quarantine backoff",
    "fallback opens must repair failed alternate agent lanes",
    "fallback alternate-lane scans must not allocate sorted lane snapshots",
    "active stream transport failures must trigger lane repair",
    "bounded retry",
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
    live_bench = LIVE_BENCH.read_text(encoding="utf-8")
    live_fixture = LIVE_FIXTURE.read_text(encoding="utf-8")
    smoke_lib = SMOKE_LIB.read_text(encoding="utf-8")
    agent_sidecars = AGENT_SIDECARS.read_text(encoding="utf-8")
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

    missing_live_smoke = [
        snippet for snippet in REQUIRED_LIVE_SMOKE_SNIPPETS if snippet not in live_smoke
    ]
    if missing_live_smoke:
        fail(
            "scripts/smoke-live-tunnel.sh is missing required snippets: "
            f"{missing_live_smoke!r}"
        )

    missing_smoke_lib = [
        snippet for snippet in REQUIRED_SMOKE_LIB_SNIPPETS if snippet not in smoke_lib
    ]
    if missing_smoke_lib:
        fail(f"scripts/smoke-lib.sh is missing required snippets: {missing_smoke_lib!r}")

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
