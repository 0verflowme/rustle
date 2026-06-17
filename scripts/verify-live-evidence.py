#!/usr/bin/env python3
"""Verify release-candidate live benchmark evidence artifacts."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
import shutil
import tempfile
from types import ModuleType


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
FIXTURE_DIR_RE = re.compile(r"^fixture-(?P<body_bytes>[1-9][0-9]*)-bytes$")
HOTPATH_COLUMNS = {
    "transport",
    "flows",
    "failed_flows",
    "remote_bytes_min",
    "ready_wait_p50_ms",
    "flow_throughput_min_mib_s",
    "tcp_recv_queue_wait_p50_ms",
    "tcp_recv_queue_wait_max_ms",
    "tcp_recv_queue_wait_avg_ms",
    "local_queue_wait_p50_ms",
    "local_queue_wait_max_ms",
    "local_queue_wait_avg_ms",
    "remote_event_wait_max_ms",
    "remote_event_wait_avg_ms",
    "likely_bottleneck",
}
QUIC_DIAGNOSTIC_COLUMNS = {
    "category",
    "events",
    "failures",
    "max_elapsed_ms",
    "stages",
}


def load_module(path: pathlib.Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"failed to load verifier module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LIVE_BENCHMARK_ROWS = load_module(
    SCRIPT_DIR / "verify-live-benchmark-rows.py",
    "verify_live_benchmark_rows",
)
LIVE_FIXTURE_ROWS = load_module(
    SCRIPT_DIR / "verify-live-fixture-rows.py",
    "verify_live_fixture_rows",
)


def require_file(path: pathlib.Path) -> pathlib.Path:
    if not path.is_file():
        raise SystemExit(f"missing required live evidence file: {path}")
    return path


def read_tsv(path: pathlib.Path) -> tuple[list[str], list[list[str]]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if not lines:
        raise SystemExit(f"empty live evidence TSV: {path}")
    header = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:]]
    if not rows:
        raise SystemExit(f"live evidence TSV has header but no rows: {path}")
    for row in rows:
        if len(row) != len(header):
            raise SystemExit(f"invalid live evidence TSV row in {path}: {row!r}")
    return header, rows


def verify_hotpath_summary(path: pathlib.Path) -> None:
    header, rows = read_tsv(require_file(path))
    missing = sorted(HOTPATH_COLUMNS.difference(header))
    if missing:
        raise SystemExit(f"hotpath summary {path} missing columns {missing!r}")
    flows_index = header.index("flows")
    failed_index = header.index("failed_flows")
    for row in rows:
        flows = int(row[flows_index])
        failed = int(row[failed_index])
        if flows < 1:
            raise SystemExit(f"hotpath summary {path} has non-positive flow count")
        if failed < 0 or failed > flows:
            raise SystemExit(f"hotpath summary {path} has invalid failed flow count")


def verify_quic_diagnostics(path: pathlib.Path) -> None:
    header, rows = read_tsv(require_file(path))
    missing = sorted(QUIC_DIAGNOSTIC_COLUMNS.difference(header))
    if missing:
        raise SystemExit(f"QUIC diagnostics {path} missing columns {missing!r}")
    events_index = header.index("events")
    failures_index = header.index("failures")
    max_elapsed_index = header.index("max_elapsed_ms")
    for row in rows:
        events = int(row[events_index])
        failures = int(row[failures_index])
        max_elapsed = int(row[max_elapsed_index])
        if events < 1:
            raise SystemExit(f"QUIC diagnostics {path} has non-positive event count")
        if failures < 0 or failures > events:
            raise SystemExit(f"QUIC diagnostics {path} has invalid failure count")
        if max_elapsed < 0:
            raise SystemExit(f"QUIC diagnostics {path} has negative elapsed time")


def verify_optional_quic_diagnostics(directory: pathlib.Path) -> None:
    diagnostics = directory / "quic-diagnostics.tsv"
    if diagnostics.exists():
        verify_quic_diagnostics(diagnostics)


def verify_live_compare(directory: pathlib.Path, require_hotpath: bool) -> None:
    live_compare = directory / "live-compare"
    if not live_compare.is_dir():
        raise SystemExit(f"missing live comparison evidence directory: {live_compare}")
    LIVE_BENCHMARK_ROWS.verify(require_file(live_compare / "live-results.tsv"))
    if require_hotpath:
        verify_hotpath_summary(live_compare / "hotpath-summary.tsv")
    verify_optional_quic_diagnostics(live_compare)


def fixture_dirs(directory: pathlib.Path) -> list[tuple[int, pathlib.Path]]:
    fixtures: list[tuple[int, pathlib.Path]] = []
    for child in sorted(directory.iterdir()):
        if not child.is_dir():
            continue
        match = FIXTURE_DIR_RE.match(child.name)
        if match is None:
            continue
        fixtures.append((int(match.group("body_bytes")), child))
    return fixtures


def verify_fixtures(directory: pathlib.Path, require_hotpath: bool) -> None:
    fixtures = fixture_dirs(directory)
    if not fixtures:
        raise SystemExit(f"no controlled fixture evidence directories found in {directory}")
    for body_bytes, fixture_dir in fixtures:
        LIVE_FIXTURE_ROWS.verify(
            require_file(fixture_dir / "fixture-results.tsv"),
            body_bytes,
        )
        LIVE_BENCHMARK_ROWS.verify(require_file(fixture_dir / "live-results.tsv"))
        if require_hotpath:
            verify_hotpath_summary(fixture_dir / "hotpath-summary.tsv")
        verify_optional_quic_diagnostics(fixture_dir)


def verify(directory: pathlib.Path, require_hotpath: bool) -> None:
    if not directory.is_dir():
        raise SystemExit(f"live evidence directory does not exist: {directory}")
    verify_live_compare(directory, require_hotpath)
    verify_fixtures(directory, require_hotpath)


def write_sample_live_results(path: pathlib.Path, body_bytes: int = 1024) -> None:
    path.write_text(
        "\n".join(
            [
                (
                    "rustle-agent\t1\t4\t2\t4\t0\t100\t10.0\t20.0\t"
                    f"{body_bytes * 4}\t39.06\t40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0"
                ),
                (
                    "sshuttle\t1\t4\t2\t4\t0\t120\t12.0\t22.0\t"
                    f"{body_bytes * 4}\t32.55\t33.33\t1.0\t2.0\t\t\t\t\t\t"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def write_sample_fixture_results(path: pathlib.Path, body_bytes: int) -> None:
    path.write_text(
        "\n".join(
            [
                (
                    "tool\trun\trequests\tconcurrency\tsuccess\tfailed\twall_ms\t"
                    "p50_ms\tp95_ms\tbytes\tthroughput_mib_s\treq_s\tavg_cpu_pct\t"
                    "max_cpu_pct\tssh_opened\tssh_failed\tagent_reconnect_attempts\t"
                    "agent_reconnect_ok\tagent_reconnect_failed\tbacklog_overflow"
                ),
                (
                    "rustle-agent\t1\t4\t2\t4\t0\t100\t10.0\t20.0\t"
                    f"{body_bytes * 4}\t39.06\t40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def write_sample_hotpath(path: pathlib.Path) -> None:
    path.write_text(
        "\n".join(
            [
                (
                    "transport\tflows\tok_flows\tfailed_flows\tlocal_bytes\tremote_bytes\t"
                    "remote_bytes_min\tremote_bytes_p50\t"
                    "stream_ready_p50_ms\topened_p50_ms\tfirst_local_p50_ms\t"
                    "first_local_sent_p50_ms\tfirst_remote_p50_ms\t"
                    "first_remote_p95_ms\tremote_open_wait_p50_ms\t"
                    "ready_wait_p50_ms\tready_wait_total_ms\t"
                    "payload_queue_wait_p50_ms\tfirst_byte_wait_p50_ms\t"
                    "body_drain_p50_ms\tlocal_send_wait_p50_ms\t"
                    "local_send_wait_total_ms\tlocal_send_wait_max_ms\t"
                    "local_send_wait_avg_ms\tlocal_send_waits\t"
                    "tcp_recv_queue_wait_p50_ms\ttcp_recv_queue_wait_total_ms\t"
                    "tcp_recv_queue_wait_max_ms\ttcp_recv_queue_wait_avg_ms\t"
                    "tcp_recv_queue_waits\t"
                    "local_queue_wait_p50_ms\tlocal_queue_wait_total_ms\t"
                    "local_queue_wait_max_ms\tlocal_queue_wait_avg_ms\t"
                    "local_queue_waits\t"
                    "agent_send_credit_wait_p50_ms\tagent_send_credit_wait_total_ms\t"
                    "agent_send_credit_wait_max_ms\tagent_send_credit_wait_avg_ms\t"
                    "agent_send_outbound_wait_p50_ms\t"
                    "agent_send_outbound_wait_total_ms\tagent_send_outbound_wait_max_ms\t"
                    "agent_send_outbound_wait_avg_ms\tagent_send_frames\t"
                    "remote_event_wait_p50_ms\tremote_event_wait_total_ms\t"
                    "remote_event_wait_max_ms\tremote_event_wait_avg_ms\t"
                    "remote_event_waits\tduration_p50_ms\tduration_p95_ms\t"
                    "flow_throughput_min_mib_s\tflow_throughput_p50_mib_s\t"
                    "flow_throughput_p95_mib_s\t"
                    "avg_flow_throughput_mib_s\tlikely_bottleneck"
                ),
                (
                    "agent\t2\t2\t0\t512\t4096\t2048\t2048\t0.100\t0.200\t0.300\t"
                    "0.400\t0.500\t0.700\t0.100\t0.050\t0.100\t0.100\t"
                    "0.100\t0.200\t"
                    "0.000\t0.000\t0.000\t-\t0\t"
                    "0.000\t0.000\t0.000\t-\t0\t"
                    "0.000\t0.000\t0.000\t-\t0\t"
                    "0.000\t0.000\t0.000\t0.000\t"
                    "0.000\t0.000\t0.000\t0.000\t4\t"
                    "0.000\t0.000\t0.000\t-\t0\t1.000\t2.000\t"
                    "0.95\t1.95\t2.95\t1.95\tbody_drain"
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def write_sample_quic_diagnostics(path: pathlib.Path) -> None:
    path.write_text(
        "\n".join(
            [
                "category\tevents\tfailures\tmax_elapsed_ms\tstages\tremotes\tpaths",
                "quic-native/connect\t1\t1\t77\tconnect_establish\t203.0.113.9:4433\trun.log",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def populate_sample_evidence(directory: pathlib.Path) -> None:
    live_compare = directory / "live-compare"
    fixture = directory / "fixture-1048576-bytes"
    live_compare.mkdir(parents=True)
    fixture.mkdir(parents=True)
    write_sample_live_results(live_compare / "live-results.tsv")
    write_sample_hotpath(live_compare / "hotpath-summary.tsv")
    write_sample_quic_diagnostics(live_compare / "quic-diagnostics.tsv")
    write_sample_live_results(fixture / "live-results.tsv", body_bytes=1048576)
    write_sample_fixture_results(fixture / "fixture-results.tsv", body_bytes=1048576)
    write_sample_hotpath(fixture / "hotpath-summary.tsv")


def assert_rejects(directory: pathlib.Path, expected_message: str) -> None:
    try:
        verify(directory, require_hotpath=True)
    except SystemExit as exc:
        if expected_message not in str(exc):
            raise AssertionError(
                f"expected {expected_message!r} in rejection, got {str(exc)!r}"
            ) from exc
    else:
        raise AssertionError("expected live evidence verification to reject sample")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "evidence"
        populate_sample_evidence(root)
        verify(root, require_hotpath=True)

        missing_fixture = pathlib.Path(tmp) / "missing-fixture"
        shutil.copytree(root, missing_fixture)
        shutil.rmtree(missing_fixture / "fixture-1048576-bytes")
        assert_rejects(missing_fixture, "no controlled fixture evidence")

        missing_hotpath = pathlib.Path(tmp) / "missing-hotpath"
        shutil.copytree(root, missing_hotpath)
        (missing_hotpath / "live-compare" / "hotpath-summary.tsv").unlink()
        assert_rejects(missing_hotpath, "missing required live evidence file")

        invalid_fixture = pathlib.Path(tmp) / "invalid-fixture"
        shutil.copytree(root, invalid_fixture)
        write_sample_fixture_results(
            invalid_fixture / "fixture-1048576-bytes" / "fixture-results.tsv",
            body_bytes=512,
        )
        assert_rejects(invalid_fixture, "produced invalid benchmark rows")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="verify release-candidate live evidence artifacts"
    )
    parser.add_argument("evidence_dir", nargs="?", type=pathlib.Path)
    parser.add_argument("--require-hotpath", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if args.evidence_dir is None:
        raise SystemExit("evidence_dir is required unless --self-test is set")
    verify(args.evidence_dir, require_hotpath=args.require_hotpath)


if __name__ == "__main__":
    main()
