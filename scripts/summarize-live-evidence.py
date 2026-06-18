#!/usr/bin/env python3
"""Summarize live Rustle benchmark evidence into first-look diagnoses."""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
import tempfile


BENCH_COLUMNS = [
    "tool",
    "run",
    "requests",
    "concurrency",
    "success",
    "failed",
    "wall_ms",
    "p50_ms",
    "p95_ms",
    "bytes",
    "throughput_mib_s",
    "req_s",
    "avg_cpu_pct",
    "max_cpu_pct",
    "ssh_opened",
    "ssh_failed",
    "agent_reconnect_attempts",
    "agent_reconnect_ok",
    "agent_reconnect_failed",
    "backlog_overflow",
    "remote_backlog_bytes",
    "remote_backlog_bytes_max",
    "bridge_event_queue_remote_bytes",
    "bridge_event_queue_remote_bytes_max",
]
BENCH_NUMERIC_COLUMNS = {
    "success",
    "failed",
    "p50_ms",
    "throughput_mib_s",
    "ssh_failed",
    "agent_reconnect_failed",
    "backlog_overflow",
    "remote_backlog_bytes",
    "remote_backlog_bytes_max",
    "bridge_event_queue_remote_bytes",
    "bridge_event_queue_remote_bytes_max",
}
OUTPUT_COLUMNS = [
    "path",
    "rows",
    "rustle_success_rows",
    "rustle_failed_rows",
    "agent_p50_ms",
    "sshuttle_p50_ms",
    "agent_sshuttle_p50_ratio",
    "agent_throughput_mib_s",
    "max_remote_backlog_bytes",
    "max_bridge_event_queue_remote_bytes",
    "hotpath_bottleneck",
    "quic_failures",
    "diagnosis",
]
PRESSURE_BYTES = 1024 * 1024


def parse_float(value: str, field: str) -> float:
    if value == "":
        return 0.0
    try:
        parsed = float(value)
    except ValueError as exc:
        raise SystemExit(f"invalid numeric {field} value {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"invalid negative {field} value {value!r}")
    return parsed


def parse_int(value: str, field: str) -> int:
    return int(parse_float(value, field))


def format_float(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def average(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def read_tsv(path: pathlib.Path) -> tuple[list[str], list[dict[str, str]]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if not lines:
        raise SystemExit(f"empty TSV: {path}")
    first = lines[0].split("\t")
    if first and first[0] == "tool":
        header = first
        body = lines[1:]
    else:
        header = BENCH_COLUMNS
        body = lines
    rows: list[dict[str, str]] = []
    for line in body:
        parts = line.split("\t")
        if len(parts) != len(header):
            raise SystemExit(f"invalid TSV row in {path}: {line!r}")
        row = dict(zip(header, parts))
        for field in BENCH_NUMERIC_COLUMNS.intersection(row):
            parse_float(row[field], field)
        rows.append(row)
    return header, rows


def find_evidence_dirs(path: pathlib.Path) -> list[pathlib.Path]:
    if path.is_file():
        return [path.parent]
    if (path / "live-results.tsv").is_file():
        return [path]
    dirs = sorted({child.parent for child in path.rglob("live-results.tsv")})
    if not dirs:
        raise SystemExit(f"no live-results.tsv found under {path}")
    return dirs


def successful_rustle_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row["tool"].startswith("rustle")
        and parse_int(row["success"], "success") > 0
        and parse_int(row["failed"], "failed") == 0
    ]


def failed_rustle_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row["tool"].startswith("rustle") and parse_int(row["failed"], "failed") > 0
    ]


def average_for_tool(rows: list[dict[str, str]], tool: str, field: str) -> float | None:
    values = [
        parse_float(row[field], field)
        for row in rows
        if row["tool"] == tool
        and parse_int(row["success"], "success") > 0
        and parse_int(row["failed"], "failed") == 0
    ]
    return average(values)


def max_int(rows: list[dict[str, str]], field: str) -> int:
    return max((parse_int(row.get(field, "0"), field) for row in rows), default=0)


def read_hotpath_bottleneck(directory: pathlib.Path) -> str:
    path = directory / "hotpath-summary.tsv"
    if not path.is_file():
        return "-"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) < 2:
        return "-"
    header = lines[0].split("\t")
    if "likely_bottleneck" not in header:
        return "-"
    index = header.index("likely_bottleneck")
    counts: collections.Counter[str] = collections.Counter()
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(header):
            raise SystemExit(f"invalid hotpath row in {path}: {line!r}")
        value = parts[index]
        if value and value != "-":
            counts[value] += 1
    if not counts:
        return "-"
    return counts.most_common(1)[0][0]


def read_quic_failures(directory: pathlib.Path) -> int:
    path = directory / "quic-diagnostics.tsv"
    if not path.is_file():
        return 0
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) < 2:
        return 0
    header = lines[0].split("\t")
    if "failures" not in header:
        return 0
    index = header.index("failures")
    failures = 0
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(header):
            raise SystemExit(f"invalid QUIC diagnostic row in {path}: {line!r}")
        failures += parse_int(parts[index], "failures")
    return failures


def diagnose(
    rows: list[dict[str, str]],
    remote_backlog_max: int,
    bridge_event_queue_max: int,
    hotpath_bottleneck: str,
    quic_failures: int,
    agent_p50: float | None,
    sshuttle_p50: float | None,
) -> str:
    if failed_rustle_rows(rows):
        return "rustle_failed_rows"
    for row in successful_rustle_rows(rows):
        for field in (
            "ssh_failed",
            "agent_reconnect_failed",
            "backlog_overflow",
            "remote_backlog_bytes",
            "bridge_event_queue_remote_bytes",
        ):
            if parse_int(row.get(field, "0"), field) != 0:
                return f"diagnostic_failure:{field}"
    if (
        bridge_event_queue_max >= PRESSURE_BYTES
        and bridge_event_queue_max >= remote_backlog_max
    ):
        return "supervisor_event_queue_pressure"
    if remote_backlog_max >= PRESSURE_BYTES:
        return "packet_engine_backlog_pressure"
    if hotpath_bottleneck != "-":
        return f"hotpath:{hotpath_bottleneck}"
    if quic_failures > 0:
        return "quic_startup_or_auth_failure"
    if agent_p50 is not None and sshuttle_p50 is not None and agent_p50 > sshuttle_p50:
        return "agent_latency_lags_sshuttle"
    return "no_local_bottleneck_signal"


def summarize_dir(directory: pathlib.Path, root: pathlib.Path) -> dict[str, str]:
    live_results = directory / "live-results.tsv"
    if not live_results.is_file():
        raise SystemExit(f"missing live results: {live_results}")
    _, rows = read_tsv(live_results)
    rustle_success_rows = successful_rustle_rows(rows)
    rustle_failed_rows = failed_rustle_rows(rows)
    agent_p50 = average_for_tool(rows, "rustle-agent", "p50_ms")
    sshuttle_p50 = average_for_tool(rows, "sshuttle", "p50_ms")
    agent_throughput = average_for_tool(rows, "rustle-agent", "throughput_mib_s")
    ratio = (
        agent_p50 / sshuttle_p50
        if agent_p50 is not None and sshuttle_p50 not in (None, 0)
        else None
    )
    remote_backlog_max = max_int(rustle_success_rows, "remote_backlog_bytes_max")
    bridge_event_queue_max = max_int(
        rustle_success_rows,
        "bridge_event_queue_remote_bytes_max",
    )
    hotpath_bottleneck = read_hotpath_bottleneck(directory)
    quic_failures = read_quic_failures(directory)
    diagnosis = diagnose(
        rows,
        remote_backlog_max,
        bridge_event_queue_max,
        hotpath_bottleneck,
        quic_failures,
        agent_p50,
        sshuttle_p50,
    )
    return {
        "path": str(directory.relative_to(root)) if directory != root else ".",
        "rows": str(len(rows)),
        "rustle_success_rows": str(len(rustle_success_rows)),
        "rustle_failed_rows": str(len(rustle_failed_rows)),
        "agent_p50_ms": format_float(agent_p50),
        "sshuttle_p50_ms": format_float(sshuttle_p50),
        "agent_sshuttle_p50_ratio": format_float(ratio),
        "agent_throughput_mib_s": format_float(agent_throughput),
        "max_remote_backlog_bytes": str(remote_backlog_max),
        "max_bridge_event_queue_remote_bytes": str(bridge_event_queue_max),
        "hotpath_bottleneck": hotpath_bottleneck,
        "quic_failures": str(quic_failures),
        "diagnosis": diagnosis,
    }


def summarize(path: pathlib.Path) -> list[dict[str, str]]:
    root = path if path.is_dir() else path.parent
    return [summarize_dir(directory, root) for directory in find_evidence_dirs(path)]


def print_summary(rows: list[dict[str, str]]) -> None:
    print("\t".join(OUTPUT_COLUMNS))
    for row in rows:
        print("\t".join(row[column] for column in OUTPUT_COLUMNS))


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        live_compare = root / "live-compare"
        live_compare.mkdir()
        (live_compare / "live-results.tsv").write_text(
            "\n".join(
                [
                    "rustle-agent\t1\t4\t2\t4\t0\t100\t12.0\t20.0\t4096\t25.00\t40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t2097152\t0\t2048",
                    "sshuttle\t1\t4\t2\t4\t0\t120\t10.0\t22.0\t4096\t20.00\t33.33\t1.0\t2.0\t\t\t\t\t\t\t\t\t\t",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (live_compare / "hotpath-summary.tsv").write_text(
            "transport\tflows\tfailed_flows\tlikely_bottleneck\n"
            "agent\t4\t0\tbody_drain\n",
            encoding="utf-8",
        )
        (live_compare / "quic-diagnostics.tsv").write_text(
            "category\tevents\tfailures\tmax_elapsed_ms\tstages\tremotes\tpaths\n"
            "quic-native/client-auth\t1\t0\t10\tread_ack\t203.0.113.10:4433\tlog\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert len(rows) == 1
        row = rows[0]
        assert row["path"] == "live-compare"
        assert row["rustle_success_rows"] == "1"
        assert row["agent_sshuttle_p50_ratio"] == "1.20"
        assert row["max_remote_backlog_bytes"] == "2097152"
        assert row["diagnosis"] == "packet_engine_backlog_pressure"

        (live_compare / "live-results.tsv").write_text(
            "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t25.00\t40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t0\t0\t2097152\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert rows[0]["diagnosis"] == "supervisor_event_queue_pressure"

        (live_compare / "live-results.tsv").write_text(
            "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t25.00\t40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t1024\t0\t2048\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert rows[0]["diagnosis"] == "hotpath:body_drain"


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return

    parser = argparse.ArgumentParser(
        description="summarize live benchmark evidence into first-look diagnoses"
    )
    parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()
    print_summary(summarize(args.path))


if __name__ == "__main__":
    main()
