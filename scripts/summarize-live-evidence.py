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
    "max_agent_writer_queued_bytes",
    "agent_writer_enqueue_wait_max_us",
    "agent_writer_write_max_us",
    "agent_writer_flush_max_us",
    "hotpath_bottleneck",
    "hotpath_pressure",
    "quic_failures",
    "diagnosis",
]
PRESSURE_BYTES = 1024 * 1024
WRITER_PRESSURE_US = 50_000
HOTPATH_PRESSURE_MS = 50.0
HOTPATH_PRESSURE_FIELDS = (
    ("agent_remote_output_credit_wait_max_ms", "agent_remote_output_credit_pressure"),
    ("agent_remote_output_send_wait_max_ms", "agent_remote_output_send_pressure"),
    ("remote_event_wait_max_ms", "supervisor_remote_event_pressure"),
    ("agent_send_credit_wait_max_ms", "agent_send_credit_pressure"),
    ("agent_send_outbound_wait_max_ms", "agent_send_outbound_pressure"),
    ("pre_bridge_queue_wait_max_ms", "pre_bridge_queue_pressure"),
    ("tcp_recv_queue_wait_max_ms", "tcp_recv_queue_pressure"),
    ("local_queue_wait_max_ms", "local_queue_pressure"),
)


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


def parse_optional_float(value: str, field: str) -> float | None:
    if value in ("", "-"):
        return None
    return parse_float(value, field)


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


def read_hotpath_pressure(directory: pathlib.Path) -> str:
    path = directory / "hotpath-summary.tsv"
    if not path.is_file():
        return "-"
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) < 2:
        return "-"
    header = lines[0].split("\t")
    indexes = {
        field: header.index(field)
        for field, _ in HOTPATH_PRESSURE_FIELDS
        if field in header
    }
    if not indexes:
        return "-"
    strongest: tuple[float, str] | None = None
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(header):
            raise SystemExit(f"invalid hotpath row in {path}: {line!r}")
        for field, label in HOTPATH_PRESSURE_FIELDS:
            if field not in indexes:
                continue
            value = parse_optional_float(parts[indexes[field]], field)
            if value is None or value < HOTPATH_PRESSURE_MS:
                continue
            candidate = (value, label)
            if strongest is None or candidate[0] > strongest[0]:
                strongest = candidate
    return "-" if strongest is None else strongest[1]


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


def read_agent_writer_pressure(directory: pathlib.Path) -> dict[str, int]:
    pressure = {
        "max_agent_writer_queued_bytes": 0,
        "agent_writer_enqueue_wait_max_us": 0,
        "agent_writer_write_max_us": 0,
        "agent_writer_flush_max_us": 0,
    }
    path = directory / "agent-writer-summary.tsv"
    if not path.is_file():
        return pressure
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(lines) < 2:
        return pressure
    header = lines[0].split("\t")
    required = {
        "queued_bytes_max",
        "enqueue_wait_max_us",
        "write_max_us",
        "flush_max_us",
    }
    missing = sorted(required.difference(header))
    if missing:
        raise SystemExit(f"agent writer summary {path} missing columns {missing!r}")
    indexes = {field: header.index(field) for field in required}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(header):
            raise SystemExit(f"invalid agent writer row in {path}: {line!r}")
        pressure["max_agent_writer_queued_bytes"] = max(
            pressure["max_agent_writer_queued_bytes"],
            parse_int(parts[indexes["queued_bytes_max"]], "queued_bytes_max"),
        )
        pressure["agent_writer_enqueue_wait_max_us"] = max(
            pressure["agent_writer_enqueue_wait_max_us"],
            parse_int(parts[indexes["enqueue_wait_max_us"]], "enqueue_wait_max_us"),
        )
        pressure["agent_writer_write_max_us"] = max(
            pressure["agent_writer_write_max_us"],
            parse_int(parts[indexes["write_max_us"]], "write_max_us"),
        )
        pressure["agent_writer_flush_max_us"] = max(
            pressure["agent_writer_flush_max_us"],
            parse_int(parts[indexes["flush_max_us"]], "flush_max_us"),
        )
    return pressure


def diagnose(
    rows: list[dict[str, str]],
    remote_backlog_max: int,
    bridge_event_queue_max: int,
    agent_writer_pressure: dict[str, int],
    hotpath_bottleneck: str,
    hotpath_pressure: str,
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
    if agent_writer_pressure["max_agent_writer_queued_bytes"] >= PRESSURE_BYTES:
        return "agent_writer_queue_pressure"
    if agent_writer_pressure["agent_writer_enqueue_wait_max_us"] >= WRITER_PRESSURE_US:
        return "agent_writer_queue_pressure"
    if agent_writer_pressure["agent_writer_write_max_us"] >= WRITER_PRESSURE_US:
        return "agent_writer_write_pressure"
    if agent_writer_pressure["agent_writer_flush_max_us"] >= WRITER_PRESSURE_US:
        return "agent_writer_flush_pressure"
    if hotpath_pressure != "-":
        return f"hotpath:{hotpath_pressure}"
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
    hotpath_pressure = read_hotpath_pressure(directory)
    quic_failures = read_quic_failures(directory)
    agent_writer_pressure = read_agent_writer_pressure(directory)
    diagnosis = diagnose(
        rows,
        remote_backlog_max,
        bridge_event_queue_max,
        agent_writer_pressure,
        hotpath_bottleneck,
        hotpath_pressure,
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
        "max_agent_writer_queued_bytes": str(
            agent_writer_pressure["max_agent_writer_queued_bytes"]
        ),
        "agent_writer_enqueue_wait_max_us": str(
            agent_writer_pressure["agent_writer_enqueue_wait_max_us"]
        ),
        "agent_writer_write_max_us": str(
            agent_writer_pressure["agent_writer_write_max_us"]
        ),
        "agent_writer_flush_max_us": str(
            agent_writer_pressure["agent_writer_flush_max_us"]
        ),
        "hotpath_bottleneck": hotpath_bottleneck,
        "hotpath_pressure": hotpath_pressure,
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
            "transport\tflows\tfailed_flows\tlikely_bottleneck\t"
            "agent_remote_output_credit_wait_max_ms\t"
            "agent_remote_output_send_wait_max_ms\tremote_event_wait_max_ms\t"
            "agent_send_credit_wait_max_ms\tagent_send_outbound_wait_max_ms\t"
            "pre_bridge_queue_wait_max_ms\ttcp_recv_queue_wait_max_ms\t"
            "local_queue_wait_max_ms\n"
            "agent\t4\t0\tbody_drain\t0.000\t0.000\t0.000\t0.000\t0.000\t"
            "0.000\t0.000\t0.000\n",
            encoding="utf-8",
        )
        (live_compare / "quic-diagnostics.tsv").write_text(
            "category\tevents\tfailures\tmax_elapsed_ms\tstages\tremotes\tpaths\n"
            "quic-native/client-auth\t1\t0\t10\tread_ack\t203.0.113.10:4433\tlog\n",
            encoding="utf-8",
        )
        (live_compare / "agent-writer-summary.tsv").write_text(
            "tool\tstatus_lines\tqueued_frames_max\tqueued_bytes_max\tbursts\t"
            "burst_frames\tburst_bytes\tburst_frames_max\tburst_bytes_max\t"
            "enqueue_wait_samples\tenqueue_wait_total_us\tenqueue_wait_max_us\t"
            "write_total_us\twrite_max_us\tflush_total_us\tflush_max_us\tpaths\n"
            "rustle-agent\t1\t2\t2097152\t8\t16\t4096\t4\t2048\t16\t"
            "120000\t90000\t40000\t30000\t20000\t10000\tlog\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert len(rows) == 1
        row = rows[0]
        assert row["path"] == "live-compare"
        assert row["rustle_success_rows"] == "1"
        assert row["agent_sshuttle_p50_ratio"] == "1.20"
        assert row["max_remote_backlog_bytes"] == "2097152"
        assert row["max_agent_writer_queued_bytes"] == "2097152"
        assert row["agent_writer_enqueue_wait_max_us"] == "90000"
        assert row["hotpath_pressure"] == "-"
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
        assert rows[0]["diagnosis"] == "agent_writer_queue_pressure"

        (live_compare / "agent-writer-summary.tsv").write_text(
            "tool\tstatus_lines\tqueued_frames_max\tqueued_bytes_max\tbursts\t"
            "burst_frames\tburst_bytes\tburst_frames_max\tburst_bytes_max\t"
            "enqueue_wait_samples\tenqueue_wait_total_us\tenqueue_wait_max_us\t"
            "write_total_us\twrite_max_us\tflush_total_us\tflush_max_us\tpaths\n"
            "rustle-agent\t1\t1\t1024\t8\t16\t4096\t4\t2048\t16\t"
            "1200\t900\t400\t300\t200\t100\tlog\n",
            encoding="utf-8",
        )
        (live_compare / "hotpath-summary.tsv").write_text(
            "transport\tflows\tfailed_flows\tlikely_bottleneck\t"
            "agent_remote_output_credit_wait_max_ms\t"
            "agent_remote_output_send_wait_max_ms\tremote_event_wait_max_ms\t"
            "agent_send_credit_wait_max_ms\tagent_send_outbound_wait_max_ms\t"
            "pre_bridge_queue_wait_max_ms\ttcp_recv_queue_wait_max_ms\t"
            "local_queue_wait_max_ms\n"
            "agent\t4\t0\tbody_drain\t75.000\t0.000\t0.000\t0.000\t0.000\t"
            "0.000\t0.000\t0.000\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert rows[0]["hotpath_pressure"] == "agent_remote_output_credit_pressure"
        assert rows[0]["diagnosis"] == "hotpath:agent_remote_output_credit_pressure"

        (live_compare / "hotpath-summary.tsv").write_text(
            "transport\tflows\tfailed_flows\tlikely_bottleneck\t"
            "agent_remote_output_credit_wait_max_ms\t"
            "agent_remote_output_send_wait_max_ms\tremote_event_wait_max_ms\t"
            "agent_send_credit_wait_max_ms\tagent_send_outbound_wait_max_ms\t"
            "pre_bridge_queue_wait_max_ms\ttcp_recv_queue_wait_max_ms\t"
            "local_queue_wait_max_ms\n"
            "agent\t4\t0\tbody_drain\t0.000\t0.000\t0.000\t0.000\t0.000\t"
            "0.000\t0.000\t0.000\n",
            encoding="utf-8",
        )
        rows = summarize(root)
        assert rows[0]["hotpath_pressure"] == "-"
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
