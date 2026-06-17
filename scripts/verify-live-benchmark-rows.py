#!/usr/bin/env python3
"""Verify live benchmark rows and optional release gates."""

from __future__ import annotations

import argparse
import collections
import fnmatch
import pathlib
import sys
import tempfile


EXPECTED_COLUMNS = 24
DIAGNOSTIC_FAILURE_COLUMNS = (
    ("ssh_failed", 15),
    ("agent_reconnect_failed", 18),
    ("backlog_overflow", 19),
    ("remote_backlog_bytes", 20),
    ("bridge_event_queue_remote_bytes", 22),
)
DIAGNOSTIC_NUMERIC_COLUMNS = (
    ("remote_backlog_bytes_max", 21),
    ("bridge_event_queue_remote_bytes_max", 23),
)


def parse_rows(path: pathlib.Path) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("tool\t"):
            continue
        parts = line.split("\t")
        if len(parts) != EXPECTED_COLUMNS:
            raise SystemExit(f"invalid live benchmark row: {line!r}")
        rows.append(parts)
    if not rows:
        raise SystemExit("live benchmark produced no benchmark rows")
    return rows


def successful_rows(rows: list[list[str]]) -> list[list[str]]:
    return [
        parts
        for parts in rows
        if int(parts[4]) > 0 and int(parts[5]) == 0
    ]


def verify_successful_rustle_diagnostics_zero(rows: list[list[str]]) -> None:
    failures: list[str] = []
    for parts in successful_rows(rows):
        tool = parts[0]
        if tool != "rustle" and not tool.startswith("rustle-"):
            continue
        run = parts[1]
        for column_name, column in DIAGNOSTIC_FAILURE_COLUMNS + DIAGNOSTIC_NUMERIC_COLUMNS:
            try:
                value = int(parts[column])
            except ValueError:
                failures.append(f"{tool} run={run} {column_name} is not numeric")
                continue
            if (column_name, column) in DIAGNOSTIC_NUMERIC_COLUMNS:
                continue
            if value != 0:
                failures.append(f"{tool} run={run} {column_name}={value}")

    if failures:
        raise SystemExit(
            "successful Rustle benchmark rows reported diagnostic failures:\n"
            + "\n".join(failures)
        )


def require_agent_and_sshuttle(
    rows: list[list[str]],
    column: int,
    gate_name: str,
) -> tuple[list[float], list[float]]:
    values: dict[str, list[float]] = collections.defaultdict(list)
    for parts in successful_rows(rows):
        values[parts[0]].append(float(parts[column]))

    agent = values.get("rustle-agent")
    sshuttle = values.get("sshuttle")
    if not agent or not sshuttle:
        raise SystemExit(
            f"{gate_name} requires successful rustle-agent and sshuttle rows; "
            'set RUSTLE_BENCH_TOOLS="rustle sshuttle" and include agent in '
            "RUSTLE_BENCH_RUSTLE_TRANSPORTS"
        )
    return agent, sshuttle


def require_quic_native_and_agent(
    rows: list[list[str]],
    column: int,
    gate_name: str,
) -> tuple[list[float], list[float]]:
    values: dict[str, list[float]] = collections.defaultdict(list)
    for parts in successful_rows(rows):
        values[parts[0]].append(float(parts[column]))

    native = values.get("rustle-quic-native")
    agent = values.get("rustle-agent")
    if not native or not agent:
        raise SystemExit(
            f"{gate_name} requires successful rustle-quic-native and "
            "rustle-agent rows; include both entries in "
            "RUSTLE_BENCH_RUSTLE_TRANSPORTS"
        )
    return native, agent


def verify_min_agent_sshuttle_throughput_ratio(
    rows: list[list[str]], min_ratio: float
) -> None:
    agent, sshuttle = require_agent_and_sshuttle(
        rows,
        column=10,
        gate_name="RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO",
    )
    agent_avg = sum(agent) / len(agent)
    sshuttle_avg = sum(sshuttle) / len(sshuttle)
    ratio = agent_avg / sshuttle_avg if sshuttle_avg else float("inf")
    if ratio < min_ratio:
        raise SystemExit(
            "rustle-agent throughput below configured sshuttle ratio "
            f"{min_ratio:.2f}: agent/sshuttle={ratio:.2f} "
            f"agent={agent_avg:.2f}MiB/s sshuttle={sshuttle_avg:.2f}MiB/s"
        )
    print(
        "rustle-agent/sshuttle throughput ratio "
        f"{ratio:.2f} passed threshold {min_ratio:.2f}",
        file=sys.stderr,
    )


def verify_max_agent_sshuttle_p50_ratio(
    rows: list[list[str]], max_ratio: float
) -> None:
    agent, sshuttle = require_agent_and_sshuttle(
        rows,
        column=7,
        gate_name="RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO",
    )
    agent_avg = sum(agent) / len(agent)
    sshuttle_avg = sum(sshuttle) / len(sshuttle)
    ratio = agent_avg / sshuttle_avg if sshuttle_avg else float("inf")
    if ratio > max_ratio:
        raise SystemExit(
            "rustle-agent p50 latency above configured sshuttle ratio "
            f"{max_ratio:.2f}: agent/sshuttle={ratio:.2f} "
            f"agent={agent_avg:.1f}ms sshuttle={sshuttle_avg:.1f}ms"
        )
    print(
        "rustle-agent/sshuttle p50 latency ratio "
        f"{ratio:.2f} passed threshold {max_ratio:.2f}",
        file=sys.stderr,
    )


def verify_min_quic_native_agent_throughput_ratio(
    rows: list[list[str]], min_ratio: float
) -> None:
    native, agent = require_quic_native_and_agent(
        rows,
        column=10,
        gate_name="RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO",
    )
    native_avg = sum(native) / len(native)
    agent_avg = sum(agent) / len(agent)
    ratio = native_avg / agent_avg if agent_avg else float("inf")
    if ratio < min_ratio:
        raise SystemExit(
            "rustle-quic-native throughput below configured rustle-agent ratio "
            f"{min_ratio:.2f}: quic-native/agent={ratio:.2f} "
            f"quic-native={native_avg:.2f}MiB/s agent={agent_avg:.2f}MiB/s"
        )
    print(
        "rustle-quic-native/rustle-agent throughput ratio "
        f"{ratio:.2f} passed threshold {min_ratio:.2f}",
        file=sys.stderr,
    )


def verify_max_quic_native_agent_p50_ratio(
    rows: list[list[str]], max_ratio: float
) -> None:
    native, agent = require_quic_native_and_agent(
        rows,
        column=7,
        gate_name="RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO",
    )
    native_avg = sum(native) / len(native)
    agent_avg = sum(agent) / len(agent)
    ratio = native_avg / agent_avg if agent_avg else float("inf")
    if ratio > max_ratio:
        raise SystemExit(
            "rustle-quic-native p50 latency above configured rustle-agent ratio "
            f"{max_ratio:.2f}: quic-native/agent={ratio:.2f} "
            f"quic-native={native_avg:.1f}ms agent={agent_avg:.1f}ms"
        )
    print(
        "rustle-quic-native/rustle-agent p50 latency ratio "
        f"{ratio:.2f} passed threshold {max_ratio:.2f}",
        file=sys.stderr,
    )


def verify_tool_thresholds(
    rows: list[list[str]],
    pattern: str,
    max_p50_ms: float | None,
    min_throughput_mib_s: float | None,
) -> None:
    failures: list[str] = []
    matched_rows = 0
    for parts in successful_rows(rows):
        tool = parts[0]
        if not fnmatch.fnmatchcase(tool, pattern):
            continue
        matched_rows += 1
        run = parts[1]
        p50 = float(parts[7])
        throughput = float(parts[10])
        if max_p50_ms is not None and p50 > max_p50_ms:
            failures.append(
                f"{tool} run={run} p50={p50:.1f}ms exceeds {max_p50_ms:.1f}ms"
            )
        if min_throughput_mib_s is not None and throughput < min_throughput_mib_s:
            failures.append(
                f"{tool} run={run} throughput={throughput:.2f}MiB/s below "
                f"{min_throughput_mib_s:.2f}MiB/s"
            )

    if matched_rows == 0:
        raise SystemExit(
            "live benchmark regression gates requested, but "
            f"tool pattern {pattern!r} matched no successful rows"
        )
    if failures:
        raise SystemExit(
            f"live benchmark regression gate failed for tool pattern {pattern!r}:\n"
            + "\n".join(failures)
        )

    checks = []
    if max_p50_ms is not None:
        checks.append(f"p50 <= {max_p50_ms:.1f}ms")
    if min_throughput_mib_s is not None:
        checks.append(f"throughput >= {min_throughput_mib_s:.2f}MiB/s")
    print(
        f"live benchmark regression gate passed for tool pattern {pattern!r}: "
        + ", ".join(checks),
        file=sys.stderr,
    )


def verify(
    path: pathlib.Path,
    min_agent_sshuttle_throughput_ratio: float | None = None,
    max_agent_sshuttle_p50_ratio: float | None = None,
    min_quic_native_agent_throughput_ratio: float | None = None,
    max_quic_native_agent_p50_ratio: float | None = None,
    tool_pattern: str | None = None,
    max_p50_ms: float | None = None,
    min_throughput_mib_s: float | None = None,
) -> None:
    rows = parse_rows(path)
    verify_successful_rustle_diagnostics_zero(rows)
    if min_agent_sshuttle_throughput_ratio is not None:
        verify_min_agent_sshuttle_throughput_ratio(
            rows, min_agent_sshuttle_throughput_ratio
        )
    if max_agent_sshuttle_p50_ratio is not None:
        verify_max_agent_sshuttle_p50_ratio(rows, max_agent_sshuttle_p50_ratio)
    if min_quic_native_agent_throughput_ratio is not None:
        verify_min_quic_native_agent_throughput_ratio(
            rows, min_quic_native_agent_throughput_ratio
        )
    if max_quic_native_agent_p50_ratio is not None:
        verify_max_quic_native_agent_p50_ratio(rows, max_quic_native_agent_p50_ratio)
    if max_p50_ms is not None or min_throughput_mib_s is not None:
        if not tool_pattern:
            raise SystemExit(
                "set --tool-pattern when using live benchmark p50 or throughput gates"
            )
        verify_tool_thresholds(rows, tool_pattern, max_p50_ms, min_throughput_mib_s)


def assert_rejects(contents: str, expected_message: str, **kwargs: object) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(contents)
        handle.flush()
        try:
            verify(pathlib.Path(handle.name), **kwargs)
        except SystemExit as exc:
            message = str(exc)
            if expected_message not in message:
                raise AssertionError(
                    f"expected {expected_message!r} in rejection, got {message!r}"
                ) from exc
        else:
            raise AssertionError("expected live benchmark row verification to reject sample")


def self_test() -> None:
    header = (
        "tool\trun\trequests\tconcurrency\tsuccess\tfailed\twall_ms\tp50_ms\t"
        "p95_ms\tbytes\tthroughput_mib_s\treq_s\tavg_cpu_pct\tmax_cpu_pct\t"
        "ssh_opened\tssh_failed\tagent_reconnect_attempts\tagent_reconnect_ok\t"
        "agent_reconnect_failed\tbacklog_overflow\tremote_backlog_bytes\t"
        "remote_backlog_bytes_max\tbridge_event_queue_remote_bytes\t"
        "bridge_event_queue_remote_bytes_max\n"
    )
    good = header + (
        "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t8192\t0\t2048\n"
        "rustle-quic-native\t1\t4\t2\t4\t0\t90\t7.0\t18.0\t4096\t50.00\t"
        "44.44\t1.0\t2.0\t1\t0\t0\t0\t0\t0\t0\t4096\t0\t1024\n"
        "sshuttle\t1\t4\t2\t4\t0\t120\t10.0\t22.0\t4096\t30.00\t"
        "33.33\t1.0\t2.0\t\t\t\t\t\t\t\t\t\t\n"
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(good)
        handle.flush()
        verify(
            pathlib.Path(handle.name),
            min_agent_sshuttle_throughput_ratio=1.0,
            max_agent_sshuttle_p50_ratio=1.0,
            min_quic_native_agent_throughput_ratio=1.0,
            max_quic_native_agent_p50_ratio=1.0,
            tool_pattern="rustle-*",
            max_p50_ms=20.0,
            min_throughput_mib_s=20.0,
        )

    assert_rejects("", "produced no benchmark rows")
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t20.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t8192\t0\t2048\n"
        + "sshuttle\t1\t4\t2\t4\t0\t120\t10.0\t22.0\t4096\t30.00\t"
        "33.33\t1.0\t2.0\t\t\t\t\t\t\t\t\t\t\n",
        "throughput below configured sshuttle ratio",
        min_agent_sshuttle_throughput_ratio=1.0,
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t12.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t8192\t0\t2048\n"
        + "sshuttle\t1\t4\t2\t4\t0\t120\t10.0\t22.0\t4096\t30.00\t"
        "33.33\t1.0\t2.0\t\t\t\t\t\t\t\t\t\t\n",
        "p50 latency above configured sshuttle ratio",
        max_agent_sshuttle_p50_ratio=1.0,
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t8192\t0\t2048\n"
        + "rustle-quic-native\t1\t4\t2\t4\t0\t120\t7.0\t18.0\t4096\t30.00\t"
        "33.33\t1.0\t2.0\t1\t0\t0\t0\t0\t0\t0\t4096\t0\t1024\n",
        "quic-native throughput below configured rustle-agent ratio",
        min_quic_native_agent_throughput_ratio=1.0,
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t8192\t0\t2048\n"
        + "rustle-quic-native\t1\t4\t2\t4\t0\t120\t10.0\t18.0\t4096\t50.00\t"
        "33.33\t1.0\t2.0\t1\t0\t0\t0\t0\t0\t0\t4096\t0\t1024\n",
        "quic-native p50 latency above configured rustle-agent ratio",
        max_quic_native_agent_p50_ratio=1.0,
    )
    assert_rejects(
        header + "rustle-agent\t1\t4\t2\t4\t1\t100\t8.0\t20.0\t4096\t40.00\n",
        "invalid live benchmark row",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t1\t0\t0\t0\t0\t0\t8192\t0\t2048\n",
        "ssh_failed=1",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t1\t0\t1\t0\t0\t8192\t0\t2048\n",
        "agent_reconnect_failed=1",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t1\t0\t8192\t0\t2048\n",
        "backlog_overflow=1",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t1024\t1024\t0\t2048\n",
        "remote_backlog_bytes=1024",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\tnot-a-number\t0\t2048\n",
        "remote_backlog_bytes_max is not numeric",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t4096\t4096\t4096\n",
        "bridge_event_queue_remote_bytes=4096",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t8.0\t20.0\t4096\t40.00\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\t0\t4096\t0\tnot-a-number\n",
        "bridge_event_queue_remote_bytes_max is not numeric",
    )
    assert_rejects(
        good,
        "matched no successful rows",
        tool_pattern="missing-*",
        max_p50_ms=20.0,
    )
    assert_rejects(
        good,
        "p50=8.0ms exceeds 5.0ms",
        tool_pattern="rustle-agent",
        max_p50_ms=5.0,
    )


def positive_float(value: str, name: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"{name} must be greater than 0")
    return parsed


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return

    parser = argparse.ArgumentParser(
        description="verify live benchmark TSV rows and optional gates"
    )
    parser.add_argument("results_tsv", type=pathlib.Path)
    parser.add_argument("--tool-pattern")
    parser.add_argument(
        "--min-agent-sshuttle-throughput-ratio",
        type=lambda value: positive_float(
            value, "--min-agent-sshuttle-throughput-ratio"
        ),
    )
    parser.add_argument(
        "--max-agent-sshuttle-p50-ratio",
        type=lambda value: positive_float(value, "--max-agent-sshuttle-p50-ratio"),
    )
    parser.add_argument(
        "--min-quic-native-agent-throughput-ratio",
        type=lambda value: positive_float(
            value, "--min-quic-native-agent-throughput-ratio"
        ),
    )
    parser.add_argument(
        "--max-quic-native-agent-p50-ratio",
        type=lambda value: positive_float(value, "--max-quic-native-agent-p50-ratio"),
    )
    parser.add_argument(
        "--max-p50-ms",
        type=lambda value: positive_float(value, "--max-p50-ms"),
    )
    parser.add_argument(
        "--min-throughput-mib-s",
        type=lambda value: positive_float(value, "--min-throughput-mib-s"),
    )
    args = parser.parse_args()
    verify(
        args.results_tsv,
        min_agent_sshuttle_throughput_ratio=args.min_agent_sshuttle_throughput_ratio,
        max_agent_sshuttle_p50_ratio=args.max_agent_sshuttle_p50_ratio,
        min_quic_native_agent_throughput_ratio=(
            args.min_quic_native_agent_throughput_ratio
        ),
        max_quic_native_agent_p50_ratio=args.max_quic_native_agent_p50_ratio,
        tool_pattern=args.tool_pattern,
        max_p50_ms=args.max_p50_ms,
        min_throughput_mib_s=args.min_throughput_mib_s,
    )


if __name__ == "__main__":
    main()
