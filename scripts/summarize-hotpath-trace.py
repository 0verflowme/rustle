#!/usr/bin/env python3
"""Summarize opt-in Rustle TCP hotpath trace lines."""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
import tempfile


TRACE_PREFIX = "rustle_hotpath_tcp"
TIMING_FIELDS = (
    "stream_ready_us",
    "opened_us",
    "first_local_us",
    "first_local_sent_us",
    "first_remote_us",
    "duration_us",
)
OPTIONAL_COUNTER_FIELDS = (
    "ready_wait_us",
    "local_send_wait_us",
    "local_send_wait_max_us",
    "local_send_waits",
    "tcp_recv_queue_wait_us",
    "tcp_recv_queue_wait_max_us",
    "tcp_recv_queue_waits",
    "local_queue_wait_us",
    "local_queue_wait_max_us",
    "local_queue_waits",
    "agent_send_credit_wait_us",
    "agent_send_credit_wait_max_us",
    "agent_send_outbound_wait_us",
    "agent_send_outbound_wait_max_us",
    "agent_send_frames",
    "remote_event_wait_us",
    "remote_event_wait_max_us",
    "remote_event_waits",
)
DERIVED_LATENCIES = (
    ("remote_open_wait_us", "stream_ready_us", "opened_us"),
    ("payload_queue_wait_us", "first_local_us", "first_local_sent_us"),
    ("first_byte_wait_us", "first_local_sent_us", "first_remote_us"),
    ("body_drain_us", "first_remote_us", "duration_us"),
)
SUCCESS_OUTCOMES = {
    "closed",
    "local_eof",
    "remote_eof",
    "remote_close",
    "remote_stream_closed",
}


def percentile(values: list[int], percentile_value: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = int((len(ordered) * percentile_value + 99) // 100)
    index = min(max(rank, 1), len(ordered)) - 1
    return ordered[index]


def percentile_float(values: list[float], percentile_value: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = int((len(ordered) * percentile_value + 99) // 100)
    index = min(max(rank, 1), len(ordered)) - 1
    return ordered[index]


def format_ms(value_us: int | None) -> str:
    if value_us is None:
        return "-"
    return f"{value_us / 1000:.3f}"


def format_float(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def format_average_ms(total_us: int, count: int) -> str:
    if count <= 0:
        return "-"
    return f"{(total_us / count) / 1000:.3f}"


def parse_optional_us(value: str) -> int | None:
    if value == "-":
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"invalid trace duration value {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"invalid negative trace duration value {value!r}")
    return parsed


def parse_counter(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"invalid hotpath {field} value {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"invalid negative hotpath {field} value {value!r}")
    return parsed


def optional_counter(row: dict[str, str], field: str) -> int | None:
    if field not in row:
        return None
    return parse_counter(row[field], field)


def nonnegative_delta(row: dict[str, str], start_field: str, end_field: str) -> int | None:
    start = parse_optional_us(row[start_field])
    end = parse_optional_us(row[end_field])
    if start is None or end is None or end < start:
        return None
    return end - start


def flow_throughput_mib_s(row: dict[str, str]) -> float | None:
    duration_us = parse_optional_us(row["duration_us"])
    if duration_us is None or duration_us <= 0:
        return None
    return (parse_counter(row["remote_bytes"], "remote_bytes") / (1024 * 1024)) / (
        duration_us / 1_000_000
    )


def parse_trace_line(line: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("\t")
    if not parts or parts[0] != TRACE_PREFIX:
        return None
    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise SystemExit(f"invalid hotpath trace field {item!r}")
        key, value = item.split("=", 1)
        fields[key] = value
    required = {"transport", "flow", "generation", "local_bytes", "remote_bytes", "outcome"}
    missing = sorted(required.difference(fields))
    if missing:
        raise SystemExit(f"hotpath trace line missing required fields {missing!r}: {line!r}")
    for field in TIMING_FIELDS:
        if field not in fields:
            raise SystemExit(f"hotpath trace line missing {field}: {line!r}")
        parse_optional_us(fields[field])
    for field in OPTIONAL_COUNTER_FIELDS:
        if field in fields:
            parse_counter(fields[field], field)
    for field in ("local_bytes", "remote_bytes"):
        parse_counter(fields[field], "byte count")
    return fields


def read_path(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return pathlib.Path(path).read_text(encoding="utf-8")


def read_paths(paths: list[str]) -> str:
    if not paths:
        return sys.stdin.read()
    return "\n".join(read_path(path) for path in paths)


def summarize(text: str) -> list[dict[str, object]]:
    by_transport: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for line in text.splitlines():
        fields = parse_trace_line(line)
        if fields is not None:
            by_transport[fields["transport"]].append(fields)
    if not by_transport:
        raise SystemExit("no rustle_hotpath_tcp trace lines found")

    summaries: list[dict[str, object]] = []
    for transport, rows in sorted(by_transport.items()):
        outcomes = collections.Counter(row["outcome"] for row in rows)
        timing_values = {
            field: [
                value
                for row in rows
                if (value := parse_optional_us(row[field])) is not None
            ]
            for field in TIMING_FIELDS
        }
        derived_values = {
            name: [
                value
                for row in rows
                if (value := nonnegative_delta(row, start, end)) is not None
            ]
            for name, start, end in DERIVED_LATENCIES
        }
        derived_p50 = {
            name: percentile(values, 50) for name, values in derived_values.items()
        }
        ready_wait_values = [
            parse_counter(row["ready_wait_us"], "ready_wait_us")
            for row in rows
            if "ready_wait_us" in row
        ]
        local_send_wait_values = [
            parse_counter(row["local_send_wait_us"], "local_send_wait_us")
            for row in rows
            if "local_send_wait_us" in row
        ]
        local_send_wait_max_values = [
            parse_counter(row["local_send_wait_max_us"], "local_send_wait_max_us")
            for row in rows
            if "local_send_wait_max_us" in row
        ]
        local_queue_wait_values = [
            parse_counter(row["local_queue_wait_us"], "local_queue_wait_us")
            for row in rows
            if "local_queue_wait_us" in row
        ]
        tcp_recv_queue_wait_values = [
            parse_counter(row["tcp_recv_queue_wait_us"], "tcp_recv_queue_wait_us")
            for row in rows
            if "tcp_recv_queue_wait_us" in row
        ]
        tcp_recv_queue_wait_max_values = [
            parse_counter(row["tcp_recv_queue_wait_max_us"], "tcp_recv_queue_wait_max_us")
            for row in rows
            if "tcp_recv_queue_wait_max_us" in row
        ]
        local_queue_wait_max_values = [
            parse_counter(row["local_queue_wait_max_us"], "local_queue_wait_max_us")
            for row in rows
            if "local_queue_wait_max_us" in row
        ]
        pre_bridge_queue_wait_values = []
        pre_bridge_queue_wait_max_values = []
        pre_bridge_queue_waits = 0
        for row in rows:
            tcp_wait = optional_counter(row, "tcp_recv_queue_wait_us")
            local_wait = optional_counter(row, "local_queue_wait_us")
            if tcp_wait is not None or local_wait is not None:
                pre_bridge_queue_wait_values.append((tcp_wait or 0) + (local_wait or 0))

            tcp_wait_max = optional_counter(row, "tcp_recv_queue_wait_max_us")
            local_wait_max = optional_counter(row, "local_queue_wait_max_us")
            if tcp_wait_max is not None or local_wait_max is not None:
                pre_bridge_queue_wait_max_values.append(
                    (tcp_wait_max or 0) + (local_wait_max or 0)
                )

            wait_counts = [
                value
                for field in ("tcp_recv_queue_waits", "local_queue_waits")
                if (value := optional_counter(row, field)) is not None
            ]
            pre_bridge_queue_waits += max(wait_counts, default=0)
        agent_send_credit_wait_values = [
            parse_counter(row["agent_send_credit_wait_us"], "agent_send_credit_wait_us")
            for row in rows
            if "agent_send_credit_wait_us" in row
        ]
        agent_send_credit_wait_max_values = [
            parse_counter(
                row["agent_send_credit_wait_max_us"], "agent_send_credit_wait_max_us"
            )
            for row in rows
            if "agent_send_credit_wait_max_us" in row
        ]
        agent_send_outbound_wait_values = [
            parse_counter(row["agent_send_outbound_wait_us"], "agent_send_outbound_wait_us")
            for row in rows
            if "agent_send_outbound_wait_us" in row
        ]
        agent_send_outbound_wait_max_values = [
            parse_counter(
                row["agent_send_outbound_wait_max_us"], "agent_send_outbound_wait_max_us"
            )
            for row in rows
            if "agent_send_outbound_wait_max_us" in row
        ]
        remote_event_wait_values = [
            parse_counter(row["remote_event_wait_us"], "remote_event_wait_us")
            for row in rows
            if "remote_event_wait_us" in row
        ]
        remote_event_wait_max_values = [
            parse_counter(row["remote_event_wait_max_us"], "remote_event_wait_max_us")
            for row in rows
            if "remote_event_wait_max_us" in row
        ]
        wait_p50 = {
            "ready_wait_us": percentile(ready_wait_values, 50),
            "local_send_wait_us": percentile(local_send_wait_values, 50),
            "tcp_recv_queue_wait_us": percentile(tcp_recv_queue_wait_values, 50),
            "local_queue_wait_us": percentile(local_queue_wait_values, 50),
            "pre_bridge_queue_wait_us": percentile(pre_bridge_queue_wait_values, 50),
            "agent_send_credit_wait_us": percentile(agent_send_credit_wait_values, 50),
            "agent_send_outbound_wait_us": percentile(agent_send_outbound_wait_values, 50),
            "remote_event_wait_us": percentile(remote_event_wait_values, 50),
        }
        likely_bottleneck = max(
            (
                (value, name.removesuffix("_us"))
                for name, value in (derived_p50 | wait_p50).items()
                if value is not None
            ),
            default=(None, "-"),
        )[1]
        remote_bytes = sum(int(row["remote_bytes"]) for row in rows)
        local_bytes = sum(int(row["local_bytes"]) for row in rows)
        remote_byte_values = [parse_counter(row["remote_bytes"], "remote_bytes") for row in rows]
        flow_throughput_values = [
            value for row in rows if (value := flow_throughput_mib_s(row)) is not None
        ]
        ready_wait_total = sum(ready_wait_values)
        local_send_waits = sum(
            parse_counter(row["local_send_waits"], "local_send_waits")
            for row in rows
            if "local_send_waits" in row
        )
        local_send_wait_total = sum(local_send_wait_values)
        tcp_recv_queue_waits = sum(
            parse_counter(row["tcp_recv_queue_waits"], "tcp_recv_queue_waits")
            for row in rows
            if "tcp_recv_queue_waits" in row
        )
        tcp_recv_queue_wait_total = sum(tcp_recv_queue_wait_values)
        local_queue_waits = sum(
            parse_counter(row["local_queue_waits"], "local_queue_waits")
            for row in rows
            if "local_queue_waits" in row
        )
        local_queue_wait_total = sum(local_queue_wait_values)
        pre_bridge_queue_wait_total = sum(pre_bridge_queue_wait_values)
        agent_send_credit_wait_total = sum(agent_send_credit_wait_values)
        agent_send_outbound_wait_total = sum(agent_send_outbound_wait_values)
        agent_send_frames = sum(
            parse_counter(row["agent_send_frames"], "agent_send_frames")
            for row in rows
            if "agent_send_frames" in row
        )
        remote_event_waits = sum(
            parse_counter(row["remote_event_waits"], "remote_event_waits")
            for row in rows
            if "remote_event_waits" in row
        )
        remote_event_wait_total = sum(remote_event_wait_values)
        duration_values = timing_values["duration_us"]
        total_duration_us = sum(duration_values)
        avg_flow_throughput = (
            (remote_bytes / (1024 * 1024)) / (total_duration_us / 1_000_000)
            if total_duration_us > 0
            else 0.0
        )
        summaries.append(
            {
                "transport": transport,
                "flows": len(rows),
                "ok_flows": sum(outcomes[outcome] for outcome in SUCCESS_OUTCOMES),
                "failed_flows": len(rows)
                - sum(outcomes[outcome] for outcome in SUCCESS_OUTCOMES),
                "local_bytes": local_bytes,
                "remote_bytes": remote_bytes,
                "remote_bytes_min": min(remote_byte_values, default=0),
                "remote_bytes_p50": percentile(remote_byte_values, 50) or 0,
                "stream_ready_p50_ms": format_ms(percentile(timing_values["stream_ready_us"], 50)),
                "opened_p50_ms": format_ms(percentile(timing_values["opened_us"], 50)),
                "first_local_p50_ms": format_ms(percentile(timing_values["first_local_us"], 50)),
                "first_local_sent_p50_ms": format_ms(
                    percentile(timing_values["first_local_sent_us"], 50)
                ),
                "first_remote_p50_ms": format_ms(percentile(timing_values["first_remote_us"], 50)),
                "first_remote_p95_ms": format_ms(percentile(timing_values["first_remote_us"], 95)),
                "remote_open_wait_p50_ms": format_ms(derived_p50["remote_open_wait_us"]),
                "ready_wait_p50_ms": format_ms(wait_p50["ready_wait_us"]),
                "ready_wait_total_ms": format_ms(ready_wait_total),
                "payload_queue_wait_p50_ms": format_ms(derived_p50["payload_queue_wait_us"]),
                "first_byte_wait_p50_ms": format_ms(derived_p50["first_byte_wait_us"]),
                "body_drain_p50_ms": format_ms(derived_p50["body_drain_us"]),
                "local_send_wait_p50_ms": format_ms(wait_p50["local_send_wait_us"]),
                "local_send_wait_total_ms": format_ms(local_send_wait_total),
                "local_send_wait_max_ms": format_ms(
                    max(local_send_wait_max_values, default=None)
                ),
                "local_send_wait_avg_ms": format_average_ms(
                    local_send_wait_total, local_send_waits
                ),
                "local_send_waits": local_send_waits,
                "tcp_recv_queue_wait_p50_ms": format_ms(wait_p50["tcp_recv_queue_wait_us"]),
                "tcp_recv_queue_wait_total_ms": format_ms(tcp_recv_queue_wait_total),
                "tcp_recv_queue_wait_max_ms": format_ms(
                    max(tcp_recv_queue_wait_max_values, default=None)
                ),
                "tcp_recv_queue_wait_avg_ms": format_average_ms(
                    tcp_recv_queue_wait_total, tcp_recv_queue_waits
                ),
                "tcp_recv_queue_waits": tcp_recv_queue_waits,
                "local_queue_wait_p50_ms": format_ms(wait_p50["local_queue_wait_us"]),
                "local_queue_wait_total_ms": format_ms(local_queue_wait_total),
                "local_queue_wait_max_ms": format_ms(
                    max(local_queue_wait_max_values, default=None)
                ),
                "local_queue_wait_avg_ms": format_average_ms(
                    local_queue_wait_total, local_queue_waits
                ),
                "local_queue_waits": local_queue_waits,
                "pre_bridge_queue_wait_p50_ms": format_ms(
                    wait_p50["pre_bridge_queue_wait_us"]
                ),
                "pre_bridge_queue_wait_total_ms": format_ms(pre_bridge_queue_wait_total),
                "pre_bridge_queue_wait_max_ms": format_ms(
                    max(pre_bridge_queue_wait_max_values, default=None)
                ),
                "pre_bridge_queue_wait_avg_ms": format_average_ms(
                    pre_bridge_queue_wait_total, pre_bridge_queue_waits
                ),
                "pre_bridge_queue_waits": pre_bridge_queue_waits,
                "agent_send_credit_wait_p50_ms": format_ms(
                    wait_p50["agent_send_credit_wait_us"]
                ),
                "agent_send_credit_wait_total_ms": format_ms(agent_send_credit_wait_total),
                "agent_send_credit_wait_max_ms": format_ms(
                    max(agent_send_credit_wait_max_values, default=None)
                ),
                "agent_send_credit_wait_avg_ms": format_average_ms(
                    agent_send_credit_wait_total, agent_send_frames
                ),
                "agent_send_outbound_wait_p50_ms": format_ms(
                    wait_p50["agent_send_outbound_wait_us"]
                ),
                "agent_send_outbound_wait_total_ms": format_ms(agent_send_outbound_wait_total),
                "agent_send_outbound_wait_max_ms": format_ms(
                    max(agent_send_outbound_wait_max_values, default=None)
                ),
                "agent_send_outbound_wait_avg_ms": format_average_ms(
                    agent_send_outbound_wait_total, agent_send_frames
                ),
                "agent_send_frames": agent_send_frames,
                "remote_event_wait_p50_ms": format_ms(wait_p50["remote_event_wait_us"]),
                "remote_event_wait_total_ms": format_ms(remote_event_wait_total),
                "remote_event_wait_max_ms": format_ms(
                    max(remote_event_wait_max_values, default=None)
                ),
                "remote_event_wait_avg_ms": format_average_ms(
                    remote_event_wait_total, remote_event_waits
                ),
                "remote_event_waits": remote_event_waits,
                "duration_p50_ms": format_ms(percentile(duration_values, 50)),
                "duration_p95_ms": format_ms(percentile(duration_values, 95)),
                "flow_throughput_min_mib_s": format_float(
                    min(flow_throughput_values) if flow_throughput_values else None
                ),
                "flow_throughput_p50_mib_s": format_float(
                    percentile_float(flow_throughput_values, 50)
                ),
                "flow_throughput_p95_mib_s": format_float(
                    percentile_float(flow_throughput_values, 95)
                ),
                "avg_flow_throughput_mib_s": f"{avg_flow_throughput:.2f}",
                "likely_bottleneck": likely_bottleneck,
                "outcomes": ",".join(
                    f"{outcome}:{count}" for outcome, count in sorted(outcomes.items())
                ),
            }
        )
    return summaries


def print_summary(summaries: list[dict[str, object]]) -> None:
    columns = (
        "transport",
        "flows",
        "ok_flows",
        "failed_flows",
        "local_bytes",
        "remote_bytes",
        "remote_bytes_min",
        "remote_bytes_p50",
        "stream_ready_p50_ms",
        "opened_p50_ms",
        "first_local_p50_ms",
        "first_local_sent_p50_ms",
        "first_remote_p50_ms",
        "first_remote_p95_ms",
        "remote_open_wait_p50_ms",
        "ready_wait_p50_ms",
        "ready_wait_total_ms",
        "payload_queue_wait_p50_ms",
        "first_byte_wait_p50_ms",
        "body_drain_p50_ms",
        "local_send_wait_p50_ms",
        "local_send_wait_total_ms",
        "local_send_wait_max_ms",
        "local_send_wait_avg_ms",
        "local_send_waits",
        "tcp_recv_queue_wait_p50_ms",
        "tcp_recv_queue_wait_total_ms",
        "tcp_recv_queue_wait_max_ms",
        "tcp_recv_queue_wait_avg_ms",
        "tcp_recv_queue_waits",
        "local_queue_wait_p50_ms",
        "local_queue_wait_total_ms",
        "local_queue_wait_max_ms",
        "local_queue_wait_avg_ms",
        "local_queue_waits",
        "pre_bridge_queue_wait_p50_ms",
        "pre_bridge_queue_wait_total_ms",
        "pre_bridge_queue_wait_max_ms",
        "pre_bridge_queue_wait_avg_ms",
        "pre_bridge_queue_waits",
        "agent_send_credit_wait_p50_ms",
        "agent_send_credit_wait_total_ms",
        "agent_send_credit_wait_max_ms",
        "agent_send_credit_wait_avg_ms",
        "agent_send_outbound_wait_p50_ms",
        "agent_send_outbound_wait_total_ms",
        "agent_send_outbound_wait_max_ms",
        "agent_send_outbound_wait_avg_ms",
        "agent_send_frames",
        "remote_event_wait_p50_ms",
        "remote_event_wait_total_ms",
        "remote_event_wait_max_ms",
        "remote_event_wait_avg_ms",
        "remote_event_waits",
        "duration_p50_ms",
        "duration_p95_ms",
        "flow_throughput_min_mib_s",
        "flow_throughput_p50_mib_s",
        "flow_throughput_p95_mib_s",
        "avg_flow_throughput_mib_s",
        "likely_bottleneck",
        "outcomes",
    )
    print("\t".join(columns))
    for summary in summaries:
        print("\t".join(str(summary[column]) for column in columns))


def assert_rejects(contents: str, expected_message: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(contents)
        handle.flush()
        try:
            summarize(pathlib.Path(handle.name).read_text(encoding="utf-8"))
        except SystemExit as exc:
            if expected_message not in str(exc):
                raise AssertionError(
                    f"expected {expected_message!r} in rejection, got {exc!s}"
                ) from exc
        else:
            raise AssertionError("expected hotpath summary to reject sample")


def self_test() -> None:
    sample = "\n".join(
        [
            "unrelated log line",
            "rustle_hotpath_tcp\ttransport=agent\tflow=10.0.0.1:49152->198.18.77.77:80\tgeneration=1\tready_wait_us=2000\tstream_ready_us=1000\topened_us=2000\tfirst_local_us=3000\tfirst_local_sent_us=4000\tfirst_remote_us=10000\tduration_us=20000\tlocal_bytes=64\tremote_bytes=1024\tlocal_send_wait_us=7000\tlocal_send_wait_max_us=5000\tlocal_send_waits=2\ttcp_recv_queue_wait_us=4000\ttcp_recv_queue_wait_max_us=3000\ttcp_recv_queue_waits=2\tlocal_queue_wait_us=3000\tlocal_queue_wait_max_us=2000\tlocal_queue_waits=2\tagent_send_credit_wait_us=6000\tagent_send_credit_wait_max_us=4000\tagent_send_outbound_wait_us=1000\tagent_send_outbound_wait_max_us=1000\tagent_send_frames=2\tremote_event_wait_us=5000\tremote_event_wait_max_us=5000\tremote_event_waits=1\toutcome=remote_eof",
            "rustle_hotpath_tcp\ttransport=agent\tflow=10.0.0.2:49153->198.18.77.77:80\tgeneration=1\tready_wait_us=5000\tstream_ready_us=1200\topened_us=2200\tfirst_local_us=3200\tfirst_local_sent_us=4200\tfirst_remote_us=30000\tduration_us=50000\tlocal_bytes=64\tremote_bytes=2048\tlocal_send_wait_us=11000\tlocal_send_wait_max_us=8000\tlocal_send_waits=3\ttcp_recv_queue_wait_us=12000\ttcp_recv_queue_wait_max_us=10000\ttcp_recv_queue_waits=3\tlocal_queue_wait_us=5000\tlocal_queue_wait_max_us=4000\tlocal_queue_waits=3\tagent_send_credit_wait_us=2000\tagent_send_credit_wait_max_us=2000\tagent_send_outbound_wait_us=9000\tagent_send_outbound_wait_max_us=6000\tagent_send_frames=3\tremote_event_wait_us=9000\tremote_event_wait_max_us=6000\tremote_event_waits=2\toutcome=closed",
            "rustle_hotpath_tcp\ttransport=quic-native\tflow=10.0.0.3:49154->198.18.77.77:80\tgeneration=1\tstream_ready_us=500\topened_us=1500\tfirst_local_us=-\tfirst_local_sent_us=-\tfirst_remote_us=-\tduration_us=2500\tlocal_bytes=0\tremote_bytes=0\toutcome=open_timeout",
        ]
    )
    summaries = summarize(sample)
    assert len(summaries) == 2
    agent = next(summary for summary in summaries if summary["transport"] == "agent")
    assert agent["flows"] == 2
    assert agent["ok_flows"] == 2
    assert agent["failed_flows"] == 0
    assert agent["remote_bytes"] == 3072
    assert agent["remote_bytes_min"] == 1024
    assert agent["remote_bytes_p50"] == 1024
    assert agent["first_remote_p50_ms"] == "10.000"
    assert agent["first_remote_p95_ms"] == "30.000"
    assert agent["remote_open_wait_p50_ms"] == "1.000"
    assert agent["ready_wait_p50_ms"] == "2.000"
    assert agent["ready_wait_total_ms"] == "7.000"
    assert agent["payload_queue_wait_p50_ms"] == "1.000"
    assert agent["first_byte_wait_p50_ms"] == "6.000"
    assert agent["body_drain_p50_ms"] == "10.000"
    assert agent["local_send_wait_p50_ms"] == "7.000"
    assert agent["local_send_wait_total_ms"] == "18.000"
    assert agent["local_send_wait_max_ms"] == "8.000"
    assert agent["local_send_wait_avg_ms"] == "3.600"
    assert agent["local_send_waits"] == 5
    assert agent["tcp_recv_queue_wait_p50_ms"] == "4.000"
    assert agent["tcp_recv_queue_wait_total_ms"] == "16.000"
    assert agent["tcp_recv_queue_wait_max_ms"] == "10.000"
    assert agent["tcp_recv_queue_wait_avg_ms"] == "3.200"
    assert agent["tcp_recv_queue_waits"] == 5
    assert agent["local_queue_wait_p50_ms"] == "3.000"
    assert agent["local_queue_wait_total_ms"] == "8.000"
    assert agent["local_queue_wait_max_ms"] == "4.000"
    assert agent["local_queue_wait_avg_ms"] == "1.600"
    assert agent["local_queue_waits"] == 5
    assert agent["pre_bridge_queue_wait_p50_ms"] == "7.000"
    assert agent["pre_bridge_queue_wait_total_ms"] == "24.000"
    assert agent["pre_bridge_queue_wait_max_ms"] == "14.000"
    assert agent["pre_bridge_queue_wait_avg_ms"] == "4.800"
    assert agent["pre_bridge_queue_waits"] == 5
    assert agent["agent_send_credit_wait_p50_ms"] == "2.000"
    assert agent["agent_send_credit_wait_total_ms"] == "8.000"
    assert agent["agent_send_credit_wait_max_ms"] == "4.000"
    assert agent["agent_send_credit_wait_avg_ms"] == "1.600"
    assert agent["agent_send_outbound_wait_p50_ms"] == "1.000"
    assert agent["agent_send_outbound_wait_total_ms"] == "10.000"
    assert agent["agent_send_outbound_wait_max_ms"] == "6.000"
    assert agent["agent_send_outbound_wait_avg_ms"] == "2.000"
    assert agent["agent_send_frames"] == 5
    assert agent["remote_event_wait_p50_ms"] == "5.000"
    assert agent["remote_event_wait_total_ms"] == "14.000"
    assert agent["remote_event_wait_max_ms"] == "6.000"
    assert agent["remote_event_wait_avg_ms"] == "4.667"
    assert agent["remote_event_waits"] == 3
    assert agent["flow_throughput_min_mib_s"] == "0.04"
    assert agent["flow_throughput_p50_mib_s"] == "0.04"
    assert agent["flow_throughput_p95_mib_s"] == "0.05"
    assert agent["likely_bottleneck"] == "body_drain"
    assert agent["outcomes"] == "closed:1,remote_eof:1"
    native = next(summary for summary in summaries if summary["transport"] == "quic-native")
    assert native["failed_flows"] == 1
    assert native["first_remote_p50_ms"] == "-"
    assert native["first_byte_wait_p50_ms"] == "-"
    assert native["local_send_wait_p50_ms"] == "-"
    assert native["likely_bottleneck"] == "remote_open_wait"
    assert native["outcomes"] == "open_timeout:1"

    assert_rejects("", "no rustle_hotpath_tcp")
    assert_rejects(
        "rustle_hotpath_tcp\ttransport=agent\tflow=f\tgeneration=1\t"
        "stream_ready_us=bad\topened_us=-\tfirst_local_us=-\t"
        "first_local_sent_us=-\tfirst_remote_us=-\tduration_us=1\t"
        "local_bytes=0\tremote_bytes=0\toutcome=closed\n",
        "invalid trace duration",
    )
    assert_rejects(
        "rustle_hotpath_tcp\ttransport=agent\tflow=f\tgeneration=1\t"
        "stream_ready_us=-\topened_us=-\tfirst_local_us=-\t"
        "first_local_sent_us=-\tfirst_remote_us=-\tduration_us=1\t"
        "local_bytes=0\tremote_bytes=0\tlocal_send_waits=-1\toutcome=closed\n",
        "invalid negative hotpath local_send_waits",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Rustle stderr/log paths, or - for stdin")
    parser.add_argument("--self-test", action="store_true", help="run parser self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    print_summary(summarize(read_paths(args.paths)))


if __name__ == "__main__":
    main()
