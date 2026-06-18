#!/usr/bin/env python3
"""Summarize Rustle framed-agent writer pressure from status logs."""

from __future__ import annotations

import argparse
import collections
import pathlib
import re
import sys
import tempfile


AGENT_WRITER_RE = re.compile(
    r"agent_writer=queued_frames:(?P<queued_frames>[0-9]+) "
    r"queued_bytes:(?P<queued_bytes>[0-9]+) "
    r"queued_frames_max:(?P<queued_frames_max>[0-9]+) "
    r"queued_bytes_max:(?P<queued_bytes_max>[0-9]+) "
    r"bursts:(?P<bursts>[0-9]+) "
    r"burst_frames:(?P<burst_frames>[0-9]+) "
    r"burst_bytes:(?P<burst_bytes>[0-9]+) "
    r"burst_frames_max:(?P<burst_frames_max>[0-9]+) "
    r"burst_bytes_max:(?P<burst_bytes_max>[0-9]+) "
    r"enqueue_wait=samples:(?P<enqueue_wait_samples>[0-9]+) "
    r"total_us:(?P<enqueue_wait_total_us>[0-9]+) "
    r"max_us:(?P<enqueue_wait_max_us>[0-9]+) "
    r"write_us:(?P<write_total_us>[0-9]+) "
    r"write_max_us:(?P<write_max_us>[0-9]+) "
    r"flush_us:(?P<flush_total_us>[0-9]+) "
    r"flush_max_us:(?P<flush_max_us>[0-9]+)"
)
COUNTER_FIELDS = (
    "queued_frames",
    "queued_bytes",
    "queued_frames_max",
    "queued_bytes_max",
    "bursts",
    "burst_frames",
    "burst_bytes",
    "burst_frames_max",
    "burst_bytes_max",
    "enqueue_wait_samples",
    "enqueue_wait_total_us",
    "enqueue_wait_max_us",
    "write_total_us",
    "write_max_us",
    "flush_total_us",
    "flush_max_us",
)
SUM_FIELDS = (
    "bursts",
    "burst_frames",
    "burst_bytes",
    "enqueue_wait_samples",
    "enqueue_wait_total_us",
    "write_total_us",
    "flush_total_us",
)
MAX_FIELDS = (
    "queued_frames",
    "queued_bytes",
    "queued_frames_max",
    "queued_bytes_max",
    "burst_frames_max",
    "burst_bytes_max",
    "enqueue_wait_max_us",
    "write_max_us",
    "flush_max_us",
)
OUTPUT_COLUMNS = (
    "tool",
    "status_lines",
    "queued_frames_max",
    "queued_bytes_max",
    "bursts",
    "burst_frames",
    "burst_bytes",
    "burst_frames_max",
    "burst_bytes_max",
    "enqueue_wait_samples",
    "enqueue_wait_total_us",
    "enqueue_wait_max_us",
    "write_total_us",
    "write_max_us",
    "flush_total_us",
    "flush_max_us",
    "paths",
)


def parse_counter(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"invalid agent writer {field} value {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"invalid negative agent writer {field} value {value!r}")
    return parsed


def parse_status_line(line: str) -> dict[str, int] | None:
    match = AGENT_WRITER_RE.search(line)
    if match is None:
        return None
    return {
        field: parse_counter(match.group(field), field) for field in COUNTER_FIELDS
    }


def tool_from_path(path: str) -> str:
    if path == "-":
        return "stdin"
    parent = pathlib.Path(path).parent.name
    match = re.match(r"^(?P<tool>rustle-[A-Za-z0-9_-]+)-[0-9]+$", parent)
    if match is not None:
        return match.group("tool")
    return parent or "unknown"


def read_path(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return pathlib.Path(path).read_text(encoding="utf-8")


def summarize_log(path: str) -> dict[str, object] | None:
    status_lines = 0
    latest = {field: 0 for field in COUNTER_FIELDS}
    peaks = {field: 0 for field in MAX_FIELDS}
    for line in read_path(path).splitlines():
        parsed = parse_status_line(line)
        if parsed is None:
            continue
        status_lines += 1
        latest = parsed
        for field in MAX_FIELDS:
            peaks[field] = max(peaks[field], parsed[field])
    if status_lines == 0:
        return None
    summary: dict[str, object] = {
        "tool": tool_from_path(path),
        "status_lines": status_lines,
        "path": path,
    }
    for field in SUM_FIELDS:
        summary[field] = latest[field]
    for field in MAX_FIELDS:
        summary[field] = peaks[field]
    return summary


def summarize(paths: list[str]) -> list[dict[str, object]]:
    if not paths:
        paths = ["-"]
    grouped: dict[str, list[dict[str, object]]] = collections.defaultdict(list)
    for path in paths:
        summary = summarize_log(path)
        if summary is not None:
            grouped[str(summary["tool"])].append(summary)
    if not grouped:
        raise SystemExit("no agent_writer status lines found")

    rows: list[dict[str, object]] = []
    for tool, summaries in sorted(grouped.items()):
        row: dict[str, object] = {
            "tool": tool,
            "status_lines": sum(int(summary["status_lines"]) for summary in summaries),
            "paths": ",".join(str(summary["path"]) for summary in summaries),
        }
        for field in SUM_FIELDS:
            row[field] = sum(int(summary[field]) for summary in summaries)
        for field in MAX_FIELDS:
            row[field] = max(int(summary[field]) for summary in summaries)
        rows.append(row)
    return rows


def print_summary(rows: list[dict[str, object]]) -> None:
    print("\t".join(OUTPUT_COLUMNS))
    for row in rows:
        print("\t".join(str(row[column]) for column in OUTPUT_COLUMNS))


def assert_rejects(contents: str, expected_message: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(contents)
        handle.flush()
        try:
            summarize([handle.name])
        except SystemExit as exc:
            if expected_message not in str(exc):
                raise AssertionError(
                    f"expected {expected_message!r} in rejection, got {exc!s}"
                ) from exc
        else:
            raise AssertionError("expected agent writer summary to reject sample")


def self_test() -> None:
    sample = "\n".join(
        [
            "unrelated log line",
            "stats: uptime=1.000s agent_writer=queued_frames:1 queued_bytes:32 queued_frames_max:1 queued_bytes_max:32 bursts:2 burst_frames:3 burst_bytes:96 burst_frames_max:2 burst_bytes_max:64 enqueue_wait=samples:3 total_us:1500 max_us:900 write_us:700 write_max_us:400 flush_us:300 flush_max_us:250 flow=expired:0",
            "stats: final uptime=2.000s agent_writer=queued_frames:0 queued_bytes:0 queued_frames_max:3 queued_bytes_max:4096 bursts:5 burst_frames:8 burst_bytes:8192 burst_frames_max:4 burst_bytes_max:4096 enqueue_wait=samples:8 total_us:7000 max_us:2500 write_us:1200 write_max_us:600 flush_us:900 flush_max_us:500 flow=expired:0",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = pathlib.Path(tmp) / "rustle-agent-1"
        run_dir.mkdir()
        log = run_dir / "rustle.log"
        log.write_text(sample, encoding="utf-8")
        rows = summarize([str(log)])
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "rustle-agent"
    assert row["status_lines"] == 2
    assert row["queued_frames_max"] == 3
    assert row["queued_bytes_max"] == 4096
    assert row["bursts"] == 5
    assert row["burst_frames"] == 8
    assert row["enqueue_wait_samples"] == 8
    assert row["enqueue_wait_max_us"] == 2500
    assert row["write_max_us"] == 600
    assert row["flush_max_us"] == 500

    assert_rejects("", "no agent_writer status lines")
    assert_rejects(
        "stats: agent_writer=queued_frames:bad queued_bytes:0",
        "no agent_writer status lines",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Rustle stderr/log paths, or - for stdin")
    parser.add_argument("--self-test", action="store_true", help="run parser self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    print_summary(summarize(args.paths))


if __name__ == "__main__":
    main()
