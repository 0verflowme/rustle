#!/usr/bin/env python3
"""Summarize opt-in Rustle agent startup trace lines."""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
import tempfile


TRACE_PREFIX = "rustle_agent_startup"
REQUIRED_FIELDS = {
    "mode",
    "desired",
    "established",
    "primary_us",
    "primary_ok",
    "extra_batches",
    "extra_connects",
    "extra_success",
    "extra_fail",
    "extra_us",
    "extra_max_us",
    "retry_batches",
    "retry_connects",
    "retry_success",
    "retry_fail",
    "retry_us",
    "retry_max_us",
    "duration_us",
    "outcome",
}
COUNTER_FIELDS = (
    "desired",
    "established",
    "extra_batches",
    "extra_connects",
    "extra_success",
    "extra_fail",
    "extra_us",
    "extra_max_us",
    "retry_batches",
    "retry_connects",
    "retry_success",
    "retry_fail",
    "retry_us",
    "retry_max_us",
    "duration_us",
)
SUCCESS_OUTCOMES = {"ok"}
DEGRADED_OUTCOMES = {"degraded"}


def percentile(values: list[int], percentile_value: float) -> int | None:
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


def parse_counter(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"invalid agent startup {field} value {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"invalid negative agent startup {field} value {value!r}")
    return parsed


def parse_optional_us(value: str) -> int | None:
    if value == "-":
        return None
    return parse_counter(value, "duration")


def parse_optional_bool(value: str) -> bool | None:
    if value == "-":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    raise SystemExit(f"invalid agent startup primary_ok value {value!r}")


def parse_trace_line(line: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("\t")
    if not parts or parts[0] != TRACE_PREFIX:
        return None
    fields: dict[str, str] = {}
    for item in parts[1:]:
        if "=" not in item:
            raise SystemExit(f"invalid agent startup trace field {item!r}")
        key, value = item.split("=", 1)
        fields[key] = value
    missing = sorted(REQUIRED_FIELDS.difference(fields))
    if missing:
        raise SystemExit(
            f"agent startup trace line missing required fields {missing!r}: {line!r}"
        )
    for field in COUNTER_FIELDS:
        parse_counter(fields[field], field)
    parse_optional_us(fields["primary_us"])
    parse_optional_bool(fields["primary_ok"])
    desired = parse_counter(fields["desired"], "desired")
    established = parse_counter(fields["established"], "established")
    if established > desired:
        raise SystemExit(
            f"agent startup established count exceeds desired count: {line!r}"
        )
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
    by_mode: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for line in text.splitlines():
        fields = parse_trace_line(line)
        if fields is not None:
            by_mode[fields["mode"]].append(fields)
    if not by_mode:
        raise SystemExit("no rustle_agent_startup trace lines found")

    summaries: list[dict[str, object]] = []
    for mode, rows in sorted(by_mode.items()):
        outcomes = collections.Counter(row["outcome"] for row in rows)
        primary_values = [
            value
            for row in rows
            if (value := parse_optional_us(row["primary_us"])) is not None
        ]
        duration_values = [parse_counter(row["duration_us"], "duration_us") for row in rows]
        extra_max_values = [parse_counter(row["extra_max_us"], "extra_max_us") for row in rows]
        retry_max_values = [parse_counter(row["retry_max_us"], "retry_max_us") for row in rows]
        desired_total = sum(parse_counter(row["desired"], "desired") for row in rows)
        established_total = sum(
            parse_counter(row["established"], "established") for row in rows
        )
        primary_ok_values = [parse_optional_bool(row["primary_ok"]) for row in rows]
        ok_starts = sum(outcomes[outcome] for outcome in SUCCESS_OUTCOMES)
        degraded_starts = sum(outcomes[outcome] for outcome in DEGRADED_OUTCOMES)
        failed_starts = len(rows) - ok_starts - degraded_starts
        summaries.append(
            {
                "mode": mode,
                "starts": len(rows),
                "ok_starts": ok_starts,
                "degraded_starts": degraded_starts,
                "failed_starts": failed_starts,
                "desired_total": desired_total,
                "established_total": established_total,
                "missing_total": desired_total - established_total,
                "primary_ok": sum(value is True for value in primary_ok_values),
                "primary_fail": sum(value is False for value in primary_ok_values),
                "primary_p50_ms": format_ms(percentile(primary_values, 50)),
                "primary_p95_ms": format_ms(percentile(primary_values, 95)),
                "duration_p50_ms": format_ms(percentile(duration_values, 50)),
                "duration_p95_ms": format_ms(percentile(duration_values, 95)),
                "extra_batches": sum(
                    parse_counter(row["extra_batches"], "extra_batches") for row in rows
                ),
                "extra_connects": sum(
                    parse_counter(row["extra_connects"], "extra_connects") for row in rows
                ),
                "extra_success": sum(
                    parse_counter(row["extra_success"], "extra_success") for row in rows
                ),
                "extra_fail": sum(
                    parse_counter(row["extra_fail"], "extra_fail") for row in rows
                ),
                "extra_total_ms": format_ms(
                    sum(parse_counter(row["extra_us"], "extra_us") for row in rows)
                ),
                "extra_max_ms": format_ms(max(extra_max_values, default=None)),
                "retry_batches": sum(
                    parse_counter(row["retry_batches"], "retry_batches") for row in rows
                ),
                "retry_connects": sum(
                    parse_counter(row["retry_connects"], "retry_connects") for row in rows
                ),
                "retry_success": sum(
                    parse_counter(row["retry_success"], "retry_success") for row in rows
                ),
                "retry_fail": sum(
                    parse_counter(row["retry_fail"], "retry_fail") for row in rows
                ),
                "retry_total_ms": format_ms(
                    sum(parse_counter(row["retry_us"], "retry_us") for row in rows)
                ),
                "retry_max_ms": format_ms(max(retry_max_values, default=None)),
                "outcomes": ",".join(
                    f"{outcome}:{count}" for outcome, count in sorted(outcomes.items())
                ),
            }
        )
    return summaries


def print_summary(summaries: list[dict[str, object]]) -> None:
    columns = (
        "mode",
        "starts",
        "ok_starts",
        "degraded_starts",
        "failed_starts",
        "desired_total",
        "established_total",
        "missing_total",
        "primary_ok",
        "primary_fail",
        "primary_p50_ms",
        "primary_p95_ms",
        "duration_p50_ms",
        "duration_p95_ms",
        "extra_batches",
        "extra_connects",
        "extra_success",
        "extra_fail",
        "extra_total_ms",
        "extra_max_ms",
        "retry_batches",
        "retry_connects",
        "retry_success",
        "retry_fail",
        "retry_total_ms",
        "retry_max_ms",
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
            raise AssertionError("expected agent startup summary to reject sample")


def self_test() -> None:
    sample = "\n".join(
        [
            "unrelated log line",
            "rustle_agent_startup\tmode=initial\tdesired=3\testablished=3\tprimary_us=10000\tprimary_ok=true\textra_batches=1\textra_connects=2\textra_success=2\textra_fail=0\textra_us=40000\textra_max_us=40000\tretry_batches=0\tretry_connects=0\tretry_success=0\tretry_fail=0\tretry_us=0\tretry_max_us=0\tduration_us=55000\toutcome=ok",
            "rustle_agent_startup\tmode=initial\tdesired=3\testablished=2\tprimary_us=20000\tprimary_ok=true\textra_batches=1\textra_connects=2\textra_success=1\textra_fail=1\textra_us=60000\textra_max_us=60000\tretry_batches=1\tretry_connects=1\tretry_success=0\tretry_fail=1\tretry_us=30000\tretry_max_us=30000\tduration_us=115000\toutcome=degraded",
            "rustle_agent_startup\tmode=fast\tdesired=4\testablished=0\tprimary_us=-\tprimary_ok=false\textra_batches=0\textra_connects=0\textra_success=0\textra_fail=0\textra_us=0\textra_max_us=0\tretry_batches=0\tretry_connects=0\tretry_success=0\tretry_fail=0\tretry_us=0\tretry_max_us=0\tduration_us=5000\toutcome=primary_error",
        ]
    )
    summaries = summarize(sample)
    assert len(summaries) == 2
    initial = next(summary for summary in summaries if summary["mode"] == "initial")
    assert initial["starts"] == 2
    assert initial["ok_starts"] == 1
    assert initial["degraded_starts"] == 1
    assert initial["failed_starts"] == 0
    assert initial["desired_total"] == 6
    assert initial["established_total"] == 5
    assert initial["missing_total"] == 1
    assert initial["primary_ok"] == 2
    assert initial["primary_fail"] == 0
    assert initial["primary_p50_ms"] == "10.000"
    assert initial["primary_p95_ms"] == "20.000"
    assert initial["duration_p50_ms"] == "55.000"
    assert initial["duration_p95_ms"] == "115.000"
    assert initial["extra_batches"] == 2
    assert initial["extra_connects"] == 4
    assert initial["extra_success"] == 3
    assert initial["extra_fail"] == 1
    assert initial["extra_total_ms"] == "100.000"
    assert initial["extra_max_ms"] == "60.000"
    assert initial["retry_batches"] == 1
    assert initial["retry_connects"] == 1
    assert initial["retry_success"] == 0
    assert initial["retry_fail"] == 1
    assert initial["retry_total_ms"] == "30.000"
    assert initial["retry_max_ms"] == "30.000"
    assert initial["outcomes"] == "degraded:1,ok:1"
    fast = next(summary for summary in summaries if summary["mode"] == "fast")
    assert fast["starts"] == 1
    assert fast["failed_starts"] == 1
    assert fast["primary_ok"] == 0
    assert fast["primary_fail"] == 1
    assert fast["primary_p50_ms"] == "-"
    assert fast["outcomes"] == "primary_error:1"

    assert_rejects("", "no rustle_agent_startup")
    assert_rejects(
        "rustle_agent_startup\tmode=initial\tdesired=bad\testablished=1\t"
        "primary_us=-\tprimary_ok=-\textra_batches=0\textra_connects=0\t"
        "extra_success=0\textra_fail=0\textra_us=0\textra_max_us=0\t"
        "retry_batches=0\tretry_connects=0\tretry_success=0\tretry_fail=0\t"
        "retry_us=0\tretry_max_us=0\tduration_us=1\toutcome=ok\n",
        "invalid agent startup desired",
    )
    assert_rejects(
        "rustle_agent_startup\tmode=initial\tdesired=1\testablished=2\t"
        "primary_us=-\tprimary_ok=-\textra_batches=0\textra_connects=0\t"
        "extra_success=0\textra_fail=0\textra_us=0\textra_max_us=0\t"
        "retry_batches=0\tretry_connects=0\tretry_success=0\tretry_fail=0\t"
        "retry_us=0\tretry_max_us=0\tduration_us=1\toutcome=ok\n",
        "established count exceeds desired",
    )
    assert_rejects(
        "rustle_agent_startup\tmode=initial\tdesired=1\testablished=1\t"
        "primary_us=-\tprimary_ok=maybe\textra_batches=0\textra_connects=0\t"
        "extra_success=0\textra_fail=0\textra_us=0\textra_max_us=0\t"
        "retry_batches=0\tretry_connects=0\tretry_success=0\tretry_fail=0\t"
        "retry_us=0\tretry_max_us=0\tduration_us=1\toutcome=ok\n",
        "invalid agent startup primary_ok",
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
