#!/usr/bin/env python3
"""Verify live fixture benchmark rows match the configured response size."""

from __future__ import annotations

import pathlib
import sys
import tempfile


def verify(path: pathlib.Path, body_bytes: int) -> None:
    rows = 0
    failures: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("tool\t"):
            continue
        parts = line.split("\t")
        if len(parts) != 20:
            raise SystemExit(f"invalid live fixture benchmark row: {line!r}")
        tool = parts[0]
        success = int(parts[4])
        failed = int(parts[5])
        bytes_total = int(parts[9])
        rows += 1
        expected = body_bytes * success
        if success <= 0 or failed != 0 or bytes_total != expected:
            failures.append(
                f"{tool}: success={success} failed={failed} "
                f"bytes={bytes_total} expected={expected}"
            )

    if rows == 0:
        raise SystemExit(f"live fixture body_bytes={body_bytes} produced no benchmark rows")

    if failures:
        raise SystemExit(
            f"live fixture body_bytes={body_bytes} produced invalid benchmark rows:\n"
            + "\n".join(failures)
        )


def assert_rejects(contents: str, body_bytes: int, expected_message: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(contents)
        handle.flush()
        try:
            verify(pathlib.Path(handle.name), body_bytes)
        except SystemExit as exc:
            message = str(exc)
            if expected_message not in message:
                raise AssertionError(
                    f"expected {expected_message!r} in rejection, got {message!r}"
                ) from exc
        else:
            raise AssertionError("expected fixture row verification to reject sample")


def self_test() -> None:
    header = (
        "tool\trun\trequests\tconcurrency\tsuccess\tfailed\twall_ms\tp50_ms\t"
        "p95_ms\tbytes\tthroughput_mib_s\treq_s\tavg_cpu_pct\tmax_cpu_pct\t"
        "ssh_opened\tssh_failed\tagent_reconnect_attempts\tagent_reconnect_ok\t"
        "agent_reconnect_failed\tbacklog_overflow\n"
    )
    good = header + (
        "rustle-agent\t1\t4\t2\t4\t0\t100\t10.0\t20.0\t4096\t39.06\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\n"
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
        handle.write(good)
        handle.flush()
        verify(pathlib.Path(handle.name), 1024)

    assert_rejects(header, 1024, "produced no benchmark rows")
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t0\t100\t10.0\t20.0\t3072\t29.30\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\n",
        1024,
        "produced invalid benchmark rows",
    )
    assert_rejects(
        header
        + "rustle-agent\t1\t4\t2\t4\t1\t100\t10.0\t20.0\t4096\t39.06\t"
        "40.00\t1.0\t2.0\t4\t0\t0\t0\t0\t0\n",
        1024,
        "produced invalid benchmark rows",
    )


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: verify-live-fixture-rows.py RESULTS_TSV BODY_BYTES\n"
            "       verify-live-fixture-rows.py --self-test"
        )
    body_bytes = int(sys.argv[2])
    if body_bytes < 1:
        raise SystemExit("BODY_BYTES must be at least 1")
    verify(pathlib.Path(sys.argv[1]), body_bytes)


if __name__ == "__main__":
    main()
