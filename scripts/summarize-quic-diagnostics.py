#!/usr/bin/env python3
"""Summarize Rustle QUIC startup and auth diagnostic log lines."""

from __future__ import annotations

import argparse
import collections
import pathlib
import re
import sys
import tempfile


DATA_PLANE_CONNECTED_RE = re.compile(
    r"(?P<label>quic-agent|quic-native): UDP data plane connected to "
    r"(?P<remote>\S+) on attempt (?P<attempt>\d+/\d+) after (?P<elapsed>\d+)ms"
)
DATA_PLANE_ATTEMPT_RE = re.compile(
    r"attempt (?P<attempt>\d+/\d+) (?P<remote>\S+) after (?P<elapsed>\d+)ms"
)
CONNECT_RE = re.compile(
    r"(?P<label>QUIC agent|native QUIC bridge) remote=(?P<remote>\S+).*?"
    r"stage=(?P<stage>connect_establish).*?elapsed_ms=(?P<elapsed>\d+)"
)
STRUCTURED_CONNECT_RE = re.compile(
    r"quic-connect: transport=(?P<transport>quic-native) remote=(?P<remote>\S+).*?"
    r"stage=(?P<stage>[a-z_]+) result=(?P<result>[a-z_]+) "
    r"elapsed_ms=(?P<elapsed>\d+)"
)
AUTH_RE = re.compile(
    r"(?P<label>QUIC agent|native QUIC bridge)(?P<server> server)? auth"
    r"(?: remote=(?P<remote>\S+))?.*?stage=(?P<stage>[a-z_]+)"
    r".*?elapsed_ms=(?P<elapsed>\d+)"
)
STRUCTURED_AUTH_RE = re.compile(
    r"quic-auth: transport=(?P<transport>quic-native) side=(?P<side>client|server) "
    r"remote=(?P<remote>\S+) stage=(?P<stage>[a-z_]+) result=(?P<result>[a-z_]+) "
    r"elapsed_ms=(?P<elapsed>\d+)"
)
QUIC_DIAGNOSTIC_HINTS = (
    "quic-auth:",
    "quic-connect:",
    "UDP data plane connected",
    "failed to establish UDP data plane",
    "auth_token_sha256_prefix",
    "stage=connect_establish",
    "QUIC agent auth",
    "native QUIC bridge auth",
    "QUIC agent server auth",
    "native QUIC bridge server auth",
)


def read_path(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return pathlib.Path(path).read_text(encoding="utf-8")


def event_status(line: str) -> str:
    lowered = line.lower()
    if any(word in lowered for word in ("failed", "timed out", "timed_out", "rejected", "invalid")):
        return "failure"
    return "ok"


def result_status(result: str) -> str:
    return "ok" if result == "ok" else "failure"


def auth_category(match: re.Match[str]) -> str:
    label = match.group("label")
    server = bool(match.group("server"))
    transport = "quic-agent" if label == "QUIC agent" else "quic-native"
    side = "server-auth" if server else "client-auth"
    return f"{transport}/{side}"


def parse_line(line: str, path: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    if not any(hint in line for hint in QUIC_DIAGNOSTIC_HINTS):
        return events

    structured_connect = STRUCTURED_CONNECT_RE.search(line)
    if structured_connect:
        events.append(
            {
                "category": f"{structured_connect.group('transport')}/connect",
                "status": result_status(structured_connect.group("result")),
                "elapsed_ms": int(structured_connect.group("elapsed")),
                "stage": structured_connect.group("stage"),
                "remote": structured_connect.group("remote"),
                "path": path,
            }
        )

    connect = CONNECT_RE.search(line)
    if connect:
        transport = "quic-agent" if connect.group("label") == "QUIC agent" else "quic-native"
        events.append(
            {
                "category": f"{transport}/connect",
                "status": event_status(line),
                "elapsed_ms": int(connect.group("elapsed")),
                "stage": connect.group("stage"),
                "remote": connect.group("remote"),
                "path": path,
            }
        )

    connected = DATA_PLANE_CONNECTED_RE.search(line)
    if connected:
        events.append(
            {
                "category": f"{connected.group('label')}/data-plane",
                "status": "ok",
                "elapsed_ms": int(connected.group("elapsed")),
                "stage": f"attempt:{connected.group('attempt')}",
                "remote": connected.group("remote"),
                "path": path,
            }
        )
        return events

    if "failed to establish UDP data plane" in line:
        label = "quic-agent" if "quic-agent" in line else "quic-native"
        for attempt in DATA_PLANE_ATTEMPT_RE.finditer(line):
            events.append(
                {
                    "category": f"{label}/data-plane",
                    "status": "failure",
                    "elapsed_ms": int(attempt.group("elapsed")),
                    "stage": f"attempt:{attempt.group('attempt')}",
                    "remote": attempt.group("remote"),
                    "path": path,
                }
            )

    structured_auth = STRUCTURED_AUTH_RE.search(line)
    if structured_auth:
        side = "client-auth" if structured_auth.group("side") == "client" else "server-auth"
        events.append(
            {
                "category": f"{structured_auth.group('transport')}/{side}",
                "status": result_status(structured_auth.group("result")),
                "elapsed_ms": int(structured_auth.group("elapsed")),
                "stage": structured_auth.group("stage"),
                "remote": structured_auth.group("remote"),
                "path": path,
            }
        )

    auth = AUTH_RE.search(line)
    if auth:
        events.append(
            {
                "category": auth_category(auth),
                "status": event_status(line),
                "elapsed_ms": int(auth.group("elapsed")),
                "stage": auth.group("stage"),
                "remote": auth.group("remote") or "-",
                "path": path,
            }
        )
    return events


def summarize_paths(paths: list[str]) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    input_paths = paths or ["-"]
    for path in input_paths:
        for line in read_path(path).splitlines():
            events.extend(parse_line(line, path))

    by_category: dict[str, list[dict[str, object]]] = collections.defaultdict(list)
    for event in events:
        by_category[str(event["category"])].append(event)

    summaries: list[dict[str, object]] = []
    for category, category_events in sorted(by_category.items()):
        stages = sorted({str(event["stage"]) for event in category_events})
        remotes = sorted({str(event["remote"]) for event in category_events if event["remote"] != "-"})
        paths_seen = sorted({str(event["path"]) for event in category_events})
        elapsed_values = [int(event["elapsed_ms"]) for event in category_events]
        failures = sum(1 for event in category_events if event["status"] == "failure")
        summaries.append(
            {
                "category": category,
                "events": len(category_events),
                "failures": failures,
                "max_elapsed_ms": max(elapsed_values) if elapsed_values else 0,
                "stages": ",".join(stages) or "-",
                "remotes": ",".join(remotes) or "-",
                "paths": ",".join(paths_seen) or "-",
            }
        )
    return summaries


def print_summary(summaries: list[dict[str, object]]) -> None:
    columns = ("category", "events", "failures", "max_elapsed_ms", "stages", "remotes", "paths")
    print("\t".join(columns))
    for summary in summaries:
        print("\t".join(str(summary[column]) for column in columns))


def assert_rejects(text: str) -> None:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    try:
        tmp.write(text)
        tmp.close()
        summaries = summarize_paths([tmp.name])
        if summaries:
            raise AssertionError(f"unexpected QUIC summaries for {text!r}: {summaries!r}")
    finally:
        pathlib.Path(tmp.name).unlink(missing_ok=True)


def self_test() -> None:
    sample = "\n".join(
        [
            "quic-agent: UDP data plane connected to 203.0.113.9:4433 on attempt 1/2 after 42ms",
            "quic-native: failed to establish UDP data plane to any resolved address after SSH bootstrap; tried=[203.0.113.10:4444]; failures=[attempt 1/1 203.0.113.10:4444 after 8001ms: quic-native: timed out after 8000ms establishing UDP data plane]",
            "quic-native: failed to establish UDP data plane to any resolved address after SSH bootstrap; tried=[203.0.113.11:4444]; failures=[attempt 1/1 203.0.113.11:4444 after 77ms: quic-native: failed to establish UDP data plane: native QUIC bridge remote=203.0.113.11:4444 cert_sha256=abc cert_der_len=256 auth_token_sha256_prefix=abcdef123456 stage=connect_establish elapsed_ms=77: connection failed]",
            "QUIC agent remote=203.0.113.9:4433 cert_sha256=abc cert_der_len=256 auth_token_sha256_prefix=123456789abc QUIC agent auth stage=read_ack elapsed_ms=5: failed to confirm QUIC agent auth",
            "quic-bridge-agent: rejected unauthenticated connection: native QUIC bridge server auth remote=198.51.100.7:5353 stage=read_token elapsed_ms=1: invalid QUIC helper auth token",
            "quic-connect: transport=quic-native remote=203.0.113.12:4444 local_udp_addr=0.0.0.0:51234 server_name=rustle-quic-agent.local stage=connect_establish result=ok elapsed_ms=44 cert_sha256=abc cert_der_len=256 auth_token_sha256_prefix=abcdef123456",
            "quic-auth: transport=quic-native side=client remote=203.0.113.12:4444 stage=read_ack result=ok elapsed_ms=2 timeout_ms=5000 auth_token_sha256_prefix=abcdef123456",
            "quic-auth: transport=quic-native side=server remote=198.51.100.8:5354 stage=finish_send result=timeout elapsed_ms=5001 timeout_ms=5000 auth_token_sha256_prefix=abcdef123456",
        ]
    )
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    try:
        tmp.write(sample)
        tmp.close()
        summaries = {summary["category"]: summary for summary in summarize_paths([tmp.name])}
    finally:
        pathlib.Path(tmp.name).unlink(missing_ok=True)

    assert summaries["quic-agent/data-plane"]["events"] == 1
    assert summaries["quic-agent/data-plane"]["max_elapsed_ms"] == 42
    assert summaries["quic-native/data-plane"]["failures"] == 2
    assert summaries["quic-native/data-plane"]["max_elapsed_ms"] == 8001
    assert summaries["quic-native/connect"]["failures"] == 1
    assert summaries["quic-native/connect"]["max_elapsed_ms"] == 77
    assert summaries["quic-native/connect"]["stages"] == "connect_establish"
    assert summaries["quic-agent/client-auth"]["failures"] == 1
    assert summaries["quic-agent/client-auth"]["stages"] == "read_ack"
    assert summaries["quic-native/server-auth"]["events"] == 2
    assert summaries["quic-native/server-auth"]["failures"] == 2
    assert summaries["quic-native/server-auth"]["remotes"] == "198.51.100.7:5353,198.51.100.8:5354"
    assert summaries["quic-native/client-auth"]["events"] == 1
    assert summaries["quic-native/client-auth"]["failures"] == 0
    assert_rejects("ordinary rustle log line without QUIC diagnostics\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    summaries = summarize_paths(args.paths)
    if summaries:
        print_summary(summaries)


if __name__ == "__main__":
    main()
