#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-bridge-bench.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bench_bin)"
RUNS="${RUSTLE_BENCH_RUNS:-3}"
WARMUP_RUNS="${RUSTLE_BENCH_WARMUP_RUNS:-1}"
CONNECTIONS="${RUSTLE_BENCH_CONNECTIONS:-1 8 32 64}"
BODY_BYTES="${RUSTLE_BENCH_BODY_BYTES:-65536}"
TRANSPORTS="${RUSTLE_BENCH_BRIDGE_TRANSPORTS:-agent direct-tcpip}"
MIN_AGENT_DIRECT_RATIO="${RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO:-}"
RATIO_MIN_CONNECTIONS="${RUSTLE_BENCH_RATIO_MIN_CONNECTIONS:-1}"
MIN_THROUGHPUT_MIB_S="${RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S:-}"
MAX_ELAPSED_MS="${RUSTLE_BENCH_MAX_ELAPSED_MS:-}"
RESULTS_TSV="${TMPDIR}/bridge-results.tsv"

case "$RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_RUNS must be a non-negative integer" ;;
esac
case "$WARMUP_RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_WARMUP_RUNS must be a non-negative integer" ;;
esac
case "$RATIO_MIN_CONNECTIONS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_RATIO_MIN_CONNECTIONS must be a non-negative integer" ;;
esac
if [[ -n "$MIN_AGENT_DIRECT_RATIO" ]]; then
  "$(smoke_python)" - "$MIN_AGENT_DIRECT_RATIO" <<'PY'
import sys

try:
    ratio = float(sys.argv[1])
except ValueError as exc:
    raise SystemExit("RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO must be a number") from exc
if ratio <= 0:
    raise SystemExit("RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO must be greater than 0")
PY
fi
if [[ -n "$MIN_THROUGHPUT_MIB_S" ]]; then
  "$(smoke_python)" - "$MIN_THROUGHPUT_MIB_S" <<'PY'
import sys

try:
    threshold = float(sys.argv[1])
except ValueError as exc:
    raise SystemExit("RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S must be a number") from exc
if threshold <= 0:
    raise SystemExit("RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S must be greater than 0")
PY
fi
if [[ -n "$MAX_ELAPSED_MS" ]]; then
  case "$MAX_ELAPSED_MS" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_MAX_ELAPSED_MS must be a positive integer" ;;
  esac
  if [[ "$MAX_ELAPSED_MS" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_MAX_ELAPSED_MS must be at least 1"
  fi
fi

smoke_start_sshd "$TMPDIR"

printf 'transport\tbody_bytes\tconnections\trun\telapsed_ms\tresponse_bytes\tthroughput_mib_s\n'
: >"$RESULTS_TSV"

for body_bytes in $BODY_BYTES; do
  case "$body_bytes" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_BODY_BYTES entries must be positive integers" ;;
  esac
  if [[ "$body_bytes" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_BODY_BYTES entries must be at least 1"
  fi

  export RUSTLE_SMOKE_HTTP_BODY_BYTES="$body_bytes"
  http_tmp="${TMPDIR}/http-${body_bytes}"
  mkdir -p "$http_tmp"
  smoke_start_http_server "$http_tmp"

  for transport in $TRANSPORTS; do
    case "$transport" in
      auto | direct-tcpip | agent) ;;
      *) smoke_die "RUSTLE_BENCH_BRIDGE_TRANSPORTS entries must be auto, direct-tcpip, or agent" ;;
    esac

    for connections in $CONNECTIONS; do
      case "$connections" in
        '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_CONNECTIONS entries must be positive integers" ;;
      esac
      if [[ "$connections" -lt 1 ]]; then
        smoke_die "RUSTLE_BENCH_CONNECTIONS entries must be at least 1"
      fi

      total_runs=$((WARMUP_RUNS + RUNS))
      for ((run = 1; run <= total_runs; run++)); do
        out="${TMPDIR}/bench-${transport}-${body_bytes}-${connections}-${run}.out"
        err="${TMPDIR}/bench-${transport}-${body_bytes}-${connections}-${run}.err"
        request=$'GET / HTTP/1.1\r\nHost: rustle-bench\r\nConnection: close\r\n\r\n'
        cmd=(
          "$RUSTLE_BIN_RESOLVED"
          bridge-lab
          -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}"
          -i "$SMOKE_CLIENT_KEY"
          --known-hosts "$SMOKE_KNOWN_HOSTS"
          --destination "127.0.0.1:${SMOKE_HTTP_PORT}"
          --request "$request"
          --connections "$connections"
          --summary
        )
        cmd+=(--bridge-transport "$transport")
        if [[ "$transport" != "direct-tcpip" ]]; then
          cmd+=(--agent-command "${RUSTLE_BENCH_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}")
          if [[ -n "${RUSTLE_BENCH_AGENT_SESSIONS:-}" ]]; then
            cmd+=(--agent-sessions "$RUSTLE_BENCH_AGENT_SESSIONS")
          fi
        fi

        set +e
        "${cmd[@]}" >"$out" 2>"$err"
        status=$?
        set -e

        if [[ "$status" -ne 0 ]]; then
          sed 's/^/rustle stderr: /' "$err" >&2 || true
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "bridge benchmark exited with status ${status} for transport ${transport}"
        fi

        summary="$(tail -n 1 "$out")"
        response_bytes="$(printf '%s\n' "$summary" | sed -n 's/.* response_bytes=\([0-9][0-9]*\).*/\1/p')"
        elapsed_ms="$(printf '%s\n' "$summary" | sed -n 's/.* elapsed_ms=\([0-9][0-9]*\).*/\1/p')"
        if [[ -z "$response_bytes" || -z "$elapsed_ms" || "$elapsed_ms" -eq 0 ]]; then
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "could not parse bridge benchmark summary for transport ${transport}"
        fi

        expected_min=$((body_bytes * connections))
        if [[ "$response_bytes" -lt "$expected_min" ]]; then
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "bridge benchmark returned ${response_bytes} bytes, expected at least ${expected_min}"
        fi

        if [[ "$run" -le "$WARMUP_RUNS" ]]; then
          continue
        fi

        measured_run=$((run - WARMUP_RUNS))
        throughput="$("$(smoke_python)" - "$response_bytes" "$elapsed_ms" <<'PY'
import sys

response_bytes = int(sys.argv[1])
elapsed_ms = int(sys.argv[2])
throughput = (response_bytes / (1024 * 1024)) / (elapsed_ms / 1000)
print(f"{throughput:.2f}")
PY
        )"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$transport" "$body_bytes" "$connections" "$measured_run" "$elapsed_ms" "$response_bytes" "$throughput"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$transport" "$body_bytes" "$connections" "$measured_run" "$elapsed_ms" "$response_bytes" "$throughput" >>"$RESULTS_TSV"
      done
    done
  done

  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  unset SMOKE_HTTP_PID SMOKE_HTTP_PORT SMOKE_HTTP_LOG
done

if [[ -n "$MIN_AGENT_DIRECT_RATIO" ]]; then
  "$(smoke_python)" - "$RESULTS_TSV" "$MIN_AGENT_DIRECT_RATIO" "$RATIO_MIN_CONNECTIONS" <<'PY'
import collections
import sys

path = sys.argv[1]
min_ratio = float(sys.argv[2])
min_connections = int(sys.argv[3])

samples = collections.defaultdict(list)
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 7:
            raise SystemExit(f"invalid benchmark row: {line!r}")
        transport, body_bytes, connections, _run, _elapsed, _response, throughput = parts
        connections = int(connections)
        if connections < min_connections:
            continue
        samples[(body_bytes, connections, transport)].append(float(throughput))

failures = []
comparisons = 0
keys = sorted({(body, conns) for body, conns, _transport in samples})
for body_bytes, connections in keys:
    direct = samples.get((body_bytes, connections, "direct-tcpip"))
    agent = samples.get((body_bytes, connections, "agent"))
    if not direct or not agent:
        continue
    comparisons += 1
    direct_avg = sum(direct) / len(direct)
    agent_avg = sum(agent) / len(agent)
    ratio = agent_avg / direct_avg if direct_avg else float("inf")
    if ratio < min_ratio:
        failures.append(
            f"body={body_bytes} connections={connections} "
            f"agent/direct={ratio:.2f} agent={agent_avg:.2f}MiB/s direct={direct_avg:.2f}MiB/s"
        )

if comparisons == 0:
    raise SystemExit(
        "agent/direct throughput sanity ratio was requested, but no matching "
        f"direct-tcpip and agent rows met min_connections={min_connections}"
    )

if failures:
    raise SystemExit(
        "agent bridge throughput below configured sanity ratio "
        f"{min_ratio:.2f}:\n" + "\n".join(failures)
    )
PY
fi

if [[ -n "$MIN_THROUGHPUT_MIB_S" ]]; then
  "$(smoke_python)" - "$RESULTS_TSV" "$MIN_THROUGHPUT_MIB_S" <<'PY'
import sys

path = sys.argv[1]
minimum = float(sys.argv[2])

failures = []
rows = 0
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 7:
            raise SystemExit(f"invalid benchmark row: {line!r}")
        transport, body_bytes, connections, run, _elapsed, _response, throughput = parts
        rows += 1
        value = float(throughput)
        if value < minimum:
            failures.append(
                f"{transport} body={body_bytes} connections={connections} run={run} "
                f"throughput={value:.2f}MiB/s"
            )

if rows == 0:
    raise SystemExit("throughput floor was requested, but benchmark produced no measured rows")

if failures:
    raise SystemExit(
        "bridge throughput below configured floor "
        f"{minimum:.2f}MiB/s:\n" + "\n".join(failures)
    )
PY
fi

if [[ -n "$MAX_ELAPSED_MS" ]]; then
  "$(smoke_python)" - "$RESULTS_TSV" "$MAX_ELAPSED_MS" <<'PY'
import sys

path = sys.argv[1]
maximum = int(sys.argv[2])

failures = []
rows = 0
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 7:
            raise SystemExit(f"invalid benchmark row: {line!r}")
        transport, body_bytes, connections, run, elapsed, _response, _throughput = parts
        rows += 1
        value = int(elapsed)
        if value > maximum:
            failures.append(
                f"{transport} body={body_bytes} connections={connections} run={run} "
                f"elapsed_ms={value}"
            )

if rows == 0:
    raise SystemExit("elapsed ceiling was requested, but benchmark produced no measured rows")

if failures:
    raise SystemExit(
        "bridge elapsed time above configured ceiling "
        f"{maximum}ms:\n" + "\n".join(failures)
    )
PY
fi
