#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-dns-bench.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_DNS_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bench_bin)"
RUNS="${RUSTLE_BENCH_RUNS:-3}"
WARMUP_RUNS="${RUSTLE_BENCH_WARMUP_RUNS:-1}"
QUERIES="${RUSTLE_BENCH_AGENT_DNS_QUERIES:-32}"
TRANSPORTS="${RUSTLE_BENCH_AGENT_DNS_TRANSPORTS:-agent}"
NAME="${RUSTLE_BENCH_AGENT_DNS_NAME:-rustle-smoke.example.com}"
REMOTE_HOST="${RUSTLE_BENCH_AGENT_DNS_REMOTE_HOST:-127.0.0.1}"
MAX_P50_US="${RUSTLE_BENCH_AGENT_DNS_MAX_P50_US:-}"
RESULTS_TSV="${TMPDIR}/agent-dns-results.tsv"

case "$RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_RUNS must be a non-negative integer" ;;
esac
case "$WARMUP_RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_WARMUP_RUNS must be a non-negative integer" ;;
esac
if [[ -n "$MAX_P50_US" ]]; then
  case "$MAX_P50_US" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_DNS_MAX_P50_US must be a positive integer" ;;
  esac
  if [[ "$MAX_P50_US" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_AGENT_DNS_MAX_P50_US must be at least 1"
  fi
fi

smoke_start_sshd "$TMPDIR"
smoke_start_dns_tcp_server "$TMPDIR"

printf 'transport\tqueries\trun\telapsed_ms\tresponse_bytes\tp50_us\tp95_us\tmax_us\n'
: >"$RESULTS_TSV"

for transport in $TRANSPORTS; do
  case "$transport" in
    auto | auto-quic | direct-tcpip | agent | quic-agent | quic-native) ;;
    *) smoke_die "RUSTLE_BENCH_AGENT_DNS_TRANSPORTS entries must be auto, auto-quic, direct-tcpip, agent, quic-agent, or quic-native" ;;
  esac

  for queries in $QUERIES; do
    case "$queries" in
      '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_DNS_QUERIES entries must be positive integers" ;;
    esac
    if [[ "$queries" -lt 1 ]]; then
      smoke_die "RUSTLE_BENCH_AGENT_DNS_QUERIES entries must be at least 1"
    fi

    total_runs=$((WARMUP_RUNS + RUNS))
    for ((run = 1; run <= total_runs; run++)); do
      out="${TMPDIR}/bench-agent-dns-${transport}-${queries}-${run}.out"
      err="${TMPDIR}/bench-agent-dns-${transport}-${queries}-${run}.err"
      cmd=(
        "$RUSTLE_BIN_RESOLVED"
        agent-dns-lab
        -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}"
        -i "$SMOKE_CLIENT_KEY"
        --known-hosts "$SMOKE_KNOWN_HOSTS"
        --dns-remote "${REMOTE_HOST}:${SMOKE_DNS_TCP_PORT}"
        --name "$NAME"
        --queries "$queries"
        --bridge-transport "$transport"
      )
      if [[ "$transport" != "direct-tcpip" ]]; then
        if [[ "$transport" == "auto-quic" ]]; then
          cmd+=(--agent-path "${RUSTLE_BENCH_AUTO_QUIC_AGENT_PATH:-${RUSTLE_BENCH_AGENT_PATH:-${RUSTLE_BIN_RESOLVED}}}")
        elif [[ "$transport" == "quic-agent" ]]; then
          cmd+=(--agent-command "${RUSTLE_BENCH_QUIC_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' quic-agent}")
        elif [[ "$transport" == "quic-native" ]]; then
          cmd+=(--agent-command "${RUSTLE_BENCH_QUIC_NATIVE_COMMAND:-'${RUSTLE_BIN_RESOLVED}' quic-bridge-agent}")
        else
          cmd+=(--agent-command "${RUSTLE_BENCH_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}")
        fi
        if [[ "$transport" != "quic-native" && -n "${RUSTLE_BENCH_AGENT_SESSIONS:-}" ]]; then
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
        smoke_die "agent DNS benchmark exited with status ${status} for transport ${transport}"
      fi

      summary="$(tail -n 1 "$out")"
      summary_queries="$(printf '%s\n' "$summary" | sed -n 's/.* queries=\([0-9][0-9]*\).*/\1/p')"
      response_bytes="$(printf '%s\n' "$summary" | sed -n 's/.* response_bytes=\([0-9][0-9]*\).*/\1/p')"
      elapsed_ms="$(printf '%s\n' "$summary" | sed -n 's/.* elapsed_ms=\([0-9][0-9]*\).*/\1/p')"
      p50_us="$(printf '%s\n' "$summary" | sed -n 's/.* p50_us=\([0-9][0-9]*\).*/\1/p')"
      p95_us="$(printf '%s\n' "$summary" | sed -n 's/.* p95_us=\([0-9][0-9]*\).*/\1/p')"
      max_us="$(printf '%s\n' "$summary" | sed -n 's/.* max_us=\([0-9][0-9]*\).*/\1/p')"
      if [[ -z "$summary_queries" || -z "$response_bytes" || -z "$elapsed_ms" || -z "$p50_us" || -z "$p95_us" || -z "$max_us" ]]; then
        sed 's/^/rustle stdout: /' "$out" >&2 || true
        smoke_die "could not parse agent DNS benchmark summary for transport ${transport}"
      fi
      if [[ "$summary_queries" != "$queries" ]]; then
        sed 's/^/rustle stdout: /' "$out" >&2 || true
        smoke_die "agent DNS benchmark summary does not match requested queries"
      fi
      if [[ "$response_bytes" -lt "$queries" ]]; then
        sed 's/^/rustle stdout: /' "$out" >&2 || true
        smoke_die "agent DNS benchmark returned too few response bytes"
      fi

      if [[ "$run" -le "$WARMUP_RUNS" ]]; then
        continue
      fi

      measured_run=$((run - WARMUP_RUNS))
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$transport" "$queries" "$measured_run" "$elapsed_ms" "$response_bytes" "$p50_us" "$p95_us" "$max_us"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$transport" "$queries" "$measured_run" "$elapsed_ms" "$response_bytes" "$p50_us" "$p95_us" "$max_us" >>"$RESULTS_TSV"
    done
  done
done

if [[ -n "$MAX_P50_US" ]]; then
  "$(smoke_python)" - "$RESULTS_TSV" "$MAX_P50_US" <<'PY'
import sys

path = sys.argv[1]
maximum = int(sys.argv[2])

failures = []
rows = 0
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 8:
            raise SystemExit(f"invalid agent DNS benchmark row: {line!r}")
        transport, queries, run, _elapsed_ms, _response_bytes, p50_us, _p95_us, _max_us = parts
        rows += 1
        value = int(p50_us)
        if value > maximum:
            failures.append(
                f"{transport} queries={queries} run={run} p50_us={value}"
            )

if rows == 0:
    raise SystemExit("DNS p50 ceiling was requested, but benchmark produced no measured rows")

if failures:
    raise SystemExit(
        "agent DNS p50 latency above configured ceiling "
        f"{maximum}us:\n" + "\n".join(failures)
    )
PY
fi
