#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-udp-bench.XXXXXX")"

cleanup() {
  smoke_stop_pid "${UDP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bench_bin)"
RUNS="${RUSTLE_BENCH_RUNS:-3}"
WARMUP_RUNS="${RUSTLE_BENCH_WARMUP_RUNS:-1}"
BODY_BYTES="${RUSTLE_BENCH_AGENT_UDP_BODY_BYTES:-64 512 1200}"
MESSAGES="${RUSTLE_BENCH_AGENT_UDP_MESSAGES:-1024 8192}"
PIPELINES="${RUSTLE_BENCH_AGENT_UDP_PIPELINES:-1 32 128}"
REQUEST="${RUSTLE_BENCH_AGENT_UDP_REQUEST:-rustle-agent-udp-bench}"

case "$RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_RUNS must be a non-negative integer" ;;
esac
case "$WARMUP_RUNS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_WARMUP_RUNS must be a non-negative integer" ;;
esac

smoke_start_sshd "$TMPDIR"

printf 'body_bytes\tmessages\tpipeline\trun\telapsed_ms\tresponse_bytes\tthroughput_mib_s\tdatagrams_s\n'

for body_bytes in $BODY_BYTES; do
  case "$body_bytes" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_UDP_BODY_BYTES entries must be positive integers" ;;
  esac
  if [[ "$body_bytes" -lt 1 || "$body_bytes" -gt 65507 ]]; then
    smoke_die "RUSTLE_BENCH_AGENT_UDP_BODY_BYTES entries must be between 1 and 65507"
  fi

  smoke_stop_pid "${UDP_PID:-}"
  unset UDP_PID || true
  UDP_PORT="${RUSTLE_BENCH_AGENT_UDP_PORT:-$(smoke_find_free_port)}"
  UDP_READY="${TMPDIR}/udp-${body_bytes}.ready"
  UDP_LOG="${TMPDIR}/udp-${body_bytes}.log"
  "$(smoke_python)" - "$UDP_PORT" "$body_bytes" "$UDP_READY" >"$UDP_LOG" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
body_size = int(sys.argv[2])
ready = sys.argv[3]
body = b"u" * body_size

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write(str(port))

    while True:
        _, peer = sock.recvfrom(65535)
        sock.sendto(body, peer)
PY
  UDP_PID=$!

  if ! smoke_wait_for_file "$UDP_READY" 5; then
    sed 's/^/udp: /' "$UDP_LOG" >&2 || true
    smoke_die "agent UDP benchmark server did not start"
  fi

  for messages in $MESSAGES; do
    case "$messages" in
      '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_UDP_MESSAGES entries must be positive integers" ;;
    esac
    if [[ "$messages" -lt 1 ]]; then
      smoke_die "RUSTLE_BENCH_AGENT_UDP_MESSAGES entries must be at least 1"
    fi

    for pipeline in $PIPELINES; do
      case "$pipeline" in
        '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_UDP_PIPELINES entries must be positive integers" ;;
      esac
      if [[ "$pipeline" -lt 1 ]]; then
        smoke_die "RUSTLE_BENCH_AGENT_UDP_PIPELINES entries must be at least 1"
      fi

      total_runs=$((WARMUP_RUNS + RUNS))
      for ((run = 1; run <= total_runs; run++)); do
        out="${TMPDIR}/bench-agent-udp-${body_bytes}-${messages}-${pipeline}-${run}.out"
        err="${TMPDIR}/bench-agent-udp-${body_bytes}-${messages}-${pipeline}-${run}.err"
        set +e
        "$RUSTLE_BIN_RESOLVED" \
          agent-udp-lab \
          -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
          -i "$SMOKE_CLIENT_KEY" \
          --known-hosts "$SMOKE_KNOWN_HOSTS" \
          --agent-command "${RUSTLE_BENCH_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}" \
          --destination "127.0.0.1:${UDP_PORT}" \
          --request "$REQUEST" \
          --messages "$messages" \
          --pipeline "$pipeline" \
          --summary \
          >"$out" 2>"$err"
        status=$?
        set -e

        if [[ "$status" -ne 0 ]]; then
          sed 's/^/rustle stderr: /' "$err" >&2 || true
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "agent UDP benchmark exited with status ${status}"
        fi

        summary="$(tail -n 1 "$out")"
        response_bytes="$(printf '%s\n' "$summary" | sed -n 's/.* response_bytes=\([0-9][0-9]*\).*/\1/p')"
        elapsed_ms="$(printf '%s\n' "$summary" | sed -n 's/.* elapsed_ms=\([0-9][0-9]*\).*/\1/p')"
        summary_messages="$(printf '%s\n' "$summary" | sed -n 's/.* messages=\([0-9][0-9]*\).*/\1/p')"
        summary_pipeline="$(printf '%s\n' "$summary" | sed -n 's/.* pipeline=\([0-9][0-9]*\).*/\1/p')"
        if [[ -z "$response_bytes" || -z "$elapsed_ms" || -z "$summary_messages" || -z "$summary_pipeline" ]]; then
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "could not parse agent UDP benchmark summary"
        fi
        if [[ "$summary_messages" != "$messages" || "$summary_pipeline" != "$pipeline" ]]; then
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "agent UDP benchmark summary does not match requested messages/pipeline"
        fi

        expected_min=$((body_bytes * messages))
        if [[ "$response_bytes" -lt "$expected_min" ]]; then
          sed 's/^/rustle stdout: /' "$out" >&2 || true
          smoke_die "agent UDP benchmark returned ${response_bytes} bytes, expected at least ${expected_min}"
        fi

        if [[ "$run" -le "$WARMUP_RUNS" ]]; then
          continue
        fi

        measured_run=$((run - WARMUP_RUNS))
        if [[ "$elapsed_ms" -eq 0 ]]; then
          elapsed_ms=1
        fi
        read -r throughput datagrams_s < <("$(smoke_python)" - "$response_bytes" "$messages" "$elapsed_ms" <<'PY'
import sys

response_bytes = int(sys.argv[1])
messages = int(sys.argv[2])
elapsed_ms = int(sys.argv[3])
seconds = elapsed_ms / 1000
throughput = (response_bytes / (1024 * 1024)) / seconds
datagrams_s = messages / seconds
print(f"{throughput:.2f} {datagrams_s:.2f}")
PY
)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$body_bytes" "$messages" "$pipeline" "$measured_run" "$elapsed_ms" "$response_bytes" "$throughput" "$datagrams_s"
      done
    done
  done
done
