#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-reconnect-bench.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bench_bin)"
HELPER="${TMPDIR}/flaky-agent.sh"
RUNS="${RUSTLE_BENCH_RUNS:-3}"
WARMUP_RUNS="${RUSTLE_BENCH_WARMUP_RUNS:-1}"
CONNECTIONS="${RUSTLE_BENCH_AGENT_RECONNECT_CONNECTIONS:-4}"
MIN_COMPLETED="${RUSTLE_BENCH_AGENT_RECONNECT_MIN_COMPLETED:-2}"
DEADLINE_MS="${RUSTLE_BENCH_AGENT_RECONNECT_DEADLINE_MS:-6000}"
MAX_ELAPSED_MS="${RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS:-}"
MAX_P50_US="${RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US:-}"
export RUSTLE_SMOKE_HTTP_BODY_BYTES="${RUSTLE_BENCH_AGENT_RECONNECT_BODY_BYTES:-65536}"

for numeric in RUNS WARMUP_RUNS CONNECTIONS MIN_COMPLETED DEADLINE_MS RUSTLE_SMOKE_HTTP_BODY_BYTES; do
  case "${!numeric}" in
    '' | *[!0-9]*) smoke_die "${numeric} must be a non-negative integer" ;;
  esac
done
if [[ "$CONNECTIONS" -lt 1 ]]; then
  smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_CONNECTIONS must be at least 1"
fi
if [[ "$MIN_COMPLETED" -lt 1 || "$MIN_COMPLETED" -gt "$CONNECTIONS" ]]; then
  smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_MIN_COMPLETED must be between 1 and the connection count"
fi
if [[ "$DEADLINE_MS" -lt 1 ]]; then
  smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_DEADLINE_MS must be at least 1"
fi
if [[ "$RUNS" -lt 1 ]]; then
  smoke_die "RUSTLE_BENCH_RUNS must be at least 1"
fi
if [[ "$WARMUP_RUNS" -ge "$RUNS" ]]; then
  smoke_die "RUSTLE_BENCH_WARMUP_RUNS must be less than RUSTLE_BENCH_RUNS"
fi
if [[ "$RUSTLE_SMOKE_HTTP_BODY_BYTES" -lt 1 ]]; then
  smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_BODY_BYTES must be at least 1"
fi
if [[ -n "$MAX_ELAPSED_MS" ]]; then
  case "$MAX_ELAPSED_MS" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS must be a positive integer" ;;
  esac
  if [[ "$MAX_ELAPSED_MS" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS must be at least 1"
  fi
fi
if [[ -n "$MAX_P50_US" ]]; then
  case "$MAX_P50_US" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US must be a positive integer" ;;
  esac
  if [[ "$MAX_P50_US" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US must be at least 1"
  fi
fi

cat >"$HELPER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

marker="$1"
rustle_bin="$2"
mtu="${3:-1300}"

if [[ ! -f "$marker" ]]; then
  : >"$marker"
  python3 - "$mtu" <<'PY'
import struct
import sys

mtu = int(sys.argv[1])
sys.stdin.buffer.read(40)
payload = struct.pack(">HHIQ", 1, mtu, 65536, 15)
header = (
    b"RLA1"
    + bytes([1, 0])
    + struct.pack(">H", 0)
    + struct.pack(">Q", 0)
    + struct.pack(">I", 0)
    + struct.pack(">I", len(payload))
)
sys.stdout.buffer.write(header + payload)
sys.stdout.buffer.flush()
PY
  exit 0
fi

exec "$rustle_bin" agent
SH
chmod +x "$HELPER"

quote_arg() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

smoke_start_sshd "$TMPDIR"
smoke_start_http_server "$TMPDIR"

REQUEST=$'GET / HTTP/1.1\r\nHost: rustle-agent-reconnect-bench\r\nConnection: close\r\n\r\n'

printf 'connections\tmin_completed\trun\tcompleted\telapsed_ms\tresponse_bytes\tp50_us\tp95_us\tmax_us\n'

total_runs=$((RUNS + WARMUP_RUNS))
for run in $(seq 1 "$total_runs"); do
  marker="${TMPDIR}/flaky-agent-${run}.used"
  agent_command="$(quote_arg "$HELPER") $(quote_arg "$marker") $(quote_arg "$RUSTLE_BIN_RESOLVED") 1300"
  out="${TMPDIR}/agent-reconnect-${run}.out"
  err="${TMPDIR}/agent-reconnect-${run}.err"

  set +e
  "$RUSTLE_BIN_RESOLVED" \
    bridge-lab \
    -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
    -i "$SMOKE_CLIENT_KEY" \
    --known-hosts "$SMOKE_KNOWN_HOSTS" \
    --destination "127.0.0.1:${SMOKE_HTTP_PORT}" \
    --request "$REQUEST" \
    --connections "$CONNECTIONS" \
    --min-completed "$MIN_COMPLETED" \
    --deadline-ms "$DEADLINE_MS" \
    --bridge-transport agent \
    --agent-sessions 1 \
    --agent-command "$agent_command" \
    --summary \
    >"$out" 2>"$err"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    sed 's/^/rustle stderr: /' "$err" >&2 || true
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark exited with status ${status}"
  fi
  if ! grep -q 'agent: reconnecting after transport failure' "$err"; then
    sed 's/^/rustle stderr: /' "$err" >&2 || true
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark did not observe a reconnect"
  fi

  summary="$(tail -n 1 "$out")"
  summary_connections="$(printf '%s\n' "$summary" | sed -n 's/.* connections=\([0-9][0-9]*\).*/\1/p')"
  completed="$(printf '%s\n' "$summary" | sed -n 's/.* completed=\([0-9][0-9]*\).*/\1/p')"
  response_bytes="$(printf '%s\n' "$summary" | sed -n 's/.* response_bytes=\([0-9][0-9]*\).*/\1/p')"
  elapsed_ms="$(printf '%s\n' "$summary" | sed -n 's/.* elapsed_ms=\([0-9][0-9]*\).*/\1/p')"
  p50_us="$(printf '%s\n' "$summary" | sed -n 's/.* p50_us=\([0-9][0-9]*\).*/\1/p')"
  p95_us="$(printf '%s\n' "$summary" | sed -n 's/.* p95_us=\([0-9][0-9]*\).*/\1/p')"
  max_us="$(printf '%s\n' "$summary" | sed -n 's/.* max_us=\([0-9][0-9]*\).*/\1/p')"
  active_flows="$(printf '%s\n' "$summary" | sed -n 's/.* active_flows=\([0-9][0-9]*\).*/\1/p')"
  active_bridges="$(printf '%s\n' "$summary" | sed -n 's/.* active_bridges=\([0-9][0-9]*\).*/\1/p')"
  backlog_flows="$(printf '%s\n' "$summary" | sed -n 's/.* backlog_flows=\([0-9][0-9]*\).*/\1/p')"
  backlog_bytes="$(printf '%s\n' "$summary" | sed -n 's/.* backlog_bytes=\([0-9][0-9]*\).*/\1/p')"

  if [[ -z "$summary_connections" || -z "$completed" || -z "$response_bytes" || -z "$elapsed_ms" || -z "$p50_us" || -z "$p95_us" || -z "$max_us" || -z "$active_flows" || -z "$active_bridges" || -z "$backlog_flows" || -z "$backlog_bytes" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "could not parse agent reconnect benchmark summary"
  fi
  if [[ "$summary_connections" != "$CONNECTIONS" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark summary reported ${summary_connections} connections, expected ${CONNECTIONS}"
  fi
  if [[ "$completed" -lt "$MIN_COMPLETED" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark completed ${completed} flows, expected at least ${MIN_COMPLETED}"
  fi
  expected_min=$((RUSTLE_SMOKE_HTTP_BODY_BYTES * completed))
  if [[ "$response_bytes" -lt "$expected_min" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark returned ${response_bytes} bytes, expected at least ${expected_min}"
  fi
  if [[ "$active_flows" -ne 0 || "$active_bridges" -ne 0 || "$backlog_flows" -ne 0 || "$backlog_bytes" -ne 0 ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect benchmark leaked lifecycle state: active_flows=${active_flows} active_bridges=${active_bridges} backlog_flows=${backlog_flows} backlog_bytes=${backlog_bytes}"
  fi
  if [[ -n "$MAX_ELAPSED_MS" && "$elapsed_ms" -gt "$MAX_ELAPSED_MS" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect elapsed_ms=${elapsed_ms} exceeded max ${MAX_ELAPSED_MS}"
  fi
  if [[ -n "$MAX_P50_US" && "$p50_us" -gt "$MAX_P50_US" ]]; then
    sed 's/^/rustle stdout: /' "$out" >&2 || true
    smoke_die "agent reconnect p50_us=${p50_us} exceeded max ${MAX_P50_US}"
  fi

  if [[ "$run" -le "$WARMUP_RUNS" ]]; then
    continue
  fi
  measured_run=$((run - WARMUP_RUNS))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$CONNECTIONS" "$MIN_COMPLETED" "$measured_run" "$completed" "$elapsed_ms" "$response_bytes" "$p50_us" "$p95_us" "$max_us"
done
