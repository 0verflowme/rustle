#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "live benchmark is implemented for macOS and Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=()
else
  smoke_require sudo
  sudo -n true >/dev/null 2>&1 || smoke_die "passwordless sudo is required for live benchmark"
  SUDO_CMD=(sudo -n)
fi

smoke_require curl
if [[ "$(uname -s)" == "Linux" ]]; then
  smoke_require ip
fi

REMOTE="${RUSTLE_BENCH_REMOTE:-${RUSTLE_LIVE_REMOTE:-}}"
TARGET_CIDR="${RUSTLE_BENCH_TARGET_CIDR:-${RUSTLE_LIVE_TARGET_CIDR:-}}"
URL="${RUSTLE_BENCH_URL:-${RUSTLE_LIVE_URL:-}}"
REQUESTS="${RUSTLE_BENCH_REQUESTS:-16}"
CONCURRENCY="${RUSTLE_BENCH_CONCURRENCY:-4}"
RUNS="${RUSTLE_BENCH_RUNS:-1}"
TOOLS="${RUSTLE_BENCH_TOOLS:-rustle}"
RUSTLE_TRANSPORTS="${RUSTLE_BENCH_RUSTLE_TRANSPORTS:-${RUSTLE_LIVE_RUSTLE_TRANSPORTS:-}}"
CURL_TIMEOUT="${RUSTLE_BENCH_CURL_TIMEOUT:-45}"
START_TIMEOUT="${RUSTLE_BENCH_START_TIMEOUT:-45}"
KEEP_LOGS="${RUSTLE_BENCH_KEEP_LOGS:-0}"
MIN_AGENT_SSHUTTLE_RATIO="${RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO:-}"
EXPECT_BYTES="${RUSTLE_BENCH_EXPECT_BYTES:-${RUSTLE_LIVE_EXPECT_BYTES:-}}"

[[ -n "$REMOTE" ]] || smoke_die "set RUSTLE_BENCH_REMOTE, for example user@ssh.example.com"
[[ -n "$TARGET_CIDR" ]] || smoke_die "set RUSTLE_BENCH_TARGET_CIDR, for example 192.168.0.0/16"
[[ -n "$URL" ]] || smoke_die "set RUSTLE_BENCH_URL, for example https://192.168.190.45/"

for value_name in REQUESTS CONCURRENCY RUNS; do
  value="${!value_name}"
  case "$value" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_${value_name} must be a positive integer" ;;
  esac
  if [[ "$value" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_${value_name} must be at least 1"
  fi
done
case "$START_TIMEOUT" in
  '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_START_TIMEOUT must be a positive integer" ;;
esac
if [[ -n "$MIN_AGENT_SSHUTTLE_RATIO" ]]; then
  "$(smoke_python)" - "$MIN_AGENT_SSHUTTLE_RATIO" <<'PY'
import sys

try:
    ratio = float(sys.argv[1])
except ValueError as exc:
    raise SystemExit("RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO must be a number") from exc
if ratio <= 0:
    raise SystemExit("RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO must be greater than 0")
PY
fi
if [[ -n "$EXPECT_BYTES" ]]; then
  case "$EXPECT_BYTES" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_EXPECT_BYTES must be a positive integer" ;;
  esac
  if [[ "$EXPECT_BYTES" -lt 1 ]]; then
    smoke_die "RUSTLE_BENCH_EXPECT_BYTES must be at least 1"
  fi
fi
if [[ "$CONCURRENCY" -gt "$REQUESTS" ]]; then
  CONCURRENCY="$REQUESTS"
fi
if [[ -z "$RUSTLE_TRANSPORTS" ]]; then
  RUSTLE_TRANSPORTS="${RUSTLE_BENCH_BRIDGE_TRANSPORT:-${RUSTLE_LIVE_BRIDGE_TRANSPORT:-}}"
fi
if [[ -z "$RUSTLE_TRANSPORTS" ]]; then
  RUSTLE_TRANSPORTS="agent direct-tcpip"
fi
for transport in $RUSTLE_TRANSPORTS; do
  case "$transport" in
    direct-tcpip | agent) ;;
    *) smoke_die "RUSTLE_BENCH_RUSTLE_TRANSPORTS entries must be direct-tcpip or agent" ;;
  esac
done

URL_ROUTE_PROBE_IP="${RUSTLE_BENCH_ROUTE_PROBE_IP:-}"
if [[ -z "$URL_ROUTE_PROBE_IP" ]]; then
  URL_ROUTE_PROBE_IP="$("$(smoke_python)" - "$URL" <<'PY'
import ipaddress
import socket
import sys
from urllib.parse import urlparse

host = urlparse(sys.argv[1]).hostname
if not host:
    raise SystemExit("benchmark URL must include a host")
try:
    print(ipaddress.ip_address(host))
except ValueError:
    print(socket.gethostbyname(host))
PY
)"
fi

cidr_parts() {
  "$(smoke_python)" - "$TARGET_CIDR" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=False)
print(network.network_address)
print(network.netmask)
print(network.prefixlen)
PY
}

CIDR_INFO="$(cidr_parts)"
TARGET_NETWORK="$(printf '%s\n' "$CIDR_INFO" | sed -n '1p')"
TARGET_NETMASK="$(printf '%s\n' "$CIDR_INFO" | sed -n '2p')"
TARGET_PREFIX="$(printf '%s\n' "$CIDR_INFO" | sed -n '3p')"

route_snapshot() {
  case "$(uname -s)" in
    Darwin)
      if [[ "$TARGET_PREFIX" == "0" ]]; then
        netstat -rn -f inet | grep -E '(^|[[:space:]])(0/1|0\.0\.0\.0/1|128\.0/1|128\.0\.0\.0/1)([[:space:]]|$)' || true
      else
        netstat -rn -f inet | grep -E "(^|[[:space:]])${TARGET_NETWORK//./\\.}([[:space:]]|/|$)" || true
      fi
      ;;
    Linux)
      if [[ "$TARGET_PREFIX" == "0" ]]; then
        { ip route show "0.0.0.0/1"; ip route show "128.0.0.0/1"; } || true
      else
        ip route show "$TARGET_CIDR" || true
      fi
      ;;
  esac
}

route_lookup_interface() {
  local probe_ip="$1"
  case "$(uname -s)" in
    Darwin)
      route -n get "$probe_ip" 2>/dev/null | awk '/interface:/{print $2; exit}'
      ;;
    Linux)
      ip route get "$probe_ip" 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) {
          if ($i == "dev") {
            print $(i + 1)
            exit
          }
        }
      }'
      ;;
  esac
}

route_lookup_dump() {
  local probe_ip="$1"
  case "$(uname -s)" in
    Darwin)
      route -n get "$probe_ip" 2>/dev/null || true
      ;;
    Linux)
      ip route get "$probe_ip" 2>/dev/null || true
      ;;
  esac
}

wait_for_route_interface() {
  local probe_ip="$1"
  local expected_if="$2"
  for ((i = 0; i < 50; i++)); do
    if [[ "$(route_lookup_interface "$probe_ip")" == "$expected_if" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

delete_target_route_best_effort() {
  case "$(uname -s)" in
    Darwin)
      if [[ "$TARGET_PREFIX" == "0" ]]; then
        "${SUDO_CMD[@]}" route -n delete -net 0.0.0.0 -netmask 128.0.0.0 \
          >/dev/null 2>&1 || true
        "${SUDO_CMD[@]}" route -n delete -net 128.0.0.0 -netmask 128.0.0.0 \
          >/dev/null 2>&1 || true
      elif [[ "$TARGET_PREFIX" == "32" ]]; then
        "${SUDO_CMD[@]}" route -n delete -host "$TARGET_NETWORK" \
          >/dev/null 2>&1 || true
      else
        "${SUDO_CMD[@]}" route -n delete -net "$TARGET_NETWORK" -netmask "$TARGET_NETMASK" \
          >/dev/null 2>&1 || true
      fi
      ;;
    Linux)
      if [[ "$TARGET_PREFIX" == "0" ]]; then
        "${SUDO_CMD[@]}" ip route del "0.0.0.0/1" >/dev/null 2>&1 || true
        "${SUDO_CMD[@]}" ip route del "128.0.0.0/1" >/dev/null 2>&1 || true
      else
        "${SUDO_CMD[@]}" ip route del "$TARGET_CIDR" >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-live-bench.XXXXXX")"
RESULTS_TSV="${TMPDIR}/live-results.tsv"
: >"$RESULTS_TSV"
ROUTE_BEFORE="$(route_snapshot)"
CURRENT_STOPPER=""
CURRENT_PASSWORD_FILE=""

cleanup() {
  local status="${1:-0}"
  if [[ -n "$CURRENT_STOPPER" ]]; then
    "$CURRENT_STOPPER" || true
  fi
  if [[ -n "$CURRENT_PASSWORD_FILE" ]]; then
    rm -f "$CURRENT_PASSWORD_FILE"
  fi
  local after
  after="$(route_snapshot)"
  if [[ "$after" != "$ROUTE_BEFORE" ]]; then
    delete_target_route_best_effort
  fi
  if [[ "$status" -ne 0 || "$KEEP_LOGS" == "1" ]]; then
    smoke_info "kept live benchmark logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
}
trap 'cleanup $?' EXIT

bench_now_ms() {
  "$(smoke_python)" - <<'PY'
import time
print(time.monotonic_ns() // 1_000_000)
PY
}

start_cpu_sampler() {
  local root_pid="$1"
  local out="$2"
  "$(smoke_python)" - "$root_pid" "$out" >"${out}.sampler.log" 2>&1 <<'PY' &
import subprocess
import sys
import time

root = int(sys.argv[1])
out = sys.argv[2]

def descendants(rows, pid):
    children = {}
    cpus = {}
    for row in rows:
        parts = row.strip().split(None, 2)
        if len(parts) != 3:
            continue
        child, parent, cpu = parts
        try:
            child_i = int(child)
            parent_i = int(parent)
            cpu_f = float(cpu)
        except ValueError:
            continue
        children.setdefault(parent_i, []).append(child_i)
        cpus[child_i] = cpu_f
    stack = [pid]
    seen = set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(children.get(current, []))
    return sum(cpus.get(pid, 0.0) for pid in seen)

with open(out, "w", encoding="utf-8") as handle:
    while True:
        try:
            subprocess.run(["kill", "-0", str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            break
        rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,%cpu="], text=True).splitlines()
        handle.write(f"{descendants(rows, root):.2f}\n")
        handle.flush()
        time.sleep(0.2)
PY
  printf '%s\n' "$!"
}

stop_sampler() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

write_password_file() {
  local path="$1"
  local password_value="$2"
  (umask 077 && printf '%s' "$password_value" >"$path")
}

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
RUSTLE_PASSWORD_VALUE="${RUSTLE_BENCH_PASSWORD_VALUE:-${RUSTLE_LIVE_PASSWORD_VALUE:-}}"
if [[ -z "$RUSTLE_PASSWORD_VALUE" && "${RUSTLE_BENCH_PASSWORD:-${RUSTLE_LIVE_PASSWORD:-0}}" == "1" ]]; then
  printf 'SSH password for Rustle: ' >&2
  IFS= read -r -s RUSTLE_PASSWORD_VALUE
  printf '\n' >&2
fi
SSHUTTLE_PASSWORD_VALUE="${RUSTLE_BENCH_SSHUTTLE_PASSWORD_VALUE:-}"
if [[ -z "$SSHUTTLE_PASSWORD_VALUE" && "${RUSTLE_BENCH_SSHUTTLE_PASSWORD:-0}" == "1" ]]; then
  smoke_require sshpass
  printf 'SSH password for sshuttle: ' >&2
  IFS= read -r -s SSHUTTLE_PASSWORD_VALUE
  printf '\n' >&2
fi

start_rustle() {
  local run_dir="$1"
  local transport="$2"
  local child_pid_file="${run_dir}/rustle.pid"
  local log="${run_dir}/rustle.log"
  local password_file=""
  local cmd_env=()
  local cmd=("$RUSTLE_BIN_RESOLVED" -r "$REMOTE")

  if [[ -n "${RUSTLE_BENCH_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}" ]]; then
    cmd+=(-i "${RUSTLE_BENCH_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}")
  fi
  if [[ -n "${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}" ]]; then
    cmd+=(--known-hosts "${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}")
  fi
  if [[ "${RUSTLE_BENCH_INSECURE_HOST_KEY:-${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}}" == "1" ]]; then
    cmd+=(--insecure-accept-host-key)
  fi
  if [[ -n "$RUSTLE_PASSWORD_VALUE" ]]; then
    password_file="${run_dir}/ssh-password"
    write_password_file "$password_file" "$RUSTLE_PASSWORD_VALUE"
    CURRENT_PASSWORD_FILE="$password_file"
    cmd+=(--password-file "$password_file")
  fi
  if [[ -n "$transport" ]]; then
    cmd+=(--bridge-transport "$transport")
  fi
  if [[ -n "${RUSTLE_BENCH_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}" ]]; then
    cmd+=(--agent-command "${RUSTLE_BENCH_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}")
  fi
  if [[ -n "${RUSTLE_BENCH_AGENT_SESSIONS:-${RUSTLE_LIVE_AGENT_SESSIONS:-}}" ]]; then
    cmd+=(--agent-sessions "${RUSTLE_BENCH_AGENT_SESSIONS:-${RUSTLE_LIVE_AGENT_SESSIONS:-}}")
  fi

  cmd+=("$TARGET_CIDR")

  if [[ "${#cmd_env[@]}" -gt 0 ]]; then
    "${SUDO_CMD[@]}" env "${cmd_env[@]}" sh -c 'trap - INT TERM; echo $$ > "$1"; shift; exec "$@"' \
      sh "$child_pid_file" "${cmd[@]}" >"$log" 2>&1 &
  else
    "${SUDO_CMD[@]}" env sh -c 'trap - INT TERM; echo $$ > "$1"; shift; exec "$@"' \
      sh "$child_pid_file" "${cmd[@]}" >"$log" 2>&1 &
  fi
  local wrapper_pid=$!
  RUSTLE_WRAPPER_PID="$wrapper_pid"
  RUSTLE_CHILD_PID=""
  CURRENT_STOPPER=stop_rustle

  if ! smoke_wait_for_file "$child_pid_file" 5; then
    sed 's/^/rustle: /' "$log" >&2 || true
    smoke_die "Rustle wrapper did not publish a child PID"
  fi
  RUSTLE_CHILD_PID="$(cat "$child_pid_file")"
  if ! smoke_wait_for_log_or_exit 'tun: created' "$log" "$START_TIMEOUT" "$RUSTLE_CHILD_PID" rustle; then
    sed 's/^/rustle: /' "$log" >&2 || true
    smoke_die "Rustle did not create a TUN device"
  fi
  if ! smoke_wait_for_rustle_target_route_logs \
    "$TARGET_PREFIX" "$TARGET_CIDR" "$log" "$START_TIMEOUT" "$RUSTLE_CHILD_PID" rustle; then
    sed 's/^/rustle: /' "$log" >&2 || true
    smoke_die "Rustle did not add the target route"
  fi

  local tun_if
  tun_if="$(sed -n 's/^tun: created \([^ ]*\) .*/\1/p' "$log" | tail -n 1)"
  if [[ -z "$tun_if" ]]; then
    sed 's/^/rustle: /' "$log" >&2 || true
    smoke_die "could not determine Rustle TUN interface name"
  fi
  if ! wait_for_route_interface "$URL_ROUTE_PROBE_IP" "$tun_if"; then
    printf 'route lookup for %s did not use %s:\n' "$URL_ROUTE_PROBE_IP" "$tun_if" >&2
    route_lookup_dump "$URL_ROUTE_PROBE_IP" >&2
    sed 's/^/rustle: /' "$log" >&2 || true
    smoke_die "benchmark target route is not using Rustle TUN"
  fi

  RUSTLE_LOG="$log"
}

stop_rustle() {
  [[ -n "${RUSTLE_WRAPPER_PID:-}" ]] || return 0
  if [[ -n "${RUSTLE_CHILD_PID:-}" ]]; then
    "${SUDO_CMD[@]}" kill -INT "$RUSTLE_CHILD_PID" >/dev/null 2>&1 \
      || kill -INT "$RUSTLE_CHILD_PID" >/dev/null 2>&1 \
      || true
  fi
  "${SUDO_CMD[@]}" kill -INT "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 \
    || kill -INT "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 \
    || true
  for ((i = 0; i < 100; i++)); do
    if ! kill -0 "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1; then
      wait "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 || true
      RUSTLE_WRAPPER_PID=""
      return 0
    fi
    sleep 0.1
  done
  if [[ -n "${RUSTLE_CHILD_PID:-}" ]]; then
    "${SUDO_CMD[@]}" kill -TERM "$RUSTLE_CHILD_PID" >/dev/null 2>&1 \
      || kill -TERM "$RUSTLE_CHILD_PID" >/dev/null 2>&1 \
      || true
  fi
  "${SUDO_CMD[@]}" kill -TERM "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 \
    || kill -TERM "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 \
    || true
  wait "$RUSTLE_WRAPPER_PID" >/dev/null 2>&1 || true
  RUSTLE_WRAPPER_PID=""
}

start_sshuttle() {
  local run_dir="$1"
  smoke_require sshuttle
  local log="${run_dir}/sshuttle.log"
  local remote="${RUSTLE_BENCH_SSHUTTLE_REMOTE:-$REMOTE}"
  local password_file=""
  local cmd=(sshuttle -r "$remote" "$TARGET_CIDR" --disable-ipv6)

  if [[ -n "${RUSTLE_BENCH_SSHUTTLE_METHOD:-}" ]]; then
    cmd+=(--method "$RUSTLE_BENCH_SSHUTTLE_METHOD")
  fi
  if [[ -n "${RUSTLE_BENCH_SSHUTTLE_SSH_CMD:-}" ]]; then
    cmd+=(-e "$RUSTLE_BENCH_SSHUTTLE_SSH_CMD")
  elif [[ -n "$SSHUTTLE_PASSWORD_VALUE" ]]; then
    smoke_require sshpass
    password_file="${run_dir}/sshuttle-password"
    (umask 077 && printf '%s\n' "$SSHUTTLE_PASSWORD_VALUE" >"$password_file")
    CURRENT_PASSWORD_FILE="$password_file"
    local ssh_cmd="sshpass -f ${password_file} ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o KbdInteractiveAuthentication=yes -o NumberOfPasswordPrompts=1"
    if [[ "${RUSTLE_BENCH_INSECURE_HOST_KEY:-${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}}" == "1" ]]; then
      ssh_cmd+=" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    elif [[ -n "${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}" ]]; then
      ssh_cmd+=" -o UserKnownHostsFile=${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}} -o StrictHostKeyChecking=yes"
    fi
    cmd+=(-e "$ssh_cmd")
  elif [[ -n "${RUSTLE_BENCH_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}" ]]; then
    local ssh_cmd="ssh -i ${RUSTLE_BENCH_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}} -o IdentitiesOnly=yes"
    if [[ -n "${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}" ]]; then
      ssh_cmd+=" -o UserKnownHostsFile=${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}} -o StrictHostKeyChecking=yes"
    fi
    cmd+=(-e "$ssh_cmd")
  fi

  "${SUDO_CMD[@]}" "${cmd[@]}" >"$log" 2>&1 &
  SSHUTTLE_PID=$!
  SSHUTTLE_LOG="$log"
  CURRENT_STOPPER=stop_sshuttle

  local probe_args=(
    --fail
    --show-error
    --silent
    --noproxy '*'
    --connect-timeout "${RUSTLE_BENCH_READY_CONNECT_TIMEOUT:-1}"
    --max-time "${RUSTLE_BENCH_READY_TIMEOUT:-2}"
  )
  if [[ "${RUSTLE_BENCH_CURL_INSECURE:-${RUSTLE_LIVE_CURL_INSECURE:-1}}" == "1" ]]; then
    probe_args+=(-k)
  fi
  local ready_method="${RUSTLE_BENCH_READY_METHOD:-GET}"
  case "$ready_method" in
    GET) ;;
    HEAD) probe_args+=(--head) ;;
    *) smoke_die "RUSTLE_BENCH_READY_METHOD must be GET or HEAD" ;;
  esac
  local ready_seconds="${RUSTLE_BENCH_READY_SECONDS:-30}"
  case "$ready_seconds" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_READY_SECONDS must be a positive integer" ;;
  esac
  local ready_deadline_ms
  ready_deadline_ms=$(( $(bench_now_ms) + ready_seconds * 1000 ))
  while [[ "$(bench_now_ms)" -lt "$ready_deadline_ms" ]]; do
    if ! smoke_process_running "$SSHUTTLE_PID"; then
      sed 's/^/sshuttle: /' "$log" >&2 || true
      smoke_die "sshuttle exited before benchmark traffic"
    fi
    if curl "${probe_args[@]}" "$URL" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  sed 's/^/sshuttle: /' "$log" >&2 || true
  smoke_die "sshuttle did not make benchmark URL reachable"
}

stop_sshuttle() {
  [[ -n "${SSHUTTLE_PID:-}" ]] || return 0
  smoke_interrupt_process_tree "$SSHUTTLE_PID" >/dev/null 2>&1 || true
  wait "$SSHUTTLE_PID" >/dev/null 2>&1 || true
  SSHUTTLE_PID=""
}

run_curl_batch() {
  local tool="$1"
  local run="$2"
  local out_dir="$3"
  local metrics_dir="${out_dir}/curl"
  mkdir -p "$metrics_dir"

  local curl_args=(--fail --show-error --silent --noproxy '*' --max-time "$CURL_TIMEOUT")
  if [[ "${RUSTLE_BENCH_CURL_INSECURE:-${RUSTLE_LIVE_CURL_INSECURE:-1}}" == "1" ]]; then
    curl_args+=(-k)
  fi

  local request_index=0
  local failed=0
  local started_ms
  local ended_ms
  started_ms="$(bench_now_ms)"
  while [[ "$request_index" -lt "$REQUESTS" ]]; do
    local pids=()
    local launched=0
    while [[ "$launched" -lt "$CONCURRENCY" && "$request_index" -lt "$REQUESTS" ]]; do
      local response_path="${metrics_dir}/${request_index}.body"
      local metric_path="${metrics_dir}/${request_index}.metric"
      local error_path="${metrics_dir}/${request_index}.err"
      curl "${curl_args[@]}" \
        -w "%{time_total}\t%{size_download}\n" \
        -o "$response_path" \
        "$URL" >"$metric_path" 2>"$error_path" &
      pids+=("$!")
      request_index=$((request_index + 1))
      launched=$((launched + 1))
    done
    for pid in "${pids[@]}"; do
      if ! wait "$pid"; then
        failed=$((failed + 1))
      fi
    done
  done
  ended_ms="$(bench_now_ms)"

  if [[ -n "${RUSTLE_BENCH_EXPECT:-${RUSTLE_LIVE_EXPECT:-}}" ]]; then
    for response_path in "$metrics_dir"/*.body; do
      if ! grep -q "${RUSTLE_BENCH_EXPECT:-${RUSTLE_LIVE_EXPECT:-}}" "$response_path"; then
        sed 's/^/curl: /' "$response_path" >&2 || true
        smoke_die "${tool} response did not contain expected text"
      fi
    done
  fi
  if [[ -n "$EXPECT_BYTES" ]]; then
    for metric_path in "$metrics_dir"/*.metric; do
      local size_download
      size_download="$(awk 'NF >= 2 { printf "%.0f", $2; exit }' "$metric_path")"
      if [[ "$size_download" != "$EXPECT_BYTES" ]]; then
        sed 's/^/curl: /' "${metric_path%.metric}.err" >&2 || true
        smoke_die "${tool} response downloaded ${size_download:-0} bytes, expected ${EXPECT_BYTES}"
      fi
    done
  fi

  "$(smoke_python)" - "$tool" "$run" "$REQUESTS" "$CONCURRENCY" "$failed" "$started_ms" "$ended_ms" "$metrics_dir" <<'PY'
import pathlib
import statistics
import sys

tool, run, requests, concurrency, failed, started_ms, ended_ms, metrics_dir = sys.argv[1:]
requests = int(requests)
concurrency = int(concurrency)
failed = int(failed)
started_ms = int(started_ms)
ended_ms = int(ended_ms)
metrics = pathlib.Path(metrics_dir)

latencies = []
bytes_total = 0
for path in sorted(metrics.glob("*.metric")):
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        continue
    parts = text.split()
    if len(parts) < 2:
        continue
    latencies.append(float(parts[0]) * 1000)
    bytes_total += int(float(parts[1]))

success = len(latencies)
wall_ms = max(ended_ms - started_ms, 1)
latencies.sort()

def percentile(values, pct):
    if not values:
        return 0.0
    index = max(0, min(len(values) - 1, int((pct / 100) * (len(values) - 1) + 0.999999)))
    return values[index]

throughput = (bytes_total / (1024 * 1024)) / (wall_ms / 1000)
req_s = success / (wall_ms / 1000)
print(
    f"{tool}\t{run}\t{requests}\t{concurrency}\t{success}\t{failed}\t"
    f"{wall_ms}\t{percentile(latencies, 50):.1f}\t{percentile(latencies, 95):.1f}\t"
    f"{bytes_total}\t{throughput:.2f}\t{req_s:.2f}"
)
PY
  if [[ "$failed" -ne 0 ]]; then
    return 2
  fi
}

run_curl_batch_with_timeout() {
  local out_file="$1"
  local tool="$2"
  local run="$3"
  local out_dir="$4"
  local batches=$(( (REQUESTS + CONCURRENCY - 1) / CONCURRENCY ))
  local default_timeout=$(( (CURL_TIMEOUT + 5) * batches + 10 ))
  local timeout_seconds="${RUSTLE_BENCH_BATCH_TIMEOUT_SECONDS:-$default_timeout}"
  case "$timeout_seconds" in
    '' | *[!0-9]*) smoke_die "RUSTLE_BENCH_BATCH_TIMEOUT_SECONDS must be a positive integer" ;;
  esac

  (
    run_curl_batch "$tool" "$run" "$out_dir"
  ) >"$out_file" &
  local batch_pid=$!
  local deadline_ms
  deadline_ms=$(( $(bench_now_ms) + timeout_seconds * 1000 ))

  while kill -0 "$batch_pid" >/dev/null 2>&1; do
    if [[ "$(bench_now_ms)" -ge "$deadline_ms" ]]; then
      kill -TERM "$batch_pid" >/dev/null 2>&1 || true
      wait "$batch_pid" >/dev/null 2>&1 || true
      return 124
    fi
    sleep 0.2
  done

  wait "$batch_pid"
}

cpu_summary() {
  local samples="$1"
  "$(smoke_python)" - "$samples" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
values = []
if path.exists():
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            values.append(float(line.strip()))
        except ValueError:
            pass
if not values:
    print("0.00\t0.00")
else:
    print(f"{sum(values) / len(values):.2f}\t{max(values):.2f}")
PY
}

rustle_extra_stats() {
  local log="$1"
  local final_stats
  final_stats="$(grep 'stats: final' "$log" | tail -n 1 || true)"
  if [[ -z "$final_stats" ]]; then
    printf '\t\t\t\t\t'
    return
  fi
  local ssh_opened
  local ssh_failed
  local agent_reconnect_attempts
  local agent_reconnect_ok
  local agent_reconnect_failed
  local backlog_overflow
  ssh_opened="$(smoke_stat_value "$final_stats" '.*ssh=open:([0-9]+) fail:.*')"
  ssh_failed="$(smoke_stat_value "$final_stats" '.*ssh=open:[0-9]+ fail:([0-9]+) eof:.*')"
  agent_reconnect_attempts="$(smoke_stat_value "$final_stats" '.*agent_reconnect=attempt:([0-9]+) ok:.*')"
  agent_reconnect_ok="$(smoke_stat_value "$final_stats" '.*agent_reconnect=attempt:[0-9]+ ok:([0-9]+) fail:.*')"
  agent_reconnect_failed="$(smoke_stat_value "$final_stats" '.*agent_reconnect=attempt:[0-9]+ ok:[0-9]+ fail:([0-9]+).*')"
  backlog_overflow="$(smoke_stat_value "$final_stats" '.*backlog_overflow:([0-9]+).*')"
  printf '%s\t%s\t%s\t%s\t%s\t%s' \
    "$ssh_opened" "$ssh_failed" \
    "$agent_reconnect_attempts" "$agent_reconnect_ok" "$agent_reconnect_failed" \
    "$backlog_overflow"
}

printf 'tool\trun\trequests\tconcurrency\tsuccess\tfailed\twall_ms\tp50_ms\tp95_ms\tbytes\tthroughput_mib_s\treq_s\tavg_cpu_pct\tmax_cpu_pct\tssh_opened\tssh_failed\tagent_reconnect_attempts\tagent_reconnect_ok\tagent_reconnect_failed\tbacklog_overflow\n'

for tool in $TOOLS; do
  case "$tool" in
    rustle | sshuttle) ;;
    *) smoke_die "unknown benchmark tool: ${tool}; expected rustle or sshuttle" ;;
  esac

  tool_transports="-"
  if [[ "$tool" == "rustle" ]]; then
    tool_transports="$RUSTLE_TRANSPORTS"
  fi

  for transport in $tool_transports; do
    tool_label="$tool"
    if [[ "$tool" == "rustle" ]]; then
      tool_label="rustle-${transport}"
    fi

    for ((run = 1; run <= RUNS; run++)); do
      run_dir="${TMPDIR}/${tool_label}-${run}"
      mkdir -p "$run_dir"
      CURRENT_STOPPER=""
      CURRENT_PASSWORD_FILE=""

      if [[ "$tool" == "rustle" ]]; then
        smoke_info "benchmarking Rustle ${transport} run ${run}/${RUNS}"
        start_rustle "$run_dir" "$transport"
        CURRENT_STOPPER=stop_rustle
        sample_pid="$RUSTLE_CHILD_PID"
      else
        smoke_info "benchmarking sshuttle run ${run}/${RUNS}"
        start_sshuttle "$run_dir"
        CURRENT_STOPPER=stop_sshuttle
        sample_pid="$SSHUTTLE_PID"
      fi

      cpu_samples="${run_dir}/cpu.samples"
      sampler_pid="$(start_cpu_sampler "$sample_pid" "$cpu_samples")"
      metrics_file="${run_dir}/batch.tsv"
      if ! run_curl_batch_with_timeout "$metrics_file" "$tool_label" "$run" "$run_dir"; then
        stop_sampler "$sampler_pid"
        if [[ "$tool" == "rustle" ]]; then
          tail -n 120 "$RUSTLE_LOG" 2>/dev/null | sed 's/^/rustle: /' >&2 || true
        elif [[ -n "${SSHUTTLE_LOG:-}" ]]; then
          tail -n 120 "$SSHUTTLE_LOG" 2>/dev/null | sed 's/^/sshuttle: /' >&2 || true
        fi
        smoke_die "${tool_label} benchmark request batch failed or timed out"
      fi
      metrics_line="$(cat "$metrics_file")"
      stop_sampler "$sampler_pid"

      if [[ "$tool" == "rustle" ]]; then
        stop_rustle
        CURRENT_STOPPER=""
        extra="$(rustle_extra_stats "$RUSTLE_LOG")"
      else
        stop_sshuttle
        CURRENT_STOPPER=""
        extra=$'\t\t\t\t\t'
      fi
      if [[ -n "$CURRENT_PASSWORD_FILE" ]]; then
        rm -f "$CURRENT_PASSWORD_FILE"
        CURRENT_PASSWORD_FILE=""
      fi

      cpu="$(cpu_summary "$cpu_samples")"
      row="$(printf '%s\t%s\t%s' "$metrics_line" "$cpu" "$extra")"
      printf '%s\n' "$row"
      printf '%s\n' "$row" >>"$RESULTS_TSV"

      after="$(route_snapshot)"
      if [[ "$after" != "$ROUTE_BEFORE" ]]; then
        delete_target_route_best_effort
      fi
    done
  done
done

if [[ -n "$MIN_AGENT_SSHUTTLE_RATIO" ]]; then
  "$(smoke_python)" - "$RESULTS_TSV" "$MIN_AGENT_SSHUTTLE_RATIO" <<'PY'
import collections
import sys

path = sys.argv[1]
min_ratio = float(sys.argv[2])

throughput = collections.defaultdict(list)
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 20:
            raise SystemExit(f"invalid live benchmark row: {line!r}")
        tool = parts[0]
        success = int(parts[4])
        failed = int(parts[5])
        if failed != 0 or success == 0:
            continue
        throughput[tool].append(float(parts[10]))

agent = throughput.get("rustle-agent")
sshuttle = throughput.get("sshuttle")
if not agent or not sshuttle:
    raise SystemExit(
        "RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO requires successful "
        "rustle-agent and sshuttle rows; set "
        'RUSTLE_BENCH_TOOLS="rustle sshuttle" and include agent in '
        "RUSTLE_BENCH_RUSTLE_TRANSPORTS"
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
PY
fi
