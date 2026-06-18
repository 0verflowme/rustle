#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "live UDP smoke is implemented for macOS and Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=(env)
else
  smoke_require sudo
  sudo -n true >/dev/null 2>&1 || smoke_die "passwordless sudo is required for live UDP smoke"
  SUDO_CMD=(sudo -n)
fi

smoke_require ssh
if [[ "$(uname -s)" == "Linux" ]]; then
  smoke_require ip
fi

REMOTE="${RUSTLE_LIVE_UDP_REMOTE:-${RUSTLE_LIVE_REMOTE:-}}"
FIXTURE_HOST="${RUSTLE_LIVE_UDP_HOST:-${RUSTLE_LIVE_HOST:-}}"
FIXTURE_BIND="${RUSTLE_LIVE_UDP_BIND:-0.0.0.0}"
FIXTURE_PORT="${RUSTLE_LIVE_UDP_PORT:-0}"
FIXTURE_PYTHON="${RUSTLE_LIVE_UDP_PYTHON:-python3}"
TARGET_CIDR="${RUSTLE_LIVE_UDP_TARGET_CIDR:-${RUSTLE_LIVE_TARGET_CIDR:-}}"
MESSAGES="${RUSTLE_LIVE_UDP_MESSAGES:-3}"
UDP_IDLE_TIMEOUT_MS="${RUSTLE_LIVE_UDP_IDLE_TIMEOUT_MS:-500}"
UDP_IDLE_GRACE_MS="${RUSTLE_LIVE_UDP_IDLE_GRACE_MS:-1500}"
START_TIMEOUT="${RUSTLE_LIVE_UDP_START_TIMEOUT:-45}"
BRIDGE_TRANSPORT="${RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT:-agent}"
FIXTURE_TTL_SECONDS="${RUSTLE_LIVE_UDP_FIXTURE_TTL_SECONDS:-300}"

[[ -n "$REMOTE" ]] || smoke_die "set RUSTLE_LIVE_UDP_REMOTE or RUSTLE_LIVE_REMOTE, for example user@ssh.example.com"
[[ -n "$FIXTURE_HOST" ]] || smoke_die "set RUSTLE_LIVE_UDP_HOST to the remote IP reachable through Rustle, for example 192.168.190.45"
if [[ -z "$TARGET_CIDR" ]]; then
  TARGET_CIDR="${FIXTURE_HOST}/32"
fi

for value_name in FIXTURE_PORT MESSAGES UDP_IDLE_TIMEOUT_MS UDP_IDLE_GRACE_MS START_TIMEOUT; do
  value="${!value_name}"
  case "$value" in
    '' | *[!0-9]*) smoke_die "${value_name/RUSTLE_/RUSTLE_LIVE_UDP_} must be a non-negative integer" ;;
  esac
done
case "$FIXTURE_TTL_SECONDS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_UDP_FIXTURE_TTL_SECONDS must be a positive integer" ;;
esac
if [[ "$MESSAGES" -lt 1 ]]; then
  smoke_die "RUSTLE_LIVE_UDP_MESSAGES must be at least 1"
fi
if [[ "$UDP_IDLE_TIMEOUT_MS" -lt 1 ]]; then
  smoke_die "RUSTLE_LIVE_UDP_IDLE_TIMEOUT_MS must be at least 1"
fi
if [[ "$UDP_IDLE_GRACE_MS" -le "$UDP_IDLE_TIMEOUT_MS" ]]; then
  smoke_die "RUSTLE_LIVE_UDP_IDLE_GRACE_MS must be greater than RUSTLE_LIVE_UDP_IDLE_TIMEOUT_MS"
fi
if [[ "$FIXTURE_TTL_SECONDS" -lt 1 ]]; then
  smoke_die "RUSTLE_LIVE_UDP_FIXTURE_TTL_SECONDS must be at least 1"
fi
case "$BRIDGE_TRANSPORT" in
  agent|auto-quic|quic-agent|quic-native) ;;
  *) smoke_die "RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT must be agent, auto-quic, quic-agent, or quic-native" ;;
esac
if [[ -n "${RUSTLE_LIVE_UDP_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}" && -n "${RUSTLE_LIVE_UDP_AGENT_PATH:-${RUSTLE_LIVE_AGENT_PATH:-}}" ]]; then
  smoke_die "RUSTLE_LIVE_UDP_AGENT_COMMAND/RUSTLE_LIVE_AGENT_COMMAND cannot be combined with RUSTLE_LIVE_UDP_AGENT_PATH/RUSTLE_LIVE_AGENT_PATH"
fi
if [[ "$BRIDGE_TRANSPORT" == "auto-quic" && -n "${RUSTLE_LIVE_UDP_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}" ]]; then
  smoke_die "auto-quic needs distinct quic-bridge-agent and agent helper commands; use RUSTLE_LIVE_UDP_AGENT_PATH/RUSTLE_LIVE_AGENT_PATH or sidecar upload instead of RUSTLE_LIVE_UDP_AGENT_COMMAND/RUSTLE_LIVE_AGENT_COMMAND"
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-live-udp-smoke.XXXXXX")"
RUSTLE_PID=""
RUSTLE_CHILD_PID_FILE="${TMPDIR}/rustle.pid"
FIXTURE_PID=""
FIXTURE_REMOTE_PID=""
FIXTURE_PASSWORD_FILE=""
RUSTLE_PASSWORD_FILE=""

parse_ssh_remote() {
  local remote="$1"
  if [[ "$remote" =~ ^([^@]+@)?([^:]+):([0-9]+)$ ]]; then
    printf '%s%s\n%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  else
    printf '%s\n\n' "$remote"
  fi
}

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

ROUTE_BEFORE="$(route_snapshot)"

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

stop_fixture() {
  if [[ -n "$FIXTURE_REMOTE_PID" ]]; then
    "${SSH_CMD[@]}" "kill ${FIXTURE_REMOTE_PID} >/dev/null 2>&1 || true" \
      >/dev/null 2>&1 || true
    FIXTURE_REMOTE_PID=""
  fi
  if [[ -n "$FIXTURE_PID" ]]; then
    kill "$FIXTURE_PID" >/dev/null 2>&1 || true
    wait "$FIXTURE_PID" >/dev/null 2>&1 || true
    FIXTURE_PID=""
  fi
}

stop_rustle() {
  [[ -n "$RUSTLE_PID" ]] || return 0

  local child_pid=""
  if [[ -s "$RUSTLE_CHILD_PID_FILE" ]]; then
    read -r child_pid <"$RUSTLE_CHILD_PID_FILE" || child_pid=""
  fi

  if [[ -n "$child_pid" ]]; then
    "${SUDO_CMD[@]}" kill -INT "$child_pid" >/dev/null 2>&1 \
      || kill -INT "$child_pid" >/dev/null 2>&1 \
      || true
  fi
  "${SUDO_CMD[@]}" kill -INT "$RUSTLE_PID" >/dev/null 2>&1 \
    || kill -INT "$RUSTLE_PID" >/dev/null 2>&1 \
    || true

  for ((i = 0; i < 100; i++)); do
    if ! kill -0 "$RUSTLE_PID" >/dev/null 2>&1; then
      wait "$RUSTLE_PID" >/dev/null 2>&1 || true
      RUSTLE_PID=""
      return 0
    fi
    sleep 0.1
  done

  if [[ -n "$child_pid" ]]; then
    "${SUDO_CMD[@]}" kill -TERM "$child_pid" >/dev/null 2>&1 \
      || kill -TERM "$child_pid" >/dev/null 2>&1 \
      || true
  fi
  "${SUDO_CMD[@]}" kill -TERM "$RUSTLE_PID" >/dev/null 2>&1 \
    || kill -TERM "$RUSTLE_PID" >/dev/null 2>&1 \
    || true
  wait "$RUSTLE_PID" >/dev/null 2>&1 || true
  RUSTLE_PID=""
}

cleanup() {
  local status="${1:-0}"
  stop_rustle
  stop_fixture
  if [[ -n "$FIXTURE_PASSWORD_FILE" ]]; then
    rm -f "$FIXTURE_PASSWORD_FILE"
  fi
  if [[ -n "$RUSTLE_PASSWORD_FILE" ]]; then
    rm -f "$RUSTLE_PASSWORD_FILE"
  fi
  local after
  after="$(route_snapshot)"
  if [[ "$after" != "$ROUTE_BEFORE" ]]; then
    delete_target_route_best_effort
  fi
  if [[ "$status" -ne 0 || "${RUSTLE_LIVE_UDP_KEEP_LOGS:-0}" == "1" ]]; then
    smoke_info "kept live UDP smoke logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
}
trap 'cleanup $?' EXIT

SSH_REMOTE_INFO="$(parse_ssh_remote "${RUSTLE_LIVE_UDP_SSH_REMOTE:-$REMOTE}")"
SSH_REMOTE="$(printf '%s\n' "$SSH_REMOTE_INFO" | sed -n '1p')"
SSH_PORT="$(printf '%s\n' "$SSH_REMOTE_INFO" | sed -n '2p')"
LIVE_IDENTITY="${RUSTLE_LIVE_UDP_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}"
LIVE_SSH_CONFIG="${RUSTLE_LIVE_UDP_SSH_CONFIG:-${RUSTLE_LIVE_SSH_CONFIG:-}}"
LIVE_INSECURE_HOST_KEY="${RUSTLE_LIVE_UDP_INSECURE_HOST_KEY:-${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}}"
LIVE_KNOWN_HOSTS="${RUSTLE_LIVE_UDP_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}"
SSH_PASSWORD_VALUE="${RUSTLE_LIVE_UDP_PASSWORD_VALUE:-${RUSTLE_LIVE_PASSWORD_VALUE:-}}"
if [[ -z "$SSH_PASSWORD_VALUE" && "${RUSTLE_LIVE_UDP_PASSWORD:-0}" == "1" ]]; then
  printf 'SSH password for live UDP smoke: ' >&2
  IFS= read -r -s SSH_PASSWORD_VALUE
  printf '\n' >&2
fi

SSH_CMD=()
if [[ -n "$SSH_PASSWORD_VALUE" ]]; then
  smoke_require sshpass
  FIXTURE_PASSWORD_FILE="${TMPDIR}/fixture-ssh-password"
  (umask 077 && printf '%s\n' "$SSH_PASSWORD_VALUE" >"$FIXTURE_PASSWORD_FILE")
  SSH_CMD=(sshpass -f "$FIXTURE_PASSWORD_FILE" ssh)
else
  SSH_CMD=(ssh)
fi
SSH_CMD+=(-T)
if [[ -n "$SSH_PORT" ]]; then
  SSH_CMD+=(-p "$SSH_PORT")
fi
if [[ -n "$LIVE_SSH_CONFIG" ]]; then
  SSH_CMD+=(-F "$LIVE_SSH_CONFIG")
fi
if [[ -n "$LIVE_IDENTITY" ]]; then
  SSH_CMD+=(-i "$LIVE_IDENTITY" -o IdentitiesOnly=yes)
fi
if [[ "$LIVE_INSECURE_HOST_KEY" == "1" ]]; then
  SSH_CMD+=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
elif [[ -n "$LIVE_KNOWN_HOSTS" ]]; then
  SSH_CMD+=(-o UserKnownHostsFile="$LIVE_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
fi
if [[ -n "$SSH_PASSWORD_VALUE" ]]; then
  SSH_CMD+=(
    -o PubkeyAuthentication=no
    -o PreferredAuthentications=password,keyboard-interactive
    -o KbdInteractiveAuthentication=yes
    -o NumberOfPasswordPrompts=1
  )
fi
SSH_CMD+=("$SSH_REMOTE")

write_rustle_password_file() {
  local password_value="$1"
  RUSTLE_PASSWORD_FILE="${TMPDIR}/rustle-ssh-password"
  (umask 077 && printf '%s' "$password_value" >"$RUSTLE_PASSWORD_FILE")
}

wait_for_fixture_ready() {
  local ready_file="$1"
  local err_file="$2"
  local seconds="${RUSTLE_LIVE_UDP_READY_SECONDS:-15}"
  case "$seconds" in
    '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_UDP_READY_SECONDS must be a positive integer" ;;
  esac
  local attempts=$((seconds * 10))
  for ((i = 0; i < attempts; i++)); do
    if grep -Eq '^READY [0-9]+ [0-9]+$' "$ready_file" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$FIXTURE_PID" ]] && ! smoke_process_running "$FIXTURE_PID"; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

start_udp_fixture() {
  local out_file="$1"
  local err_file="$2"
  local start_retries="${RUSTLE_LIVE_UDP_FIXTURE_START_RETRIES:-3}"

  case "$start_retries" in
    '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_UDP_FIXTURE_START_RETRIES must be a positive integer" ;;
  esac
  if [[ "$start_retries" -lt 1 ]]; then
    smoke_die "RUSTLE_LIVE_UDP_FIXTURE_START_RETRIES must be at least 1"
  fi

  for ((attempt = 1; attempt <= start_retries; attempt++)); do
    : >"$out_file"
    : >"$err_file"
    FIXTURE_PID=""
    "${SSH_CMD[@]}" "$FIXTURE_PYTHON" - "$FIXTURE_BIND" "$FIXTURE_PORT" "$FIXTURE_TTL_SECONDS" \
      >"$out_file" 2>"$err_file" <<'PY' &
from __future__ import print_function
import os
import socket
import sys
import time

bind = sys.argv[1]
port = int(sys.argv[2])
ttl_seconds = int(sys.argv[3])
response_prefix = b"rustle-live-udp-pong:"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.settimeout(1.0)
    deadline = time.time() + ttl_seconds
    sys.stdout.write("READY %d %d\n" % (sock.getsockname()[1], os.getpid()))
    sys.stdout.flush()
    while time.time() < deadline:
        try:
            data, peer = sock.recvfrom(65535)
        except socket.timeout:
            continue
        sock.sendto(response_prefix + data, peer)
finally:
    sock.close()
PY
    FIXTURE_PID=$!
    if wait_for_fixture_ready "$out_file" "$err_file"; then
      return 0
    fi
    stop_fixture
    if [[ "$attempt" -lt "$start_retries" ]]; then
      smoke_info "remote live UDP fixture startup attempt ${attempt}/${start_retries} failed; retrying"
      sleep 1
    fi
  done

  sed 's/^/fixture: /' "$err_file" >&2 || true
  smoke_die "remote live UDP fixture did not become ready after ${start_retries} attempt(s)"
}

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bench_bin)"
FIXTURE_OUT="${TMPDIR}/fixture.out"
FIXTURE_ERR="${TMPDIR}/fixture.err"
RUSTLE_LOG="${TMPDIR}/rustle.log"

start_udp_fixture "$FIXTURE_OUT" "$FIXTURE_ERR"
ACTUAL_PORT="$(awk '/^READY / { print $2 }' "$FIXTURE_OUT" | tail -n 1)"
FIXTURE_REMOTE_PID="$(awk '/^READY / { print $3 }' "$FIXTURE_OUT" | tail -n 1)"

CMD_ENV=()
if [[ -n "${RUSTLE_AGENT_DIR:-}" ]]; then
  CMD_ENV+=(RUSTLE_AGENT_DIR="$RUSTLE_AGENT_DIR")
fi

CMD=(
  "$RUSTLE_BIN_RESOLVED"
  -r "$REMOTE"
)
if [[ -n "${RUSTLE_LIVE_UDP_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}" ]]; then
  CMD+=(-i "${RUSTLE_LIVE_UDP_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}")
fi
if [[ -n "$LIVE_SSH_CONFIG" ]]; then
  CMD+=(--ssh-config "$LIVE_SSH_CONFIG")
fi
if [[ -n "${RUSTLE_LIVE_UDP_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}" ]]; then
  CMD+=(--known-hosts "${RUSTLE_LIVE_UDP_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}")
fi
if [[ "${RUSTLE_LIVE_UDP_INSECURE_HOST_KEY:-${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}}" == "1" ]]; then
  CMD+=(--insecure-accept-host-key)
fi
if [[ -n "$SSH_PASSWORD_VALUE" ]]; then
  write_rustle_password_file "$SSH_PASSWORD_VALUE"
  CMD+=(--password-file "$RUSTLE_PASSWORD_FILE")
elif [[ "${RUSTLE_LIVE_UDP_RUSTLE_PASSWORD:-0}" == "1" ]]; then
  printf 'SSH password for Rustle: ' >&2
  IFS= read -r -s rustle_password_value
  printf '\n' >&2
  write_rustle_password_file "$rustle_password_value"
  unset rustle_password_value
  CMD+=(--password-file "$RUSTLE_PASSWORD_FILE")
fi
CMD+=(--bridge-transport "$BRIDGE_TRANSPORT")
if [[ -n "${RUSTLE_LIVE_UDP_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}" ]]; then
  CMD+=(--agent-command "${RUSTLE_LIVE_UDP_AGENT_COMMAND:-${RUSTLE_LIVE_AGENT_COMMAND:-}}")
fi
if [[ -n "${RUSTLE_LIVE_UDP_AGENT_PATH:-${RUSTLE_LIVE_AGENT_PATH:-}}" ]]; then
  CMD+=(--agent-path "${RUSTLE_LIVE_UDP_AGENT_PATH:-${RUSTLE_LIVE_AGENT_PATH:-}}")
fi
if [[ -n "${RUSTLE_LIVE_UDP_AGENT_SESSIONS:-${RUSTLE_LIVE_AGENT_SESSIONS:-}}" ]]; then
  CMD+=(--agent-sessions "${RUSTLE_LIVE_UDP_AGENT_SESSIONS:-${RUSTLE_LIVE_AGENT_SESSIONS:-}}")
fi
CMD+=(--udp-idle-timeout-ms "$UDP_IDLE_TIMEOUT_MS")
CMD+=("$TARGET_CIDR")

smoke_info "starting live UDP smoke to ${REMOTE} for ${TARGET_CIDR}; fixture=${FIXTURE_HOST}:${ACTUAL_PORT}; log: ${RUSTLE_LOG}"
"${SUDO_CMD[@]}" env "${CMD_ENV[@]}" sh -c 'trap - INT TERM; echo $$ > "$1"; shift; exec "$@"' \
  sh "$RUSTLE_CHILD_PID_FILE" "${CMD[@]}" >"$RUSTLE_LOG" 2>&1 &
RUSTLE_PID=$!

if ! smoke_wait_for_file "$RUSTLE_CHILD_PID_FILE" 5; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle wrapper did not publish a child PID"
fi
read -r RUSTLE_CHILD_PID <"$RUSTLE_CHILD_PID_FILE" || RUSTLE_CHILD_PID=""

if ! smoke_wait_for_log_or_exit 'tun: created' "$RUSTLE_LOG" "$START_TIMEOUT" "$RUSTLE_CHILD_PID" rustle; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not create a TUN device"
fi
if ! smoke_wait_for_rustle_target_route_logs \
  "$TARGET_PREFIX" "$TARGET_CIDR" "$RUSTLE_LOG" "$START_TIMEOUT" "$RUSTLE_CHILD_PID" rustle; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not add the live UDP target route"
fi

TUN_IF_NAME="$(sed -n 's/^tun: created \([^ ]*\) .*/\1/p' "$RUSTLE_LOG" | tail -n 1)"
if [[ -z "$TUN_IF_NAME" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "could not determine Rustle TUN interface name"
fi
if ! wait_for_route_interface "$FIXTURE_HOST" "$TUN_IF_NAME"; then
  printf 'route lookup for %s did not use %s:\n' "$FIXTURE_HOST" "$TUN_IF_NAME" >&2
  route_lookup_dump "$FIXTURE_HOST" >&2
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "live UDP target route is not using Rustle TUN"
fi

smoke_info "sending ${MESSAGES} UDP datagram(s) to ${FIXTURE_HOST}:${ACTUAL_PORT}"
"$(smoke_python)" - "$FIXTURE_HOST" "$ACTUAL_PORT" "$MESSAGES" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
messages = int(sys.argv[3])
response_prefix = b"rustle-live-udp-pong:"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(10)
    for index in range(messages):
        request = ("rustle-live-udp-ping-%d" % index).encode("ascii")
        expected = response_prefix + request
        sock.sendto(request, (host, port))
        data, peer = sock.recvfrom(65535)
        if data != expected:
            raise SystemExit("unexpected UDP response %r from %r" % (data, peer))
        if peer[0] != host or peer[1] != port:
            raise SystemExit("unexpected UDP response peer %r" % (peer,))

print("live UDP smoke response ok")
PY

if ! smoke_wait_for_log "udp: forwarding datagram .* -> ${FIXTURE_HOST}:${ACTUAL_PORT} over " "$RUSTLE_LOG" 5; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not log generic UDP forwarding"
fi

smoke_info "waiting for UDP association idle cleanup"
"$(smoke_python)" - "$UDP_IDLE_GRACE_MS" <<'PY'
import sys
import time

time.sleep(int(sys.argv[1]) / 1000.0)
PY

stop_rustle

FINAL_STATS="$(grep 'stats: final' "$RUSTLE_LOG" | tail -n 1 || true)"
if [[ -z "$FINAL_STATS" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not print final stats during live UDP smoke shutdown"
fi

TUN_RX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_rx=([0-9]+)/.*')"
TUN_TX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_tx=([0-9]+)/.*')"
UDP_FORWARDED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:([0-9]+) ok:.*')"
UDP_OK="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:([0-9]+) fail:.*')"
UDP_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:([0-9]+) drop:.*')"
UDP_DROPPED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:([0-9]+) active:.*')"
UDP_ACTIVE="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:[0-9]+ active:([0-9]+).*')"
BRIDGE_SEND_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*bridge_send_fail:([0-9]+).*')"
BACKLOG_OVERFLOWED="$(smoke_stat_value "$FINAL_STATS" '.*backlog_overflow:([0-9]+).*')"
BRIDGE_EVENT_QUEUE_REMOTE_BYTES="$(smoke_stat_value "$FINAL_STATS" '.*bridge_event_queue=.* remote_bytes_raw:([0-9]+) max_raw:.*')"

smoke_require_stat_at_least "TUN RX packets" "$TUN_RX_PACKETS" "$MESSAGES" "$FINAL_STATS"
smoke_require_stat_at_least "TUN TX packets" "$TUN_TX_PACKETS" "$MESSAGES" "$FINAL_STATS"
smoke_require_stat_at_least "UDP forwarded" "$UDP_FORWARDED" "$MESSAGES" "$FINAL_STATS"
smoke_require_stat_at_least "UDP successes" "$UDP_OK" "$MESSAGES" "$FINAL_STATS"
smoke_require_stat_zero "UDP failures" "$UDP_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "UDP drops" "$UDP_DROPPED" "$FINAL_STATS"
smoke_require_stat_zero "UDP active associations" "$UDP_ACTIVE" "$FINAL_STATS"
smoke_require_stat_zero "bridge send failures" "$BRIDGE_SEND_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "remote backlog overflows" "$BACKLOG_OVERFLOWED" "$FINAL_STATS"
smoke_require_stat_zero "bridge event queued remote bytes" "$BRIDGE_EVENT_QUEUE_REMOTE_BYTES" "$FINAL_STATS"

ROUTE_AFTER="$(route_snapshot)"
if [[ "$ROUTE_AFTER" != "$ROUTE_BEFORE" ]]; then
  printf 'before route snapshot:\n%s\n' "$ROUTE_BEFORE" >&2
  printf 'after route snapshot:\n%s\n' "$ROUTE_AFTER" >&2
  smoke_die "live UDP target route table did not return to its original state"
fi

smoke_info "live UDP smoke passed"
