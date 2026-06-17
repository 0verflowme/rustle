#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "live tunnel smoke is implemented for macOS and Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=(env)
else
  smoke_require sudo
  sudo -n true >/dev/null 2>&1 || smoke_die "passwordless sudo is required for live tunnel smoke"
  SUDO_CMD=(sudo -n)
fi

smoke_require curl
if [[ "$(uname -s)" == "Linux" ]]; then
  smoke_require ip
fi

REMOTE="${RUSTLE_LIVE_REMOTE:-}"
TARGET_CIDR="${RUSTLE_LIVE_TARGET_CIDR:-}"
URL="${RUSTLE_LIVE_URL:-}"
REQUESTS="${RUSTLE_LIVE_REQUESTS:-1}"
CONCURRENCY="${RUSTLE_LIVE_CONCURRENCY:-1}"
START_TIMEOUT="${RUSTLE_LIVE_START_TIMEOUT:-45}"
BRIDGE_TRANSPORT="${RUSTLE_LIVE_BRIDGE_TRANSPORT:-agent}"

[[ -n "$REMOTE" ]] || smoke_die "set RUSTLE_LIVE_REMOTE, for example user@ssh.example.com"
[[ -n "$TARGET_CIDR" ]] || smoke_die "set RUSTLE_LIVE_TARGET_CIDR, for example 192.168.0.0/16"
[[ -n "$URL" ]] || smoke_die "set RUSTLE_LIVE_URL, for example https://192.168.190.45/"
case "$REQUESTS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_REQUESTS must be a positive integer" ;;
esac
case "$CONCURRENCY" in
  '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_CONCURRENCY must be a positive integer" ;;
esac
case "$START_TIMEOUT" in
  '' | *[!0-9]*) smoke_die "RUSTLE_LIVE_START_TIMEOUT must be a positive integer" ;;
esac
if [[ "$REQUESTS" -lt 1 ]]; then
  smoke_die "RUSTLE_LIVE_REQUESTS must be at least 1"
fi
if [[ "$CONCURRENCY" -lt 1 ]]; then
  smoke_die "RUSTLE_LIVE_CONCURRENCY must be at least 1"
fi
if [[ "$CONCURRENCY" -gt "$REQUESTS" ]]; then
  CONCURRENCY="$REQUESTS"
fi

URL_ROUTE_PROBE_IP="${RUSTLE_LIVE_ROUTE_PROBE_IP:-}"
if [[ -z "$URL_ROUTE_PROBE_IP" ]]; then
  URL_ROUTE_PROBE_IP="$("$(smoke_python)" - "$URL" <<'PY'
import ipaddress
import socket
import sys
from urllib.parse import urlparse

host = urlparse(sys.argv[1]).hostname
if not host:
    raise SystemExit("RUSTLE_LIVE_URL must include a host")
try:
    print(ipaddress.ip_address(host))
except ValueError:
    print(socket.gethostbyname(host))
PY
)"
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-live-smoke.XXXXXX")"
RUSTLE_PID=""
RUSTLE_CHILD_PID_FILE="${TMPDIR}/rustle.pid"
RUSTLE_PASSWORD_FILE=""

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
  if [[ -n "$RUSTLE_PASSWORD_FILE" ]]; then
    rm -f "$RUSTLE_PASSWORD_FILE"
  fi
  local after
  after="$(route_snapshot)"
  if [[ "$after" != "$ROUTE_BEFORE" ]]; then
    delete_target_route_best_effort
  fi
  if [[ "$status" -ne 0 || "${RUSTLE_SMOKE_KEEP_LOGS:-0}" == "1" ]]; then
    smoke_info "kept live smoke logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
}
trap 'cleanup $?' EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
RUSTLE_LOG="${TMPDIR}/rustle-live.log"
RESPONSE_DIR="${TMPDIR}/responses"
mkdir -p "$RESPONSE_DIR"
CMD_ENV=()
if [[ -n "${RUSTLE_AGENT_DIR:-}" ]]; then
  CMD_ENV+=(RUSTLE_AGENT_DIR="$RUSTLE_AGENT_DIR")
fi

write_password_file() {
  local password_value="$1"
  RUSTLE_PASSWORD_FILE="${TMPDIR}/ssh-password"
  (umask 077 && printf '%s' "$password_value" >"$RUSTLE_PASSWORD_FILE")
}

CMD=(
  "$RUSTLE_BIN_RESOLVED"
  -r "$REMOTE"
)

if [[ -n "${RUSTLE_LIVE_IDENTITY:-}" ]]; then
  CMD+=(-i "$RUSTLE_LIVE_IDENTITY")
fi
if [[ -n "${RUSTLE_LIVE_SSH_CONFIG:-}" ]]; then
  CMD+=(--ssh-config "$RUSTLE_LIVE_SSH_CONFIG")
fi
if [[ -n "${RUSTLE_LIVE_KNOWN_HOSTS:-}" ]]; then
  CMD+=(--known-hosts "$RUSTLE_LIVE_KNOWN_HOSTS")
fi
if [[ "${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}" == "1" ]]; then
  CMD+=(--insecure-accept-host-key)
fi
if [[ -n "${RUSTLE_LIVE_PASSWORD_VALUE:-}" ]]; then
  write_password_file "$RUSTLE_LIVE_PASSWORD_VALUE"
  CMD+=(--password-file "$RUSTLE_PASSWORD_FILE")
elif [[ "${RUSTLE_LIVE_PASSWORD:-0}" == "1" ]]; then
  printf 'SSH password: ' >&2
  IFS= read -r -s password_value
  printf '\n' >&2
  write_password_file "$password_value"
  unset password_value
  CMD+=(--password-file "$RUSTLE_PASSWORD_FILE")
fi
if [[ "${RUSTLE_LIVE_DNS:-0}" == "1" ]]; then
  CMD+=(--dns)
fi
if [[ -n "${RUSTLE_LIVE_DNS_REMOTE:-}" ]]; then
  CMD+=(--dns-remote "$RUSTLE_LIVE_DNS_REMOTE")
fi
if [[ -n "${RUSTLE_LIVE_BRIDGE_TRANSPORT:-}" ]]; then
  CMD+=(--bridge-transport "$RUSTLE_LIVE_BRIDGE_TRANSPORT")
fi
if [[ -n "${RUSTLE_LIVE_AGENT_COMMAND:-}" ]]; then
  CMD+=(--agent-command "$RUSTLE_LIVE_AGENT_COMMAND")
fi
if [[ -n "${RUSTLE_LIVE_AGENT_SESSIONS:-}" ]]; then
  CMD+=(--agent-sessions "$RUSTLE_LIVE_AGENT_SESSIONS")
fi

CMD+=("$TARGET_CIDR")

smoke_info "starting live tunnel to ${REMOTE} for ${TARGET_CIDR}; log: ${RUSTLE_LOG}"
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
  smoke_die "Rustle did not add the live target route"
fi

TUN_IF_NAME="$(sed -n 's/^tun: created \([^ ]*\) .*/\1/p' "$RUSTLE_LOG" | tail -n 1)"
if [[ -z "$TUN_IF_NAME" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "could not determine Rustle TUN interface name"
fi
if ! wait_for_route_interface "$URL_ROUTE_PROBE_IP" "$TUN_IF_NAME"; then
  printf 'route lookup for %s did not use %s:\n' "$URL_ROUTE_PROBE_IP" "$TUN_IF_NAME" >&2
  route_lookup_dump "$URL_ROUTE_PROBE_IP" >&2
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "live target URL route is not using Rustle TUN"
fi

CURL_ARGS=(--fail --show-error --silent --noproxy '*' --max-time "${RUSTLE_LIVE_CURL_TIMEOUT:-45}")
if [[ "${RUSTLE_LIVE_CURL_INSECURE:-1}" == "1" ]]; then
  CURL_ARGS+=(-k)
fi

smoke_info "requesting ${URL} through Rustle ${REQUESTS} time(s), concurrency ${CONCURRENCY}"
request_index=0
failed=0
SECONDS=0
while [[ "$request_index" -lt "$REQUESTS" ]]; do
  pids=()
  launched=0
  while [[ "$launched" -lt "$CONCURRENCY" && "$request_index" -lt "$REQUESTS" ]]; do
    response_path="${RESPONSE_DIR}/${request_index}.out"
    curl "${CURL_ARGS[@]}" "$URL" >"$response_path" &
    pids+=("$!")
    request_index=$((request_index + 1))
    launched=$((launched + 1))
  done

  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done
done

if [[ "$failed" -ne 0 ]]; then
  tail -n 120 "$RUSTLE_LOG" 2>/dev/null | sed 's/^/rustle: /' >&2 || true
  smoke_die "one or more live tunnel curl requests failed"
fi
smoke_info "completed ${REQUESTS} request(s) in ${SECONDS}s"

if [[ -n "${RUSTLE_LIVE_EXPECT:-}" ]]; then
  for response_path in "$RESPONSE_DIR"/*.out; do
    if ! grep -q "$RUSTLE_LIVE_EXPECT" "$response_path"; then
      sed 's/^/curl: /' "$response_path" >&2 || true
      smoke_die "live tunnel response did not contain RUSTLE_LIVE_EXPECT"
    fi
  done
fi

stop_rustle

FINAL_STATS="$(grep 'stats: final' "$RUSTLE_LOG" | tail -n 1 || true)"
if [[ -z "$FINAL_STATS" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not print final stats during live smoke shutdown"
fi
SSH_OPENED="$(printf '%s\n' "$FINAL_STATS" | sed -n 's/.*ssh=open:\([0-9][0-9]*\).*/\1/p')"
TUN_RX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_rx=([0-9]+)/.*')"
TUN_TX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_tx=([0-9]+)/.*')"
SSH_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*ssh=open:[0-9]+ fail:([0-9]+) eof:.*')"
AGENT_RECONNECT_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*agent_reconnect=attempt:[0-9]+ ok:[0-9]+ fail:([0-9]+).*')"
BRIDGE_SEND_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*bridge_send_fail:([0-9]+).*')"
BACKLOG_OVERFLOWED="$(smoke_stat_value "$FINAL_STATS" '.*backlog_overflow:([0-9]+).*')"

smoke_require_stat_at_least "ssh opens" "$SSH_OPENED" "$REQUESTS" "$FINAL_STATS"
smoke_require_stat_at_least "TUN RX packets" "$TUN_RX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_at_least "TUN TX packets" "$TUN_TX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_zero "SSH open failures" "$SSH_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "agent reconnect failures" "$AGENT_RECONNECT_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "bridge send failures" "$BRIDGE_SEND_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "remote backlog overflows" "$BACKLOG_OVERFLOWED" "$FINAL_STATS"

case "$BRIDGE_TRANSPORT" in
  direct-tcpip)
    if ! grep -q 'ssh: opening direct-tcpip' "$RUSTLE_LOG"; then
      tail -n 120 "$RUSTLE_LOG" 2>/dev/null | sed 's/^/rustle: /' >&2 || true
      smoke_die "live smoke requested direct-tcpip but did not observe direct-tcpip opens"
    fi
    ;;
  agent)
    if ! grep -q 'agent: established' "$RUSTLE_LOG" || ! grep -q 'agent: opening stream' "$RUSTLE_LOG"; then
      tail -n 120 "$RUSTLE_LOG" 2>/dev/null | sed 's/^/rustle: /' >&2 || true
      smoke_die "live smoke requested agent but did not observe agent transport and stream opens"
    fi
    ;;
  auto)
    if ! grep -Eq 'transport: auto selected agent|transport: auto could not start agent|transport: auto selected direct-tcpip' "$RUSTLE_LOG"; then
      tail -n 120 "$RUSTLE_LOG" 2>/dev/null | sed 's/^/rustle: /' >&2 || true
      smoke_die "live smoke auto transport did not report its selected transport"
    fi
    ;;
esac

ROUTE_AFTER="$(route_snapshot)"
if [[ "$ROUTE_AFTER" != "$ROUTE_BEFORE" ]]; then
  printf 'before route snapshot:\n%s\n' "$ROUTE_BEFORE" >&2
  printf 'after route snapshot:\n%s\n' "$ROUTE_AFTER" >&2
  smoke_die "live target route table did not return to its original state"
fi

smoke_info "live tunnel smoke passed"
