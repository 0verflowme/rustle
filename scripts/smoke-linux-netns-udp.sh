#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Linux) ;;
  *) smoke_skip "Linux network namespace UDP smoke requires Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=(env)
else
  smoke_require sudo
  sudo -n true >/dev/null 2>&1 || smoke_die "passwordless sudo is required for netns UDP smoke"
  SUDO_CMD=(sudo -n)
fi

smoke_require ip
smoke_require ssh
smoke_require ssh-keygen

if [[ ! -c /dev/net/tun ]]; then
  if command -v modprobe >/dev/null 2>&1; then
    "${SUDO_CMD[@]}" modprobe tun >/dev/null 2>&1 || true
  fi
fi
[[ -c /dev/net/tun ]] || smoke_skip "Linux TUN device /dev/net/tun is unavailable"

SSHD_PATH="${SSHD:-}"
if [[ -z "$SSHD_PATH" ]]; then
  if command -v sshd >/dev/null 2>&1; then
    SSHD_PATH="$(command -v sshd)"
  elif [[ -x /usr/sbin/sshd ]]; then
    SSHD_PATH=/usr/sbin/sshd
  else
    smoke_skip "OpenSSH sshd is not installed"
  fi
fi
[[ -x "$SSHD_PATH" ]] || smoke_die "sshd is not executable: $SSHD_PATH"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-netns-udp-smoke.XXXXXX")"
NS_NAME="rustle-udp-$$"
VETH_HOST="rsuh$$"
VETH_REMOTE="rsur$$"
HOST_IP="${RUSTLE_NETNS_UDP_HOST_IP:-172.31.254.1}"
REMOTE_IP="${RUSTLE_NETNS_UDP_REMOTE_IP:-172.31.254.2}"
SSH_IP="${RUSTLE_NETNS_UDP_SSH_IP:-198.18.1.2}"
SSH_ROUTE_CIDR="${RUSTLE_NETNS_UDP_SSH_ROUTE_CIDR:-198.18.1.0/24}"
SSH_PORT="${RUSTLE_NETNS_UDP_SSH_PORT:-2223}"
TARGET_IP="${RUSTLE_NETNS_UDP_TARGET_IP:-10.77.1.5}"
TARGET_CIDR="${RUSTLE_NETNS_UDP_TARGET_CIDR:-${TARGET_IP}/32}"
UDP_PORT="${RUSTLE_NETNS_UDP_PORT:-18181}"
UDP_IDLE_TIMEOUT_MS="${RUSTLE_NETNS_UDP_IDLE_TIMEOUT_MS:-500}"
UDP_IDLE_GRACE_MS="${RUSTLE_NETNS_UDP_IDLE_GRACE_MS:-1500}"
RUSTLE_PID=""
RUSTLE_CHILD_PID_FILE="${TMPDIR}/rustle.pid"
SSHD_PID=""
UDP_PID=""

case "$UDP_IDLE_TIMEOUT_MS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_NETNS_UDP_IDLE_TIMEOUT_MS must be a positive integer" ;;
esac
case "$UDP_IDLE_GRACE_MS" in
  '' | *[!0-9]*) smoke_die "RUSTLE_NETNS_UDP_IDLE_GRACE_MS must be a positive integer" ;;
esac
if [[ "$UDP_IDLE_TIMEOUT_MS" -lt 1 ]]; then
  smoke_die "RUSTLE_NETNS_UDP_IDLE_TIMEOUT_MS must be at least 1"
fi
if [[ "$UDP_IDLE_GRACE_MS" -le "$UDP_IDLE_TIMEOUT_MS" ]]; then
  smoke_die "RUSTLE_NETNS_UDP_IDLE_GRACE_MS must be greater than RUSTLE_NETNS_UDP_IDLE_TIMEOUT_MS"
fi

route_snapshot() {
  if [[ "$TARGET_CIDR" == "0.0.0.0/0" ]]; then
    {
      ip route show "0.0.0.0/1"
      ip route show "128.0.0.0/1"
      ip route show "${SSH_IP}/32"
    } || true
  else
    {
      ip route show "$TARGET_CIDR"
      ip route show "${SSH_IP}/32"
    } || true
  fi
}

ROUTE_BEFORE="$(route_snapshot)"

delete_target_route_best_effort() {
  if [[ "$TARGET_CIDR" == "0.0.0.0/0" ]]; then
    "${SUDO_CMD[@]}" ip route del "0.0.0.0/1" >/dev/null 2>&1 || true
    "${SUDO_CMD[@]}" ip route del "128.0.0.0/1" >/dev/null 2>&1 || true
  else
    "${SUDO_CMD[@]}" ip route del "$TARGET_CIDR" >/dev/null 2>&1 || true
  fi
  "${SUDO_CMD[@]}" ip route del "${SSH_IP}/32" >/dev/null 2>&1 || true
}

delete_setup_routes_best_effort() {
  "${SUDO_CMD[@]}" ip route del "$SSH_ROUTE_CIDR" >/dev/null 2>&1 || true
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
  smoke_interrupt_process_tree "$UDP_PID" >/dev/null 2>&1 || true
  smoke_interrupt_process_tree "$SSHD_PID" >/dev/null 2>&1 || true
  delete_target_route_best_effort
  delete_setup_routes_best_effort
  "${SUDO_CMD[@]}" ip netns del "$NS_NAME" >/dev/null 2>&1 || true
  if [[ "$status" -ne 0 || "${RUSTLE_NETNS_UDP_KEEP_LOGS:-0}" == "1" ]]; then
    smoke_info "kept netns UDP smoke logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
}
trap 'cleanup $?' EXIT

"${SUDO_CMD[@]}" ip netns add "$NS_NAME"
"${SUDO_CMD[@]}" ip link add "$VETH_HOST" type veth peer name "$VETH_REMOTE"
"${SUDO_CMD[@]}" ip link set "$VETH_REMOTE" netns "$NS_NAME"
"${SUDO_CMD[@]}" ip addr add "${HOST_IP}/30" dev "$VETH_HOST"
"${SUDO_CMD[@]}" ip link set "$VETH_HOST" up
"${SUDO_CMD[@]}" ip -n "$NS_NAME" addr add "${REMOTE_IP}/30" dev "$VETH_REMOTE"
"${SUDO_CMD[@]}" ip -n "$NS_NAME" link set "$VETH_REMOTE" up
"${SUDO_CMD[@]}" ip -n "$NS_NAME" link set lo up
"${SUDO_CMD[@]}" ip -n "$NS_NAME" addr add "${SSH_IP}/32" dev lo
"${SUDO_CMD[@]}" ip -n "$NS_NAME" addr add "${TARGET_IP}/32" dev lo
"${SUDO_CMD[@]}" ip route add "$SSH_ROUTE_CIDR" via "$REMOTE_IP" dev "$VETH_HOST"

SMOKE_SSH_USER="${RUSTLE_SMOKE_USER:-${USER:-$(id -un)}}"
CLIENT_KEY="${TMPDIR}/client_ed25519"
HOST_KEY="${TMPDIR}/ssh_host_ed25519_key"
AUTHORIZED_KEYS="${TMPDIR}/authorized_keys"
KNOWN_HOSTS="${TMPDIR}/known_hosts"
SSHD_CONFIG="${TMPDIR}/sshd_config"
SSHD_LOG="${TMPDIR}/sshd.log"
UDP_READY="${TMPDIR}/udp.ready"
UDP_LOG="${TMPDIR}/udp.log"
RUSTLE_LOG="${TMPDIR}/rustle.log"

ssh-keygen -q -t ed25519 -N '' -f "$CLIENT_KEY"
ssh-keygen -q -t ed25519 -N '' -f "$HOST_KEY"
cp "$CLIENT_KEY.pub" "$AUTHORIZED_KEYS"
chmod 600 "$CLIENT_KEY" "$AUTHORIZED_KEYS"

host_pub="$(awk '{ print $1 " " $2 }' "$HOST_KEY.pub")"
printf '[%s]:%s %s\n' "$SSH_IP" "$SSH_PORT" "$host_pub" >"$KNOWN_HOSTS"

{
  printf 'Port %s\n' "$SSH_PORT"
  printf 'ListenAddress %s\n' "$SSH_IP"
  printf 'HostKey %s\n' "$HOST_KEY"
  printf 'PidFile %s\n' "${TMPDIR}/sshd.pid"
  printf 'AuthorizedKeysFile %s\n' "$AUTHORIZED_KEYS"
  printf 'PasswordAuthentication no\n'
  printf 'KbdInteractiveAuthentication no\n'
  printf 'ChallengeResponseAuthentication no\n'
  printf 'PubkeyAuthentication yes\n'
  printf 'StrictModes no\n'
  printf 'UsePAM no\n'
  printf 'AllowTcpForwarding yes\n'
  printf 'PermitOpen any\n'
  printf 'PermitTunnel no\n'
  printf 'X11Forwarding no\n'
  printf 'PrintMotd no\n'
  printf 'LogLevel ERROR\n'
} >"$SSHD_CONFIG"

"${SUDO_CMD[@]}" ip netns exec "$NS_NAME" "$SSHD_PATH" -f "$SSHD_CONFIG" -D -e \
  >"$SSHD_LOG" 2>&1 &
SSHD_PID=$!

if ! smoke_wait_for_port "$SSH_IP" "$SSH_PORT" 10; then
  sed 's/^/sshd: /' "$SSHD_LOG" >&2 || true
  smoke_die "netns sshd did not start on ${SSH_IP}:${SSH_PORT}"
fi

ssh \
  -o BatchMode=yes \
  -o ConnectTimeout=3 \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  -i "$CLIENT_KEY" \
  -p "$SSH_PORT" \
  "${SMOKE_SSH_USER}@${SSH_IP}" true >/dev/null 2>>"$SSHD_LOG" \
  || {
    sed 's/^/sshd: /' "$SSHD_LOG" >&2 || true
    smoke_die "could not authenticate to netns sshd as ${SMOKE_SSH_USER}"
  }

"${SUDO_CMD[@]}" ip netns exec "$NS_NAME" "$(smoke_python)" - "$TARGET_IP" "$UDP_PORT" "$UDP_READY" \
  >"$UDP_LOG" 2>&1 <<'PY' &
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
ready = sys.argv[3]
expected = b"rustle-netns-udp-ping"
response = b"rustle-netns-udp-pong"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    with open(ready, "w") as handle:
        handle.write(str(port))

    while True:
        data, peer = sock.recvfrom(65535)
        if data == expected:
            sock.sendto(response, peer)
        else:
            sock.sendto(b"rustle-netns-udp-unexpected", peer)
finally:
    sock.close()
PY
UDP_PID=$!

if ! smoke_wait_for_file "$UDP_READY" 5; then
  sed 's/^/udp: /' "$UDP_LOG" >&2 || true
  smoke_die "netns UDP server did not start"
fi

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
CMD=(
  "$RUSTLE_BIN_RESOLVED"
  -r "${SMOKE_SSH_USER}@${SSH_IP}:${SSH_PORT}"
  -i "$CLIENT_KEY"
  --known-hosts "$KNOWN_HOSTS"
  --bridge-transport agent
  --agent-command "${RUSTLE_NETNS_UDP_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}"
  --udp-idle-timeout-ms "$UDP_IDLE_TIMEOUT_MS"
  "$TARGET_CIDR"
)

smoke_info "starting Rustle netns UDP smoke (agent) for ${TARGET_CIDR} via SSH ${SSH_IP}; log: ${RUSTLE_LOG}"
"${SUDO_CMD[@]}" sh -c 'trap - INT TERM; echo $$ > "$1"; shift; exec "$@"' \
  sh "$RUSTLE_CHILD_PID_FILE" "${CMD[@]}" >"$RUSTLE_LOG" 2>&1 &
RUSTLE_PID=$!

if ! smoke_wait_for_file "$RUSTLE_CHILD_PID_FILE" 5; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle wrapper did not publish a child PID"
fi
if ! smoke_wait_for_log 'tun: created' "$RUSTLE_LOG" 15; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not create a TUN device"
fi
if [[ "$TARGET_CIDR" == "0.0.0.0/0" ]]; then
  if ! smoke_wait_for_log "route: protected SSH control connection to ${SSH_IP}" "$RUSTLE_LOG" 15; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not protect the SSH control route"
  fi
  if ! smoke_wait_for_log "route: added 0.0.0.0/1" "$RUSTLE_LOG" 15; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not add the lower split full-tunnel route"
  fi
  if ! smoke_wait_for_log "route: added 128.0.0.0/1" "$RUSTLE_LOG" 15; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not add the upper split full-tunnel route"
  fi
else
  if ! smoke_wait_for_log "route: added ${TARGET_CIDR}" "$RUSTLE_LOG" 15; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not add the target route"
  fi
fi

smoke_info "sending UDP datagram to ${TARGET_IP}:${UDP_PORT}"
"$(smoke_python)" - "$TARGET_IP" "$UDP_PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
request = b"rustle-netns-udp-ping"
expected = b"rustle-netns-udp-pong"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.settimeout(10)
    sock.sendto(request, (host, port))
    data, peer = sock.recvfrom(65535)
finally:
    sock.close()

if data != expected:
    raise SystemExit("unexpected UDP response %r from %r" % (data, peer))
if peer[0] != host or peer[1] != port:
    raise SystemExit("unexpected UDP response peer %r" % (peer,))
print("udp smoke response ok")
PY

if ! smoke_wait_for_log "udp: forwarding datagram .* -> ${TARGET_IP}:${UDP_PORT} over agent" "$RUSTLE_LOG" 5; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not log generic UDP forwarding"
fi

smoke_info "waiting for UDP association idle cleanup"
"$(smoke_python)" - "$UDP_IDLE_GRACE_MS" <<'PY'
import sys
import time

time.sleep(int(sys.argv[1]) / 1000)
PY

stop_rustle

FINAL_STATS="$(grep 'stats: final' "$RUSTLE_LOG" | tail -n 1 || true)"
if [[ -z "$FINAL_STATS" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not print final stats during netns UDP smoke shutdown"
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
BRIDGE_EVENT_QUEUE_REMOTE_BYTES="$(smoke_stat_value "$FINAL_STATS" '.*bridge_event_queue=remote_bytes:([^ ]+) max:.*')"

smoke_require_stat_at_least "TUN RX packets" "$TUN_RX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_at_least "TUN TX packets" "$TUN_TX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_at_least "UDP forwarded" "$UDP_FORWARDED" 1 "$FINAL_STATS"
smoke_require_stat_at_least "UDP successes" "$UDP_OK" 1 "$FINAL_STATS"
smoke_require_stat_zero "UDP failures" "$UDP_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "UDP drops" "$UDP_DROPPED" "$FINAL_STATS"
smoke_require_stat_zero "UDP active associations" "$UDP_ACTIVE" "$FINAL_STATS"
smoke_require_stat_zero "bridge send failures" "$BRIDGE_SEND_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "remote backlog overflows" "$BACKLOG_OVERFLOWED" "$FINAL_STATS"
smoke_require_stat_zero_bytes "bridge event queued remote bytes" "$BRIDGE_EVENT_QUEUE_REMOTE_BYTES" "$FINAL_STATS"

ROUTE_AFTER="$(route_snapshot)"
if [[ "$ROUTE_AFTER" != "$ROUTE_BEFORE" ]]; then
  printf 'before route snapshot:\n%s\n' "$ROUTE_BEFORE" >&2
  printf 'after route snapshot:\n%s\n' "$ROUTE_AFTER" >&2
  smoke_die "netns target route table did not return to its original state"
fi

smoke_info "Linux netns UDP smoke passed"
