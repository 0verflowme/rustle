#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "TUN DNS smoke is implemented for macOS and Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=()
else
  smoke_require sudo
  sudo -n true >/dev/null 2>&1 || smoke_die "passwordless sudo is required for TUN smoke"
  SUDO_CMD=(sudo -n)
fi

if [[ "$(uname -s)" == "Linux" ]]; then
  smoke_require ip
  if [[ ! -c /dev/net/tun ]]; then
    if command -v modprobe >/dev/null 2>&1; then
      "${SUDO_CMD[@]}" modprobe tun >/dev/null 2>&1 || true
    fi
  fi
  [[ -c /dev/net/tun ]] || smoke_skip "Linux TUN device /dev/net/tun is unavailable"
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-tun-dns-smoke.XXXXXX")"
RUSTLE_PID=""
RUSTLE_CHILD_PID_FILE="${TMPDIR}/rustle.pid"

TARGET_CIDR="${RUSTLE_SMOKE_TARGET_CIDR:-198.51.100.77/32}"
TARGET_IP="${TARGET_CIDR%/*}"
TUN_IP="${RUSTLE_SMOKE_TUN_IP:-10.255.255.1}"
TUN_PREFIX="${RUSTLE_SMOKE_TUN_PREFIX:-24}"
VIRTUAL_DNS_IP="${RUSTLE_SMOKE_VIRTUAL_DNS_IP:-10.255.255.53}"
CONFIGURE_DNS="${RUSTLE_SMOKE_CONFIGURE_DNS:-0}"
DNS_BEFORE=""

case "$CONFIGURE_DNS" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_SMOKE_CONFIGURE_DNS must be 0 or 1" ;;
esac

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  case "$(uname -s)" in
    Darwin) smoke_require networksetup ;;
    Linux) smoke_require resolvectl ;;
  esac
fi

dns_snapshot() {
  case "$(uname -s)" in
    Darwin)
      local services service
      services="$(networksetup -listallnetworkservices | awk '
        NF && $0 !~ /^An asterisk/ && $0 !~ /^\*/ { print }
      ')"
      while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        printf 'service:%s\n' "$service"
        networksetup -getdnsservers "$service" 2>&1 | sed 's/^/  /'
      done <<<"$services"
      ;;
    Linux)
      SYSTEMD_PAGER=cat resolvectl status 2>&1 || true
      ;;
  esac
}

dns_settings_use_virtual_resolver() {
  local if_name="$1"
  case "$(uname -s)" in
    Darwin)
      local services service servers
      services="$(networksetup -listallnetworkservices | awk '
        NF && $0 !~ /^An asterisk/ && $0 !~ /^\*/ { print }
      ')"
      while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        servers="$(networksetup -getdnsservers "$service" 2>&1 | sed '/^$/d')"
        if [[ "$servers" != "$VIRTUAL_DNS_IP" ]]; then
          printf 'service %s DNS servers are not %s:\n%s\n' \
            "$service" "$VIRTUAL_DNS_IP" "$servers" >&2
          return 1
        fi
      done <<<"$services"
      ;;
    Linux)
      local status
      status="$(SYSTEMD_PAGER=cat resolvectl status "$if_name" 2>&1 || true)"
      if ! grep -Fq "$VIRTUAL_DNS_IP" <<<"$status" || ! grep -Fq '~.' <<<"$status"; then
        printf 'resolvectl status for %s did not contain %s and route-only domain ~.:\n%s\n' \
          "$if_name" "$VIRTUAL_DNS_IP" "$status" >&2
        return 1
      fi
      ;;
  esac
}

delete_target_route_best_effort() {
  case "$(uname -s)" in
    Darwin)
      "${SUDO_CMD[@]}" route -n delete -host "$TARGET_IP" >/dev/null 2>&1 || true
      ;;
    Linux)
      "${SUDO_CMD[@]}" ip route del "$TARGET_CIDR" >/dev/null 2>&1 || true
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
  stop_rustle
  delete_target_route_best_effort
  smoke_stop_pid "${SMOKE_DNS_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"

smoke_start_sshd "$TMPDIR"
smoke_start_dns_tcp_server "$TMPDIR"

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  DNS_BEFORE="$(dns_snapshot)"
fi

RUSTLE_LOG="${TMPDIR}/rustle-tun.log"
CMD=(
  "$RUSTLE_BIN_RESOLVED"
  tunnel
  -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}"
  -i "$SMOKE_CLIENT_KEY"
  --known-hosts "$SMOKE_KNOWN_HOSTS"
  --dns-remote "127.0.0.1:${SMOKE_DNS_TCP_PORT}"
  --tun-ip "$TUN_IP"
  --tun-prefix "$TUN_PREFIX"
)

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  CMD+=(--dns)
fi
if [[ -n "${RUSTLE_SMOKE_BRIDGE_TRANSPORT:-}" ]]; then
  CMD+=(--bridge-transport "$RUSTLE_SMOKE_BRIDGE_TRANSPORT")
fi
if [[ -n "${RUSTLE_SMOKE_AGENT_COMMAND:-}" ]]; then
  CMD+=(--agent-command "$RUSTLE_SMOKE_AGENT_COMMAND")
fi

CMD+=(--target "$TARGET_CIDR")

smoke_info "starting Rustle TUN DNS smoke for ${TARGET_CIDR}; log: ${RUSTLE_LOG}"
"${SUDO_CMD[@]}" sh -c 'trap - INT TERM; echo $$ > "$1"; shift; exec "$@"' \
  sh "$RUSTLE_CHILD_PID_FILE" "${CMD[@]}" >"$RUSTLE_LOG" 2>&1 &
RUSTLE_PID=$!

if ! smoke_wait_for_file "$RUSTLE_CHILD_PID_FILE" 5; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle wrapper did not publish a child PID"
fi

if ! smoke_wait_for_log 'tun: created' "$RUSTLE_LOG" 10; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not create a TUN device"
fi
TUN_IF_NAME="$(sed -n 's/^tun: created \([^ ]*\) .*/\1/p' "$RUSTLE_LOG" | tail -n 1)"
if [[ -z "$TUN_IF_NAME" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "could not determine Rustle TUN interface name"
fi

if ! smoke_wait_for_log "route: added ${TARGET_CIDR}" "$RUSTLE_LOG" 10; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not add the target route"
fi

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  if ! smoke_wait_for_log "dns: configured host resolver to use virtual DNS ${VIRTUAL_DNS_IP}" \
    "$RUSTLE_LOG" 10; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not report DNS resolver takeover"
  fi
  if ! dns_settings_use_virtual_resolver "$TUN_IF_NAME"; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "system DNS settings did not point at Rustle virtual resolver"
  fi
fi

smoke_info "sending UDP DNS query to ${VIRTUAL_DNS_IP}:53"
"$(smoke_python)" - "$VIRTUAL_DNS_IP" <<'PY'
import socket
import struct
import sys

server = sys.argv[1]
query_id = 0x5255
labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in "rustle-smoke.invalid".split("."))
question = labels + b"\x00" + b"\x00\x01" + b"\x00\x01"
query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(8)
    sock.sendto(query, (server, 53))
    response, _ = sock.recvfrom(4096)

if len(response) < 12:
    raise SystemExit("DNS response is too short")

resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", response[:12])
rcode = flags & 0x000F

if resp_id != query_id:
    raise SystemExit(f"DNS response id mismatch: {resp_id:#x}")
if rcode != 0:
    raise SystemExit(f"DNS response returned rcode {rcode}")
if qdcount != 1 or ancount < 1:
    raise SystemExit(f"DNS response has qdcount={qdcount} ancount={ancount}")
if bytes([203, 0, 113, 7]) not in response:
    raise SystemExit("DNS response did not contain expected A record 203.0.113.7")

print("dns smoke response ok")
PY

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  smoke_info "resolving through the system resolver after DNS takeover"
  "$(smoke_python)" - <<'PY'
import socket

expected = "203.0.113.7"
resolved = socket.gethostbyname("rustle-smoke.invalid")
if resolved != expected:
    raise SystemExit(f"system resolver returned {resolved}, expected {expected}")
print("system resolver DNS smoke response ok")
PY
fi

stop_rustle

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  DNS_AFTER="$(dns_snapshot)"
  if [[ "$DNS_AFTER" != "$DNS_BEFORE" ]]; then
    printf 'DNS snapshot before Rustle:\n%s\n' "$DNS_BEFORE" >&2
    printf 'DNS snapshot after Rustle:\n%s\n' "$DNS_AFTER" >&2
    smoke_die "system DNS settings did not return to their original state"
  fi
fi

FINAL_STATS="$(grep 'stats: final' "$RUSTLE_LOG" | tail -n 1 || true)"
if [[ -z "$FINAL_STATS" ]]; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not print final stats during TUN DNS smoke shutdown"
fi

TUN_RX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_rx=([0-9]+)/.*')"
TUN_TX_PACKETS="$(smoke_stat_value "$FINAL_STATS" '.*tun_tx=([0-9]+)/.*')"
DNS_FORWARDED="$(smoke_stat_value "$FINAL_STATS" '.*dns=fwd:([0-9]+) ok:.*')"
DNS_OK="$(smoke_stat_value "$FINAL_STATS" '.*dns=fwd:[0-9]+ ok:([0-9]+) fail:.*')"
DNS_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*dns=fwd:[0-9]+ ok:[0-9]+ fail:([0-9]+) drop:.*')"
DNS_DROPPED="$(smoke_stat_value "$FINAL_STATS" '.*dns=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:([0-9]+) inflight:.*')"
DNS_INFLIGHT="$(smoke_stat_value "$FINAL_STATS" '.*dns=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:[0-9]+ inflight:([0-9]+).*')"
UDP_FORWARDED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:([0-9]+) ok:.*')"
UDP_OK="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:([0-9]+) fail:.*')"
UDP_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:([0-9]+) drop:.*')"
UDP_DROPPED="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:([0-9]+) active:.*')"
UDP_ACTIVE="$(smoke_stat_value "$FINAL_STATS" '.*udp=fwd:[0-9]+ ok:[0-9]+ fail:[0-9]+ drop:[0-9]+ active:([0-9]+).*')"
BRIDGE_SEND_FAILED="$(smoke_stat_value "$FINAL_STATS" '.*bridge_send_fail:([0-9]+).*')"
BACKLOG_OVERFLOWED="$(smoke_stat_value "$FINAL_STATS" '.*backlog_overflow:([0-9]+).*')"

smoke_require_stat_at_least "TUN RX packets" "$TUN_RX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_at_least "TUN TX packets" "$TUN_TX_PACKETS" 1 "$FINAL_STATS"
smoke_require_stat_at_least "DNS forwarded" "$DNS_FORWARDED" 1 "$FINAL_STATS"
smoke_require_stat_at_least "DNS successes" "$DNS_OK" 1 "$FINAL_STATS"
smoke_require_stat_zero "DNS failures" "$DNS_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "DNS drops" "$DNS_DROPPED" "$FINAL_STATS"
smoke_require_stat_zero "DNS in-flight queries" "$DNS_INFLIGHT" "$FINAL_STATS"
smoke_require_stat_zero "UDP forwarded" "$UDP_FORWARDED" "$FINAL_STATS"
smoke_require_stat_zero "UDP successes" "$UDP_OK" "$FINAL_STATS"
smoke_require_stat_zero "UDP failures" "$UDP_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "UDP drops" "$UDP_DROPPED" "$FINAL_STATS"
smoke_require_stat_zero "UDP active associations" "$UDP_ACTIVE" "$FINAL_STATS"
smoke_require_stat_zero "bridge send failures" "$BRIDGE_SEND_FAILED" "$FINAL_STATS"
smoke_require_stat_zero "remote backlog overflows" "$BACKLOG_OVERFLOWED" "$FINAL_STATS"

case "$(uname -s)" in
  Darwin)
    if netstat -rn -f inet | grep -Eq "(^|[[:space:]])${TARGET_IP//./\\.}([[:space:]]|$)"; then
      netstat -rn -f inet | grep -E "${TARGET_IP//./\\.}" >&2 || true
      smoke_die "target route still exists after Rustle shutdown"
    fi
    ;;
  Linux)
    if ip route show "$TARGET_CIDR" | grep -q "$TARGET_IP"; then
      ip route show "$TARGET_CIDR" >&2 || true
      smoke_die "target route still exists after Rustle shutdown"
    fi
    ;;
esac

smoke_info "TUN DNS smoke passed"
