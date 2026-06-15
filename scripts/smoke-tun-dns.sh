#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "TUN DNS smoke is implemented for macOS and Linux" ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO_CMD=(env)
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
TUN_IP="${RUSTLE_SMOKE_TUN_IP:-198.18.255.1}"
TUN_PREFIX="${RUSTLE_SMOKE_TUN_PREFIX:-24}"
VIRTUAL_DNS_IP="${RUSTLE_SMOKE_VIRTUAL_DNS_IP:-198.18.255.53}"
case "$(uname -s)" in
  Darwin) SYSTEM_DNS_IP="${RUSTLE_SMOKE_SYSTEM_DNS_IP:-127.0.0.1}" ;;
  *) SYSTEM_DNS_IP="${RUSTLE_SMOKE_SYSTEM_DNS_IP:-$VIRTUAL_DNS_IP}" ;;
esac
CONFIGURE_DNS="${RUSTLE_SMOKE_CONFIGURE_DNS:-0}"
ROUTE_ONLY="${RUSTLE_SMOKE_ROUTE_ONLY:-0}"
DNS_NAME="${RUSTLE_SMOKE_DNS_NAME:-rustle-smoke.example.com}"
DNS_BEFORE=""
DNS_RESTORE_CHECKED=0
VIRTUAL_DNS_ROUTE_ADDED=0

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

case "$CONFIGURE_DNS" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_SMOKE_CONFIGURE_DNS must be 0 or 1" ;;
esac
case "$ROUTE_ONLY" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_SMOKE_ROUTE_ONLY must be 0 or 1" ;;
esac

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  [[ "$ROUTE_ONLY" == "0" ]] || smoke_die "RUSTLE_SMOKE_ROUTE_ONLY=1 cannot be combined with RUSTLE_SMOKE_CONFIGURE_DNS=1"
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

dns_settings_use_expected_resolver() {
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
        if [[ "$servers" != "$SYSTEM_DNS_IP" ]]; then
          printf 'service %s DNS servers are not %s:\n%s\n' \
            "$service" "$SYSTEM_DNS_IP" "$servers" >&2
          return 1
        fi
      done <<<"$services"
      ;;
    Linux)
      local status
      status="$(SYSTEMD_PAGER=cat resolvectl status "$if_name" 2>&1 || true)"
      if ! grep -Fq "$SYSTEM_DNS_IP" <<<"$status" || ! grep -Fq '~.' <<<"$status"; then
        printf 'resolvectl status for %s did not contain %s and route-only domain ~.:\n%s\n' \
          "$if_name" "$SYSTEM_DNS_IP" "$status" >&2
        return 1
      fi
      ;;
  esac
}

runtime_dns_uses_expected_resolver() {
  case "$(uname -s)" in
    Darwin)
      local config global_config
      config="$(scutil --dns 2>&1 || true)"
      global_config="${config%%DNS configuration (for scoped queries)*}"
      grep -Fq "nameserver[0] : ${SYSTEM_DNS_IP}" <<<"$global_config"
      ;;
    Linux)
      dns_settings_use_expected_resolver "$1"
      ;;
  esac
}

diagnose_runtime_dns_conflict() {
  case "$(uname -s)" in
    Darwin)
      local config global_config
      config="$(scutil --dns 2>&1 || true)"
      global_config="${config%%DNS configuration (for scoped queries)*}"
      if grep -Fq 'nameserver[0] :' <<<"$global_config" \
        && ! grep -Fq "nameserver[0] : ${SYSTEM_DNS_IP}" <<<"$global_config"; then
        printf '%s\n' \
          "macOS runtime DNS is still using a global resolver before scoped service DNS; a VPN or profile-managed resolver may be overriding networksetup DNS." >&2
      fi
      ;;
    Linux) ;;
  esac
}

wait_for_runtime_dns() {
  local if_name="$1"
  for ((i = 0; i < 50; i++)); do
    if runtime_dns_uses_expected_resolver "$if_name"; then
      return 0
    fi
    sleep 0.1
  done
  case "$(uname -s)" in
    Darwin) scutil --dns >&2 || true ;;
    Linux) SYSTEMD_PAGER=cat resolvectl status "$if_name" >&2 || true ;;
  esac
  return 1
}

verify_dns_restored() {
  [[ "$CONFIGURE_DNS" == "1" && -n "$DNS_BEFORE" ]] || return 0
  DNS_RESTORE_CHECKED=1
  local dns_after
  dns_after="$(dns_snapshot)"
  if [[ "$dns_after" != "$DNS_BEFORE" ]]; then
    printf 'DNS snapshot before Rustle:\n%s\n' "$DNS_BEFORE" >&2
    printf 'DNS snapshot after Rustle:\n%s\n' "$dns_after" >&2
    return 1
  fi
}

flush_system_dns_cache_best_effort() {
  case "$(uname -s)" in
    Darwin)
      dscacheutil -flushcache >/dev/null 2>&1 || true
      "${SUDO_CMD[@]}" killall -HUP mDNSResponder >/dev/null 2>&1 || true
      ;;
    Linux) ;;
  esac
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

delete_virtual_dns_route_best_effort() {
  [[ "$VIRTUAL_DNS_ROUTE_ADDED" == "1" ]] || return 0
  case "$(uname -s)" in
    Darwin)
      "${SUDO_CMD[@]}" route -n delete -host "$VIRTUAL_DNS_IP" >/dev/null 2>&1 || true
      ;;
    Linux)
      "${SUDO_CMD[@]}" ip route del "${VIRTUAL_DNS_IP}/32" >/dev/null 2>&1 || true
      ;;
  esac
  VIRTUAL_DNS_ROUTE_ADDED=0
}

add_virtual_dns_route() {
  local if_name="$1"
  case "$(uname -s)" in
    Darwin)
      if ! "${SUDO_CMD[@]}" route -n add -host "$VIRTUAL_DNS_IP" -interface "$if_name" >/dev/null 2>&1; then
        "${SUDO_CMD[@]}" route -n change -host "$VIRTUAL_DNS_IP" -interface "$if_name" >/dev/null 2>&1 \
          || smoke_die "failed to route virtual DNS ${VIRTUAL_DNS_IP} through ${if_name}"
      fi
      ;;
    Linux)
      "${SUDO_CMD[@]}" ip route replace "${VIRTUAL_DNS_IP}/32" dev "$if_name" \
        || smoke_die "failed to route virtual DNS ${VIRTUAL_DNS_IP} through ${if_name}"
      ;;
  esac
  VIRTUAL_DNS_ROUTE_ADDED=1
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
  local cleanup_failed=0
  stop_rustle
  delete_virtual_dns_route_best_effort
  local route_after
  route_after="$(route_snapshot)"
  if [[ "$route_after" != "$ROUTE_BEFORE" ]]; then
    delete_target_route_best_effort
  fi
  smoke_stop_pid "${SMOKE_DNS_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  if [[ "$DNS_RESTORE_CHECKED" != "1" ]] && ! verify_dns_restored; then
    cleanup_failed=1
  fi
  if [[ "$status" -ne 0 || "${RUSTLE_SMOKE_KEEP_LOGS:-0}" == "1" ]]; then
    smoke_info "kept TUN DNS smoke logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
  if [[ "$cleanup_failed" -ne 0 && "$status" -eq 0 ]]; then
    return 1
  fi
  return "$status"
}
trap 'cleanup $?' EXIT

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
add_virtual_dns_route "$TUN_IF_NAME"

if ! smoke_wait_for_rustle_target_route_logs \
  "$TARGET_PREFIX" "$TARGET_CIDR" "$RUSTLE_LOG" 10 "$RUSTLE_PID" rustle; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not add the target route"
fi

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  if ! smoke_wait_for_log "dns: configured host resolver to use DNS ${SYSTEM_DNS_IP}" \
    "$RUSTLE_LOG" 10; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "Rustle did not report DNS resolver takeover"
  fi
  if ! dns_settings_use_expected_resolver "$TUN_IF_NAME"; then
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "system DNS settings did not point at the expected Rustle resolver"
  fi
  flush_system_dns_cache_best_effort
  if ! wait_for_runtime_dns "$TUN_IF_NAME"; then
    diagnose_runtime_dns_conflict
    sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
    smoke_die "runtime DNS resolver did not pick up the expected Rustle resolver"
  fi
fi

if [[ "$ROUTE_ONLY" == "1" ]]; then
  stop_rustle
  ROUTE_AFTER="$(route_snapshot)"
  if [[ "$ROUTE_AFTER" != "$ROUTE_BEFORE" ]]; then
    printf 'before route snapshot:\n%s\n' "$ROUTE_BEFORE" >&2
    printf 'after route snapshot:\n%s\n' "$ROUTE_AFTER" >&2
    smoke_die "target route table did not return to its original state"
  fi
  smoke_info "TUN route smoke passed"
  exit 0
fi

smoke_info "sending UDP DNS query for ${DNS_NAME} to ${VIRTUAL_DNS_IP}:53"
"$(smoke_python)" - "$VIRTUAL_DNS_IP" "$DNS_NAME" <<'PY'
import socket
import struct
import sys

server = sys.argv[1]
name = sys.argv[2]
query_id = 0x5255
labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.rstrip(".").split("."))
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

if ! smoke_wait_for_log 'dns: forwarding UDP query' "$RUSTLE_LOG" 10; then
  sed 's/^/rustle: /' "$RUSTLE_LOG" >&2 || true
  smoke_die "Rustle did not log the TUN DNS query"
fi

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  smoke_info "resolving through the system resolver after DNS takeover"
  "$(smoke_python)" - "$DNS_NAME" <<'PY'
import socket
import sys

name = sys.argv[1]
expected = "203.0.113.7"
resolved = socket.gethostbyname(name)
if resolved != expected:
    raise SystemExit(f"system resolver returned {resolved} for {name}, expected {expected}")
print("system resolver DNS smoke response ok")
PY
fi

stop_rustle

if [[ "$CONFIGURE_DNS" == "1" ]]; then
  if ! verify_dns_restored; then
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

ROUTE_AFTER="$(route_snapshot)"
if [[ "$ROUTE_AFTER" != "$ROUTE_BEFORE" ]]; then
  printf 'before route snapshot:\n%s\n' "$ROUTE_BEFORE" >&2
  printf 'after route snapshot:\n%s\n' "$ROUTE_AFTER" >&2
  smoke_die "target route table did not return to its original state"
fi

smoke_info "TUN DNS smoke passed"
