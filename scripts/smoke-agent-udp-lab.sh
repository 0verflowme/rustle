#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-udp-smoke.XXXXXX")"

cleanup() {
  smoke_stop_pid "${UDP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
AGENT_COMMAND="${RUSTLE_SMOKE_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}"
MESSAGES="${RUSTLE_SMOKE_AGENT_UDP_MESSAGES:-4}"
REQUEST="${RUSTLE_SMOKE_AGENT_UDP_REQUEST:-rustle-agent-udp-ping}"

smoke_start_sshd "$TMPDIR"

UDP_PORT="${RUSTLE_SMOKE_AGENT_UDP_PORT:-$(smoke_find_free_port)}"
UDP_READY="${TMPDIR}/udp.ready"
UDP_LOG="${TMPDIR}/udp.log"
"$(smoke_python)" - "$UDP_PORT" "$UDP_READY" >"$UDP_LOG" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
ready = sys.argv[2]
response_prefix = b"rustle-agent-udp-ok:"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write(str(port))

    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(response_prefix + data, peer)
PY
UDP_PID=$!

if ! smoke_wait_for_file "$UDP_READY" 5; then
  sed 's/^/udp: /' "$UDP_LOG" >&2 || true
  smoke_die "agent UDP lab server did not start"
fi

OUT="${TMPDIR}/agent-udp.out"
ERR="${TMPDIR}/agent-udp.err"

smoke_info "running agent-udp-lab through local sshd on port ${SMOKE_SSHD_PORT}"
set +e
"$RUSTLE_BIN_RESOLVED" \
  agent-udp-lab \
  -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
  -i "$SMOKE_CLIENT_KEY" \
  --known-hosts "$SMOKE_KNOWN_HOSTS" \
  --agent-command "$AGENT_COMMAND" \
  --destination "127.0.0.1:${UDP_PORT}" \
  --request "$REQUEST" \
  --messages "$MESSAGES" \
  >"$OUT" 2>"$ERR"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent-udp-lab exited with status ${status}"
fi

received_markers="$( (grep -ao "rustle-agent-udp-ok:${REQUEST}" "$OUT" || true) | wc -l | tr -d '[:space:]')"
if [[ "$received_markers" != "$MESSAGES" ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent UDP lab smoke received ${received_markers} expected markers, wanted ${MESSAGES}"
fi

smoke_info "agent UDP lab smoke passed with ${MESSAGES} datagrams"
