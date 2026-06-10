#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-bridge-smoke.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
BRIDGE_CONNECTIONS="${RUSTLE_SMOKE_AGENT_BRIDGE_CONNECTIONS:-${RUSTLE_SMOKE_BRIDGE_CONNECTIONS:-8}}"
AGENT_SESSIONS="${RUSTLE_SMOKE_AGENT_SESSIONS:-2}"
AGENT_COMMAND="${RUSTLE_SMOKE_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}"
export RUSTLE_SMOKE_HTTP_BODY_BYTES="${RUSTLE_SMOKE_HTTP_BODY_BYTES:-65536}"

smoke_start_sshd "$TMPDIR"
smoke_start_http_server "$TMPDIR"

REQUEST=$'GET / HTTP/1.1\r\nHost: rustle-agent-bridge-smoke\r\nConnection: close\r\n\r\n'
OUT="${TMPDIR}/agent-bridge.out"
ERR="${TMPDIR}/agent-bridge.err"

smoke_info "running bridge-lab over agent transport through local sshd on port ${SMOKE_SSHD_PORT}"
set +e
"$RUSTLE_BIN_RESOLVED" \
  bridge-lab \
  -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
  -i "$SMOKE_CLIENT_KEY" \
  --known-hosts "$SMOKE_KNOWN_HOSTS" \
  --destination "127.0.0.1:${SMOKE_HTTP_PORT}" \
  --request "$REQUEST" \
  --connections "$BRIDGE_CONNECTIONS" \
  --bridge-transport agent \
  --agent-sessions "$AGENT_SESSIONS" \
  --agent-command "$AGENT_COMMAND" \
  >"$OUT" 2>"$ERR"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent bridge-lab exited with status ${status}"
fi

received_markers="$( (grep -ao 'rustle-smoke-ok' "$OUT" || true) | wc -l | tr -d '[:space:]')"
if [[ "$received_markers" != "$BRIDGE_CONNECTIONS" ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent bridge-lab smoke received ${received_markers} expected markers, wanted ${BRIDGE_CONNECTIONS}"
fi

if ! grep -q "agent: established ${AGENT_SESSIONS}/${AGENT_SESSIONS} exec transport(s)" "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent bridge-lab did not establish ${AGENT_SESSIONS} exec transport(s)"
fi

smoke_info "agent bridge-lab smoke passed with ${BRIDGE_CONNECTIONS} connections over ${AGENT_SESSIONS} exec transport(s)"
