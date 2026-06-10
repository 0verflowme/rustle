#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-smoke.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
AGENT_COMMAND="${RUSTLE_SMOKE_AGENT_COMMAND:-'${RUSTLE_BIN_RESOLVED}' agent}"
export RUSTLE_SMOKE_HTTP_BODY_BYTES="${RUSTLE_SMOKE_HTTP_BODY_BYTES:-65536}"

smoke_start_sshd "$TMPDIR"
smoke_start_http_server "$TMPDIR"

REQUEST=$'GET / HTTP/1.1\r\nHost: rustle-agent-smoke\r\nConnection: close\r\n\r\n'
OUT="${TMPDIR}/agent.out"
ERR="${TMPDIR}/agent.err"

smoke_info "running agent-lab through local sshd on port ${SMOKE_SSHD_PORT}"
set +e
"$RUSTLE_BIN_RESOLVED" \
  agent-lab \
  -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
  -i "$SMOKE_CLIENT_KEY" \
  --known-hosts "$SMOKE_KNOWN_HOSTS" \
  --agent-command "$AGENT_COMMAND" \
  --destination "127.0.0.1:${SMOKE_HTTP_PORT}" \
  --request "$REQUEST" \
  >"$OUT" 2>"$ERR"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent-lab exited with status ${status}"
fi

if ! grep -aq 'rustle-smoke-ok' "$OUT"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent-lab smoke did not receive expected marker"
fi

smoke_info "agent-lab smoke passed"
