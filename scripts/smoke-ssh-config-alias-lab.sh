#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-ssh-config-smoke.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
BRIDGE_CONNECTIONS="${RUSTLE_SMOKE_SSH_CONFIG_CONNECTIONS:-${RUSTLE_SMOKE_BRIDGE_CONNECTIONS:-4}}"
SSH_ALIAS="${RUSTLE_SMOKE_SSH_CONFIG_ALIAS:-contabo}"
SSH_CONFIG="${TMPDIR}/ssh_config"
export RUSTLE_SMOKE_HTTP_BODY_BYTES="${RUSTLE_SMOKE_HTTP_BODY_BYTES:-65536}"

smoke_start_sshd "$TMPDIR"
smoke_start_http_server "$TMPDIR"

cat >"$SSH_CONFIG" <<EOF
Host ${SSH_ALIAS}
  HostName 127.0.0.1
  Port ${SMOKE_SSHD_PORT}
  User ${SMOKE_SSH_USER}
  IdentityFile "${SMOKE_CLIENT_KEY}"
  UserKnownHostsFile "${SMOKE_KNOWN_HOSTS}"
EOF
chmod 600 "$SSH_CONFIG"

REQUEST=$'GET / HTTP/1.1\r\nHost: rustle-ssh-config-smoke\r\nConnection: close\r\n\r\n'
OUT="${TMPDIR}/ssh-config.out"
ERR="${TMPDIR}/ssh-config.err"

smoke_info "running bridge-lab through SSH config alias ${SSH_ALIAS} on local sshd port ${SMOKE_SSHD_PORT}"
set +e
"$RUSTLE_BIN_RESOLVED" \
  bridge-lab \
  -r "$SSH_ALIAS" \
  --ssh-config "$SSH_CONFIG" \
  --destination "127.0.0.1:${SMOKE_HTTP_PORT}" \
  --request "$REQUEST" \
  --connections "$BRIDGE_CONNECTIONS" \
  --bridge-transport direct-tcpip \
  >"$OUT" 2>"$ERR"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "SSH config alias bridge-lab exited with status ${status}"
fi

received_markers="$( (grep -ao 'rustle-smoke-ok' "$OUT" || true) | wc -l | tr -d '[:space:]')"
if [[ "$received_markers" != "$BRIDGE_CONNECTIONS" ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "SSH config alias smoke received ${received_markers} expected markers, wanted ${BRIDGE_CONNECTIONS}"
fi

if ! grep -q "ssh: connecting to 127.0.0.1:${SMOKE_SSHD_PORT}" "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "SSH config alias smoke did not resolve HostName and Port"
fi

if ! grep -q "ssh: connected to 127.0.0.1:${SMOKE_SSHD_PORT}; authenticating as ${SMOKE_SSH_USER}" "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "SSH config alias smoke did not resolve User"
fi

if ! grep -q 'ssh: opening direct-tcpip' "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "SSH config alias smoke did not prove direct-tcpip channel opens"
fi

smoke_info "SSH config alias smoke passed with ${BRIDGE_CONNECTIONS} connections"
