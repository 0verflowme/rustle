#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_skip "live fixture benchmark is implemented for macOS and Linux" ;;
esac

smoke_require ssh

REMOTE="${RUSTLE_FIXTURE_REMOTE:-${RUSTLE_BENCH_REMOTE:-${RUSTLE_LIVE_REMOTE:-}}}"
FIXTURE_HOST="${RUSTLE_FIXTURE_HOST:-${RUSTLE_BENCH_FIXTURE_HOST:-}}"
FIXTURE_BIND="${RUSTLE_FIXTURE_BIND:-0.0.0.0}"
FIXTURE_PORT="${RUSTLE_FIXTURE_PORT:-0}"
FIXTURE_BODY_BYTES="${RUSTLE_FIXTURE_BODY_BYTES:-1048576 10485760 104857600}"
FIXTURE_PYTHON="${RUSTLE_FIXTURE_PYTHON:-python3}"
FIXTURE_LISTEN_BACKLOG="${RUSTLE_FIXTURE_LISTEN_BACKLOG:-256}"
TARGET_CIDR="${RUSTLE_FIXTURE_TARGET_CIDR:-${RUSTLE_BENCH_TARGET_CIDR:-}}"

[[ -n "$REMOTE" ]] || smoke_die "set RUSTLE_FIXTURE_REMOTE or RUSTLE_BENCH_REMOTE, for example user@ssh.example.com"
[[ -n "$FIXTURE_HOST" ]] || smoke_die "set RUSTLE_FIXTURE_HOST to the remote IP reachable through Rustle, for example 192.168.190.45"
if [[ -z "$TARGET_CIDR" ]]; then
  TARGET_CIDR="${FIXTURE_HOST}/32"
fi
case "$FIXTURE_PORT" in
  '' | *[!0-9]*) smoke_die "RUSTLE_FIXTURE_PORT must be a non-negative integer" ;;
esac
case "$FIXTURE_LISTEN_BACKLOG" in
  '' | *[!0-9]*) smoke_die "RUSTLE_FIXTURE_LISTEN_BACKLOG must be a positive integer" ;;
esac
if [[ "$FIXTURE_LISTEN_BACKLOG" -lt 1 ]]; then
  smoke_die "RUSTLE_FIXTURE_LISTEN_BACKLOG must be at least 1"
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-live-fixture.XXXXXX")"
FIXTURE_PID=""
FIXTURE_PASSWORD_FILE=""

cleanup() {
  if [[ -n "$FIXTURE_PID" ]]; then
    kill "$FIXTURE_PID" >/dev/null 2>&1 || true
    wait "$FIXTURE_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$FIXTURE_PASSWORD_FILE" ]]; then
    rm -f "$FIXTURE_PASSWORD_FILE"
  fi
  if [[ "${RUSTLE_FIXTURE_KEEP_LOGS:-0}" == "1" ]]; then
    smoke_info "kept live fixture logs in ${TMPDIR}"
  else
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

parse_ssh_remote() {
  local remote="$1"
  if [[ "$remote" =~ ^([^@]+@)?([^:]+):([0-9]+)$ ]]; then
    printf '%s%s\n%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
  else
    printf '%s\n\n' "$remote"
  fi
}

SSH_REMOTE_INFO="$(parse_ssh_remote "${RUSTLE_FIXTURE_SSH_REMOTE:-$REMOTE}")"
SSH_REMOTE="$(printf '%s\n' "$SSH_REMOTE_INFO" | sed -n '1p')"
SSH_PORT="$(printf '%s\n' "$SSH_REMOTE_INFO" | sed -n '2p')"
FIXTURE_IDENTITY="${RUSTLE_FIXTURE_IDENTITY:-${RUSTLE_BENCH_IDENTITY:-${RUSTLE_LIVE_IDENTITY:-}}}"
FIXTURE_INSECURE_HOST_KEY="${RUSTLE_FIXTURE_INSECURE_HOST_KEY:-${RUSTLE_BENCH_INSECURE_HOST_KEY:-${RUSTLE_LIVE_INSECURE_HOST_KEY:-0}}}"
FIXTURE_KNOWN_HOSTS="${RUSTLE_FIXTURE_KNOWN_HOSTS:-${RUSTLE_BENCH_KNOWN_HOSTS:-${RUSTLE_LIVE_KNOWN_HOSTS:-}}}"
SSH_PASSWORD_VALUE="${RUSTLE_FIXTURE_PASSWORD_VALUE:-${RUSTLE_BENCH_PASSWORD_VALUE:-${RUSTLE_LIVE_PASSWORD_VALUE:-}}}"
if [[ -z "$SSH_PASSWORD_VALUE" && "${RUSTLE_FIXTURE_PASSWORD:-0}" == "1" ]]; then
  printf 'SSH password for live fixture: ' >&2
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
if [[ -n "$FIXTURE_IDENTITY" ]]; then
  SSH_CMD+=(-i "$FIXTURE_IDENTITY" -o IdentitiesOnly=yes)
fi
if [[ "$FIXTURE_INSECURE_HOST_KEY" == "1" ]]; then
  SSH_CMD+=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
elif [[ -n "$FIXTURE_KNOWN_HOSTS" ]]; then
  SSH_CMD+=(-o UserKnownHostsFile="$FIXTURE_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
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

BENCH_ENV=()
if [[ -n "$SSH_PASSWORD_VALUE" && -z "${RUSTLE_BENCH_PASSWORD_VALUE:-}" && -z "${RUSTLE_LIVE_PASSWORD_VALUE:-}" ]]; then
  BENCH_ENV+=(RUSTLE_BENCH_PASSWORD_VALUE="$SSH_PASSWORD_VALUE")
fi
if [[ -n "$SSH_PASSWORD_VALUE" && -z "${RUSTLE_BENCH_SSHUTTLE_PASSWORD_VALUE:-}" ]]; then
  BENCH_ENV+=(RUSTLE_BENCH_SSHUTTLE_PASSWORD_VALUE="$SSH_PASSWORD_VALUE")
fi
if [[ -n "${RUSTLE_FIXTURE_IDENTITY:-}" && -z "${RUSTLE_BENCH_IDENTITY:-}" && -z "${RUSTLE_LIVE_IDENTITY:-}" ]]; then
  BENCH_ENV+=(RUSTLE_BENCH_IDENTITY="$RUSTLE_FIXTURE_IDENTITY")
fi
if [[ -n "${RUSTLE_FIXTURE_INSECURE_HOST_KEY:-}" && -z "${RUSTLE_BENCH_INSECURE_HOST_KEY:-}" && -z "${RUSTLE_LIVE_INSECURE_HOST_KEY:-}" ]]; then
  BENCH_ENV+=(RUSTLE_BENCH_INSECURE_HOST_KEY="$RUSTLE_FIXTURE_INSECURE_HOST_KEY")
fi
if [[ -n "${RUSTLE_FIXTURE_KNOWN_HOSTS:-}" && -z "${RUSTLE_BENCH_KNOWN_HOSTS:-}" && -z "${RUSTLE_LIVE_KNOWN_HOSTS:-}" ]]; then
  BENCH_ENV+=(RUSTLE_BENCH_KNOWN_HOSTS="$RUSTLE_FIXTURE_KNOWN_HOSTS")
fi

wait_for_fixture_ready() {
  local ready_file="$1"
  local err_file="$2"
  local seconds="${RUSTLE_FIXTURE_READY_SECONDS:-15}"
  case "$seconds" in
    '' | *[!0-9]*) smoke_die "RUSTLE_FIXTURE_READY_SECONDS must be a positive integer" ;;
  esac
  local attempts=$((seconds * 10))
  for ((i = 0; i < attempts; i++)); do
    if grep -Eq '^READY [0-9]+$' "$ready_file" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$FIXTURE_PID" ]] && ! smoke_process_running "$FIXTURE_PID"; then
      sed 's/^/fixture: /' "$err_file" >&2 || true
      smoke_die "remote live fixture exited before readiness"
    fi
    sleep 0.1
  done
  sed 's/^/fixture: /' "$err_file" >&2 || true
  smoke_die "remote live fixture did not become ready"
}

start_fixture() {
  local body_bytes="$1"
  local out_file="$2"
  local err_file="$3"
  FIXTURE_PID=""
  "${SSH_CMD[@]}" "$FIXTURE_PYTHON" - "$FIXTURE_BIND" "$FIXTURE_PORT" "$body_bytes" "$FIXTURE_LISTEN_BACKLOG" \
    >"$out_file" 2>"$err_file" <<'PY' &
import socket
import sys
import threading

bind = sys.argv[1]
port = int(sys.argv[2])
body_size = int(sys.argv[3])
listen_backlog = int(sys.argv[4])
marker = b"rustle-live-fixture\n"
if body_size < len(marker):
    body_prefix = marker[:body_size]
    filler_len = 0
else:
    body_prefix = marker
    filler_len = body_size - len(marker)
response_header = (
    b"HTTP/1.1 200 OK\r\n"
    + b"Content-Type: application/octet-stream\r\n"
    + b"Content-Length: "
    + str(body_size).encode("ascii")
    + b"\r\nConnection: close\r\n\r\n"
)
filler = b"x" * 65536

def serve(conn):
    try:
        conn.settimeout(5)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        is_head = data[:5].upper() == b"HEAD "
        conn.sendall(response_header)
        if is_head:
            return
        if body_prefix:
            conn.sendall(body_prefix)
        remaining = filler_len
        while remaining > 0:
            chunk = filler[: min(len(filler), remaining)]
            conn.sendall(chunk)
            remaining -= len(chunk)
    finally:
        conn.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(listen_backlog)
    sys.stdout.write("READY %d\n" % sock.getsockname()[1])
    sys.stdout.flush()
    while True:
        conn, _peer = sock.accept()
        thread = threading.Thread(target=serve, args=(conn,))
        thread.daemon = True
        thread.start()
finally:
    sock.close()
PY
  FIXTURE_PID=$!
  wait_for_fixture_ready "$out_file" "$err_file"
}

stop_fixture() {
  if [[ -n "$FIXTURE_PID" ]]; then
    kill "$FIXTURE_PID" >/dev/null 2>&1 || true
    wait "$FIXTURE_PID" >/dev/null 2>&1 || true
    FIXTURE_PID=""
  fi
}

for body_bytes in $FIXTURE_BODY_BYTES; do
  case "$body_bytes" in
    '' | *[!0-9]*) smoke_die "RUSTLE_FIXTURE_BODY_BYTES entries must be positive integers" ;;
  esac
  if [[ "$body_bytes" -lt 1 ]]; then
    smoke_die "RUSTLE_FIXTURE_BODY_BYTES entries must be at least 1"
  fi

  fixture_out="${TMPDIR}/fixture-${body_bytes}.out"
  fixture_err="${TMPDIR}/fixture-${body_bytes}.err"
  start_fixture "$body_bytes" "$fixture_out" "$fixture_err"
  actual_port="$(sed -n 's/^READY //p' "$fixture_out" | tail -n 1)"
  fixture_url="http://${FIXTURE_HOST}:${actual_port}/"
  smoke_info "benchmarking live fixture body_bytes=${body_bytes} url=${fixture_url}"

  env "${BENCH_ENV[@]}" \
    RUSTLE_BENCH_REMOTE="$REMOTE" \
    RUSTLE_BENCH_TARGET_CIDR="$TARGET_CIDR" \
    RUSTLE_BENCH_URL="$fixture_url" \
    RUSTLE_BENCH_ROUTE_PROBE_IP="$FIXTURE_HOST" \
    RUSTLE_BENCH_EXPECT=rustle-live-fixture \
    RUSTLE_BENCH_EXPECT_BYTES="$body_bytes" \
    RUSTLE_BENCH_READY_METHOD=HEAD \
    "${SCRIPT_DIR}/bench-live-compare.sh"
  stop_fixture
done
