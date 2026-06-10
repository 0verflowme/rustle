#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-active-failure-smoke.XXXXXX")"

cleanup() {
  smoke_stop_pid "${SMOKE_HTTP_PID:-}"
  smoke_stop_pid "${SMOKE_SSHD_PID:-}"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

RUSTLE_BIN_RESOLVED="$(smoke_resolve_rustle_bin)"
HELPER="${TMPDIR}/active-failure-agent.sh"
HELPER_PY="${TMPDIR}/active-failure-agent.py"
MARKER="${TMPDIR}/active-failure-agent.used"
BRIDGE_CONNECTIONS="${RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_CONNECTIONS:-4}"
MIN_COMPLETED="${RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_MIN_COMPLETED:-2}"
DEADLINE_MS="${RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_DEADLINE_MS:-6000}"
AGENT_SESSIONS="${RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_SESSIONS:-1}"
REQUIRE_RESET="${RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_REQUIRE_RESET:-1}"
export RUSTLE_SMOKE_HTTP_BODY_BYTES="${RUSTLE_SMOKE_HTTP_BODY_BYTES:-4096}"

cat >"$HELPER_PY" <<'PY'
import struct
import sys

HELLO = 1
OPEN_TCP = 2
DATA = 4
OPENED = 9

mtu = int(sys.argv[1])

def read_exact(length):
    data = sys.stdin.buffer.read(length)
    if len(data) != length:
        sys.exit(0)
    return data

def read_frame():
    header = read_exact(24)
    if header[:4] != b"RLA1":
        sys.exit(2)
    kind = header[4]
    stream_id = struct.unpack(">Q", header[8:16])[0]
    credit = struct.unpack(">I", header[16:20])[0]
    payload_len = struct.unpack(">I", header[20:24])[0]
    payload = read_exact(payload_len)
    return kind, stream_id, credit, payload

def write_frame(kind, stream_id, payload=b"", credit=0):
    header = (
        b"RLA1"
        + bytes([kind, 0])
        + struct.pack(">H", 0)
        + struct.pack(">Q", stream_id)
        + struct.pack(">I", credit)
        + struct.pack(">I", len(payload))
    )
    sys.stdout.buffer.write(header + payload)
    sys.stdout.buffer.flush()

kind, stream_id, _credit, _payload = read_frame()
if kind != HELLO:
    sys.exit(3)

hello_payload = struct.pack(">HHIQ", 1, mtu, 65536, 15)
write_frame(HELLO, 0, hello_payload)

kind, stream_id, _credit, _payload = read_frame()
if kind != OPEN_TCP:
    sys.exit(4)

write_frame(OPENED, stream_id, credit=256 * 1024)

for _ in range(16):
    kind, current_stream_id, _credit, payload = read_frame()
    if current_stream_id == stream_id and kind == DATA and payload:
        sys.exit(0)

sys.exit(5)
PY

cat >"$HELPER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

marker="$1"
rustle_bin="$2"
python_file="$3"
mtu="${4:-1300}"

if [[ ! -f "$marker" ]]; then
  : >"$marker"
  python3 "$python_file" "$mtu"
  exit 0
fi

exec "$rustle_bin" agent
SH
chmod +x "$HELPER"

quote_arg() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

AGENT_COMMAND="$(quote_arg "$HELPER") $(quote_arg "$MARKER") $(quote_arg "$RUSTLE_BIN_RESOLVED") $(quote_arg "$HELPER_PY") 1300"

smoke_start_sshd "$TMPDIR"
smoke_start_http_server "$TMPDIR"

REQUEST=$'GET / HTTP/1.1\r\nHost: rustle-agent-active-failure-smoke\r\nConnection: close\r\n\r\n'
OUT="${TMPDIR}/agent-active-failure.out"
ERR="${TMPDIR}/agent-active-failure.err"

smoke_info "running agent active-failure bridge-lab through local sshd on port ${SMOKE_SSHD_PORT}"
set +e
"$RUSTLE_BIN_RESOLVED" \
  bridge-lab \
  -r "${SMOKE_SSH_USER}@127.0.0.1:${SMOKE_SSHD_PORT}" \
  -i "$SMOKE_CLIENT_KEY" \
  --known-hosts "$SMOKE_KNOWN_HOSTS" \
  --destination "127.0.0.1:${SMOKE_HTTP_PORT}" \
  --request "$REQUEST" \
  --connections "$BRIDGE_CONNECTIONS" \
  --min-completed "$MIN_COMPLETED" \
  --deadline-ms "$DEADLINE_MS" \
  --bridge-transport agent \
  --agent-sessions "$AGENT_SESSIONS" \
  --agent-command "$AGENT_COMMAND" \
  >"$OUT" 2>"$ERR"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent active-failure bridge-lab exited with status ${status}"
fi

if [[ "$REQUIRE_RESET" == "1" ]] && ! grep -q 'agent: reconnecting after transport failure' "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent active-failure smoke did not observe a reconnect"
fi

if ! grep -q "agent: established ${AGENT_SESSIONS}/${AGENT_SESSIONS} exec transport(s)" "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent active-failure smoke did not establish ${AGENT_SESSIONS} exec transport(s)"
fi

if [[ "$REQUIRE_RESET" == "1" ]] && ! grep -q 'bridge: Write failed.*agent stream reset' "$ERR"; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent active-failure smoke did not observe an active stream reset"
fi

received_markers="$( (grep -ao 'rustle-smoke-ok' "$OUT" || true) | wc -l | tr -d '[:space:]')"
if [[ "$received_markers" -lt "$MIN_COMPLETED" ]]; then
  sed 's/^/rustle stderr: /' "$ERR" >&2 || true
  sed 's/^/rustle stdout: /' "$OUT" >&2 || true
  smoke_die "agent active-failure smoke received ${received_markers} completed responses, wanted at least ${MIN_COMPLETED}"
fi

smoke_info "agent active-failure bridge-lab smoke passed with ${received_markers}/${BRIDGE_CONNECTIONS} completed responses over ${AGENT_SESSIONS} exec transport(s)"
