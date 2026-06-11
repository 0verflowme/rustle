# shellcheck shell=bash

SMOKE_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SMOKE_REPO_ROOT="$(cd -- "${SMOKE_LIB_DIR}/.." && pwd)"

smoke_info() {
  printf 'smoke: %s\n' "$*" >&2
}

smoke_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

smoke_skip() {
  printf 'skip: %s\n' "$*" >&2
  exit 77
}

smoke_require() {
  command -v "$1" >/dev/null 2>&1 || smoke_die "missing required command: $1"
}

smoke_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
  elif command -v python >/dev/null 2>&1; then
    printf '%s\n' python
  else
    smoke_die "missing required command: python3"
  fi
}

smoke_find_free_port() {
  local py
  py="$(smoke_python)"
  "$py" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

smoke_temp_root() {
  printf '%s\n' "${TMPDIR:-/tmp}"
}

smoke_uploaded_agent_artifacts() {
  local root
  root="$(smoke_temp_root)"
  [[ -d "$root" ]] || return 0

  find "$root" -maxdepth 1 \( \
    -name 'rustle-agent-[0-9]*' \
    -o -name 'rustle-agent-[0-9]*.refs' \
  \) -print 2>/dev/null | sort
}

smoke_uploaded_agent_artifact_count() {
  smoke_uploaded_agent_artifacts | wc -l | tr -d '[:space:]'
}

smoke_wait_for_uploaded_agent_cleanup() {
  local seconds="${1:-5}"
  local attempts=$((seconds * 10))
  local count

  for ((i = 0; i <= attempts; i++)); do
    count="$(smoke_uploaded_agent_artifact_count)"
    if [[ "$count" == "0" ]]; then
      return 0
    fi
    sleep 0.1
  done

  smoke_info "uploaded agent artifacts remain under $(smoke_temp_root):"
  smoke_uploaded_agent_artifacts | sed 's/^/  /' >&2 || true
  smoke_die "uploaded agent cleanup left ${count} artifact(s)"
}

smoke_wait_for_file() {
  local path="$1"
  local seconds="$2"
  local attempts=$((seconds * 10))

  for ((i = 0; i < attempts; i++)); do
    [[ -s "$path" ]] && return 0
    sleep 0.1
  done

  return 1
}

smoke_wait_for_log() {
  local pattern="$1"
  local path="$2"
  local seconds="$3"
  local attempts=$((seconds * 10))

  for ((i = 0; i < attempts; i++)); do
    if [[ -f "$path" ]] && grep -Eq "$pattern" "$path"; then
      return 0
    fi
    sleep 0.1
  done

  return 1
}

smoke_process_running() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 1
  local stat
  stat="$(ps -o stat= -p "$pid" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  [[ -n "$stat" && "${stat#Z}" == "$stat" ]]
}

smoke_wait_for_log_or_exit() {
  local pattern="$1"
  local path="$2"
  local seconds="$3"
  local pid="$4"
  local label="$5"
  local attempts=$((seconds * 10))

  for ((i = 0; i < attempts; i++)); do
    if [[ -f "$path" ]] && grep -Eq "$pattern" "$path"; then
      return 0
    fi
    if ! smoke_process_running "$pid"; then
      sed "s/^/${label}: /" "$path" >&2 || true
      smoke_die "${label} exited before readiness"
    fi
    sleep 0.1
  done

  return 1
}

smoke_wait_for_log_fixed_or_exit() {
  local text="$1"
  local path="$2"
  local seconds="$3"
  local pid="$4"
  local label="$5"
  local attempts=$((seconds * 10))

  for ((i = 0; i < attempts; i++)); do
    if [[ -f "$path" ]] && grep -Fq "$text" "$path"; then
      return 0
    fi
    if ! smoke_process_running "$pid"; then
      sed "s/^/${label}: /" "$path" >&2 || true
      smoke_die "${label} exited before readiness"
    fi
    sleep 0.1
  done

  return 1
}

smoke_wait_for_rustle_target_route_logs() {
  local target_prefix="$1"
  local target_cidr="$2"
  local log_path="$3"
  local seconds="$4"
  local pid="$5"
  local label="$6"

  if [[ "$target_prefix" == "0" ]]; then
    smoke_wait_for_log_fixed_or_exit "route: added 0.0.0.0/1" \
      "$log_path" "$seconds" "$pid" "$label" &&
      smoke_wait_for_log_fixed_or_exit "route: added 128.0.0.0/1" \
        "$log_path" "$seconds" "$pid" "$label"
  else
    smoke_wait_for_log_fixed_or_exit "route: added ${target_cidr}" \
      "$log_path" "$seconds" "$pid" "$label"
  fi
}

smoke_wait_for_port() {
  local host="$1"
  local port="$2"
  local seconds="$3"
  local py
  py="$(smoke_python)"

  "$py" - "$host" "$port" "$seconds" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.time() + float(sys.argv[3])

while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            sys.exit(0)
    except OSError:
        time.sleep(0.1)

sys.exit(1)
PY
}

smoke_resolve_rustle_bin() {
  if [[ -n "${RUSTLE_BIN:-}" ]]; then
    [[ -x "$RUSTLE_BIN" ]] || smoke_die "RUSTLE_BIN is not executable: $RUSTLE_BIN"
    printf '%s\n' "$RUSTLE_BIN"
    return
  fi

  local candidate="${SMOKE_REPO_ROOT}/target/debug/rustle"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return
  fi

  smoke_die "missing Rustle binary; run 'cargo build' or set RUSTLE_BIN=/path/to/rustle"
}

smoke_resolve_rustle_bench_bin() {
  if [[ -n "${RUSTLE_BIN:-}" ]]; then
    smoke_resolve_rustle_bin
    return
  fi

  local profile="${RUSTLE_BENCH_PROFILE:-release}"
  case "$profile" in
    debug | release) ;;
    *) smoke_die "RUSTLE_BENCH_PROFILE must be debug or release" ;;
  esac

  local candidate="${SMOKE_REPO_ROOT}/target/${profile}/rustle"
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return
  fi

  if [[ "$profile" == "release" ]]; then
    smoke_die "missing release Rustle binary; run 'cargo build --release' or set RUSTLE_BIN=/path/to/rustle"
  fi
  smoke_die "missing debug Rustle binary; run 'cargo build' or set RUSTLE_BIN=/path/to/rustle"
}

smoke_start_sshd() {
  local tmpdir="$1"

  smoke_require ssh
  smoke_require ssh-keygen

  local sshd_path="${SSHD:-}"
  if [[ -z "$sshd_path" ]]; then
    if command -v sshd >/dev/null 2>&1; then
      sshd_path="$(command -v sshd)"
    elif [[ -x /usr/sbin/sshd ]]; then
      sshd_path=/usr/sbin/sshd
    else
      smoke_skip "OpenSSH sshd is not installed"
    fi
  fi

  [[ -x "$sshd_path" ]] || smoke_die "sshd is not executable: $sshd_path"

  SMOKE_SSHD_PORT="${RUSTLE_SMOKE_SSHD_PORT:-$(smoke_find_free_port)}"
  SMOKE_SSH_USER="${RUSTLE_SMOKE_USER:-${USER:-$(id -un)}}"
  SMOKE_CLIENT_KEY="${tmpdir}/client_ed25519"
  SMOKE_HOST_KEY="${tmpdir}/ssh_host_ed25519_key"
  SMOKE_AUTHORIZED_KEYS="${tmpdir}/authorized_keys"
  SMOKE_KNOWN_HOSTS="${tmpdir}/known_hosts"
  SMOKE_SSHD_CONFIG="${tmpdir}/sshd_config"
  SMOKE_SSHD_LOG="${tmpdir}/sshd.log"

  ssh-keygen -q -t ed25519 -N '' -f "$SMOKE_CLIENT_KEY"
  ssh-keygen -q -t ed25519 -N '' -f "$SMOKE_HOST_KEY"
  cp "$SMOKE_CLIENT_KEY.pub" "$SMOKE_AUTHORIZED_KEYS"
  chmod 600 "$SMOKE_CLIENT_KEY" "$SMOKE_AUTHORIZED_KEYS"

  local host_pub
  host_pub="$(awk '{ print $1 " " $2 }' "$SMOKE_HOST_KEY.pub")"
  printf '[127.0.0.1]:%s %s\n' "$SMOKE_SSHD_PORT" "$host_pub" >"$SMOKE_KNOWN_HOSTS"

  {
    printf 'Port %s\n' "$SMOKE_SSHD_PORT"
    printf 'ListenAddress 127.0.0.1\n'
    printf 'HostKey %s\n' "$SMOKE_HOST_KEY"
    printf 'PidFile %s\n' "${tmpdir}/sshd.pid"
    printf 'AuthorizedKeysFile %s\n' "$SMOKE_AUTHORIZED_KEYS"
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
  } >"$SMOKE_SSHD_CONFIG"

  "$sshd_path" -f "$SMOKE_SSHD_CONFIG" -D -e >"$SMOKE_SSHD_LOG" 2>&1 &
  SMOKE_SSHD_PID=$!

  if ! smoke_wait_for_port 127.0.0.1 "$SMOKE_SSHD_PORT" 10; then
    sed 's/^/sshd: /' "$SMOKE_SSHD_LOG" >&2 || true
    smoke_die "sshd did not start on 127.0.0.1:${SMOKE_SSHD_PORT}"
  fi

  local ok=0
  for ((i = 0; i < 30; i++)); do
    if ssh \
      -o BatchMode=yes \
      -o ConnectTimeout=2 \
      -o IdentitiesOnly=yes \
      -o StrictHostKeyChecking=yes \
      -o UserKnownHostsFile="$SMOKE_KNOWN_HOSTS" \
      -i "$SMOKE_CLIENT_KEY" \
      -p "$SMOKE_SSHD_PORT" \
      "${SMOKE_SSH_USER}@127.0.0.1" true >/dev/null 2>>"$SMOKE_SSHD_LOG"; then
      ok=1
      break
    fi
    sleep 0.2
  done

  if [[ "$ok" -ne 1 ]]; then
    sed 's/^/sshd: /' "$SMOKE_SSHD_LOG" >&2 || true
    smoke_die "could not authenticate to local sshd as ${SMOKE_SSH_USER}"
  fi

  export SMOKE_SSHD_PID SMOKE_SSHD_PORT SMOKE_SSH_USER SMOKE_CLIENT_KEY
  export SMOKE_KNOWN_HOSTS SMOKE_SSHD_LOG
}

smoke_start_http_server() {
  local tmpdir="$1"
  local py
  py="$(smoke_python)"

  SMOKE_HTTP_PORT="${RUSTLE_SMOKE_HTTP_PORT:-$(smoke_find_free_port)}"
  SMOKE_HTTP_READY="${tmpdir}/http.ready"
  SMOKE_HTTP_LOG="${tmpdir}/http.log"

  "$py" - "$SMOKE_HTTP_PORT" "$SMOKE_HTTP_READY" >"$SMOKE_HTTP_LOG" 2>&1 <<'PY' &
import socket
import sys
import os

port = int(sys.argv[1])
ready = sys.argv[2]
marker = b"rustle-smoke-ok\n"
body_size = int(os.environ.get("RUSTLE_SMOKE_HTTP_BODY_BYTES", str(len(marker))))
body = marker
if body_size > len(marker):
    body += b"x" * (body_size - len(marker))
response = (
    b"HTTP/1.1 200 OK\r\n"
    + b"Content-Type: text/plain\r\n"
    + b"Content-Length: "
    + str(len(body)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + body
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(50)
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write(str(port))

    while True:
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(2)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            conn.sendall(response)
PY
  SMOKE_HTTP_PID=$!

  if ! smoke_wait_for_file "$SMOKE_HTTP_READY" 5; then
    sed 's/^/http: /' "$SMOKE_HTTP_LOG" >&2 || true
    smoke_die "HTTP smoke server did not start"
  fi

  export SMOKE_HTTP_PID SMOKE_HTTP_PORT SMOKE_HTTP_LOG
}

smoke_start_dns_tcp_server() {
  local tmpdir="$1"
  local py
  py="$(smoke_python)"

  SMOKE_DNS_TCP_PORT="${RUSTLE_SMOKE_DNS_TCP_PORT:-$(smoke_find_free_port)}"
  SMOKE_DNS_READY="${tmpdir}/dns.ready"
  SMOKE_DNS_LOG="${tmpdir}/dns.log"

  "$py" - "$SMOKE_DNS_TCP_PORT" "$SMOKE_DNS_READY" >"$SMOKE_DNS_LOG" 2>&1 <<'PY' &
import socket
import struct
import sys
import threading

port = int(sys.argv[1])
ready = sys.argv[2]
answer_ip = bytes([203, 0, 113, 7])

def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def find_question_end(query):
    if len(query) < 12:
        return None
    offset = 12
    while True:
        if offset >= len(query):
            return None
        label_len = query[offset]
        offset += 1
        if label_len == 0:
            break
        if label_len & 0xC0:
            return None
        offset += label_len
    end = offset + 4
    if end > len(query):
        return None
    return end

def build_response(query):
    query_id = query[:2] if len(query) >= 2 else b"\x00\x00"
    qend = find_question_end(query)
    if qend is None:
        return query_id + b"\x81\x82" + b"\x00\x00\x00\x00\x00\x00\x00\x00"

    question = query[12:qend]
    header = query_id + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = (
        b"\xc0\x0c"
        + b"\x00\x01"
        + b"\x00\x01"
        + struct.pack("!I", 30)
        + b"\x00\x04"
        + answer_ip
    )
    return header + question + answer

def handle(conn):
    with conn:
        conn.settimeout(5)
        length = recv_exact(conn, 2)
        if length is None:
            return
        size = struct.unpack("!H", length)[0]
        query = recv_exact(conn, size)
        if query is None:
            return
        response = build_response(query)
        conn.sendall(struct.pack("!H", len(response)) + response)

def serve_udp(sock):
    while True:
        query, peer = sock.recvfrom(4096)
        response = build_response(query)
        sock.sendto(response, peer)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock, \
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("127.0.0.1", port))
    tcp_sock.listen(50)

    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("127.0.0.1", port))

    with open(ready, "w", encoding="utf-8") as handle_ready:
        handle_ready.write(str(port))

    threading.Thread(target=serve_udp, args=(udp_sock,), daemon=True).start()

    while True:
        conn, _ = tcp_sock.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY
  SMOKE_DNS_PID=$!

  if ! smoke_wait_for_file "$SMOKE_DNS_READY" 5; then
    sed 's/^/dns: /' "$SMOKE_DNS_LOG" >&2 || true
    smoke_die "DNS smoke server did not start"
  fi

  export SMOKE_DNS_PID SMOKE_DNS_TCP_PORT SMOKE_DNS_LOG
}

smoke_stop_pid() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" >/dev/null 2>&1 || return 0
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

smoke_children_of() {
  local pid="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -P "$pid" 2>/dev/null || true
  else
    ps -o pid= -P "$pid" 2>/dev/null | awk '{ print $1 }'
  fi
}

smoke_interrupt_process_tree() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0

  local child
  while read -r child; do
    [[ -n "$child" ]] || continue
    sudo -n kill -INT "$child" >/dev/null 2>&1 || kill -INT "$child" >/dev/null 2>&1 || true
  done < <(smoke_children_of "$pid")

  sudo -n kill -INT "$pid" >/dev/null 2>&1 || kill -INT "$pid" >/dev/null 2>&1 || true

  for ((i = 0; i < 50; i++)); do
    kill -0 "$pid" >/dev/null 2>&1 || return 0
    sleep 0.1
  done

  while read -r child; do
    [[ -n "$child" ]] || continue
    sudo -n kill -TERM "$child" >/dev/null 2>&1 || kill -TERM "$child" >/dev/null 2>&1 || true
  done < <(smoke_children_of "$pid")
  sudo -n kill -TERM "$pid" >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

smoke_stat_value() {
  local line="$1"
  local regex="$2"
  printf '%s\n' "$line" | sed -nE "s|${regex}|\\1|p" | tail -n 1
}

smoke_require_stat_number() {
  local label="$1"
  local value="$2"
  local final_stats="$3"
  case "$value" in
    '' | *[!0-9]*)
      printf 'final stats: %s\n' "$final_stats" >&2
      smoke_die "could not parse numeric final stat ${label}"
      ;;
  esac
}

smoke_require_stat_at_least() {
  local label="$1"
  local value="$2"
  local minimum="$3"
  local final_stats="$4"
  smoke_require_stat_number "$label" "$value" "$final_stats"
  if [[ "$value" -lt "$minimum" ]]; then
    printf 'final stats: %s\n' "$final_stats" >&2
    smoke_die "expected ${label} >= ${minimum}, saw ${value}"
  fi
}

smoke_require_stat_zero() {
  local label="$1"
  local value="$2"
  local final_stats="$3"
  smoke_require_stat_number "$label" "$value" "$final_stats"
  if [[ "$value" -ne 0 ]]; then
    printf 'final stats: %s\n' "$final_stats" >&2
    smoke_die "expected ${label}=0, saw ${value}"
  fi
}
