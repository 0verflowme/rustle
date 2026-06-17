#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

case "$(uname -s)" in
  Darwin | Linux) ;;
  *) smoke_die "release-candidate verifier requires a privileged macOS or Linux host" ;;
esac

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    smoke_die "set ${name} for release-candidate verification"
  fi
}

require_any_env() {
  local description="$1"
  shift
  local name
  for name in "$@"; do
    if [[ -n "${!name:-}" ]]; then
      return 0
    fi
  done
  smoke_die "set one of $* for ${description}"
}

require_env RUSTLE_LIVE_REMOTE
require_env RUSTLE_LIVE_TARGET_CIDR
require_env RUSTLE_LIVE_URL
require_any_env "controlled live TCP fixture" RUSTLE_FIXTURE_HOST RUSTLE_BENCH_FIXTURE_HOST
require_any_env "live UDP fixture" RUSTLE_LIVE_UDP_HOST RUSTLE_LIVE_HOST

smoke_require sshuttle
MAX_AGENT_SSHUTTLE_P50_RATIO="${RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO:-1.00}"
DEFAULT_BENCH_RUSTLE_TRANSPORTS="agent direct-tcpip"
if [[ -n "${RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO:-}" || -n "${RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO:-}" ]]; then
  DEFAULT_BENCH_RUSTLE_TRANSPORTS="agent direct-tcpip quic-native"
fi
EVIDENCE_DIR="${RUSTLE_BENCH_ARTIFACT_DIR:-${PWD}/target/live-evidence/release-candidate-$(date -u +%Y%m%dT%H%M%SZ)}"
HOTPATH_TRACE="${RUSTLE_HOTPATH_TRACE:-1}"
mkdir -p "$EVIDENCE_DIR"

verify_info() {
  smoke_info "release-candidate: $*"
}

verify_info "running full local verifier with privileged, DNS takeover, live TCP, live fixture, and live UDP gates required"
verify_info "live target: ${RUSTLE_LIVE_REMOTE} ${RUSTLE_LIVE_TARGET_CIDR} ${RUSTLE_LIVE_URL}"
verify_info "live evidence artifacts: ${EVIDENCE_DIR}"

env \
  RUSTLE_VERIFY_PRIVILEGED=1 \
  RUSTLE_VERIFY_REQUIRE_PRIVILEGED=1 \
  RUSTLE_VERIFY_DNS_TAKEOVER=1 \
  RUSTLE_VERIFY_LIVE=1 \
  RUSTLE_VERIFY_LIVE_FIXTURE=1 \
  RUSTLE_VERIFY_LIVE_UDP=1 \
  RUSTLE_VERIFY_LIVE_TRANSPORTS="${RUSTLE_VERIFY_LIVE_TRANSPORTS:-agent direct-tcpip}" \
  RUSTLE_LIVE_REQUESTS="${RUSTLE_LIVE_REQUESTS:-4}" \
  RUSTLE_LIVE_CONCURRENCY="${RUSTLE_LIVE_CONCURRENCY:-2}" \
  RUSTLE_BENCH_REQUESTS="${RUSTLE_BENCH_REQUESTS:-16}" \
  RUSTLE_BENCH_CONCURRENCY="${RUSTLE_BENCH_CONCURRENCY:-4}" \
  RUSTLE_BENCH_RUNS="${RUSTLE_BENCH_RUNS:-3}" \
  RUSTLE_BENCH_WARMUP_RUNS="${RUSTLE_BENCH_WARMUP_RUNS:-1}" \
  RUSTLE_HOTPATH_TRACE="${HOTPATH_TRACE}" \
  RUSTLE_BENCH_ARTIFACT_DIR="${EVIDENCE_DIR}" \
  RUSTLE_BENCH_TOOLS="rustle sshuttle" \
  RUSTLE_BENCH_RUSTLE_TRANSPORTS="${RUSTLE_BENCH_RUSTLE_TRANSPORTS:-$DEFAULT_BENCH_RUSTLE_TRANSPORTS}" \
  RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO="${MAX_AGENT_SSHUTTLE_P50_RATIO}" \
  "${SCRIPT_DIR}/verify-local.sh"

EVIDENCE_VERIFY_ARGS=("$EVIDENCE_DIR")
case "$HOTPATH_TRACE" in
  1 | true | yes) EVIDENCE_VERIFY_ARGS=(--require-hotpath "$EVIDENCE_DIR") ;;
  0 | false | no) ;;
  *) smoke_die "RUSTLE_HOTPATH_TRACE must be 0 or 1 for release-candidate evidence verification" ;;
esac

verify_info "verifying live evidence artifacts"
"$(smoke_python)" "${SCRIPT_DIR}/verify-live-evidence.py" "${EVIDENCE_VERIFY_ARGS[@]}"
