#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

RUN_ROOTLESS="${RUSTLE_VERIFY_ROOTLESS:-1}"
RUN_PRIVILEGED="${RUSTLE_VERIFY_PRIVILEGED:-auto}"
REQUIRE_PRIVILEGED="${RUSTLE_VERIFY_REQUIRE_PRIVILEGED:-0}"
RUN_DNS_TAKEOVER="${RUSTLE_VERIFY_DNS_TAKEOVER:-0}"
RUN_BENCH="${RUSTLE_VERIFY_BENCH:-1}"
RUN_STRESS="${RUSTLE_VERIFY_STRESS:-1}"
RUN_LIVE="${RUSTLE_VERIFY_LIVE:-0}"
RUN_LIVE_FIXTURE="${RUSTLE_VERIFY_LIVE_FIXTURE:-0}"
RUN_LIVE_UDP="${RUSTLE_VERIFY_LIVE_UDP:-0}"
LIVE_TRANSPORTS="${RUSTLE_VERIFY_LIVE_TRANSPORTS:-${RUSTLE_LIVE_BRIDGE_TRANSPORT:-agent direct-tcpip}}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

passes=0
skips=0

for bool_flag in RUN_DNS_TAKEOVER RUN_LIVE_FIXTURE RUN_LIVE_UDP; do
  case "${!bool_flag}" in
    0 | 1) ;;
    *) smoke_die "${bool_flag/RUN_/RUSTLE_VERIFY_} must be 0 or 1" ;;
  esac
done

verify_info() {
  smoke_info "verify: $*"
}

verify_run() {
  verify_info "$*"
  "$@"
  passes=$((passes + 1))
}

verify_run_skip_ok() {
  verify_info "$*"
  local status=0
  set +e
  "$@"
  status=$?
  set -e

  case "$status" in
    0)
      passes=$((passes + 1))
      ;;
    77)
      skips=$((skips + 1))
      if [[ "$REQUIRE_PRIVILEGED" == "1" ]]; then
        smoke_die "required verification gate skipped: $*"
      fi
      ;;
    *)
      smoke_die "verification gate failed with status ${status}: $*"
      ;;
  esac
}

can_passwordless_sudo() {
  [[ "$(id -u)" -eq 0 ]] || sudo -n true >/dev/null 2>&1
}

should_run_privileged() {
  case "$RUN_PRIVILEGED" in
    1 | true | yes)
      return 0
      ;;
    0 | false | no)
      return 1
      ;;
    auto)
      case "$(uname -s)" in
        Darwin | Linux)
          can_passwordless_sudo
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    *)
      smoke_die "RUSTLE_VERIFY_PRIVILEGED must be auto, 1, or 0"
      ;;
  esac
}

verify_run cargo fmt --check
verify_run cargo test
verify_run cargo clippy --all-targets -- -D warnings
verify_run "$(smoke_python)" "${SCRIPT_DIR}/verify-release-matrix.py"
verify_run "$(smoke_python)" "${SCRIPT_DIR}/code-health.py" --top 25
verify_run "$(smoke_python)" "${SCRIPT_DIR}/verify-live-benchmark-rows.py" --self-test
verify_run "$(smoke_python)" "${SCRIPT_DIR}/verify-live-fixture-rows.py" --self-test
verify_run "$(smoke_python)" "${SCRIPT_DIR}/summarize-hotpath-trace.py" --self-test
verify_run "$(smoke_python)" "${SCRIPT_DIR}/summarize-quic-diagnostics.py" --self-test
verify_run "$(smoke_python)" "${SCRIPT_DIR}/verify-release-archives.py" --self-test
verify_run "$(smoke_python)" "${SCRIPT_DIR}/verify-windows-tun-smoke.py"
for script in "${SCRIPT_DIR}"/*.sh; do
  verify_run bash -n "$script"
done
if command -v pwsh >/dev/null 2>&1; then
  verify_run pwsh -NoProfile -Command '$errors = $null; $tokens = $null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path "scripts/smoke-windows-tun.ps1"), [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | Format-List *; exit 1 }'
else
  skips=$((skips + 1))
  verify_info "PowerShell syntax check skipped; pwsh unavailable"
fi
verify_run cargo build --locked
verify_run smoke_wait_for_uploaded_agent_cleanup

if [[ "$RUN_ROOTLESS" == "1" ]]; then
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-bridge-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-ssh-config-alias-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-sidecars.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-udp-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-bridge-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-quic-agent-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-reconnect-lab.sh"
  verify_run_skip_ok "${SCRIPT_DIR}/smoke-agent-active-failure-lab.sh"
  verify_run_skip_ok env RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_SESSIONS=2 RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_CONNECTIONS=6 RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_MIN_COMPLETED=4 RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_REQUIRE_RESET=0 "${SCRIPT_DIR}/smoke-agent-active-failure-lab.sh"
  verify_run smoke_wait_for_uploaded_agent_cleanup
fi

if should_run_privileged; then
  verify_run_skip_ok env RUSTLE_SMOKE_BRIDGE_TRANSPORT=direct-tcpip "${SCRIPT_DIR}/smoke-tun-dns.sh"
  verify_run_skip_ok env RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent "${SCRIPT_DIR}/smoke-tun-dns.sh"
  verify_run_skip_ok env RUSTLE_SMOKE_TARGET_CIDR=0.0.0.0/0 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent RUSTLE_SMOKE_ROUTE_ONLY=1 "${SCRIPT_DIR}/smoke-tun-dns.sh"
  if [[ "$RUN_DNS_TAKEOVER" == "1" ]]; then
    verify_run_skip_ok env RUSTLE_SMOKE_CONFIGURE_DNS=1 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent "${SCRIPT_DIR}/smoke-tun-dns.sh"
  fi
  case "$(uname -s)" in
    Linux)
      verify_run_skip_ok "${SCRIPT_DIR}/smoke-linux-netns-tcp.sh"
      verify_run_skip_ok env RUSTLE_NETNS_BRIDGE_TRANSPORT=agent "${SCRIPT_DIR}/smoke-linux-netns-tcp.sh"
      verify_run_skip_ok "${SCRIPT_DIR}/smoke-linux-netns-udp.sh"
      ;;
    *)
      skips=$((skips + 3))
      verify_info "Linux network namespace gates skipped on $(uname -s); not required on this platform"
      ;;
  esac
  verify_run smoke_wait_for_uploaded_agent_cleanup
else
  skips=$((skips + 1))
  verify_info "privileged TUN/netns gates skipped; set RUSTLE_VERIFY_PRIVILEGED=1 to require an attempt"
  if [[ "$REQUIRE_PRIVILEGED" == "1" ]]; then
    smoke_die "privileged verification is required but unavailable or disabled"
  fi
fi

if [[ "$RUN_BENCH" == "1" ]]; then
  verify_run cargo build --locked --release
  QUIC_NATIVE_AGENT_RATIO_ENV=()
  if [[ -n "${RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO:-}" ]]; then
    QUIC_NATIVE_AGENT_RATIO_ENV=(
      RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO="$RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO"
    )
  fi

  verify_run env \
    RUSTLE_BENCH_RUNS=3 \
    RUSTLE_BENCH_WARMUP_RUNS=1 \
    RUSTLE_BENCH_BODY_BYTES=1024 \
    RUSTLE_BENCH_CONNECTIONS=1 \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent quic-native" \
    RUSTLE_BENCH_MAX_ELAPSED_MS=2000 \
    RUSTLE_BENCH_MAX_P50_US="${RUSTLE_BENCH_MAX_P50_US:-25000}" \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_HTTP_RESPONSE_DELAY_MS=25 \
    RUSTLE_BENCH_BODY_BYTES=1024 \
    RUSTLE_BENCH_CONNECTIONS=1 \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS=agent \
    RUSTLE_BENCH_MAX_ELAPSED_MS=1000 \
    RUSTLE_BENCH_MAX_P50_US=200000 \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_BODY_BYTES=1048576 \
    RUSTLE_BENCH_CONNECTIONS=1 \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent direct-tcpip" \
    RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5 \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=3 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_BODY_BYTES=104857600 \
    RUSTLE_BENCH_CONNECTIONS=1 \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent quic-native" \
    RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5 \
    "${QUIC_NATIVE_AGENT_RATIO_ENV[@]}" \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_BODY_BYTES=104857600 \
    RUSTLE_BENCH_CONNECTIONS=1 \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS="quic-agent" \
    RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5 \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=2 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_BODY_BYTES=1048576 \
    RUSTLE_BENCH_CONNECTIONS="8 32" \
    RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent direct-tcpip" \
    RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO=0.50 \
    RUSTLE_BENCH_RATIO_MIN_CONNECTIONS=32 \
    "${SCRIPT_DIR}/bench-bridge-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_UDP_BODY_BYTES=64 \
    RUSTLE_BENCH_AGENT_UDP_MESSAGES=32 \
    RUSTLE_BENCH_AGENT_UDP_PIPELINES="1 8" \
    "${SCRIPT_DIR}/bench-agent-udp-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_DNS_QUERIES=4 \
    RUSTLE_BENCH_AGENT_DNS_MAX_P50_US=500000 \
    "${SCRIPT_DIR}/bench-agent-dns-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_DNS_QUERIES=4 \
    RUSTLE_BENCH_AGENT_DNS_TRANSPORTS="quic-agent" \
    RUSTLE_BENCH_AGENT_DNS_MAX_P50_US=500000 \
    "${SCRIPT_DIR}/bench-agent-dns-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_DNS_QUERIES=4 \
    RUSTLE_BENCH_AGENT_DNS_TRANSPORTS="quic-native" \
    RUSTLE_BENCH_AGENT_DNS_MAX_P50_US=500000 \
    "${SCRIPT_DIR}/bench-agent-dns-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_DNS_QUERIES=4 \
    RUSTLE_BENCH_AGENT_DNS_TRANSPORTS="quic-native" \
    RUSTLE_BENCH_AGENT_DNS_REMOTE_HOST=localhost \
    RUSTLE_BENCH_AGENT_DNS_MAX_P50_US=500000 \
    "${SCRIPT_DIR}/bench-agent-dns-lab.sh"

  verify_run env \
    RUSTLE_BENCH_RUNS=1 \
    RUSTLE_BENCH_WARMUP_RUNS=0 \
    RUSTLE_BENCH_AGENT_RECONNECT_CONNECTIONS=4 \
    RUSTLE_BENCH_AGENT_RECONNECT_MIN_COMPLETED=2 \
    RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS=6000 \
    RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US=2000000 \
    "${SCRIPT_DIR}/bench-agent-reconnect-lab.sh"

  verify_run smoke_wait_for_uploaded_agent_cleanup
fi

if [[ "$RUN_STRESS" == "1" ]]; then
  verify_run_skip_ok "${SCRIPT_DIR}/stress-bridge-lab.sh"
  verify_run smoke_wait_for_uploaded_agent_cleanup
fi

if [[ "$RUN_LIVE" == "1" ]]; then
  for transport in $LIVE_TRANSPORTS; do
    case "$transport" in
      auto | direct-tcpip | agent) ;;
      *) smoke_die "RUSTLE_VERIFY_LIVE_TRANSPORTS entries must be auto, direct-tcpip, or agent" ;;
    esac
    verify_run env RUSTLE_LIVE_BRIDGE_TRANSPORT="$transport" "${SCRIPT_DIR}/smoke-live-tunnel.sh"
  done
  LIVE_BENCH_ENV=()
  if [[ -n "${RUSTLE_BENCH_ARTIFACT_DIR:-}" ]]; then
    LIVE_BENCH_ENV+=(RUSTLE_BENCH_ARTIFACT_DIR="${RUSTLE_BENCH_ARTIFACT_DIR}/live-compare")
  fi
  verify_run env "${LIVE_BENCH_ENV[@]}" "${SCRIPT_DIR}/bench-live-compare.sh"
  if [[ "$RUN_LIVE_FIXTURE" == "1" ]]; then
    verify_run "${SCRIPT_DIR}/bench-live-fixture.sh"
  fi
else
  skips=$((skips + 1))
  verify_info "live remote/sshuttle comparison skipped; set RUSTLE_VERIFY_LIVE=1 with RUSTLE_LIVE_* and RUSTLE_BENCH_* env"
fi

if [[ "$RUN_LIVE_UDP" == "1" ]]; then
  verify_run "${SCRIPT_DIR}/smoke-live-udp.sh"
else
  skips=$((skips + 1))
  verify_info "live generic UDP smoke skipped; set RUSTLE_VERIFY_LIVE_UDP=1 with RUSTLE_LIVE_UDP_* env"
fi

verify_info "local verification completed: passed=${passes} skipped=${skips}"
