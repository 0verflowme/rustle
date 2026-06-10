# Rustle Release Notes

## Binary Targets

The release workflow builds native archives for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl` static Linux
- `aarch64-unknown-linux-gnu`
- `aarch64-unknown-linux-musl` static Linux
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`
- `aarch64-pc-windows-msvc`

Each archive contains the Rustle binary, the README, the architecture notes, and
this release note. The workflow verifies that each archive contains those files,
extracts the archive, runs the extracted packaged binary with `--help`, checks
musl archives for static linkage, requires all eight native archives before
publishing, and publishes a `SHA256SUMS` file with one entry per archive.
`scripts/verify-release-matrix.py` keeps this target list, the release workflow
matrix, archive naming, checksum count, CI operating-system matrix, and required
smoke coverage in sync.

The same extracted package shape is used by automatic remote-agent bootstrap.
For example, a macOS operator can place `rustle-x86_64-unknown-linux-musl/rustle`
as a sibling of the local package directory, or put it under `RUSTLE_AGENT_DIR`;
if the remote probe reports Linux x64 and `rustle agent` is not already
installed remotely, Rustle uploads that sidecar instead of falling back to
`direct-tcpip`.

To prepare a local sidecar store from published artifacts:

```sh
RUSTLE_AGENT_RELEASE_TAG=vX.Y.Z \
RUSTLE_AGENT_DIR="$HOME/.cache/rustle/agents" \
scripts/prepare-agent-sidecars.sh
```

The same helper can prepare sidecars from a local release directory with
`RUSTLE_AGENT_ARCHIVE_DIR=dist`. It verifies `SHA256SUMS` when present, prepares
all eight release targets by default, accepts a smaller `RUSTLE_AGENT_TARGETS`
set for diagnostics, and creates both exact-triple aliases and short platform
aliases such as `rustle-agent-linux-x86_64`. Linux platform aliases preserve the
static musl sidecar preference when both musl and GNU archives are available.

## Platform Contract

Rustle's core tunnel model is the same on every supported OS:

```text
route -> TUN -> userspace TCP/UDP handling -> SSH transport -> remote socket
```

Platform-specific code is restricted to TUN setup, privilege preflight, route
commands, and optional DNS resolver takeover. Rustle must not depend on
`iptables`, `nftables`, `pf`, or Windows Filtering Platform.

## Windows Wintun

Windows requires an architecture-matching Wintun driver DLL. By default, the
binary checks these locations in order:

1. `RUSTLE_WINTUN_DLL`
2. The directory containing `rustle.exe`
3. The current working directory

For a self-extracting Windows binary, build with
`RUSTLE_EMBED_WINTUN_DLL=/path/to/wintun.dll`. Rustle embeds those bytes and, if
no external DLL is found, writes them to a content-addressed path under the user
temp directory before creating the TUN device. The filename includes the target
architecture and SHA-256 of the embedded DLL, so x64/arm64 builds and driver
updates do not collide on one fixed temp path; an already-materialized identical
DLL is reused without rewriting it. Release builders are responsible for
supplying the correct DLL for the target architecture and for complying with the
Wintun distribution terms. The build script reads the embedded DLL's PE/COFF
machine type and fails Windows release builds when the DLL architecture does not
match the Rust target; runtime external DLL lookup performs the same validation
before handing the path to `tun-rs`.

The GitHub release workflow supports the same mode through optional repository
secrets. Set `RUSTLE_WINDOWS_WINTUN_DLL_B64` to the base64-encoded x64
`wintun.dll`, and set `RUSTLE_WINDOWS_ARM64_WINTUN_DLL_B64` to the
base64-encoded arm64 `wintun.dll`. The release workflow requires the matching
secret for each Windows archive so published Windows artifacts remain
self-extracting single binaries. Development and CI builds can still use the
external DLL lookup order above.

Windows release archive verification rejects sidecar `wintun.dll` files. The
zip may contain `rustle.exe`, `README.md`, `ARCHITECTURE.md`, and `RELEASE.md`;
the Wintun bytes must be embedded into `rustle.exe`.

## Verification Tiers

Use the aggregate local verifier as the preflight on every development host:

```sh
scripts/verify-local.sh
```

For release-candidate evidence, run it on privileged Linux with
`RUSTLE_VERIFY_REQUIRE_PRIVILEGED=1`, and run it with `RUSTLE_VERIFY_LIVE=1`
after setting the documented live smoke and benchmark environment variables.
The live verifier runs `smoke-live-tunnel.sh` for both `direct-tcpip` and
`agent` by default; set `RUSTLE_VERIFY_LIVE_TRANSPORTS` only when intentionally
narrowing that matrix for diagnostics. Skips are useful diagnostics, but they
are not release evidence for the skipped platform or path.

Required before tagging a release:

- `scripts/verify-release-matrix.py` passes, proving the documented target list
  matches the GitHub release matrix and archive/checksum expectations, and that
  CI still covers the required OS matrix and smoke gates.
- CI passes on Linux x64, Linux arm64, macOS x64, macOS arm64, Windows x64,
  and Windows arm64.
- Remote bootstrap unit coverage passes for POSIX and Windows command
  generation, including PowerShell platform parsing, upload command selection,
  cross-platform sidecar candidate selection, Windows cleanup command shape, and
  the POSIX multi-lane staged-helper cleanup execution proof.
- `scripts/smoke-agent-sidecars.sh` passes, proving release archives can be
  verified, extracted into `RUSTLE_AGENT_DIR`, and exposed through the same
  exact-triple and short platform aliases used by automatic agent bootstrap.
- `agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure`
  passes, proving a transient extra-lane startup failure does not discard other
  successful lanes from the initial framed-agent pool.
- `agent_initial_startup_retries_missing_extra_lanes_after_transient_failure`
  passes, proving missing startup lanes get one bounded retry before a degraded
  framed-agent pool is accepted.
- `agent_bridge_repairs_missing_startup_lane_in_background` passes, proving a
  desired lane that is still missing after startup remains repairable and can be
  filled after the bridge is already running.
- `auto_agent_startup_returns_after_primary_and_warms_extra_lanes` passes,
  proving the compact default auto-lane path starts after the primary agent lane
  and warms remaining recommended lanes through background repair.
- `background_repair_retries_missing_lane_after_quarantine` passes, proving
  background repair retries a missing desired lane after bounded quarantine
  backoff without waiting for later user traffic to select that lane.
- `agent_established_message_reports_degraded_lane_pool` passes, proving startup
  telemetry reports established/requested agent lanes for degraded-pool diagnosis.
- `agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure` also
  checks the bridge snapshot keeps a desired slot for missing startup capacity
  after partial startup.
- Release Windows archives require architecture-matching embedded Wintun secrets;
  missing secrets or PE machine mismatches must fail the release workflow
  instead of silently publishing an archive that needs an external DLL.
- Windows release archives contain only `rustle.exe` plus documentation; a
  sidecar `wintun.dll` in the archive is a release failure because the driver
  bytes must be embedded.
- Embedded Wintun extraction remains content-addressed by target architecture
  and DLL SHA-256, and identical already-materialized DLLs are reused without a
  rewrite.
- `scripts/smoke-bridge-lab.sh` passes on at least one Unix host with `sshd`.
- `scripts/smoke-agent-lab.sh` passes on at least one Unix host with `sshd`.
- `scripts/smoke-agent-bridge-lab.sh` passes on at least one Unix host with
  `sshd`, proving the requested multi-lane framed agent bridge can move
  multiple synthetic TCP flows.
- `scripts/smoke-agent-reconnect-lab.sh` passes on at least one Unix host with
  `sshd`, proving a dead SSH exec agent can be replaced without adding user
  flags.
- `scripts/smoke-agent-active-failure-lab.sh` passes on at least one Unix host
  with `sshd`, proving an agent that dies after accepting an active TCP stream
  resets that flow, reconnects the exec transport, and completes later flows
  without adding user flags.
- The active-failure smoke also passes with
  `RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_SESSIONS=2` and
  `RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_REQUIRE_RESET=0`, proving one bad exec lane
  does not invalidate the multi-lane framed agent pool while the default
  one-lane run remains the reset-log proof.
- `scripts/smoke-agent-udp-lab.sh` passes on at least one Unix host with
  `sshd`, proving real SSH exec agent UDP association behavior without TUN
  privileges.
- Agent UDP unit coverage passes:
  `agent_runtime::tests::agent_opens_udp_stream_and_relays_datagram` and
  `agent_transport::tests::transport_opens_udp_stream_and_relays_datagram`.
- `dns_over_agent_prefers_udp_for_ipv4_remote` passes, proving intercepted DNS
  uses the agent UDP association path for IPv4 resolvers instead of translating
  the datagram to TCP.
- Agent heartbeat unit coverage passes:
  `agent_runtime::tests::agent_replies_to_heartbeat_ping`.
- Agent lane-policy unit coverage passes:
  `background_lane_repair_requests_are_coalesced`,
  `agent_lane_selection_prefers_less_loaded_secondary_but_repairs_failed_primary`,
  `agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy`,
  `reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails`,
  `reconnecting_agent_repairs_alternate_lane_that_fails_during_open`,
  `alternate_lane_selection_scans_by_load_without_snapshot_vector`, and
  `agent_bridge_repairs_lane_after_active_stream_transport_failure`. These prove
  known-failed primary lanes do not add reconnect latency when a healthy
  secondary is available, unhealthy hashed candidate pairs fail around to the
  least-loaded healthy lane elsewhere in the pool, fallback alternate scans do
  not allocate sorted lane snapshots while the pool is degraded, active stream
  transport failures proactively schedule repair for their owning lane,
  duplicate background repairs coalesce per lane, and the compact stats surface
  reports in-progress background lane repairs.
  Fallback opens repair failed alternate lanes instead of stranding usable
  capacity in the agent pool.
- Source inspection through `scripts/verify-release-matrix.py` proves agent
  lanes are opened by `connect_agent_bridge_transport_fresh_ssh_command`, which
  creates a fresh SSH connection for each exec lane instead of multiplexing all
  lanes over one SSH carrier.
- `agent_writer_clears_reused_buffers_between_bursts` and
  `transport_writer_clears_reused_buffers_between_bursts` pass, proving the
  remote runtime and local controller writers can reuse burst buffers across
  flushes without leaking stale frames.
- `packet_queue_device_drain_tx_into_reuses_output_vector` passes, proving the
  smoltcp packet adapter can drain TX packets into caller-owned scratch storage
  while still recycling packet buffers back into the bounded pool.
- `flow_manager_flow_keys_into_reuses_output_vector`,
  `flow_manager_ready_flow_ids_into_reuses_output_vector`, and
  `flow_manager_counts_opening_flows_without_snapshot_allocation` pass, proving
  bridge admission and local-byte drain can enumerate flows without per-tick
  vector or snapshot allocation.
- `flow_manager_cleanup_enumeration_into_reuses_output_vectors` and
  `remote_backlogs_flush_all_into_reuses_scratch_vectors` pass, proving
  backlog flushing, stale expiry, and closed-flow cleanup reuse caller-owned
  scratch storage in the central loop.
- `bridge_event_handler_into_reuses_closed_flow_scratch_vector` passes, proving
  remote-data bridge events reuse caller-owned closed-flow scratch storage while
  flushing remote bytes toward smoltcp.
- `udp_admission_moves_parsed_payload_bytes_into_association_queue` passes,
  proving generic UDP request admission moves the parsed `Bytes` payload into
  the per-association agent queue without copying it into another owned buffer.
- `udp_response_event_keeps_agent_payload_as_bytes` passes, proving generic UDP
  response events preserve the agent `Bytes` payload until TUN packet synthesis
  instead of copying every response into a temporary vector.
- `dns_response_event_keeps_remote_payload_as_bytes` passes, proving DNS
  response events preserve remote resolver payloads as `Bytes` until TUN packet
  synthesis. Source inspection must also show agent UDP DNS returns
  `frame.payload` directly and DNS-over-TCP responses are sliced from the
  accumulated frame instead of copied into a temporary vector.
- `RUSTLE_SMOKE_BRIDGE_TRANSPORT=direct-tcpip scripts/smoke-tun-dns.sh` passes
  on a privileged macOS or Linux host, proving the direct compatibility DNS
  path. Linux CI attempts this smoke when `/dev/net/tun` is available; a CI skip
  due to runner TUN limitations is not release evidence by itself.
- `RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent scripts/smoke-tun-dns.sh` passes on a
  privileged macOS or Linux host, proving default DNS interception over the
  framed agent path. Linux CI attempts this smoke when `/dev/net/tun` is
  available; a CI skip due to runner TUN limitations is not release evidence by
  itself.
- `scripts/smoke-linux-netns-tcp.sh` passes on a privileged Linux host with
  network namespace support. This is the self-contained full-path TCP proof:
  full-tunnel split routes plus SSH control-route protection -> TUN -> smoltcp
  -> russh direct-tcpip -> remote namespace HTTP target -> TUN return path.
  Linux CI attempts this smoke when the runner supports the required namespace
  and TUN operations; a skip is not release evidence by itself.
- `RUSTLE_NETNS_BRIDGE_TRANSPORT=agent scripts/smoke-linux-netns-tcp.sh` passes
  on a privileged Linux host, proving the same full-path TCP behavior through
  the framed agent transport.
- `scripts/smoke-linux-netns-udp.sh` passes on a privileged Linux host, proving
  full-path generic UDP behavior through the framed agent transport: route ->
  TUN -> agent `OpenUdp` association -> remote namespace UDP target ->
  synthesized TUN return packet. Linux CI attempts this smoke when the runner
  supports the required namespace and TUN operations; a skip is not release
  evidence by itself.
- `scripts/smoke-windows-tun.ps1` passes from an elevated native Windows shell
  with an architecture-matching Wintun DLL available. This proves Windows TUN
  creation, route add/delete, packet capture, and clean route restoration
  without requiring a remote SSH server.
- `scripts/smoke-live-tunnel.sh` passes against a real remote `sshd` and target
  URL supplied through the `RUSTLE_LIVE_*` environment variables. Release
  candidates should run it with `RUSTLE_LIVE_REQUESTS > 1` and
  `RUSTLE_LIVE_CONCURRENCY > 1` so the final stats prove multiple bridged flow
  opens over one Rustle process. The smoke also verifies nonzero TUN packet
  movement, transport-specific open logs for requested direct or agent mode, and
  zero SSH open failures, agent reconnect failures, bridge send failures, and
  remote backlog overflows in the final stats.
- Route, DNS, and process cleanup checks show no Rustle-owned leftovers.
  `uploaded_agent_command_keeps_staged_binary_until_last_lane_exits` must also
  pass so the generated upload wrapper is proven to keep one staged helper alive
  across concurrent initial agent lanes and remove it after the last lane exits.

Native Windows and Linux TUN verification must still run on real privileged
hosts before a release is promoted as field-ready for those platforms.
