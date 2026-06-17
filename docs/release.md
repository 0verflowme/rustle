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

Each archive contains the Rustle binary, the README, the architecture notes,
this release note, and the troubleshooting guide. Before any archive builds,
the release workflow runs a preflight with `cargo fmt --check`, `cargo test`,
`cargo clippy --all-targets -- -D warnings`, `scripts/verify-release-matrix.py`,
`scripts/verify-windows-tun-smoke.py`,
`scripts/verify-live-benchmark-rows.py --self-test`,
`scripts/verify-live-fixture-rows.py --self-test`,
`scripts/verify-release-archives.py --self-test`, and shell syntax checks for
all `scripts/*.sh`. The workflow then verifies that each archive contains the
expected files, extracts the archive, runs the extracted packaged binary with
`--help`, checks musl archives for static linkage, requires all eight native
archives before publishing, writes `SHA256SUMS`, and runs
`scripts/verify-release-archives.py` against the assembled archives and checksum
manifest.
The checksum job also runs `scripts/prepare-agent-sidecars.sh` against the
assembled release archives with `RUSTLE_AGENT_REQUIRE_ALL=1`, proving the release
can produce the full `RUSTLE_AGENT_DIR` sidecar store used by automatic
remote-agent bootstrap.
`scripts/verify-release-matrix.py` keeps this target list, the release workflow
matrix, archive naming, checksum/archive manifest gate, CI operating-system matrix,
and required smoke coverage in sync.

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
aliases such as `rustle-agent-linux-x86_64`, `rustle-agent-macos-aarch64`, and
`rustle-agent-windows-x86_64.exe`. Linux platform aliases preserve the static
musl sidecar preference when both musl and GNU archives are available.
The live smoke and benchmark launchers preserve `RUSTLE_AGENT_DIR` through
their privileged `sudo` wrapper so agent-mode release proof can use the same
sidecar store that automatic upload bootstrap uses in production.
When a live lab has a known-good remote Rustle install, the live smoke
launchers also accept `RUSTLE_LIVE_AGENT_PATH` and the UDP-specific
`RUSTLE_LIVE_UDP_AGENT_PATH`; like the CLI, those path overrides are mutually
exclusive with raw agent-command overrides.

For live labs that need a sidecar before published release artifacts exist,
`scripts/build-agent-sidecars.sh` builds selected release targets, packages them
with the same archive layout, writes `SHA256SUMS`, and then runs
`scripts/prepare-agent-sidecars.sh` to create the sidecar store:

```sh
RUSTLE_AGENT_BUILD_TARGETS=x86_64-unknown-linux-musl \
RUSTLE_AGENT_ARCHIVE_DIR=dist \
RUSTLE_AGENT_DIR="$HOME/.cache/rustle/agents" \
scripts/build-agent-sidecars.sh
```

On macOS cross-building Linux sidecars, install `cargo-zigbuild` and make `zig`
available on `PATH`, or set `RUSTLE_AGENT_BUILD_ZIG=/path/to/zig`. This source
build helper is for diagnostics and live proof; tagged releases are still built
by the GitHub release workflow.

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
zip may contain `rustle.exe`, `README.md`, `ARCHITECTURE.md`, `RELEASE.md`, and
`TROUBLESHOOTING.md`; the Wintun bytes must be embedded into `rustle.exe`.

## Verification Tiers

Use the aggregate local verifier as the preflight on every development host:

```sh
scripts/verify-local.sh
```

For release-candidate evidence on a privileged macOS or Linux host, set the
documented live remote variables and run:

```sh
scripts/verify-release-candidate.sh
```

That wrapper runs `scripts/verify-local.sh` with
`RUSTLE_VERIFY_REQUIRE_PRIVILEGED=1`, `RUSTLE_VERIFY_PRIVILEGED=1`,
`RUSTLE_VERIFY_DNS_TAKEOVER=1`, `RUSTLE_VERIFY_LIVE=1`,
`RUSTLE_VERIFY_LIVE_FIXTURE=1`, and `RUSTLE_VERIFY_LIVE_UDP=1`, so privileged
TUN, DNS takeover, live TCP, controlled live fixture, and live UDP skips fail
the release-candidate run. Linux network namespace gates remain required on Linux
but are treated as platform-inapplicable on macOS after the macOS privileged
TUN and DNS takeover gates pass. It also requires `sshuttle`, forces
`RUSTLE_BENCH_TOOLS="rustle sshuttle"`, and sets
`RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO=1.00`, proving the primary
`rustle-agent` live benchmark matches or beats sshuttle average p50 latency on
the same SSH server, target URL, request count, and concurrency. The live
benchmark evidence defaults to `RUSTLE_HOTPATH_TRACE=1` and writes compact TSV
artifacts under `target/live-evidence/release-candidate-<timestamp>` unless
`RUSTLE_BENCH_ARTIFACT_DIR` is set. The direct live comparison writes under
`live-compare`, and each controlled fixture body writes under its own
`fixture-<bytes>-bytes` directory so evidence from different body sizes is not
overwritten. After the live run completes, the wrapper runs
`scripts/verify-live-evidence.py --require-hotpath` against that directory so
missing live comparison rows, fixture rows, hotpath summaries, or optional QUIC
diagnostics fail the release-candidate run instead of becoming incomplete
evidence. The live
verifier runs `smoke-live-tunnel.sh` for primary `agent` first and
`direct-tcpip` second by default; set `RUSTLE_VERIFY_LIVE_TRANSPORTS` only when
intentionally narrowing that matrix for diagnostics. Skips are useful
diagnostics, but they are not release evidence for the skipped platform or path.
The live benchmark harness can also emit `rustle-quic-agent` and
`rustle-quic-native` rows. Set `RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO` or
`RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO` to require live native QUIC to
meet the configured throughput or p50 ratio against the primary `rustle-agent`
row; the release-candidate wrapper automatically adds `quic-native` to the live
benchmark transport matrix when either native/agent ratio gate is requested.

Required before tagging a release:

- `scripts/verify-release-matrix.py` passes, proving the documented target list
  matches the GitHub release matrix and archive/checksum expectations, and that
  CI still covers the required OS matrix and smoke gates.
- CI passes on Linux x64, Linux arm64, macOS x64, macOS arm64, Windows x64,
  and Windows arm64.
- Ubuntu CI runs the deterministic release-mode rootless benchmark gates:
  `scripts/verify-live-benchmark-rows.py --self-test`,
  `scripts/verify-live-evidence.py --self-test`, the tiny-response
  `bench-bridge-lab.sh` p50 gate, the 8 MiB chunked-response `agent` throughput gate,
  the 100 MiB `agent` throughput gate, the 100 MiB `quic-agent` throughput gate,
  and DNS p50 gates for both `agent` and `quic-agent`, plus
  the native `quic-native` DNS p50 gate when the local
  verifier runs. This makes PR CI cover the same rootless latency, shaped
  response throughput, DNS, and optional QUIC data-plane regressions that
  `scripts/verify-local.sh` enforces locally.
- SSH host-key UX checks pass:
  `host_key_verifier_accept_new_records_missing_host_key`,
  `host_key_verifier_accept_new_rejects_changed_known_host`, and
  `compact_cli_rejects_conflicting_host_key_modes` must prove that
  `--accept-new-host-key` records only unknown hosts while preserving hard
  failures for changed keys and staying mutually exclusive with
  `--insecure-accept-host-key`.
- SSH password handling checks pass:
  `ssh_password_file_option_reads_password_without_argv_secret`,
  `ssh_password_file_authenticates_against_russh_server`, and
  `compact_cli_rejects_conflicting_password_sources` must prove automation can
  use `--password-file` without putting secrets in argv and that it cannot be
  combined with inline or prompt-based `--password`. The russh-server test
  proves the password read from the file is sent through the real encrypted SSH
  password-auth path instead of only being parsed.
- Remote agent command handling checks pass:
  `effective_agent_command_quotes_literal_agent_path`,
  `compact_cli_accepts_hidden_agent_path_switch`, and
  `compact_cli_rejects_conflicting_agent_command_modes` must prove that raw
  `--agent-command` stays explicit while `--agent-path` quotes a literal remote
  executable path before appending the fixed `agent` subcommand.
- Remote bootstrap unit coverage passes for POSIX and Windows command
  generation, including PowerShell platform parsing, upload command selection,
  cross-platform sidecar candidate selection, Windows cleanup command shape, and
  the POSIX multi-lane staged-helper cleanup execution proof.
- `scripts/smoke-agent-sidecars.sh` passes, proving release archives for Linux,
  macOS, and Windows can be verified, extracted into `RUSTLE_AGENT_DIR`, and
  exposed through the same exact-triple and short platform aliases used by
  automatic agent bootstrap.
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
- Windows release verification runs `scripts/smoke-windows-tun.ps1` against the
  extracted `rustle.exe`, proving the packaged binary can materialize embedded
  Wintun, create a TUN, add/delete a /32 route, capture one packet, and restore
  the route table before the archive is uploaded.
- `windows_full_tunnel_routes_use_split_default_commands` passes, proving
  Windows full-tunnel targets expand to `0.0.0.0/1` and `128.0.0.0/1` and use
  matching `route.exe` add/delete commands with the TUN gateway and interface
  index.
- Embedded Wintun extraction remains content-addressed by target architecture
  and DLL SHA-256, and identical already-materialized DLLs are reused without a
  rewrite.
- `scripts/verify-windows-tun-smoke.py` passes, proving the Windows TUN smoke
  still checks administrator mode, /32 target validation, route add/delete logs,
  packet capture, fallback route cleanup, and final route-table restoration.
- `scripts/smoke-bridge-lab.sh` passes on at least one Unix host with `sshd`.
- `scripts/smoke-ssh-config-alias-lab.sh` passes on at least one Unix host with
  `sshd`, proving OpenSSH `Host` aliases can supply `HostName`, `Port`, `User`,
  `IdentityFile`, and `UserKnownHostsFile` for `rustle -r contabo`-style usage.
- `scripts/smoke-agent-lab.sh` passes on at least one Unix host with `sshd`.
- `scripts/smoke-agent-bridge-lab.sh` passes on at least one Unix host with
  `sshd`, proving the requested multi-lane framed agent bridge can move
  multiple synthetic TCP flows.
- `scripts/smoke-quic-agent-lab.sh` passes on at least one Unix host with
  `sshd`, proving the experimental QUIC carrier authenticates helper bootstrap
  through SSH, pins the helper certificate, opens a UDP/QUIC data plane, and
  moves synthetic TCP flows over the existing Rustle agent protocol. This is
  release evidence for the authenticated QUIC carrier, not proof that the
  optional data plane is faster than SSH-agent; that claim needs the native
  per-flow QUIC stream protocol and same-host ratio gates.
- `scripts/smoke-agent-reconnect-lab.sh` passes on at least one Unix host with
  `sshd`, proving a dead SSH exec agent can be replaced without adding user
  flags.
- `scripts/bench-agent-reconnect-lab.sh` passes on at least one Unix host with
  `sshd`, proving reconnect behavior is bounded as a benchmark gate: the first
  exec agent completes `Hello` and exits, Rustle logs an agent reconnect, later
  flows complete through the replacement agent, and the summary reports bounded
  `elapsed_ms` and `p50_us`.
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
  lanes are opened by
  `connect_agent_bridge_transport_fresh_prepared_ssh_command`, which reuses
  prepared credentials while creating a fresh SSH connection for each exec lane
  instead of multiplexing all lanes over one SSH carrier.
- `agent_writer_clears_reused_buffers_between_bursts` and
  `transport_writer_clears_reused_buffers_between_bursts` pass, proving the
  remote runtime and local controller writers can reuse burst buffers across
  flushes without leaking stale frames.
- `agent_writer_round_robins_non_priority_frames_inside_burst` and
  `transport_writer_round_robins_non_priority_frames_inside_burst` pass,
  proving non-priority data and EOF frames are interleaved across active streams
  inside each writer burst while preserving per-stream ordering and control
  frame priority.
- `output_producer_yield_budget_yields_after_bounded_data_frames` passes,
  proving remote output producers yield after a bounded number of data frames so
  one hot response stream cannot monopolize scheduler time before other stream
  tasks enqueue frames.
- `credit_window_grows_after_sustained_full_window_consumption`,
  `stream_recv_grows_receive_window_after_sustained_consumption`, and
  `runtime_receive_credit_grows_after_sustained_window_consumption` pass,
  proving agent receive windows start at the latency-friendly 4 MiB window and
  adapt to a bounded 24 MiB cap on sustained streams on both sides of the agent
  protocol.
- `remote_backlog_per_flow_has_agent_window_frame_headroom` passes, proving the
  per-flow remote backlog is sized from the local TCP send window with multiple
  windows of burst headroom, while the global backlog cap still bounds aggregate
  memory across flows.
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
- `stale_remote_data_storm_after_flow_removal_is_bounded` passes, proving
  high-rate stale `RemoteData` after a flow has been removed does not recreate
  remote backlog state or emit closed-flow cleanup work.
- `high_fanout_stale_remote_data_after_removal_is_bounded` passes, proving the
  same stale-data cleanup invariant across many removed flow generations without
  the external SSH or HTTP stress harness.
- `stale_remote_data_events_are_counted_without_per_chunk_log` passes, proving
  stale remote payload chunks are counted without creating a stderr log storm.
- `scripts/stress-bridge-lab.sh` passes with its default both-transport
  256 x 1 MiB matrix, proving the framed agent path and direct-tcpip fallback
  survive the high-fanout TCP lifecycle workload. The underlying bridge
  benchmark now fails if completed runs leave `active_flows`, `active_bridges`,
  `backlog_flows`, or `backlog_bytes` nonzero, so this stress gate also proves
  the synthetic TCP lifecycle drains flow, bridge, and backlog state instead of
  only proving response delivery. `bridge_lab_cleanup_aborts_incomplete_client_socket`
  must pass so chaos runs that stop after `--min-completed` also tear down
  incomplete synthetic clients before the summary is accepted. The same
  benchmark also waits for the lab `sshd` process tree to have no descendants
  after each run and checks the `sshd` process-tree fd count when the platform
  exposes descriptor data. Any leaked SSH session, remote-agent, or descriptor state fails the stress gate.
- Performance benchmark rows used for release claims are produced by release
  binaries. The benchmark scripts resolve `target/release/rustle` by default;
  `RUSTLE_BENCH_PROFILE=debug` is only for harness diagnosis and must not be
  used as throughput evidence.
- `scripts/bench-live-compare.sh` includes
  `RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO`, proving live sshuttle
  replacement latency can be gated directly from successful `rustle-agent` and
  `sshuttle` rows on the same target instead of relying only on absolute
  environment-specific p50 thresholds. It also includes
  `RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO` and
  `RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO`, so the optional live
  native-QUIC data-plane claim can be gated directly against the primary
  SSH-agent data path when the remote UDP path supports QUIC.
  `scripts/verify-live-benchmark-rows.py --self-test` must pass so the
  sshuttle throughput ratio, sshuttle p50 ratio, native QUIC throughput ratio,
  native QUIC p50 ratio, live row threshold gates, and diagnostic failure counters
  are checked locally before a live target is available.
- `scripts/verify-local.sh` includes release-mode 1-flow bridge benchmarks:
  a tiny-response gate with `RUSTLE_BENCH_MAX_ELAPSED_MS=2000` and
  median measured `RUSTLE_BENCH_MAX_P50_US=25000` across the fast-path
  transports, `agent` and `quic-native`, after one warmup run. `direct-tcpip`
  remains covered by compatibility smoke and throughput gates rather than the
  tiny-response latency target, because it pays per-flow SSH channel setup. It
  also runs a 1 MiB gate with
  `RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=5`, an 8 MiB chunked-response `agent`
  throughput gate with `RUSTLE_BENCH_HTTP_CHUNK_BYTES=262144`,
  `RUSTLE_BENCH_HTTP_CHUNK_DELAY_MS=5`, and
  `RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=20`, and a hard
  100 MiB single-flow `agent` throughput gate. The 100 MiB local gate includes
  `quic-native` with `RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO` so the native
  data plane must meet or beat the primary agent path on the same-host fixture. The same 100 MiB throughput gate
  also runs with `RUSTLE_BENCH_BRIDGE_TRANSPORTS="quic-agent"`, proving the
  optional SSH-bootstrap/UDP-QUIC data plane can sustain a large response with
  release-mode code. The large-response gates use
  `RUSTLE_BENCH_BODY_BYTES=104857600`. Together they prove the low-concurrency path
  is not accidentally measured with a debug binary, regressed into
  multi-second startup latency, lost bounded tiny-response `p50_us`, regressed
  into serial frame stalls, or unable to sustain a large response over the
  primary framed agent transport or experimental QUIC carrier.
- `scripts/verify-local.sh` also includes a rootless DNS latency gate through
  `scripts/bench-agent-dns-lab.sh` with
  `RUSTLE_BENCH_AGENT_DNS_MAX_P50_US`, proving sequential DNS queries through
  the primary `agent` transport and the `quic-agent` transport produce bounded `p50_us` latency
  against the local DNS fixture without relying on TUN
  privileges or OS resolver takeover.
- `scripts/verify-local.sh` includes a release-mode reconnect behavior gate
  through `scripts/bench-agent-reconnect-lab.sh` with
  `RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS` and
  `RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US`, proving reconnect behavior is not
  allowed to silently regress into a hang, unbounded retry, or leaked bridge
  lifecycle state.
- `udp_admission_moves_parsed_payload_bytes_into_association_queue` passes,
  proving generic UDP request admission moves the parsed `Bytes` payload into
  the per-association agent queue without copying it into another owned buffer.
- `direct_tcpip_generic_udp_drop_is_counted_without_admission` passes, proving
  direct-tcpip compatibility mode drops generic UDP intentionally and accounts
  that drop without admitting UDP association state.
- `udp_response_event_keeps_agent_payload_as_bytes` passes, proving generic UDP
  response events preserve the agent `Bytes` payload until TUN packet synthesis
  instead of copying every response into a temporary vector.
- `udp_association_idle_timeout_emits_close_for_accounting` passes, proving an
  idle generic UDP association closes deterministically and emits the close event
  the main loop uses to remove association state and release the active UDP
  association budget.
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
- `RUSTLE_SMOKE_TARGET_CIDR=0.0.0.0/0 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent
  RUSTLE_SMOKE_ROUTE_ONLY=1 scripts/smoke-tun-dns.sh` passes on a privileged
  macOS or Linux host, proving the local TUN smoke also covers full-tunnel split route setup
  (`0.0.0.0/1` and `128.0.0.0/1`) and route-table restoration after shutdown.
- `RUSTLE_SMOKE_CONFIGURE_DNS=1 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent
  scripts/smoke-tun-dns.sh` passes on at least one privileged macOS or Linux
  host, proving resolver takeover points the OS at the Rustle virtual DNS
  endpoint on Linux or the Rustle loopback DNS proxy on macOS while the tunnel
  is active, a normal system resolver lookup succeeds through that path, and
  the original resolver settings are restored on shutdown. Override
  `RUSTLE_SMOKE_DNS_NAME` only when a lab needs a different delegated-looking
  test name. On macOS, the smoke treats a VPN or managed profile that keeps the
  global `scutil --dns` resolver away from Rustle as a release-blocking failure,
  even if scoped `networksetup` service resolvers were updated.
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
  synthesized TUN return packet. The smoke uses a bounded
  `--udp-idle-timeout-ms` override and requires final `udp=... active:0` stats,
  proving idle association cleanup does not leak UDP state. Linux CI attempts
  this smoke when the runner supports the required namespace and TUN operations;
  a skip is not release evidence by itself.
- `scripts/smoke-live-udp.sh` passes against a real remote `sshd` and UDP
  fixture with the default `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=agent`, proving
  live generic UDP behavior through the framed agent transport: route -> TUN ->
  agent `OpenUdp` association -> remote UDP socket -> synthesized TUN response,
  with final `udp=... active:0` stats and route cleanup. Re-run the same smoke
  with `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=quic-native` before counting native
  QUIC UDP as release evidence on that remote; a failure there is UDP
  reachability evidence, not an agent-product regression. For OpenSSH `Host`
  aliases under `sudo`, pass `RUSTLE_LIVE_SSH_CONFIG` or
  `RUSTLE_LIVE_UDP_SSH_CONFIG` so the privileged Rustle process and fixture
  SSH command resolve the same alias. Controlled live fixture benchmarks can use
  `RUSTLE_FIXTURE_SSH_CONFIG` to apply the same OpenSSH config to the fixture
  command and nested Rustle/sshuttle comparison. Use
  `RUSTLE_LIVE_UDP_AGENT_PATH` only when this UDP proof needs a different
  preinstalled remote Rustle binary from the main live smoke.
- `scripts/smoke-windows-tun.ps1` passes from an elevated native Windows shell
  with an architecture-matching Wintun DLL available. The release workflow runs
  this smoke against the packaged Windows binary with embedded Wintun before
  upload, proving Windows TUN creation, route add/delete, packet capture, and
  clean route restoration without requiring a remote SSH server. The static
  verifier above is not a replacement for this elevated native run; it keeps the
  smoke script's required assertions from drifting between Windows proof runs.
- `scripts/smoke-live-tunnel.sh` passes against a real remote `sshd` and target
  URL supplied through the `RUSTLE_LIVE_*` environment variables. Release
  candidates should run it with `RUSTLE_LIVE_REQUESTS > 1` and
  `RUSTLE_LIVE_CONCURRENCY > 1` so the final stats prove multiple bridged flow
  opens over one Rustle process. The smoke also verifies nonzero TUN packet
  movement, transport-specific open logs for requested direct or agent mode, and
  zero SSH open failures, agent reconnect failures, bridge send failures, and
  remote backlog overflows in the final stats.
- Route, DNS, and process cleanup checks show no Rustle-owned leftovers. On
  Unix, the tunnel and capture loops must treat Ctrl-C, SIGTERM, and SIGHUP as
  graceful shutdown signals so normal route, DNS, TUN, local DNS proxy, and
  uploaded-agent cleanup guards can run; `unix_shutdown_signals_include_hangup_and_terminate`
  must pass. `uploaded_helper_command_keeps_staged_binary_until_last_lane_exits_for_each_kind`
  must also pass so the generated upload wrapper is proven to keep one staged
  helper alive across concurrent initial helper lanes and remove it after the
  last lane exits.
- Uploaded-agent temp staging checks are covered before release:
  `remote_agent_upload_commands_stage_in_private_temp_dirs` and
  `posix_remote_agent_upload_command_creates_private_executable_file` must pass
  so the upload fallback stages helpers in private directories with executable
  owner-only permissions and removes those directories during cleanup.
- Uploaded-agent integrity checks are covered before release:
  `uploaded_agent_sha256_command_uses_remote_hash_tools`,
  `windows_uploaded_agent_sha256_command_uses_get_file_hash`,
  `uploaded_agent_cleanup_command_quotes_path_and_refs`,
  `uploaded_agent_cleanup_removes_unverified_posix_staging_tree`, and
  `sha256_file_hex_hashes_local_file` must pass so the upload fallback verifies
  the staged helper before execution and removes unverified bytes, refs, and
  private staging directories on failure.

Native Windows and Linux TUN verification must still run on real privileged
hosts before a release is promoted as field-ready for those platforms.
