# Performance

Rustle has two performance questions:

1. How fast is the userspace TCP-to-SSH bridge when local OS routing and TUN are
   removed from the measurement?
2. How fast is the full product path on a real target compared with sshuttle?

Keep those measurements separate. The bridge benchmark is rootless and
repeatable. The live benchmark depends on the local OS, route table, remote SSH
server policy, target service, network RTT, and whether the comparison tool uses
kernel firewall hooks.

## Rootless Bridge Benchmark

Build first:

```sh
cargo build --release
```

Run the default bridge benchmark:

```sh
scripts/bench-bridge-lab.sh
```

Performance benchmark scripts resolve `target/release/rustle` by default so
single-flow results are not dominated by debug-build async and crypto overhead.
Set `RUSTLE_BENCH_PROFILE=debug` only when intentionally debugging benchmark
harness behavior, or set `RUSTLE_BIN=/path/to/rustle` to use an explicit binary.

The script starts a temporary local `sshd`, starts a local HTTP server, then runs
`rustle bridge-lab --summary` across a connection matrix. It benchmarks the
framed `agent` bridge first and the compatibility `direct-tcpip` bridge second
unless narrowed with `RUSTLE_BENCH_BRIDGE_TRANSPORTS`. Output is tab-separated:

```text
transport  body_bytes  connections  run  elapsed_ms  response_bytes  throughput_mib_s
```

Tune the matrix with environment variables:

```sh
RUSTLE_BENCH_BODY_BYTES="65536 1048576" \
RUSTLE_BENCH_CONNECTIONS="1 8 32 64" \
RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent direct-tcpip auto" \
RUSTLE_BENCH_AGENT_SESSIONS=2 \
RUSTLE_BENCH_RUNS=5 \
RUSTLE_BENCH_WARMUP_RUNS=1 \
scripts/bench-bridge-lab.sh
```

For local regression preflights, the benchmark can also enforce a conservative
agent/direct sanity ratio for matching body-size and connection-count rows:

```sh
RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO=0.50 \
RUSTLE_BENCH_RATIO_MIN_CONNECTIONS=32 \
scripts/bench-bridge-lab.sh
```

Use `RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S` for a low-concurrency release-mode
floor. `scripts/verify-local.sh` uses a conservative 1 MiB / 1-flow gate so a
debug binary or serious serial data-path regression cannot masquerade as
performance evidence.

Those checks are intentionally coarse guardrails, not release claims. They
catch obvious agent-path and single-flow regressions while leaving detailed
performance conclusions to multi-run live benchmarks on the same SSH server and
target.

This benchmark is useful for bridge regressions because it exercises:

- smoltcp client handshake and receive path
- Rustle `FlowManager`
- SSH channel admission and `direct-tcpip`
- local-to-remote and remote-to-local bridge queues
- bounded remote backlog flushing
- auto, direct-tcpip, and framed agent scheduling under the same response sizes
  and connection counts
- one-lane versus multi-lane framed agent behavior with
  `RUSTLE_BENCH_AGENT_SESSIONS`

`bridge-lab` disables the compact tunnel's auto-lane fast-start optimization and
waits for the requested or recommended agent lane pool before starting synthetic
clients. That keeps this benchmark focused on steady-state bridge throughput;
the real tunnel path still starts after the primary auto-selected agent lane and
warms remaining lanes in background to reduce first-request latency.

It does not exercise host route injection, TUN driver behavior, DNS takeover, or
generic UDP datagram behavior.

## Rootless Agent UDP Benchmark

Build first:

```sh
cargo build --release
```

Run the default framed-agent UDP benchmark:

```sh
scripts/bench-agent-udp-lab.sh
```

The script starts a temporary local `sshd`, starts a local UDP responder, then
runs `rustle agent-udp-lab --summary` across a datagram matrix. Output is
tab-separated:

```text
body_bytes  messages  pipeline  run  elapsed_ms  response_bytes  throughput_mib_s  datagrams_s
```

Tune the matrix with environment variables:

```sh
RUSTLE_BENCH_AGENT_UDP_BODY_BYTES="64 512 1200" \
RUSTLE_BENCH_AGENT_UDP_MESSAGES="1024 8192" \
RUSTLE_BENCH_AGENT_UDP_PIPELINES="1 32 128" \
RUSTLE_BENCH_RUNS=5 \
RUSTLE_BENCH_WARMUP_RUNS=1 \
scripts/bench-agent-udp-lab.sh
```

This benchmark is useful for framed-agent regressions because it exercises:

- one real SSH `exec` channel carrying the Rustle framed protocol
- agent UDP stream open, datagram relay, and response handling
- local client pipeline scheduling under different outstanding datagram counts
- byte-credit flow control without involving host routes or TUN driver behavior

It does not exercise the full TUN UDP path. Use
`scripts/smoke-linux-netns-udp.sh` on a privileged Linux host for that proof.

## Full Tunnel Benchmark

Use the live smoke as the correctness gate first:

```sh
RUSTLE_LIVE_REMOTE=alice@ssh.example.com \
RUSTLE_LIVE_TARGET_CIDR=0.0.0.0/0 \
RUSTLE_LIVE_URL=https://192.168.190.45/ \
RUSTLE_LIVE_REQUESTS=16 \
RUSTLE_LIVE_CONCURRENCY=4 \
scripts/smoke-live-tunnel.sh
```

When the target CIDR is `0.0.0.0/0`, the live smoke and benchmark expect
Rustle's split default routes, `0.0.0.0/1` and `128.0.0.0/1`, because that is
how the SSH control connection remains protectable.

Then run the live benchmark harness:

```sh
RUSTLE_BENCH_REMOTE=alice@ssh.example.com \
RUSTLE_BENCH_TARGET_CIDR=0.0.0.0/0 \
RUSTLE_BENCH_URL=https://192.168.190.45/ \
RUSTLE_BENCH_REQUESTS=16 \
RUSTLE_BENCH_CONCURRENCY=4 \
scripts/bench-live-compare.sh
```

Output is tab-separated:

```text
tool  run  requests  concurrency  success  failed  wall_ms  p50_ms  p95_ms  bytes  throughput_mib_s  req_s  avg_cpu_pct  max_cpu_pct  ssh_opened  ssh_failed  agent_reconnect_attempts  agent_reconnect_ok  agent_reconnect_failed  backlog_overflow
```

By default the live harness benchmarks Rustle with the primary `agent` transport
first, then the `direct-tcpip` compatibility path, producing `rustle-agent` and
`rustle-direct-tcpip` rows. To pin the transport matrix explicitly, use:

```sh
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent direct-tcpip" \
RUSTLE_BENCH_AGENT_COMMAND="/opt/rustle/rustle agent" \
RUSTLE_BENCH_AGENT_SESSIONS=2 \
scripts/bench-live-compare.sh
```

By default the harness benchmarks Rustle only. Add sshuttle with:

```sh
RUSTLE_BENCH_TOOLS="rustle sshuttle" scripts/bench-live-compare.sh
```

To make the sshuttle comparison a hard gate, set a minimum average throughput
ratio for `rustle-agent` over successful sshuttle rows:

```sh
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent" \
RUSTLE_BENCH_MIN_AGENT_SSHUTTLE_RATIO=1.00 \
scripts/bench-live-compare.sh
```

This fails the benchmark if `rustle-agent` does not meet the configured
fraction of sshuttle throughput on the same SSH server, target URL, request
count, and concurrency.

For password-auth labs, use prompt-based password collection:

```sh
RUSTLE_BENCH_PASSWORD=1 \
RUSTLE_BENCH_SSHUTTLE_PASSWORD=1 \
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
scripts/bench-live-compare.sh
```

Rustle receives the password through its `--password-file` option backed by a
private temp file. sshuttle uses `sshpass -f` with a private temp file when
`RUSTLE_BENCH_SSHUTTLE_PASSWORD=1` is set. The harness removes password files
during cleanup. Bare `--password` still supports the legacy
`RUSTLE_SSH_PASSWORD_FILE` environment path for compatibility with older local
scripts.

For compatibility with older local scripts, the live Rustle benchmark also
accepts a single transport through `RUSTLE_BENCH_BRIDGE_TRANSPORT`:

```sh
RUSTLE_BENCH_BRIDGE_TRANSPORT=agent \
RUSTLE_BENCH_AGENT_COMMAND="/opt/rustle/rustle agent" \
scripts/bench-live-compare.sh
```

Leave `RUSTLE_BENCH_BRIDGE_TRANSPORT` unset to collect both Rustle transport
rows. Set it to `direct-tcpip` only when you explicitly want the compatibility
path alone.

For an sshuttle comparison, use the same local machine, same SSH server, same
target URL, same request count, and same concurrency. Compare at least:

- successful requests
- elapsed wall time
- p50/p95 request latency
- transferred response bytes
- CPU usage on the local client
- route cleanup after shutdown

The harness treats sshuttle as an opt-in comparator because sshuttle depends on
local firewall hooks and a remote Python helper. If sshuttle cannot make the URL
reachable before the readiness deadline, the benchmark exits with diagnostics
instead of reporting a misleading comparison row.

## Controlled Live Large-Response Fixture

Use `scripts/bench-live-fixture.sh` when the existing live URL returns tiny
responses and mostly measures request latency. The fixture starts a temporary
Python HTTP server on the SSH host, then runs `scripts/bench-live-compare.sh`
against controlled 1 MiB / 10 MiB / 100 MiB responses. Each run sets
`RUSTLE_BENCH_EXPECT_BYTES` so the benchmark fails if a response is truncated.

```sh
RUSTLE_FIXTURE_REMOTE=alice@ssh.example.com \
RUSTLE_FIXTURE_HOST=192.168.190.45 \
RUSTLE_BENCH_REQUESTS=8 \
RUSTLE_BENCH_CONCURRENCY=4 \
RUSTLE_BENCH_RUSTLE_TRANSPORTS=agent \
scripts/bench-live-fixture.sh
```

`RUSTLE_FIXTURE_HOST` must be an IPv4 address on the remote SSH host that is
reachable through the Rustle target route. It should be a remote-side target
address, not the SSH control address that Rustle protects with a direct host
route. By default the script uses `${RUSTLE_FIXTURE_HOST}/32` as
`RUSTLE_BENCH_TARGET_CIDR`; set `RUSTLE_FIXTURE_TARGET_CIDR` when the fixture
address should be covered by a larger route. Override
`RUSTLE_FIXTURE_BODY_BYTES` to change the body-size matrix. The remote fixture
code is compatible with Python 2.7 and Python 3; set
`RUSTLE_FIXTURE_PYTHON=python` for older SSH hosts that do not provide
`python3`. Fixture runs set `RUSTLE_BENCH_READY_METHOD=HEAD` so sshuttle
readiness probes verify reachability without downloading the full large
response before the measured GET request.

For password-auth labs, the fixture SSH command can reuse
`RUSTLE_BENCH_PASSWORD_VALUE`/`RUSTLE_LIVE_PASSWORD_VALUE`, or prompt with
`RUSTLE_FIXTURE_PASSWORD=1`. That path requires `sshpass` because the fixture
itself is started with the OpenSSH client. When benchmark-specific credentials
are not set, fixture-only auth and host-key settings are forwarded into the
nested live benchmark run, including `RUSTLE_FIXTURE_PASSWORD_VALUE`, prompted
`RUSTLE_FIXTURE_PASSWORD`, `RUSTLE_FIXTURE_IDENTITY`,
`RUSTLE_FIXTURE_INSECURE_HOST_KEY`, and `RUSTLE_FIXTURE_KNOWN_HOSTS`.

Rustle's expected advantage is lower overhead from a native Rust single binary,
explicit bounded queues, and cross-platform TUN support. sshuttle's advantage is
that it can lean on OS-specific firewall and kernel TCP behavior. That means the
comparison is only meaningful when both tools are run on the exact same traffic
shape and target.

For a local preflight that runs the rootless bridge benchmark, rootless agent
UDP benchmark, and all locally available correctness smokes, use:

```sh
scripts/verify-local.sh
```

Set `RUSTLE_VERIFY_LIVE=1` to include the live remote smoke and benchmark in
the same run. Live smoke runs `agent` first and `direct-tcpip` second by
default before the benchmark; set `RUSTLE_VERIFY_LIVE_TRANSPORTS` to narrow the
smoke matrix when debugging one transport. Add `RUSTLE_VERIFY_LIVE_FIXTURE=1`
to include the controlled large-response fixture in the live verifier run.
Set `RUSTLE_VERIFY_DNS_TAKEOVER=1` on privileged verifier runs to include the
system resolver takeover and exact-restore DNS smoke.

## Agent Promotion Criteria

The compact command already defaults to the framed agent transport and fails
loudly if the agent cannot start or bootstrap. The hidden `auto` mode still
exists only for diagnostics and compatibility fallback. Keeping agent as the
sole public default requires evidence that it remains better than compatibility
mode on the same machines:

- rootless bridge benchmarks pass for both transports at 1, 8, 32, 64, and 256
  synthetic flows with 64 KiB and 1 MiB response bodies; the high-fanout stress
  gate defaults to both `agent` and `direct-tcpip` at 256 x 1 MiB
- rootless framed-agent UDP benchmarks pass at 64, 512, and 1200 byte responses
  with pipeline depths 1, 32, and 128
- agent throughput is at least as good as direct-tcpip at high concurrency, or
  the latency/cpu tradeoff is documented and intentional
- privileged TUN DNS smoke passes on macOS and Linux with `--bridge-transport
  agent`
- agent runtime heartbeat ping/pong tests pass, proving a silent SSH exec agent
  can be detected before new streams pile up behind a wedged transport
- `scripts/smoke-agent-reconnect-lab.sh` passes so transient agent-channel
  death does not force manual restart or UI changes
- `scripts/smoke-agent-active-failure-lab.sh` passes in the default one-lane
  mode with reset-log matching enabled, and in the
  `RUSTLE_SMOKE_AGENT_ACTIVE_FAILURE_SESSIONS=2` verifier mode with reset-log
  matching disabled, so active-stream reset and multi-lane pool recovery are
  proven without making the pool gate race post-completion log delivery
- agent UDP unit tests pass, and `scripts/smoke-linux-netns-udp.sh` passes on a
  privileged Linux host before generic UDP is treated as field-ready
- intercepted DNS in agent mode keeps IPv4 resolver traffic on `OpenUdp`; only
  direct-tcpip compatibility and hostname DNS remotes use DNS-over-TCP
- macOS system resolver takeover uses a bounded loopback DNS proxy because
  service-scoped `networksetup` resolvers do not reliably send virtual TUN DNS
  addresses through utun; a VPN-managed global `scutil --dns` resolver can still
  override that scoped setup and is treated as a failed DNS takeover proof
- `RUSTLE_SMOKE_CONFIGURE_DNS=1 RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent
  scripts/smoke-tun-dns.sh` passes on a privileged macOS or Linux host, proving
  DNS resolver takeover, normal system resolver delivery through Rustle, and
  exact resolver restoration
- Linux network-namespace TCP smoke passes with
  `RUSTLE_NETNS_BRIDGE_TRANSPORT=agent`
- live tunnel benchmark rows exist for `direct-tcpip`, `agent`, and sshuttle on
  the same SSH server, target URL, request count, and concurrency
- route, DNS, sshd, HTTP helper, and Rustle process cleanup checks remain green
- remote bootstrap remains automatic for matching OS/architecture remotes and
  does not require adding flags to the compact `rustle -r user@host CIDR...`
  path; initial multi-lane startup must reuse one staged upload instead of
  uploading the local binary once per lane, and successful extra lanes must be
  kept even if another extra lane fails during the same startup batch

## Current Guardrails

Performance work must preserve these invariants:

- the public tunnel command remains compact: `rustle -r user@host CIDR...`
- bridge queues are bounded by item count and byte count
- remote-to-local TCP backlog is bounded per flow and globally, currently 2 MiB
  per flow with a 128 MiB process-wide backlog cap
- smoltcp TX packets are drained into caller-owned scratch vectors so the TUN
  loop does not allocate a fresh `Vec<PacketBuf>` for each packet poll
- `FlowManager` enumeration for bridge admission and local-byte drain uses
  caller-owned scratch vectors for `FlowId`/`FlowKey` lists; opening-flow counts are computed directly instead of by allocating snapshots
- remote backlog flushing, stale-flow expiry, and closed-flow pruning use
  caller-owned scratch vectors for per-tick cleanup scans instead of allocating
  temporary flow lists
- bridge event handling uses caller-owned closed-flow scratch storage so
  high-rate remote-data events do not allocate temporary closed-flow vectors
- `stale_remote_data_storm_after_flow_removal_is_bounded` proves stale
  remote-data storms after flow removal do not refill remote backlog storage,
  emit closed-flow work, or trip backlog overflow accounting
- stale `RemoteData` chunks are counted without per-chunk logging; stale
  close/eof/failure/open transitions still log for diagnosis
- generic UDP request payloads are parsed into `Bytes` once from the reusable
  TUN read buffer, then moved directly into the per-association agent queue
  without a second payload allocation
- generic UDP response events keep agent `Data` frame payloads as `Bytes` until
  TUN packet synthesis instead of copying each response into a temporary
  `Vec<u8>`
- DNS response events keep remote resolver payloads as `Bytes`; agent UDP DNS
  moves agent `Data` payloads directly and DNS-over-TCP slices the accumulated
  length-prefixed frame without an extracted-response `Vec<u8>` copy
- agent streams use explicit byte-credit windows instead of unbounded SSH-channel
  buffering
- agent senders segment oversized local buffers into bounded protocol frames
  instead of relying on callers to respect frame-size limits
- agent writer tasks must reuse per-task burst frame and encoded-byte buffers
  across flushes instead of allocating them once per burst
- agent peers that advertise heartbeat support must answer periodic zero-stream
  pings; missed pongs must trip sticky transport failure and reconnect handling
- agent streams can be hashed across multiple SSH exec lanes; lane count is
  auto-selected as capped `ceil(sqrt(local CPU parallelism))` by default and
  remains a hidden/internal tuning knob so the public command stays compact
- the compact auto-lane path starts after the primary agent lane and warms the
  remaining recommended lanes in background after a short first-flow defer,
  while explicit `--agent-sessions` requests keep the full initial startup gate
- rootless `bridge-lab` keeps full lane warmup for steady-state throughput and
  stress evidence instead of timing the compact tunnel fast-start path
- each agent exec lane must be a fresh SSH connection with one exec channel, not
  another exec channel multiplexed over the same SSH carrier, so lane
  parallelism can reduce SSH TCP head-of-line blocking
- explicit initial extra agent lanes must start in bounded batches and preserve
  every successful lane even if another extra lane fails
- missing startup lanes must get one bounded retry before a degraded agent pool
  is accepted, and missing desired lane slots must remain repairable afterward
- startup logs must report `established/desired` agent exec transports so
  degraded pool capacity is visible without extra CLI flags
- periodic and final stats must keep reporting desired, available, missing,
  failed, quarantined, and repairing agent lanes so degraded capacity remains
  visible during long runs
- known-failed primary lanes must not add reconnect latency to a new flow when a
  healthy secondary lane is available; repair can happen in the background
- if both hashed candidate lanes are unhealthy, new opens must use the
  least-loaded healthy lane elsewhere in the pool while the bad candidates are
  repaired asynchronously
- background repair requests must coalesce per lane so flow bursts do not spawn
  duplicate reconnect attempts for the same failed exec transport
- background repair must retry after bounded quarantine backoff instead of
  depending on future user flows to revisit the failed or missing lane
- in-progress background lane repairs must be visible in periodic and final
  stats lines, so reconnect pressure is observable without extra CLI flags
- failed agent transports must reset current streams and reject later stream
  opens immediately instead of waiting for bridge-open timeouts
- active stream transport failures must trigger lane repair immediately after
  the reset is observed, so later flows are not the first work to rediscover the
  dead exec transport
- fallback opens must repair failed alternate agent lanes before giving up,
  including lanes that fail during their own open attempt, so a failed preferred
  lane does not strand repairable capacity elsewhere in the pool
- fallback alternate-lane scans must not allocate sorted lane snapshots while
  the bridge is already degraded; fallback alternate scans do not allocate sorted lane snapshots
  because they scan the fixed lane array with a small tried-lane bitset
- agent reconnect attempts, successes, failures, and currently repairing lanes
  remain visible in periodic and final stats lines
- SSH channel opens are admission controlled
- full-tunnel `0.0.0.0/0` expands to two split routes and must protect the SSH
  control connection with a temporary host route when needed
- every benchmark run must leave no stale routes, resolver settings, or helper
  processes
