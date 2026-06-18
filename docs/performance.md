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
transport  body_bytes  connections  run  elapsed_ms  response_bytes  throughput_mib_s  p50_us  p95_us  max_us
```

Tune the matrix with environment variables:

```sh
RUSTLE_BENCH_BODY_BYTES="65536 1048576" \
RUSTLE_BENCH_CONNECTIONS="1 8 32 64" \
RUSTLE_BENCH_BRIDGE_TRANSPORTS="agent direct-tcpip auto auto-quic quic-agent quic-native" \
RUSTLE_BENCH_AGENT_SESSIONS=2 \
RUSTLE_BENCH_RUNS=5 \
RUSTLE_BENCH_WARMUP_RUNS=1 \
scripts/bench-bridge-lab.sh
```

Set `RUSTLE_BENCH_QUIC_AGENT_COMMAND` when the remote QUIC helper is not the
same binary path as the benchmarked local `rustle`. The `quic-agent` transport
still uses SSH for helper authentication and bootstrap, then carries the framed
agent protocol over UDP/QUIC. Its release gate proves that this authenticated
carrier can sustain large responses; it is not yet the final v2 speed claim.
Local 100 MiB lab rows should be compared against `agent` on the same machine
before making any "faster than SSH-agent" assertion. The remaining high-speed
data-plane work is to replace the single framed carrier stream with native
per-flow QUIC streams.

Set `RUSTLE_BENCH_QUIC_NATIVE_COMMAND` to override the hidden native helper
command. The `quic-native` transport runs `rustle quic-bridge-agent` by default,
uses SSH only for authenticated bootstrap, and maps each TCP flow or UDP
association to its own QUIC stream. This is the current v2 native data-plane
slice for TCP, hostname TCP opens, IPv4 DNS over UDP, hostname DNS over TCP, and
generic IPv4 UDP; it still needs faster same-host rows before it should be
promoted over the primary `agent` transport.

The hidden `auto-quic` transport is an explicit experiment, not the default. It
probes `quic-native` with a short UDP data-plane timeout and falls back to the
primary SSH-agent path when the remote UDP helper port is blocked or bootstrap
fails. Use `--agent-path` with `auto-quic` when overriding the helper binary so
Rustle can derive both `agent` and `quic-bridge-agent` subcommands.

For local regression preflights, the benchmark can also enforce a conservative
agent/direct sanity ratio for matching body-size and connection-count rows:

```sh
RUSTLE_BENCH_MIN_AGENT_DIRECT_RATIO=0.50 \
RUSTLE_BENCH_RATIO_MIN_CONNECTIONS=32 \
scripts/bench-bridge-lab.sh
```

Use `RUSTLE_BENCH_MAX_ELAPSED_MS` for a low-concurrency elapsed-time ceiling,
`RUSTLE_BENCH_MAX_P50_US` for a median measured p50 request-latency ceiling, and
`RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S` for a release-mode throughput floor. Set
`RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO` to require native QUIC throughput to
stay above a fraction of the primary `agent` path on the same body/connection
matrix, and `RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO` to bound native QUIC
tiny-response p50 against `agent`.
`scripts/verify-local.sh` uses a conservative tiny-response 1-flow latency gate
with both elapsed and median measured `p50_us` ceilings across the fast-path
transports, `agent` and `quic-native`, runs a 1 MiB / 1-flow gate that keeps
`direct-tcpip` under compatibility throughput coverage, runs a delayed 1 KiB
agent gate with `RUSTLE_BENCH_HTTP_RESPONSE_DELAY_MS=25`, runs an 8 MiB
chunked-response `agent` gate with `RUSTLE_BENCH_HTTP_CHUNK_BYTES=262144`,
`RUSTLE_BENCH_HTTP_CHUNK_DELAY_MS=5`, and
`RUSTLE_BENCH_MIN_THROUGHPUT_MIB_S=20`, and runs a 100 MiB single-flow throughput gate
through both the primary `agent` transport and `quic-native`
(`RUSTLE_BENCH_BODY_BYTES=104857600`). It also runs the same 100 MiB gate through `quic-agent`,
proving the SSH-bootstrap/UDP-QUIC carrier can sustain a large response with
release-mode code. Together these guard against a debug binary, multi-second
startup regression, serious serial data-path regression, or large-response
throughput collapse masquerading as performance evidence. They do not prove the
optional QUIC carrier is faster than the primary SSH-agent carrier on real
remote networks; the local same-host gate now requires native QUIC 100 MiB
throughput to meet or beat `agent`, while tiny-response latency is bounded by an
absolute p50 ceiling. The v2 faster-data-plane claim still requires the same ratios on live
remote matrices, with the p50 ratio tightened to `1.00` before release.
Ubuntu CI also runs the deterministic release-mode subset: tiny-response p50,
8 MiB chunked-response `agent`, 100 MiB `agent`, 100 MiB `quic-agent`, and DNS
p50 for `agent`, `quic-agent`, and `quic-native`.

Those checks are intentionally coarse guardrails, not release claims. They
catch obvious agent-path and single-flow regressions while leaving detailed
performance conclusions to multi-run live benchmarks on the same SSH server and
target.

The rootless bridge benchmark can shape its local HTTP fixture with
`RUSTLE_BENCH_HTTP_RESPONSE_DELAY_MS`, `RUSTLE_BENCH_HTTP_CHUNK_BYTES`, and
`RUSTLE_BENCH_HTTP_CHUNK_DELAY_MS`. These knobs do not emulate real SSH RTT or
remote kernel behavior, but they create deterministic delayed-response and
chunked-response cases for local regression checks. When `RUSTLE_HOTPATH_TRACE`
is enabled, `scripts/bench-bridge-lab.sh` summarizes traced flow timings from
the per-run stderr logs before cleanup.

## Current Performance Posture

Rustle's performance status is mixed and should be described precisely:

- The default `agent` path is competitive with sshuttle on tiny live responses
  in the latest Contabo run, but the margin is small.
- Native QUIC is functional and faster than `agent` on the latest 100 MiB
  Contabo fixture, but it is not yet the large step-function speedup the v2 data
  plane is intended to deliver.
- Live bulk runs currently point at supervisor event-queue pressure, so the next
  performance work is data-path queue reduction before marketing claims.
- QUIC remains opt-in until live throughput, tiny p50, UDP reachability,
  fallback, reconnect, and cleanup gates are consistently green.

The framed-agent stream window starts at 4 MiB and can grow to 24 MiB. The
initial window is deliberately larger than a minimal LAN default because live
SSH-agent traffic is RTT-sensitive: at 200 ms RTT, a 1 MiB first-flight window
caps a fresh flow around 5 MiB/s before growth credit returns, while 4 MiB gives
the first response roughly 20 MiB/s of headroom. The cap stays below the
per-flow remote backlog limit so supervisor backpressure still has room to
absorb local TCP send-window bursts.

Rustle also configures the SSH client channel around the agent data plane: a
64 MiB SSH channel window and a 256 KiB max packet. Those values keep russh's
smaller defaults from becoming the real WAN throughput cap underneath the
framed-agent stream credit window.

Both sides of the framed-agent carrier read in 64 KiB chunks against the 256 KiB
protocol payload cap. That keeps max-size data frames to four carrier reads on
SSH stdio or `quic-agent` streams without making every carrier-read future hold
a full max-payload buffer.

This benchmark is useful for bridge regressions because it exercises:

- smoltcp client handshake and receive path
- Rustle `FlowManager`
- SSH channel admission and `direct-tcpip`
- local-to-remote and remote-to-local bridge queues
- bounded remote backlog flushing
- auto, direct-tcpip, framed agent, experimental quic-agent scheduling, and
  native quic-native scheduling under the same response sizes and connection
  counts
- one-lane versus multi-lane framed agent behavior with
  `RUSTLE_BENCH_AGENT_SESSIONS`

`bridge-lab` waits for the requested or recommended agent lane pool before
starting synthetic clients. That keeps this benchmark focused on steady-state
bridge throughput; the real compact tunnel defaults to one agent lane for
first-response latency, while hidden auto-lane mode starts after the primary lane
and warms remaining lanes in the background.

It does not exercise host route injection, TUN driver behavior, DNS takeover, or
generic UDP datagram behavior.

## Rootless Agent Reconnect Benchmark

Build first:

```sh
cargo build --release
```

Run the default reconnect behavior gate:

```sh
scripts/bench-agent-reconnect-lab.sh
```

The script starts a temporary local `sshd`, starts a local HTTP server, then
uses a deterministic flaky remote agent command: the first exec agent completes
the Rustle agent `Hello` handshake and exits, while the next exec starts the
real agent. This forces the framed-agent bridge to detect the failed transport,
reconnect through SSH, and complete later synthetic TCP flows. Output is
tab-separated:

```text
connections  min_completed  run  completed  elapsed_ms  response_bytes  p50_us  p95_us  max_us
```

Tune the reconnect gate with environment variables:

```sh
RUSTLE_BENCH_AGENT_RECONNECT_CONNECTIONS=4 \
RUSTLE_BENCH_AGENT_RECONNECT_MIN_COMPLETED=2 \
RUSTLE_BENCH_AGENT_RECONNECT_MAX_ELAPSED_MS=6000 \
RUSTLE_BENCH_AGENT_RECONNECT_MAX_P50_US=2000000 \
RUSTLE_BENCH_RUNS=3 \
RUSTLE_BENCH_WARMUP_RUNS=1 \
scripts/bench-agent-reconnect-lab.sh
```

`scripts/verify-local.sh` runs this as a release-mode reconnect behavior gate.
The gate also fails if the run does not log an agent reconnect or if the bridge
summary leaves active flow, bridge, or backlog state behind.

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
`scripts/smoke-linux-netns-udp.sh` on a privileged Linux host for hermetic
network-namespace proof, and use `scripts/smoke-live-udp.sh` against a real SSH
host for live generic UDP-over-TUN proof.

## Rootless Agent DNS Latency Benchmark

Build first:

```sh
cargo build --release
```

Run the default DNS latency gate:

```sh
scripts/bench-agent-dns-lab.sh
```

The script starts a temporary local `sshd`, starts the Rustle DNS fixture with
both UDP and TCP listeners, then runs `rustle agent-dns-lab` through the selected
bridge transport. Output is tab-separated:

```text
transport  queries  run  elapsed_ms  response_bytes  p50_us  p95_us  max_us
```

Tune the matrix and hard p50 ceiling with environment variables:

```sh
RUSTLE_BENCH_AGENT_DNS_QUERIES="32 128" \
RUSTLE_BENCH_AGENT_DNS_TRANSPORTS="agent direct-tcpip auto-quic quic-agent quic-native" \
RUSTLE_BENCH_AGENT_DNS_REMOTE_HOST=127.0.0.1 \
RUSTLE_BENCH_AGENT_DNS_MAX_P50_US=500000 \
RUSTLE_BENCH_RUNS=5 \
RUSTLE_BENCH_WARMUP_RUNS=1 \
scripts/bench-agent-dns-lab.sh
```

`scripts/verify-local.sh` runs this as a release-mode DNS latency gate with
`RUSTLE_BENCH_AGENT_DNS_MAX_P50_US` for the primary `agent` transport, the
experimental `quic-agent` carrier, and the native `quic-native` UDP data plane.
The default transport is the primary
`agent` transport, so standalone runs measure IPv4 DNS over the framed agent UDP
path without relying on host routes, TUN driver behavior, or OS resolver
takeover. Use `RUSTLE_BENCH_AGENT_DNS_TRANSPORTS` when comparing compatibility
`direct-tcpip` DNS or additional experimental transport rows. `quic-native`
uses native QUIC UDP for IPv4 resolver addresses and native QUIC TCP for
hostname resolver targets; set `RUSTLE_BENCH_AGENT_DNS_REMOTE_HOST=localhost`
to force the benchmark through the hostname-open path.

This benchmark is not a DNS leak or cleanup proof. Use `scripts/smoke-tun-dns.sh`
with `RUSTLE_SMOKE_CONFIGURE_DNS=1` for DNS resolver takeover, normal system
resolver delivery through Rustle, and exact resolver restoration.

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
tool  run  requests  concurrency  success  failed  wall_ms  p50_ms  p95_ms  bytes  throughput_mib_s  req_s  avg_cpu_pct  max_cpu_pct  ssh_opened  ssh_failed  agent_reconnect_attempts  agent_reconnect_ok  agent_reconnect_failed  backlog_overflow  remote_backlog_bytes  remote_backlog_bytes_max  bridge_event_queue_remote_bytes  bridge_event_queue_remote_bytes_max
```

Every run is verified before the script exits. Successful Rustle rows must have
zero diagnostic failure counters for `ssh_failed`, `agent_reconnect_failed`,
`backlog_overflow`, `remote_backlog_bytes`, and
`bridge_event_queue_remote_bytes`; nonzero values fail the live benchmark even
when request success and optional performance thresholds pass.
`remote_backlog_bytes_max` records the high-water remote bytes waiting inside
the packet engine. `bridge_event_queue_remote_bytes_max` records the high-water
remote bytes queued before packet-engine ingestion, so live throughput runs can
distinguish event-loop pressure from downstream backlog or TUN write pressure.

By default the live harness benchmarks Rustle with the primary `agent` transport
first, then the `direct-tcpip` compatibility path, producing `rustle-agent` and
`rustle-direct-tcpip` rows. It can also collect experimental `rustle-quic-agent`
and `rustle-quic-native` rows when the remote network allows the SSH-bootstrapped
UDP/QUIC data plane. To pin the transport matrix explicitly, use:

```sh
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent direct-tcpip quic-native" \
RUSTLE_BENCH_AGENT_PATH="/opt/rustle/rustle" \
RUSTLE_BENCH_AGENT_SESSIONS=2 \
scripts/bench-live-compare.sh
```

`RUSTLE_BENCH_AGENT_PATH` appends the helper subcommand needed by the selected
transport (`agent`, `quic-agent`, or `quic-bridge-agent`). Use
`RUSTLE_BENCH_AGENT_COMMAND` only when you need to provide the complete remote
helper command yourself.

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

To make the tiny-response latency replacement goal a hard gate, set a maximum
average p50 latency ratio for `rustle-agent` over successful sshuttle rows:

```sh
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent" \
RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO=1.00 \
scripts/bench-live-compare.sh
```

This fails the benchmark if `rustle-agent` has a higher average p50 latency
than sshuttle on the same SSH server, target URL, request count, and
concurrency. `scripts/verify-release-candidate.sh` enables this gate by default
while running the privileged and live release-candidate matrix.

To make the live native-QUIC data-plane claim a hard gate, compare
`rustle-quic-native` to `rustle-agent` on the same target:

```sh
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent quic-native" \
RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO=1.00 \
RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO=1.00 \
scripts/bench-live-compare.sh
```

This fails unless native QUIC meets the configured average throughput ratio and
average p50 latency ratio against the primary SSH-agent path. The release
candidate wrapper includes `quic-native` automatically when either native/agent
ratio gate is set, but it leaves those gates opt-in until the remote UDP path is
known to be reachable and stable.

For environment-specific regression checks, match the output `tool` column with
a shell-style pattern and set either or both live thresholds:

```sh
RUSTLE_BENCH_LIVE_TOOL_PATTERN=rustle-agent \
RUSTLE_BENCH_LIVE_MAX_P50_MS=250 \
RUSTLE_BENCH_LIVE_MIN_THROUGHPUT_MIB_S=20 \
scripts/bench-live-compare.sh
```

The pattern can target an exact row such as `rustle-agent`, a group such as
`rustle-*`, or `sshuttle`. The harness fails if the pattern matches no
successful rows, if any matched row exceeds `RUSTLE_BENCH_LIVE_MAX_P50_MS`, or
if any matched row falls below `RUSTLE_BENCH_LIVE_MIN_THROUGHPUT_MIB_S`. These
checks are local guardrails for a fixed machine, remote SSH server, target URL,
request count, and concurrency; they are not portable performance claims.

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

For SSH config aliases such as `contabo`, the benchmark passes the user's
`~/.ssh/config` and `~/.ssh/known_hosts` into sshuttle's SSH command when the
benchmark itself has to launch sshuttle through `sudo`. It also resolves
`IdentityFile ~/.ssh/...` entries with `ssh -G` before sudo starts sshuttle, so
the comparator uses the same user key material as a normal `ssh contabo` run.
Set `RUSTLE_BENCH_SSH_CONFIG` to pin the config used by both Rustle and
sshuttle, or `RUSTLE_BENCH_SSHUTTLE_SSH_CONFIG` when only the sshuttle
comparator needs a different config. `RUSTLE_BENCH_SSHUTTLE_SSH_CMD` still
overrides the complete sshuttle SSH command when a lab needs total control.
The controlled live fixture also accepts `RUSTLE_FIXTURE_SSH_CONFIG`; when that
fixture-specific variable is set, the remote fixture `ssh` command and the
nested Rustle/sshuttle benchmark use the same OpenSSH config.

For throwaway lab hosts, `RUSTLE_BENCH_INSECURE_HOST_KEY=1` or
`RUSTLE_LIVE_INSECURE_HOST_KEY=1` also applies to sshuttle identity mode. When
the harness constructs sshuttle's `-e ssh` command, both password and identity
mode include `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null`.

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
For large-response comparator runs where Rustle completes but sshuttle times out
or resets mid-transfer, set `RUSTLE_BENCH_ALLOW_FAILED_TOOLS=sshuttle` to keep a
failed sshuttle row in the TSV. That mode is intentionally opt-in: failed Rustle
rows and all failed comparator rows remain fatal unless the tool name is listed.

## Controlled Live Large-Response Fixture

Use `scripts/bench-live-fixture.sh` when the existing live URL returns tiny
responses and mostly measures request latency. The fixture starts a temporary
Python HTTP server on the SSH host, then runs `scripts/bench-live-compare.sh`
against controlled 1 MiB / 10 MiB / 100 MiB responses. Each run sets
`RUSTLE_BENCH_EXPECT_BYTES` so the benchmark fails if a response is truncated
and `RUSTLE_BENCH_EXPECT=rustle-live-fixture` so a same-size response from the
wrong service cannot be counted as fixture throughput. The fixture wrapper also
captures the nested benchmark TSV output for each body size and verifies that
each row reports successful requests and exactly `body_bytes * success`
downloaded bytes.

```sh
RUSTLE_FIXTURE_REMOTE=alice@ssh.example.com \
RUSTLE_FIXTURE_HOST=192.168.190.45 \
RUSTLE_AGENT_DIR="$HOME/.cache/rustle/agents" \
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
response before the measured GET request. The fixture server has a bounded TTL
(`RUSTLE_FIXTURE_TTL_SECONDS`, default 3600) and the wrapper also records the
remote PID so cleanup can kill it explicitly after each body-size run.

For agent-mode live benchmarks from a different local platform than the remote,
prepare a sidecar store with `scripts/prepare-agent-sidecars.sh` and export
`RUSTLE_AGENT_DIR` before running the smoke or benchmark. The live smoke and
benchmark launchers preserve that variable through `sudo` so Rustle can upload
the matching sidecar after route setup. When published archives are not
available yet, use `scripts/build-agent-sidecars.sh` to build selected release
targets from source and populate the same sidecar store before running the live
fixture. If the remote already has a specific Rustle binary installed, set
`RUSTLE_LIVE_AGENT_PATH` for the live smokes or `RUSTLE_BENCH_AGENT_PATH` for
the live benchmark; the launchers append the helper subcommand for the selected
transport and reject simultaneous raw command/path overrides.

For password-auth labs, the fixture SSH command can reuse
`RUSTLE_BENCH_PASSWORD_VALUE`/`RUSTLE_LIVE_PASSWORD_VALUE`, or prompt with
`RUSTLE_FIXTURE_PASSWORD=1`. That path requires `sshpass` because the fixture
itself is started with the OpenSSH client. When benchmark-specific credentials
are not set, fixture-only auth and host-key settings are forwarded into the
nested live benchmark run, including `RUSTLE_FIXTURE_PASSWORD_VALUE`, prompted
`RUSTLE_FIXTURE_PASSWORD`, `RUSTLE_FIXTURE_IDENTITY`,
`RUSTLE_FIXTURE_INSECURE_HOST_KEY`, and `RUSTLE_FIXTURE_KNOWN_HOSTS`.
Set `RUSTLE_FIXTURE_ALLOW_FAILED_TOOLS=sshuttle` when a large fixture should
preserve Rustle rows and record a partial failed sshuttle comparator row instead
of aborting the whole fixture run. The fixture row verifier still requires every
non-allowed tool row to have zero failures and exact transferred bytes.

### TCP Hotpath Trace Summary

When a live fixture fails a latency or throughput gate, enable the opt-in TCP
hotpath trace and summarize Rustle's stderr/log output:

```sh
RUSTLE_HOTPATH_TRACE=1 scripts/bench-live-fixture.sh
```

`RUSTLE_HOTPATH_TRACE=1` also enables the agent startup trace. Live benchmark
artifacts then include `hotpath-summary.tsv` for per-flow timing and
`startup-summary.tsv` for primary helper startup, extra-lane startup, retry
counts, degraded starts, and startup failures. If `startup-summary.tsv` reports
`primary_error`, fix SSH config, identity, known-host, sidecar selection, or
helper bootstrap before interpreting any tunnel latency result. If startup is
`ok` and `hotpath-summary.tsv` points at `remote_open_wait`, `first_byte_wait`,
`body_drain`, or queue waits, the remaining problem is in the data path rather
than helper bootstrap.

Use a fixture host address that is distinct from Rustle's SSH control remote.
The live fixture wrapper rejects a fixture IP that resolves to the same address
as the Rustle control target because Rustle installs a control-route guard for
that SSH host, and benchmark traffic to that same IP can bypass the tunnel. Set
`RUSTLE_FIXTURE_ALLOW_CONTROL_HOST=1` only for an explicitly non-tunnel control
experiment.

The summary groups flows by transport and reports `stream_ready`, `opened`,
first local payload, first local payload sent, first remote byte, duration,
bytes, per-flow byte distribution, per-flow throughput distribution, and
outcomes. It also derives `remote_open_wait`, `agent_remote_connect`,
`agent_open_transport_wait`, `ready_wait`, `payload_queue_wait`,
`first_byte_wait`, `post_open_first_byte_wait`, `body_drain`, cumulative
`local_send_wait`, `tcp_recv_queue_wait`, `local_queue_wait`,
`pre_bridge_queue_wait`, framed-agent `agent_send_credit_wait` and
`agent_send_outbound_wait`, `remote_event_wait`, and a `likely_bottleneck`
label. `tcp_recv_queue_wait` is the age of payload inside smoltcp before the
packet engine drains it; `local_queue_wait` is the bridge mpsc wait;
`agent_remote_connect` is measured inside the remote helper around its TCP
connect call; `agent_open_transport_wait` is the remaining local
`remote_open_wait` after subtracting that remote connect duration; and
`pre_bridge_queue_wait` combines local pre-bridge waits as a coarse "before the
data-plane task can act" diagnostic. Use those derived terms to decide which
fix comes first:
remote open latency, packet-engine bridge admission/drain delay, delayed first
payload forwarding, local bridge queueing, remote first-byte delay, flow
duration/windowing, per-flow starvation, framed-agent flow-control credit,
framed-agent outbound queue pressure, supervisor event pressure, or failed/reset
flows. The trace is deliberately opt-in and does not include payload bytes.
`scripts/bench-live-compare.sh` prints the summary to stderr during cleanup when
traced flow lines exist; set `RUSTLE_BENCH_KEEP_LOGS=1` when you also want to
keep the raw per-run `rustle.log` files.

The regular `stats:` line also carries live drain counters for untraced runs:
`tun_write=calls:<n> total_us:<n> max_us:<n>` reports TUN write pressure,
`backlog_bytes=<n> max:<n> raw:<n> max_raw:<n>` reports remote bytes waiting
inside the packet engine, and `bridge_event_queue=remote_bytes:<n> max:<n>
remote_bytes_raw:<n> max_raw:<n>` reports remote `RemoteData` bytes already
queued by bridge tasks but not yet dequeued by the packet engine.
`bridge_event_batch=count:<n> ... total_us:<n> max_us:<n> paused:<n>` reports
supervisor bridge-event batch pressure and backlog pauses.
`agent_writer=...` reports framed-agent writer pressure: current/max queued
frames and bytes, burst counts and byte totals, enqueue-to-write delay, and
writer/flush timings. Live artifacts summarize those fields into
`agent-writer-summary.tsv`; high queued bytes or enqueue wait means the local
framed-agent writer is the bottleneck, while high write or flush time points at
SSH channel or carrier backpressure underneath the writer.
Use those fields with hotpath `pre_bridge_queue_wait`, `remote_event_wait`, and
`body_drain` when deciding whether a WAN throughput failure is in the data
plane, framed-agent writer, packet engine, smoltcp drain, or TUN device writes.
`scripts/verify-release-candidate.sh` enables `RUSTLE_HOTPATH_TRACE=1` by
default and writes compact live benchmark artifacts under
`target/live-evidence/release-candidate-<timestamp>` unless
`RUSTLE_BENCH_ARTIFACT_DIR` is set. The direct live comparison uses a
`live-compare` subdirectory, and controlled fixture runs use one
`fixture-<bytes>-bytes` subdirectory per body size. `bench-live-compare.sh` also
writes `agent-writer-summary.tsv` from status lines and writes
`live-diagnosis.tsv` through `scripts/summarize-live-evidence.py` when live
results exist. That file is a first-look triage row, not a gate: it maps
nonzero final counters to `diagnostic_failure:*`, max packet-engine backlog to
`packet_engine_backlog_pressure`, max supervisor bridge queue pressure to
`supervisor_event_queue_pressure`, framed-agent writer queue/write/flush
pressure to `agent_writer_*_pressure`, hotpath labels to `hotpath:*`, and
QUIC diagnostic failures to `quic_startup_or_auth_failure`.
Validate a collected artifact tree with:

```sh
scripts/verify-live-evidence.py --require-hotpath target/live-evidence/release-candidate-YYYYMMDDTHHMMSSZ
```

The release-candidate wrapper runs that evidence verifier automatically after
the live gates complete.

Rustle's expected advantage is lower overhead from a native Rust single binary,
explicit bounded queues, and cross-platform TUN support. sshuttle's advantage is
that it can lean on OS-specific firewall and kernel TCP behavior. That means the
comparison is only meaningful when both tools are run on the exact same traffic
shape and target.

### Current Live Fixture Evidence

The following rows were collected on 2026-06-18 from a macOS client against the
`contabo` SSH config alias, using a controlled remote loopback fixture at
`198.18.77.77/32`. They are lab evidence for this client, network, and host, not
a portable release claim.

| Fixture | Tool | Runs | Result |
| --- | --- | ---: | --- |
| 1 KiB, 12 requests, concurrency 1 | `rustle-agent` | 3 | 36/36 succeeded, median p50 `163.50 ms` |
| 1 KiB, 12 requests, concurrency 1 | `sshuttle` | 3 | 36/36 succeeded, median p50 `177.73 ms` |
| 100 MiB, 1 request | `rustle-agent` | 2 | avg throughput about `10.60 MiB/s` |
| 100 MiB, 1 request | `rustle-quic-native` | 2 | avg throughput about `14.59 MiB/s` |
| 1 KiB, 4 requests, concurrency 1 | `rustle-auto-quic` | 1 | selected native QUIC and succeeded, but decision trace reached about `10 s` |
| UDP fixture | `rustle-agent` | 1 | passed, with idle association cleanup |
| UDP fixture | `rustle-quic-native` | 1 | passed, proving UDP/QUIC reachability on this host |
| 1 KiB full tunnel `0.0.0.0/0` | `rustle-agent` | 1 | passed, including split default route cleanup |

The good news: the default agent path matched or beat sshuttle p50 on this live
tiny-response run, and native QUIC was faster than agent for the 100 MiB body.
The bad news: the 100 MiB run diagnosed `supervisor_event_queue_pressure`, and
the native QUIC improvement was about 1.4x, not yet the intended high-speed
data-plane jump. Treat QUIC as functional opt-in evidence, not a default-ready
performance claim.

Operational note: these same live runs proved sidecar upload and SHA-256
verification work, but successful runs left stale remote `/tmp/rustle-agent.*`
directories. That cleanup issue is a release blocker until the helper lifecycle
and live verifier both prove no remote Rustle-owned helper artifacts remain.

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
The fixture host must be a remote-only address; the fixture harness rejects
client-local addresses such as a local Docker bridge IP because those cannot
prove TUN routing. Set `RUSTLE_FIXTURE_ALLOW_LOCAL_HOST=1` only for an
intentional non-tunnel diagnostic. Set
`RUSTLE_BENCH_REQUIRE_AUTO_QUIC_FALLBACK=1` with
`RUSTLE_BENCH_RUSTLE_TRANSPORTS=auto-quic` when the run is meant to prove that
the experimental QUIC probe failed cleanly and selected the SSH-agent fallback.
Set `RUSTLE_VERIFY_LIVE_UDP=1` to include the generic UDP live fixture; it
starts a remote UDP responder over SSH, sends multiple datagrams through the
TUN route, waits for idle cleanup, and requires final `udp=... active:0`
stats. The default `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=agent` proves the product
SSH-agent UDP path. Set `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=quic-native` when
you specifically want to prove that the remote network allows Rustle's
SSH-bootstrapped UDP/QUIC helper data plane; that run should fail clearly when
inbound UDP to the helper port is blocked.
QUIC-native live runs emit structured `quic-connect:` and `quic-auth:` lines
with stage, result, elapsed time, local UDP bind, certificate fingerprint, and
auth-token SHA-256 prefix. QUIC-agent live runs also emit
`quic-agent-protocol:` lines after UDP/QUIC auth succeeds, so a hang in framed
agent Hello negotiation is separated from UDP reachability and auth failures.
The hidden `auto-quic` experiment also emits `auto-quic-decision:` lines that
record the QUIC probe budget and whether the runtime selected native QUIC or
the SSH-agent fallback.
Summarize them with
`scripts/summarize-quic-diagnostics.py` to distinguish UDP reachability,
certificate/bootstrap, auth-stream, and framed-agent protocol failures without
exposing raw tokens.

### Current Contabo RC Blockers

The latest 2026-06-18 Contabo release-candidate run moved the blocker from
setup into product behavior. SSH alias resolution, privileged local TUN/DNS
route tests, macOS DNS takeover/restore, live agent smoke, live direct-tcpip
smoke, live agent UDP smoke, and local/rootless QUIC-native 100 MiB throughput
all passed. Local correctness gates also passed.

The failed release-candidate gate is tiny-response latency against sshuttle on
the same live target:

| Tool | avg p50 |
| --- | ---: |
| `rustle-agent` | 200.6 ms |
| `sshuttle` | 183.2 ms |

The ratio was 1.09, while the release-candidate gate requires
`rustle-agent <= sshuttle` on average p50.

The same controlled fixture showed that Rustle is much faster than sshuttle on
bulk transfer, but not fast enough to call the agent path production-grade for
large live responses yet:

| Fixture | Result |
| --- | --- |
| 1 MiB | `rustle-agent` 4.29 MiB/s, `direct-tcpip` 3.10 MiB/s, `sshuttle` 0.24 MiB/s |
| 10 MiB | `rustle-agent` 5.96 MiB/s, `direct-tcpip` timed out with partial response |
| 100 MiB single-flow | `rustle-agent` completed in 26.5 s, about 3.78 MiB/s |
| 100 MiB concurrent | default 45 s curl timeout hit; one response reached about 72.9 MiB before timeout |

QUIC-native is not production-ready on this host yet. Rebuilding the Linux
sidecar removed stale `RUSTLE_QUIC_BRIDGE_V1` bootstrap output and produced
`RUSTLE_QUIC_BRIDGE_V2`, so helper selection and upload are no longer the
blocker. Raw UDP echo to Contabo rules out a blanket provider UDP block, but it
does not prove that the helper's random advertised `bootstrap_port` is reachable
or that post-TLS token auth and bridge stream readiness are healthy. The current
live failure is therefore in the QUIC helper reachability/auth/readiness slice,
not in sidecar selection.

### Live Performance Research Plan

Treat Rustle as a transport scheduler with three independent live bottlenecks:
open latency, byte throughput, and concurrent-flow fairness. Do not guess-tune
until the hotpath artifact identifies the dominant term.

1. Capture a fresh Contabo artifact with `RUSTLE_HOTPATH_TRACE=1` and preserve
   `hotpath-summary.tsv`, `startup-summary.tsv`, `live-results.tsv`,
   `live-diagnosis.tsv`, and QUIC diagnostics. The required first split is
   `remote_open_wait` versus `post_open_first_byte_wait`; if almost all p50 is
   in `remote_open_wait`, optimize stream open scheduling, not TCP payload
   forwarding. Also add the missing writer-side counters before tuning:
   enqueue-to-write lag, burst write duration, flush duration, queued
   frames/bytes, high-water marks, and burst frame/byte counts per agent lane.
2. For tiny responses, optimize the framed-agent open path only after the trace
   proves the wait. Current code already opens TCP optimistically, grants
   optimistic initial send credit, and records first-local/first-sent timings.
   The next likely wins are coalescing `OpenTcp` with the first local payload
   into one writer turn, ensuring priority control frames are never delayed
   behind large data bursts, and reducing any bridge admission or local queue
   delay before the first payload reaches the agent writer.
3. For 100 MiB live throughput, use the trace counters to decide whether the cap
   is `agent_send_credit_wait`, `agent_send_outbound_wait`, `remote_event_wait`,
   packet-engine backlog, TUN write pressure, or writer flush/write time. The
   framed-agent window already starts at 4 MiB and grows to 24 MiB, so a
   3-6 MiB/s WAN result is more likely a scheduler/carrier/drain problem than a
   raw initial-window constant.
4. For concurrent 100 MiB transfers, prove fairness separately from raw
   throughput. The writer already round-robins non-priority frames inside each
   collected burst; remaining work is to test full writer turns under live RTT,
   make lane load byte-aware instead of only stream-count-aware if needed, and
   add a fixture gate that fails when any concurrent response starves while
   another drains.
5. For QUIC-native, add an explicit post-auth bridge liveness proof before
   treating connect success as ready. A good proof is a tiny authenticated
   health stream or a loopback-safe open/status exchange that verifies the
   remote `quic-bridge-agent` command loop is accepting streams after TLS and
   token auth complete.
6. Before QUIC-native can be default or performance-first `auto-quic`, add route
   protection for the actual resolved QUIC UDP carrier addresses under
   full-tunnel `0.0.0.0/0`, a diagnostic way to pin the helper UDP bind/port
   during live tests, clear auth-stage diagnostics for live timeouts, reconnect
   or explicit failure semantics after the QUIC connection dies, and repeated
   live TCP/DNS/UDP/100 MiB gates on both macOS and Linux.

The product order remains: fix the SSH-agent p50 release-candidate blocker
first, fix live 100 MiB drain/fairness second, then graduate QUIC-native from
experimental only after live auth/readiness and route-protection gates pass.
When `RUSTLE_LIVE_REMOTE` or `RUSTLE_LIVE_UDP_REMOTE` is an OpenSSH `Host`
alias and the smoke runs Rustle through `sudo`, set
`RUSTLE_LIVE_SSH_CONFIG=$HOME/.ssh/config` or the UDP-specific
`RUSTLE_LIVE_UDP_SSH_CONFIG` so the privileged Rustle process and the fixture
SSH command resolve the same alias. Use `RUSTLE_LIVE_UDP_AGENT_PATH` when the
UDP smoke should use a different preinstalled remote helper binary from the main
live smoke. The live benchmark harness automatically forwards the caller's
default `$HOME/.ssh/config` and `$HOME/.ssh/known_hosts` to privileged Rustle
when explicit benchmark values are not set.
Set `RUSTLE_VERIFY_DNS_TAKEOVER=1` on privileged verifier runs to include the
system resolver takeover and exact-restore DNS smoke.

For release-candidate evidence on a privileged macOS or Linux host, use:

```sh
RUSTLE_LIVE_REMOTE=alice@ssh.example.com \
RUSTLE_LIVE_TARGET_CIDR=0.0.0.0/0 \
RUSTLE_LIVE_URL=https://192.168.190.45/ \
RUSTLE_FIXTURE_HOST=192.168.190.45 \
RUSTLE_LIVE_UDP_HOST=192.168.190.45 \
scripts/verify-release-candidate.sh
```

The wrapper fails instead of skipping privileged gates, enables DNS takeover,
live TCP smoke, controlled 1 MiB / 10 MiB / 100 MiB fixture benchmarks, live
generic UDP, and `RUSTLE_BENCH_TOOLS="rustle sshuttle"`. By default it also sets
`RUSTLE_BENCH_MAX_AGENT_SSHUTTLE_P50_RATIO=1.00`, so Rustle's primary
`rustle-agent` row matches or beats sshuttle average p50 latency on the same
live target.

## Agent Promotion Criteria

The compact command already defaults to the framed agent transport and fails
loudly if the agent cannot start or bootstrap. The hidden `auto` mode still
exists only for diagnostics and compatibility fallback. Keeping agent as the
sole public default requires evidence that it remains better than compatibility
mode on the same machines:

- rootless bridge benchmarks pass for both transports at 1, 8, 32, 64, and 256
  synthetic flows with 64 KiB and 1 MiB response bodies; the high-fanout stress
  gate defaults to both `agent` and `direct-tcpip` at 256 x 1 MiB. That stress
  run is a lifecycle gate for TCP cleanup, stale remote-data handling, and
  bridge survival under fanout. The bridge benchmark summary must report
  `active_flows=0`, `active_bridges=0`, `backlog_flows=0`, and
  `backlog_bytes=0`; otherwise the harness fails the run as leaked lifecycle
  state. Chaos runs that stop after `--min-completed` abort incomplete synthetic clients
  during cleanup before the summary is accepted. Bridge benchmark rows
  also report per-flow response latency as `p50_us`, `p95_us`, and `max_us`.
  After each benchmark run, the harness also requires the lab `sshd` process tree to have no descendants
  and checks the process-tree fd count where `/proc`
  or `lsof` can expose descriptors. It is not throughput evidence unless the
  benchmark is explicitly run with a release binary and recorded as such.
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
  privileged Linux host before generic UDP is treated as field-ready; that smoke
  shortens `--udp-idle-timeout-ms`, waits for idle cleanup, and requires final
  UDP stats to report zero active associations
- `scripts/smoke-live-udp.sh` passes against a real remote `sshd` and UDP
  fixture with the default `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=agent`, proving
  generic UDP datagrams traverse route -> TUN -> agent `OpenUdp` -> remote UDP
  socket -> synthesized return packet without leaks. Re-run it with
  `RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=quic-native` before treating native QUIC
  UDP as field-ready on that remote; failure there means the local host cannot
  reach the SSH-bootstrapped QUIC helper over UDP.
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
- remote-to-local TCP backlog is bounded per flow and globally, currently 32 MiB
  per flow with a 512 MiB process-wide backlog cap
- smoltcp TX packets are drained into caller-owned scratch vectors so the TUN
  loop does not allocate a fresh `Vec<PacketBuf>` for each packet poll
- `FlowManager` enumeration for bridge admission and local-byte drain uses
  caller-owned scratch vectors for `FlowId`/`FlowKey` lists; opening-flow counts are computed directly instead of by allocating snapshots
- local-byte drain moves up to one full 64 KiB TCP receive-buffer payload per
  bridge queue item, while still capping each item below the bridge byte budget
- remote backlog flushing, stale-flow expiry, and closed-flow pruning use
  caller-owned scratch vectors for per-tick cleanup scans instead of allocating
  temporary flow lists
- bridge event handling uses caller-owned closed-flow scratch storage so
  high-rate remote-data events do not allocate temporary closed-flow vectors
- `stale_remote_data_storm_after_flow_removal_is_bounded` proves stale
  remote-data storms after flow removal do not refill remote backlog storage,
  emit closed-flow work, or trip backlog overflow accounting
- `high_fanout_stale_remote_data_after_removal_is_bounded` gives the same
  lifecycle invariant a fast multi-flow regression before the external
  256-flow bridge stress harness runs
- stale `RemoteData` chunks are counted without per-chunk logging; stale
  close/eof/failure/open transitions still log for diagnosis
- generic UDP request payloads are parsed into `Bytes` once from the reusable
  TUN read buffer, then moved directly into the per-association agent queue
  without a second payload allocation
- direct-tcpip compatibility mode drops generic UDP intentionally and accounts
  the drop without admitting UDP association state
- generic UDP response events keep agent `Data` frame payloads as `Bytes` until
  TUN packet synthesis instead of copying each response into a temporary
  `Vec<u8>`
- idle generic UDP associations emit close events that remove association state
  and release active-association budget deterministically
- DNS response events keep remote resolver payloads as `Bytes`; agent UDP DNS
  moves agent `Data` payloads directly and DNS-over-TCP slices the accumulated
  length-prefixed frame without an extracted-response `Vec<u8>` copy
- agent streams use explicit byte-credit windows instead of unbounded SSH-channel
  buffering
- single-flow remote-to-local throughput depends on both the smoltcp proxy
  response buffer and the agent stream response window; the agent window starts
  aligned at 4 MiB and sustained streams adapt up to a bounded 24 MiB cap, so one
  high-latency flow is not capped by the old 256 KiB credit window while tiny
  flows keep the lower initial window
- each remote backlog admits multiple local TCP send windows so high-throughput
  agent or native QUIC bursts are not reset solely because the event loop
  receives faster than the local TCP side drains; the global remote-backlog cap
  still bounds aggregate memory across flows
- agent senders segment oversized local buffers into bounded protocol frames
  instead of relying on callers to respect frame-size limits
- agent writer tasks must reuse per-task burst frame and encoded-byte buffers
  across flushes instead of allocating them once per burst
- agent writer bursts round-robin non-priority frames across stream ids while
  preserving per-stream order, so concurrent response streams share each encoded
  burst instead of inheriting pure FIFO ordering from the hottest producer
- remote agent output producers yield after a bounded number of data frames, so
  one hot TCP or UDP response stream cannot keep enqueueing indefinitely before
  sibling stream tasks get scheduler time
- agent peers that advertise heartbeat support must answer periodic zero-stream
  pings; missed pongs must trip sticky transport failure and reconnect handling
- agent streams can be hashed across multiple SSH exec lanes; the public compact
  command defaults to one lane for first-response latency, while hidden
  `--agent-sessions 0` selects capped `ceil(sqrt(local CPU parallelism))` auto
  lanes for lab or unusual high-bandwidth links
- the compact auto-lane path starts after the primary agent lane and warms the
  remaining recommended lanes in background, while explicit `--agent-sessions`
  requests keep the full initial startup gate
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
- Unix Ctrl-C, SIGTERM, and SIGHUP shutdowns must all return through the normal
  tunnel/capture cleanup path so route, DNS, TUN, local DNS proxy, and
  uploaded-agent cleanup guards can run
- every benchmark run must leave no stale routes, resolver settings, or helper
  processes
