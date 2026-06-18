# Rustle Architecture

Rustle is a user-space network pivot and SSH-authenticated tunneling tool. The
product pipeline is:

```text
local app
  -> OS route
  -> TUN
  -> packet engine
  -> data plane
  -> remote socket
```

The project intentionally avoids firewall redirect hooks. Route injection is
allowed because traffic must reach the TUN device, but Rustle must not depend on
`iptables`, `nftables`, `pf`, or Windows Filtering Platform.

## Current Architecture Decision

Rustle is still pre-release, but the architecture has a stable product spine:

```text
CLI
  -> Supervisor
  -> Packet Engine
  -> DataPlane trait
  -> agent | quic-native | direct-tcpip
```

The default path is the SSH-authenticated framed agent data plane. Native QUIC
is a second data plane, not a patch inside agent logic. SSH remains the
bootstrap and authentication mechanism for the remote helper; QUIC becomes only
the data carrier after helper bootstrap succeeds.

The current product rule is:

- `agent` is the v1 default and the only daily-use path.
- `quic-native` is the v2 opt-in high-performance path.
- `auto-quic` is hidden until probe latency, fallback behavior, reconnect, and
  live performance gates are stable.
- `direct-tcpip` is a compatibility/lab path, not the architecture to optimize.

## Runtime Ownership

Rustle's modules are split by ownership rather than by protocol names:

- CLI parses sshuttle-style commands, hidden lab switches, SSH auth options, and
  target CIDRs. It does not own runtime lifecycle.
- Supervisor owns lifecycle. It prepares TUN, route, DNS, SSH/control state, the
  selected data plane, signal handling, shutdown ordering, and final stats.
- Packet engine owns packet semantics. It reads and writes TUN packets, drives
  smoltcp TCP state, handles DNS/UDP ingress, tracks flow admission, and exposes
  transport-neutral bridge starts and bridge events.
- Control plane owns remote access. It resolves SSH config aliases, enforces
  host-key policy, authenticates over SSH, probes the remote platform, prepares
  helper command plans, uploads/verifies sidecars, and starts helpers.
- Data planes implement transport behavior. They expose TCP open, hostname TCP
  open, UDP association, close/reset, and telemetry semantics without leaking
  SSH or QUIC implementation details into the packet engine.
- Remote helpers own remote socket I/O. They run as explicit subcommands:
  `agent`, `quic-agent`, or `quic-bridge-agent`.

This split is the first-principles boundary: packet handling must not know
whether bytes travel over SSH stdio, QUIC streams, or lab direct-tcpip; control
plane bootstrap must not know smoltcp flow state; cleanup must be centralized in
the supervisor.

## Product Phases

```text
Rustle v1:
  TUN + smoltcp + SSH-authenticated framed agent
  Goal: sshuttle replacement for IPv4 TCP, DNS, and generic UDP

Rustle v2:
  SSH bootstrap/control plane + native QUIC data plane
  Goal: lower latency and higher throughput when UDP reachability allows it

Rustle v3 optional:
  rootful/kernel-assisted fast path
  Goal: maximum speed where both endpoints allow deeper network setup
```

v1 must be boring and deterministic. v2 must earn promotion through live gates,
not through local benchmark optimism.

## MVP Boundary

The first production target is narrow by design:

- IPv4 only.
- TCP through the userspace TCP engine.
- Explicit target CIDRs plus full-tunnel `0.0.0.0/0`. The public parser also
  accepts sshuttle-style abbreviated IPv4 CIDRs such as `0/0`, `10/8`, and
  `172.16/12`, normalizing them into the same internal IPv4 route model. Full
  tunnel expands to split IPv4 routes so the SSH control connection can be
  protected.
- Framed agent mode by default when a remote `rustle agent` can run or be
  bootstrapped, plus explicit vanilla remote `sshd` compatibility through
  `direct-tcpip`.
- DNS interception handles UDP/53 queries before the TCP stack. Agent mode keeps
  IPv4 DNS as UDP over the framed agent `OpenUdp` path, while vanilla
  `direct-tcpip` compatibility and hostname DNS remotes use DNS-over-TCP.
- Generic IPv4 UDP is supported in agent mode as bounded datagram relay. It is
  not available in explicit vanilla `direct-tcpip` compatibility mode.

## Protocol Scope

Rustle's vanilla-`sshd` transport uses SSH `direct-tcpip`, which is a TCP
forwarding channel. That gives a clean, dependency-free remote story for TCP and
for DNS after translating UDP DNS datagrams to DNS-over-TCP. Agent mode keeps default IPv4 DNS as UDP datagrams over `OpenUdp`; hostname DNS remotes still use TCP because the current agent protocol supports hostname opens for TCP only. The vanilla path does not provide a standard way to emit arbitrary UDP packets from the remote host.

Generic UDP therefore belongs to the agent lane. The TUN loop intercepts
non-DNS IPv4/UDP packets before the TCP engine, keys them by source/destination
tuple, and keeps a bounded agent `OpenUdp` association per active tuple.
Datagrams move as `Data` frames, remote response datagrams are synthesized as
reverse UDP packets back to the TUN device, and idle associations close
deterministically. Direct fallback drops generic UDP explicitly, accounts the
drop without admitting UDP association state, and logs that the active transport
does not support it.

## Transport Architecture

Rustle keeps several transport choices behind one packet-engine contract. Only
one is the normal path:

- Agent mode: the default compact `rustle -r user@host CIDR...` path. A framed
  Rustle protocol is carried over one or more SSH `exec` sessions to a
  remote `rustle agent` process. This path is the stronger architecture for
  generic UDP associations, explicit per-flow credit, lower SSH-channel churn,
  remote-side telemetry, and reconnect semantics. Initial agent startup and lane
  repair depend on an agent connector boundary, not raw SSH APIs: SSH is the
  current connector implementation, while the flow engine and lane repair logic
  only ask for one or more new agent transports. If the remote command is
  unavailable, Rustle probes the remote platform with POSIX `uname` first and
  Windows PowerShell as a fallback. It uploads the current executable when the
  local and remote OS/CPU match, or an extracted matching release sidecar beside
  the local package directory, such as `rustle-x86_64-unknown-linux-musl/rustle`,
  for cross-platform remotes. `RUSTLE_AGENT_DIR` adds a hidden deployment search
  directory for managed sidecar stores. The uploaded helper is staged inside a
  private Rustle-owned temporary directory over a separate SSH session channel,
  verified by comparing the local SHA-256 digest with a remote hash of the
  staged file, used as `agent` for every initial agent lane, and removed after
  the last lane using the OS-specific staged-helper cleanup wrapper. If the
  remote hash command fails or the digest differs, Rustle removes the staged
  helper and refuses to execute it. After the first effective command is
  known, additional startup lanes open in bounded concurrent batches; a failed
  extra lane is logged without discarding other successful lanes from the same
  startup wave. Missing startup lanes get one bounded retry before Rustle accepts
  a degraded-but-repairable pool. Desired lane slots remain represented even
  when no startup transport was established, so background repair can fill the
  missing capacity later. Startup logs report `established/desired` exec
  transports, so degraded pool capacity is visible without another CLI flag.
  Custom remote agent startup keeps raw shell and path-based forms separate:
  `--agent-command` is the explicit raw SSH exec command escape hatch, while
  `--agent-path` shell-quotes a literal remote executable path and appends the
  fixed `agent` subcommand.
  Periodic and final stats keep reporting desired, available, missing, failed,
  quarantined, and repairing lane counts, so degradation stays visible after
  startup scrollback is gone. Agent mode can open multiple
  SSH exec transports internally and hash TCP/UDP streams across them, keeping
  the public `rustle -r user@host CIDR...` UI compact while reducing head-of-line
  blocking on one SSH channel. Each lane is established through a fresh SSH connection with one exec channel.
  It is not another exec channel on an existing SSH carrier, so multi-lane mode
  can also reduce SSH TCP head-of-line blocking.
  The compact tunnel default uses one agent exec lane so the daily-use path does
  not start background SSH authentications during the first page load. The hidden
  auto setting, `--agent-sessions 0`, chooses `ceil(sqrt(local CPU parallelism))`,
  capped to four exec transports, then starts after the primary agent lane is
  established and warms the remaining recommended lanes in the background.
  Larger fixed lane counts remain available through the hidden
  `--agent-sessions` override for unusual high-latency or high-bandwidth links;
  explicit lane counts keep the full initial startup gate.
  Stream assignment uses a deterministic two-candidate choice: the primary hash
  keeps flow spread stable, but a healthier, less-loaded secondary lane can take
  new opens during bursts.
  If the primary lane is already known failed and the secondary lane is
  available, the current flow is sent to the secondary immediately while the
  failed primary is repaired in the background. If both hashed candidates are
  unhealthy but another lane is available, new opens fail around the bad pair
  and use the least-loaded healthy lane in the pool while both candidates are
  scheduled for repair. Background repair requests are coalesced per lane, so
  bursts of new flows do not spawn duplicate reconnect attempts for the same
  failed exec transport.
  Agent bridge admission also uses a larger stream-opening budget than
  direct-tcpip because agent streams are framed protocol state, not one SSH
  forwarding channel per flow; the flow manager remains the active-flow cap.
  A lane that fails reconnect is quarantined with bounded exponential backoff
  and a small deterministic per-lane spread, so new flows can use healthy
  alternate lanes instead of retrying one fragile SSH exec channel on every open.
  Fallback alternate-lane traversal scans the fixed lane array by `(load, index)`
  and tracks tried lanes in a small bitset instead of allocating and sorting a
  temporary lane snapshot while the pool is already degraded.
- Experimental QUIC agent carrier: a hidden `quic-agent` helper and
  `--bridge-transport quic-agent` path carry the same framed Rustle agent
  protocol over a QUIC bidirectional stream. SSH is used only to authenticate
  and start the remote helper. The helper emits a one-line bootstrap record
  containing its UDP port, self-signed certificate DER, certificate SHA-256,
  and an opaque bearer token generated for that helper process. The local client
  verifies the hash, pins that certificate, and proves possession of the SSH
  bootstrap token before the helper accepts agent traffic. This is the first v2
  data-plane slice, not yet the public default: it preserves existing agent
  flow-control, DNS, UDP, and reconnect semantics while moving the byte carrier
  from SSH to QUIC. The QUIC transport profile is explicit: the helper accepts
  one client-opened bidirectional carrier stream, disables unidirectional
  streams, uses a 16 MiB stream receive window, and caps connection receive/send
  windows at 64 MiB so Quinn's default 100 Mbps / 100 ms stream window does not
  undercut Rustle's own adaptive agent credit. This carrier is correctness and
  bootstrap groundwork.
- Experimental native QUIC bridge: a hidden `quic-bridge-agent` helper and
  `--bridge-transport quic-native` path reuse the same SSH-authenticated
  certificate-pinned and token-authenticated bootstrap, then map each TCP flow
  or UDP association to its own QUIC bidirectional stream with a compact open
  header. TCP uses raw stream bytes, hostname TCP opens carry a bounded hostname
  payload, and UDP preserves datagram boundaries with a compact length prefix.
  Native stream creation, open-header writes, and open-status reads have explicit
  deadlines so a wedged QUIC path fails in the open phase instead of hanging a
  DNS/UDP/TCP flow indefinitely.
  IPv4 DNS remotes, hostname DNS remotes, and generic IPv4 UDP can now use this
  native QUIC data plane. Same-host bridge and DNS benchmarks must compare
  `quic-native` against `agent` before making a faster-than-SSH-agent claim.
- `direct-tcpip` compatibility mode: an explicit hidden transport requiring only
  a normal remote SSH server with TCP forwarding enabled. This path is the
  closest to sshuttle's zero-install behavior, but it is intentionally not the
  default because per-flow SSH forwarding channels are the fragile path.
- Auto compatibility mode: an explicit hidden mode that tries agent first and
  falls back to `direct-tcpip` when agent startup or configured DNS capability is
  unavailable. This mode exists for diagnostics and compatibility, not as the
  architecture Rustle optimizes around.
- Auto-QUIC experiment: an explicit hidden `--bridge-transport auto-quic` mode
  that probes the native QUIC data plane with a short UDP connect timeout and
  falls back to the primary SSH-agent data plane when UDP bootstrap fails. This
  is the candidate shape for future performance-first selection, but the default
  remains `agent` until live QUIC reachability, fallback, reconnect, and stress
  gates are stable.

## Current Architecture Gaps

These are the gaps that still prevent a production-ready release:

- Remote helper cleanup must be proven on real remotes. Unit tests prove wrapper
  cleanup shape, and live failure cleanup has passed in some cases, but the
  latest successful Contabo runs left stale `/tmp/rustle-agent.*` directories
  after shutdown. The product invariant is stricter: normal shutdown, failed
  startup, Ctrl-C, and helper crashes must leave no Rustle-owned helper
  binaries or refs behind.
- Bulk data still crosses a central bridge-event queue before packet-engine
  ingestion. This keeps ownership simple and telemetry explicit, but latest live
  100 MiB evidence identified supervisor event-queue pressure. The next data
  path iteration should preserve single-owner packet-engine state while reducing
  remote-data queueing cost.
- `auto-quic` has the right product shape but not the right startup behavior.
  The control plane must account probe time precisely and fall back quickly
  enough that failed UDP reachability does not make the default command feel
  worse than agent mode.
- DNS takeover is intentionally platform-owned, but it is also environment
  sensitive. Managed macOS/VPN resolver profiles can override service-scoped
  settings; release evidence must prove actual resolver delivery, not just that
  configuration commands succeeded.

The agent protocol is binary and length-prefixed. Every frame has a fixed
24-byte header:

```text
magic(4) kind(1) flags(1) reserved(2) stream_id(8) credit(4) payload_len(4)
```

The current magic is `RLA1`, protocol version is `1`, and the maximum payload is
256 KiB. Frame kinds cover hello negotiation, IPv4 TCP open, hostname TCP open
for DNS relay, IPv4 UDP open, opened acknowledgements, data, window credit, EOF,
close, reset, and zero-stream heartbeat ping/pong. Payload sizes are validated
before payload allocation, reserved bits must be zero, and the decoder is
incremental so it can run directly on SSH channel byte streams.

The SSH client channel is sized for this framed data plane: Rustle advertises a
64 MiB SSH channel window and 256 KiB max packet so the carrier channel does not
reimpose russh's smaller default window below the agent stream-credit policy.

Agent mode preserves the same outer invariants as `direct-tcpip`: one local flow
maps to one stream id, remote payload is admitted only into bounded local
buffers, and backpressure is represented by explicit byte credit instead of
hidden SSH channel behavior alone. `Opened` frames grant initial send credit,
`Window` frames replenish credit as bytes are consumed or written downstream, and
senders wait before emitting `Data` frames when credit is exhausted. Each
direction starts with a 4 MiB receive window, then sustained streams grow that
window to a bounded 24 MiB cap after the receiver consumes a full current window.
That keeps tiny flows at the low-latency initial window while giving large
responses more in-flight credit without unbounded SSH-channel buffering. The
local agent transport segments oversized caller buffers into bounded `Data`
frames no larger than the negotiated/local protocol maximum. Writer tasks flush
bounded batches; within a batch, priority control frames move ahead of data, and
protocol `Hello` remains first. Non-priority data, EOF, and close frames are
round-robined across stream ids inside the collected burst while preserving each
stream's own ordering, so one busy stream cannot monopolize every encoded frame
in that burst. Remote output producers also yield after a bounded number of
data frames, giving sibling stream tasks a chance to enqueue before one hot
socket fills the shared writer queue. Each writer task reuses one burst frame
buffer and one encoded-byte buffer across bursts, so sustained traffic does not
allocate a fresh burst vector and encoded buffer for every flush. Agent transport
failure is sticky: once the underlying
SSH exec channel reports EOF or a frame write failure, current streams are reset
and later stream opens fail immediately instead of occupying bridge admission
slots until timeout. Active stream wrappers also observe carrier-level reset or
close signals and schedule repair of their owning lane immediately, so future
flows do not have to rediscover a known-dead exec transport. When the peer
advertises heartbeat support, the controller sends periodic zero-stream `Ping`
frames. `Pong` replies prove idle liveness, and any valid inbound agent frame
proves active peer liveness, so busy streams are not killed solely because a
heartbeat reply is queued behind useful traffic. If inbound peer activity stops,
the transport fails into the same reset and reconnect path as a hard SSH channel
failure. Each agent lane reconnects independently, so one dead exec channel does
not require replacing healthy lanes.
Remote TCP connect attempts are bounded below the controller stream-open timeout;
a slow or blackholed destination becomes a per-stream `Reset`, not a lane-wide
transport failure.
The remote agent reads TCP responses in protocol-payload-sized chunks, currently
256 KiB, so large responses do not pay unnecessary per-frame scheduling overhead.
Auto selection makes the framed agent path the preferred transport and keeps
`direct-tcpip` only as the compatibility fallback. Removing that fallback should
wait until live release evidence proves agent bootstrap across the supported
platforms and representative remote `sshd` configurations.

Current agent proof: `agent_runtime::tests::agent_opens_tcp_stream_and_relays_bytes`
starts the hidden `rustle agent` runtime over an in-memory duplex stream, opens a
real local TCP listener through an agent `OpenTcp` frame, relays request bytes,
observes EOF, and receives the response plus close frames.
`agent_runtime::tests::agent_opens_udp_stream_and_relays_datagram` proves the
same runtime can open a real UDP socket and relay a datagram response.
`agent_runtime::tests::agent_replies_to_heartbeat_ping` proves the remote agent
responds to protocol heartbeats without requiring any TCP or UDP stream.
`agent_client::tests::agent_client_round_trips_tcp_stream_through_runtime` proves
the local-side controller can negotiate hello, open a stream, relay data, and
consume EOF/close frames against that runtime. `scripts/smoke-agent-lab.sh`
proves the same framed TCP transport over a real SSH `exec` channel into a
local `sshd`. `scripts/smoke-agent-udp-lab.sh` proves multiple UDP datagrams can
move through one real SSH exec agent association.
`agent_transport::tests::transport_multiplexes_multiple_tcp_streams`
proves multiple framed streams can share one agent connection.
`agent_lane_index_spreads_many_flows_across_pool` proves stream hashing covers
all configured agent lanes instead of pinning every flow to one SSH exec channel.
`agent_transport::tests::stream_send_data_waits_for_window_credit` proves local
sends are gated by explicit credit, and
`agent_transport::tests::transport_flow_control_moves_large_responses_across_streams`
proves multiple streams can move responses larger than the initial window.
`agent_window::tests::credit_window_grows_after_sustained_full_window_consumption`,
`agent_transport::tests::stream_recv_grows_receive_window_after_sustained_consumption`,
and `agent_runtime::tests::runtime_receive_credit_grows_after_sustained_window_consumption`
prove the adaptive window growth logic is shared by the controller and remote
agent runtime.
`agent_transport::tests::transport_opens_udp_stream_and_relays_datagram` proves
the high-level transport API can run the UDP association through the real agent
runtime. `agent_transport::tests::transport_rejects_new_streams_after_agent_disconnect`
proves a dead agent channel fails future opens immediately.
`agent_transport::tests::active_stream_resets_and_later_opens_fail_after_agent_disconnect`
proves an already-open stream receives a reset when the agent dies and that the
transport remains sticky-failed for future opens.
`scripts/smoke-agent-bridge-lab.sh` proves the FlowManager bridge-lab can move
multiple synthetic TCP flows over the framed agent exec-lane pool.
`scripts/smoke-agent-reconnect-lab.sh` proves a shared agent bridge observes a
dead first agent, reconnects through the same compact UI path, and completes
subsequent synthetic flows. `scripts/smoke-agent-active-failure-lab.sh` proves
an agent that dies after accepting and receiving data on an active TCP stream
resets that flow, reconnects the exec transport, and completes later synthetic
flows; `verify-local` also runs the same failure with two exec lanes and reset
log matching disabled so the gate focuses on lane reconnect plus pool recovery
without racing post-completion log delivery.
`reconnecting_agent_quarantines_failed_lane_after_reconnect_failure` proves a
lane whose reconnect path fails is quarantined and the next matching flow uses a
healthy alternate lane without spending another open on the failed connector.
`agent_lane_selection_uses_least_loaded_healthy_lane_when_candidates_unhealthy`
proves selection can fail around two unhealthy hashed candidates and use the
least-loaded healthy lane elsewhere in the pool while scheduling repairs for the
bad candidates.
`reconnecting_agent_repairs_failed_alternate_lane_after_primary_reconnect_fails`
proves alternate fallback does not discard repairable failed capacity: if the
preferred lane cannot reconnect, Rustle can repair a failed alternate lane and
complete the same stream open attempt through it.
`reconnecting_agent_repairs_alternate_lane_that_fails_during_open` proves the
same policy also applies when an alternate lane dies during its own stream-open
attempt instead of being marked failed before selection.
`alternate_lane_selection_scans_by_load_without_snapshot_vector` proves fallback
alternate traversal preserves least-loaded lane ordering without allocating a
sorted lane snapshot.
`agent_bridge_repairs_lane_after_active_stream_transport_failure` proves an
already-open stream that observes carrier failure resets the active flow and
proactively starts lane repair for later flows.
`background_lane_repair_requests_are_coalesced` proves duplicate background
repair requests for the same lane collapse before they spawn redundant reconnect
work. `agent_initial_startup_keeps_successful_extra_lanes_after_extra_failure`
proves initial multi-lane startup keeps later successful lanes when one extra
lane fails during the startup batch.
`agent_initial_startup_retries_missing_extra_lanes_after_transient_failure`
proves a transient extra-lane failure is retried before accepting degraded
startup capacity.
`agent_bridge_repairs_missing_startup_lane_in_background` proves a missing
  desired startup lane remains a repairable slot and can be filled after the
  bridge is already running.
`background_repair_retries_missing_lane_after_quarantine` proves a background
repair task retries a missing desired lane after its bounded quarantine backoff
without waiting for a later user flow to select that lane.
The full TUN tunnel loop now defaults to the framed agent path for TCP flows,
DNS-over-TCP, and generic UDP datagrams. The hidden `--bridge-transport
direct-tcpip` and `--bridge-transport auto` switches remain for compatibility
comparison and diagnostics. The remaining work before treating direct-tcpip as
purely diagnostic is privileged live-TUN coverage and sustained load data across
TCP, DNS, and UDP.

## Flow Identity

Every intercepted TCP flow is identified by the 5-tuple:

```text
(src_ip, src_port, dst_ip, dst_port, protocol)
```

The destination IP and port are the remote endpoint requested by the local
application. Rustle must preserve them when opening a framed agent stream or an
explicit SSH `direct-tcpip` compatibility channel.

## Flow State Machine

```text
NewSyn
  -> TcpHandshaking
  -> TcpEstablished
  -> BridgeOpening
  -> Relaying
  -> HalfClosedLocal
  -> HalfClosedRemote
  -> Closed

Any non-terminal state may move to Reset on local TCP reset, data-plane stream
failure, timeout, or route/device shutdown.
```

## Hard Invariants

- One local TCP flow maps to at most one active data-plane stream.
- A flow must not open a data-plane stream until the local TCP handshake has
  been accepted by the userspace TCP engine.
- A flow must not acknowledge remote payload bytes to the local application
  until Rustle has accepted those bytes into bounded buffers.
- Backpressure must propagate in both directions.
- Local application bytes must not be drained from smoltcp while the per-flow
  bridge queue is full by item count or byte count; the TUN loop must keep
  serving other flows instead of awaiting one saturated data-plane sender.
- Data-plane stream creation is admission controlled. Rustle caps total active
  bridge tasks and separately caps flows in the `BridgeOpening` state so a SYN
  burst cannot spawn an unbounded number of tasks waiting on remote stream-open
  confirmations.
- Remote data-plane bytes that cannot immediately fit in the local smoltcp
  socket stay in a bounded per-flow backlog. Partial smoltcp writes must never
  drop the unsent suffix.
- The SSH control connection must never be captured by Rustle's own target
  routes. If a target CIDR captures the resolved IPv4 address of the SSH
  server, `tunnel` installs a temporary host route for that control connection
  before adding the TUN routes.
- SSH server identity must be explicit. Rustle verifies host keys against an
  OpenSSH known_hosts file by default, supports hashed host entries and revoked
  keys, supports `--accept-new-host-key` for OpenSSH-style trust-on-first-use
  recording of unknown hosts, and requires a deliberate
  `--insecure-accept-host-key` flag for lab-only bypasses. Accept-new mode
  appends only missing host entries; changed or revoked known keys remain hard
  failures.
- SSH control connection attempts are bounded by a connection timeout. A dead
  or unroutable SSH host must fail with an explicit SSH-connect diagnostic
  before target routes are installed.
- The userspace route table and OS route table must represent the same target
  CIDRs. Rustle validates route-table capacity before adding host OS routes.
- TUN and route-management preflight must run before SSH authentication. A
  missing local elevation requirement, Linux `/dev/net/tun`, Windows Wintun DLL,
  or route-management command must fail before Rustle opens the SSH control
  connection.
- DNS preflight must also run before SSH authentication when `--dns` is
  requested. Missing resolver-management tools such as `networksetup`,
  `resolvectl`, or `netsh` must fail locally before Rustle resolves or opens
  the SSH control connection.
- Every route added by Rustle must have a cleanup path on normal shutdown and
  interrupt shutdown.
- If `--dns` is enabled, every OS DNS setting changed by Rustle must have a
  cleanup path that runs before route teardown. The resolver target is a virtual
  IP inside the TUN subnet, not the local interface address itself, so DNS
  datagrams enter the TUN path.
- DNS query fan-out over SSH is bounded. New UDP/53 queries beyond the
  in-flight DNS cap receive a local DNS failure response instead of opening
  additional SSH channels.
- Generic UDP datagram fan-out over the agent is bounded. New non-DNS UDP
  datagrams that would exceed the active-association cap or per-association
  queue cap are dropped instead of allocating unbounded memory.
- Agent liveness is explicit. A live idle agent peer must answer negotiated
  zero-stream heartbeats, and a busy peer must keep producing valid inbound
  protocol frames. Missed peer activity closes the transport, resets current
  streams, and lets the reconnect manager replace the agent instead of letting
  future streams wait behind a wedged SSH exec channel.
- Agent startup and lane repair are transport-provider agnostic. The SSH
  connector currently starts initial and replacement lanes with the primary
  command or the effective uploaded helper command, but reconnect, lane fan-out,
  and flow placement code depend only on the connector contract. Agent transports
  retain their underlying provider through a small carrier guard, so SSH handles
  are lifetime details of the SSH connector rather than fields the flow engine
  understands. This preserves the option to add a non-SSH agent carrier without
  rewriting TUN, smoltcp, DNS, or flow-management logic.
- Background lane repair is autonomous but bounded. A repair task coalesces per
  lane, retries after the lane's quarantine backoff instead of waiting for a
  future user flow to select that lane, and stops after the configured repair
  retry budget if the connector keeps failing.
- Remote TCP connect latency is bounded inside the agent. A blackholed
  destination produces a per-flow reset before the controller stream-open
  timeout, preserving the distinction between an unreachable target and a broken
  SSH/agent lane.
- Agent flow placement is deterministic and bounded. TCP/UDP streams are hashed
  across the configured or auto-selected agent exec lanes, and each lane owns
  its own reconnect lock so reconnect storms do not serialize unrelated healthy
  lanes.
- Agent bootstrap is staged once for initial multi-lane startup. A missing
  remote `rustle agent` command does not cause one local-binary upload per lane;
  lanes coordinate cleanup through per-lane markers beside the staged helper.
  Additional explicit initial lanes open in bounded batches, and one failed
  extra lane must not prevent other successful extra lanes from entering the
  pool. Missing lanes get one bounded retry before Rustle accepts a degraded
  startup pool, and those missing desired slots remain repairable in the
  background. For hidden auto-lane mode, only the primary lane is required before
  the tunnel can start; remaining recommended lanes use the same background
  repair path as missing startup lanes.
  Uploaded helpers are staged in private Rustle-owned temporary directories
  before execution. POSIX remotes create the directory with `mktemp -d` under
  `umask 077` and `chmod 700`; Windows remotes create a GUID-suffixed
  `rustle-agent-*` directory under the remote temp path. The last-lane cleanup
  and verification-failure cleanup remove the helper, refs directory, and empty
  Rustle-owned parent directory. Uploaded helpers are hashed before execution:
  POSIX remotes use
  `sha256sum`, `shasum -a 256`, or `openssl dgst -sha256 -r`; Windows remotes
  use PowerShell `Get-FileHash`. Verification failure triggers best-effort
  removal of the staged helper, refs directory, and Rustle-owned parent
  directory instead of executing unverified bytes.
  POSIX remotes use a shell upload/execution wrapper, while Windows remotes use
  PowerShell for platform probing, binary upload, execution, and cleanup.
  `uploaded_helper_command_keeps_staged_binary_until_last_lane_exits_for_each_kind`
  executes the generated wrapper twice against fake helpers and proves the staged
  helper stays present until the last lane exits, then removes both the helper
  and refs.
  `uploaded_agent_cleanup_removes_unverified_posix_staging_tree` executes the
  verification-failure cleanup command against a fake unverified helper with a
  non-empty refs directory and proves the private staging tree is removed.
  Reconnects may still re-upload if the staged temporary helper has already
  been cleaned up.
- Every flow owns bounded memory. Buffer sizes are explicit, fixed, and
  released when the flow reaches a terminal state.
- The smoltcp packet adapter uses a bounded reusable packet buffer pool instead
  of allocating a fresh packet vector for each RX/TX event. The pool reserves a
  TX buffer so a full RX queue cannot prevent smoltcp from emitting required
  response packets.
- The tunnel loop drains smoltcp TX packets into a caller-owned scratch vector,
  so frequent TUN reads, bridge events, and timer polls do not allocate a
  fresh `Vec<PacketBuf>` on every poll. Draining the scratch vector drops packet
  handles promptly and returns their `BytesMut` storage to the packet pool.
- Flow admission and local-byte drain also use caller-owned scratch vectors for
  ready `FlowId` and active `FlowKey` enumeration. `FlowManager` can count
  `SshOpening` flows directly, so the bridge loop does not allocate snapshots or
  flow lists on every admission/drain tick.
- Remote-to-local backlog flushing, stale-flow expiry, and closed-flow pruning
  also enumerate into caller-owned scratch vectors. The central loop therefore
  avoids per-tick `Vec` allocation for normal backlog, expiry, and cleanup scans
  while retaining bounded backlog memory.
- Bridge event handling writes closed-flow results into caller-owned scratch
  storage, so common remote-data events can push bytes through the backlog flush
  path without allocating a fresh closed-flow vector.
- Generic UDP requests and responses keep datagram payloads as `Bytes` after the
  one unavoidable copy out of the reusable TUN read buffer. Admission moves the
  parsed request payload directly into the per-association agent queue, and the
  association reader moves `frame.payload` directly into the response event
  queue instead of copying either direction into a temporary `Vec<u8>`.
  `udp_association_idle_timeout_emits_close_for_accounting` proves idle
  associations emit the close event used to remove association state and release
  the active UDP association budget.
- DNS response events also carry remote resolver payloads as `Bytes`. Agent UDP
  DNS moves the agent `frame.payload` directly, and DNS-over-TCP paths slice the
  accumulated length-prefixed frame without copying the extracted response into
  a temporary vector.
- Flow admission is bounded. `FlowManager` owns the maximum active-flow count,
  opening timeout, idle timeout, creation time, last activity time, and byte
  counters for every TCP flow. New SYNs beyond the active-flow cap are ignored
  without allocating a socket, and stale handshakes or idle relays are reset
  from the central loop.
- TCP MSS is derived from the smoltcp interface MTU. Rustle sets a conservative
  TUN MTU so smoltcp advertises a correspondingly conservative local MSS during
  the intercepted TCP handshake. The packet-level unit test
  `flow_manager_advertises_mtu_derived_mss_in_syn_ack` verifies the emitted
  SYN/ACK MSS option, and
  `flow_manager_emits_remote_payload_packets_within_mtu` verifies large
  remote-to-local payloads are segmented into packets no larger than the
  configured MTU.
- Remote EOF closes the local smoltcp socket gracefully. SSH bridge failure
  aborts the local socket. Terminal flows are pruned after smoltcp no longer
  has an open socket for them.
- Packet parsing failures are per-packet failures, not process failures, unless
  they indicate device corruption or an invariant violation.
- Runtime telemetry must be cheap and always available. The tunnel loop emits
  periodic and final `stats:` lines for active flows, SSH channels, TUN
  packet/byte totals, TCP byte direction, DNS admission/results, UDP
  admission/results/active associations, SSH open
  latency, SSH admission deferrals, bridge backpressure, stale-flow cleanup,
  stale bridge events, bridge send failures, agent reconnects, agent lane
  desired/availability/missing/quarantine/repair/load state, and backlog overflow
  counters.
  These counters are evidence for backpressure and bounded-memory behavior
  during field tests.

## Phase Gates

### Phase 1: SSH Backbone

Proof: authenticate with `russh`, open one `direct-tcpip` channel, send raw
bytes, and receive the remote TCP response.

### Phase 2: TUN Capture

Proof: create a TUN device, add explicit routes, observe raw IPv4 packets
generated by local traffic, and remove the routes on shutdown.

### Phase 3: Userspace TCP

Proof: dynamically accept a routed TCP SYN in userspace, complete the local
handshake, and expose a byte stream for that flow.

Current automated proof:

- `tcp_core::tests::smoltcp_anyip_accepts_tcp_for_routed_arbitrary_destination`
  builds a rootless IP-medium `smoltcp` loopback interface that owns only
  `10.255.255.1/24`.
- The test adds a `172.16.0.0/16` route whose gateway is `10.255.255.1` and
  enables AnyIP.
- A client socket connects to `172.16.0.9:443`.
- A server socket listens specifically on `172.16.0.9:443`.
- `smoltcp` completes the TCP handshake and moves bytes in both directions.

That proves the core transparent-IP premise. The remaining Phase 3 work is the
runtime lifecycle: expose the accepted stream to the SSH bridge.

Current runtime progress:

- `FlowManager` owns a `smoltcp::Interface`, `SocketSet`, bounded flow sockets,
  and an IP-medium packet queue device.
- `FlowManager::ingest_packet` parses the first opening SYN, allocates exactly
  one socket for that flow key, listens on the original destination IP/port,
  feeds the packet into `smoltcp`, and returns outbound packets.
- `tcp_core::tests::flow_manager_allocates_socket_from_syn_and_moves_stream_bytes`
  pumps packets between a synthetic client stack and the manager. The manager
  dynamically completes the handshake, receives application bytes, sends
  response bytes, and preserves the original 5-tuple.
- `tun-capture` now feeds real TUN IPv4 packets into `FlowManager` and writes
  emitted packets back to the TUN interface.

### Phase 4: End-to-End TCP Pivot

Proof: map each established userspace TCP flow to one SSH `direct-tcpip`
channel, relay bytes in both directions, and preserve backpressure and cleanup.

Current runtime progress:

- `flow_bridge` creates one bounded async bridge task per flow.
- The bridge task opens `russh` `direct-tcpip` to the original destination
  IP/port and sends bridge events back to the central loop.
- Bridge local queues are bounded by item count and total queued bytes. Queue
  byte accounting is released when the bridge task consumes or drops a queued
  chunk.
- The tunnel loop limits active SSH bridge tasks and in-progress channel opens.
  Flows above those limits remain in the local TCP engine and are retried by the
  central loop, which applies normal TCP backpressure instead of allocating more
  bridge tasks.
- `run_tunnel_loop` keeps `FlowManager` single-threaded. TUN packets, SSH bridge
  events, and periodic polls all pass through that loop.
- Local stream bytes are drained from `FlowManager` into the bridge task.
- Remote SSH bytes are fed back into `FlowManager`, packetized by `smoltcp`, and
  written to the TUN device.
- The runtime loop periodically asks `FlowManager` to expire stale flows, then
  removes matching SSH bridge tasks and remote backlog state.
- UDP/53 packets bypass `FlowManager`. The tunnel loop parses the raw IPv4/UDP
  packet and sends the DNS payload through the active DNS transport. Agent mode
  uses UDP for IPv4 DNS remotes via `OpenUdp`; direct-tcpip compatibility and
  hostname DNS remotes translate the datagram to DNS-over-TCP and read a
  length-prefixed response. In all cases Rustle writes a synthesized UDP response
  packet to the TUN device. Remote DNS failures are translated into local
  SERVFAIL responses when the original DNS payload is parseable enough to
  preserve the question.
- Non-DNS IPv4/UDP packets bypass `FlowManager` when agent transport is active.
  The loop admits each tuple into a bounded UDP association table, reuses one
  agent UDP stream for multiple datagrams on the same tuple, writes response
  datagrams as synthesized reverse UDP packets to the TUN device, and closes
  idle associations through the same close-event path that frees the association
  table entry and active-association budget. The direct-tcpip fallback path logs
  and drops generic UDP without admitting association state because standard SSH
  direct forwarding is TCP only.
- `--dns` configures the host resolver to use the virtual DNS IP on Linux and
  Windows. On macOS, `networksetup` creates service-scoped resolvers that do not
  reliably route virtual TUN DNS addresses through utun, so Rustle configures
  the system resolver to `127.0.0.1` and runs a bounded local UDP/53 proxy that
  forwards through the same SSH DNS transport. The platform layer owns setup and
  restore commands: macOS uses `networksetup`, Linux uses `resolvectl`, and
  Windows uses `netsh`. A VPN or managed profile can still keep macOS' global
  resolver pointed elsewhere; the DNS takeover smoke checks the global
  `scutil --dns` section separately from scoped service resolvers and fails with
  that resolver state when the OS does not actually use Rustle for default DNS.
- `flow_bridge::tests::fake_bridge_round_trips_flow_manager_stream_bytes` proves
  the bridge architecture without root or a real SSH server.
- `bridge-lab` proves the same FlowManager plus real `russh` direct-tcpip bridge
  without root by using synthetic smoltcp clients instead of a TUN device. Its
  lab-only `--connections` option drives multiple local flows through one SSH
  control connection, which exercises SSH channel multiplexing and central-loop
  routing without changing the compact production CLI.
- SSH connection setup verifies host keys through known_hosts by default. The
  verifier covers plain entries, non-default port entries, hashed hostnames,
  wildcard/negated patterns, revoked-key rejection, and accept-new host-key
  onboarding that records unknown hosts without accepting changed keys.
- Remote agent startup command handling keeps unsafe and safe forms distinct.
  Hidden lab `--agent-command` remains a raw SSH exec command for complex
  harnesses, while hidden `--agent-path` quotes one literal executable path and
  appends the fixed `agent` argument.

## Design Preference

Prefer libraries for hard protocol machinery when they satisfy the invariants.
For the TCP engine, Rustle uses `smoltcp` with AnyIP-style acceptance and
dynamic listening sockets. If future runtime integration shows that this cannot
preserve the flow identity and backpressure invariants under real TUN traffic,
replace that layer rather than weakening the model.

## Release Gates

Before a release build is considered shippable:

- Native CI must pass on Linux x64, Linux arm64, macOS x64, macOS arm64,
  Windows x64, and Windows arm64: format, tests, Clippy, and build.
- A macOS TUN smoke must prove route add/delete cleanup.
- A rootless SSH bridge smoke must prove `russh` direct-tcpip, known_hosts, and
  FlowManager integration. `scripts/smoke-bridge-lab.sh` is the repeatable
  proof and runs in Unix CI when `sshd` is available.
- Rootless agent smokes must prove real SSH exec agent TCP, UDP, and FlowManager
  bridge behavior without TUN privileges. `scripts/smoke-agent-lab.sh`,
  `scripts/smoke-agent-udp-lab.sh`, and `scripts/smoke-agent-bridge-lab.sh` run
  in Unix CI when `sshd` is available.
- A rootless DNS latency gate must pass through
  `scripts/bench-agent-dns-lab.sh` with `RUSTLE_BENCH_AGENT_DNS_MAX_P50_US`,
  proving DNS queries over the primary framed agent transport and optional QUIC
  data planes have bounded `p50_us` latency before any privileged resolver
  takeover evidence is counted.
- A privileged TUN DNS smoke must prove UDP/53 interception through the virtual
  DNS IP. `scripts/smoke-tun-dns.sh` runs on Linux CI when `/dev/net/tun` is
  available and remains the local privileged proof for macOS and Linux.
- The privileged TUN DNS smoke must pass for both direct/auto transport and
  `RUSTLE_SMOKE_BRIDGE_TRANSPORT=agent`, proving DNS interception through the
  framed agent path as well as compatibility mode.
- The same TUN DNS smoke must also pass with `RUSTLE_SMOKE_CONFIGURE_DNS=1` on
  at least one macOS or Linux host before DNS takeover is treated as release
  evidence; that mode snapshots resolver settings, verifies the virtual
  resolver is active while Rustle runs, resolves through the system resolver
  instead of only a direct UDP probe, and requires exact resolver restoration
  after shutdown. The resolver probe uses a normal delegated-looking name by
  default so platforms that short-circuit special-use TLDs still exercise the
  configured DNS server path. On macOS this also proves the loopback DNS proxy
  used for service-scoped system resolver traffic.
- A native elevated Windows TUN smoke must prove Wintun discovery, TUN creation,
  route add/delete, packet capture, and route-table restoration.
  `scripts/smoke-windows-tun.ps1` is the Windows operator proof, the release
  workflow runs it against the packaged embedded-Wintun binary before upload,
  and `scripts/verify-windows-tun-smoke.py` statically guards those required smoke
  assertions on every local verifier run.
- A live remote TCP tunnel smoke must prove real routed traffic through a remote
  `sshd`. `scripts/smoke-live-tunnel.sh` is the env-driven proof for a real
  lab target.
- The Linux network-namespace TCP smoke must pass for both `direct-tcpip` and
  `RUSTLE_NETNS_BRIDGE_TRANSPORT=agent`, proving full TUN TCP routing without an
  external lab.
- The Linux network-namespace UDP smoke must pass for agent transport, proving
  generic UDP routing through host route injection, TUN, the framed agent
  `OpenUdp` association path, a remote UDP socket, synthesized return packet
  delivery, final UDP stats, cleanup to zero active UDP associations after the
  idle timeout, and route cleanup.
- No smoke may leave routes, Rustle processes, or DNS settings behind.
