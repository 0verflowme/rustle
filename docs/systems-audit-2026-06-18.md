# Rustle Systems Audit - 2026-06-18

This audit used dependency pruning, module boundary inspection, Dylint, mutation
testing, and Kani. It is a production-readiness audit, not a claim that QUIC is
ready to be the default transport.

## Executive Status

- Default v1 path remains SSH-agent.
- QUIC-native is still experimental. Local lab speed is promising, but live
  auth/handshake, stream lifecycle, QUIC wire framing, reconnect, and UDP proof
  are not complete enough for default promotion.
- Current hardening tranche added deterministic tests around packet parsing,
  TCP flow state, agent framing/window behavior, data-plane stream contracts,
  sidecar/control-plane helpers, platform parsing, known-hosts, and route
  command construction.
- One real bug was fixed: `tun_ipv4_packet` no longer indexes past a Linux PI
  IPv4 header with no following packet byte.

## Tool Evidence

| Area | Evidence |
| --- | --- |
| Dependency bloat | `cargo machete` passed; `cargo +nightly udeps` passed. |
| Feature bloat | Tokio no longer uses `full`; explicit feature set is in `Cargo.toml`. |
| Architecture | `cargo modules structure --bin rustle --no-fns --no-types --no-traits` captured in `target/audit/cargo-modules-structure-current.txt`. |
| Dylint | `cargo dylint --path rustle_lints --workspace` passed with five intended architecture warnings. |
| Mutation broad scan | `2679 mutants tested in 75m: 812 missed, 1415 caught, 335 unviable, 117 timeouts`. |
| Mutation post-hardening diff scan | `18 mutants tested in 2m: 16 caught, 2 unviable`. |
| Kani | `cargo kani` verified 4 harnesses, 0 failures. |
| Tests | `cargo test` passed with 480 tests after hardening. |
| Lints | `cargo clippy --all-targets -- -D warnings` passed. |
| Release metadata | `python3 scripts/verify-release-matrix.py` passed. |
| Code health | `python3 scripts/code-health.py --top 25` passed; max review score `53`. |

## Technical Debt Removed

- Removed redundant Tokio `full` feature usage in favor of explicit features.
- Fixed shared `agent-bootstrap` module drift so bootstrap compiles against the
  same agent I/O/window modules as the main binary.
- Added `cfg(kani)` lint configuration to avoid accidental proof-only cfg drift.
- Added `rustle_lints`, including `OVERSIZED_ASYNC_STATE_MACHINE`, to flag large
  async functions that hide protocol state machines.
- Added Kani harnesses for:
  - agent frame-kind wire decoding,
  - agent credit-window bounds and zero-consumption behavior,
  - IPv4 route mask contiguity.
- Replaced broad end-to-end assumptions with direct deterministic tests in:
  - `dns`,
  - `tcp_core`,
  - `packet_engine`,
  - `agent_proto`,
  - `agent_io`,
  - `agent_window`,
  - `agent_transport`,
  - `agent_bridge`,
  - `data_plane`,
  - `known_hosts`,
  - `remote_platform`,
  - `sidecar_store`,
  - `routing`,
  - `platform`,
  - `control_plane`.

## Weak Tests Exposed

Broad mutation testing found a high unresolved rate before targeted hardening:
`929 / 2679` mutants were unresolved (`812` missed, `117` timeouts).

Highest-risk production areas from the broad scan:

| Rank | Area | Finding |
| ---: | --- | --- |
| 1 | `platform.rs` | TUN/DNS preflight, Wintun/elevation, command handling under-tested. |
| 2 | `agent_runtime.rs` | Large frame handler and TCP stream loops produce many missed/timeouts. |
| 3 | `routing.rs` | Route command construction/execution needed fake-executor tests. |
| 4 | `agent_proto.rs` | Frame encode/decode mutants survived or timed out. |
| 5 | `data_plane/tcp.rs` | TCP bridge EOF/Close/Reset, counters, coalescing, and backpressure needed direct tests. |
| 6 | `hotpath_trace.rs` | Trace fields and enablement are weak despite being needed for performance diagnosis. |
| 7 | `agent_window.rs` | Credit-window threshold/progress behavior needed small invariant tests. |
| 8 | `agent_bridge/affinity.rs` | Lane hashing, candidate selection, and backoff were weak. |
| 9 | `agent_io.rs` | Frame reader/writer and burst fairness had timeout-heavy failures. |
| 10 | `agent_transport/stream.rs` | Stream side effects and credit grants needed direct tests. |

The new diff-scoped mutation scan shows the changed production code is now much
better covered: all 18 generated mutants were either caught or unviable.

## Architecture Findings

The module tree is meaningfully cleaner than the original monolithic layout:
`supervisor`, `packet_engine`, `data_plane`, `control_plane`, `remote_helper`,
`ssh_control`, and `quic_agent` are now distinct modules.

Remaining architecture hotspots:

- `agent_runtime::handle_agent_frame`: 235 code lines.
- `agent_runtime::run_tcp_connected_stream`: 135 code lines.
- `bridge_lab::run_bridge_lab`: 311 code lines.
- `control_plane::runtime::connect_tunnel_runtime`: 148 code lines.
- `TunnelSupervisor::run`: 143 code lines.

These are not just style issues. Mutation testing confirms that large async
state machines hide untested branches and convert protocol bugs into test
timeouts instead of crisp failures.

## Production Readiness Assessment

SSH-agent v1 is the correct default path. It has the most proof, but still needs
live latency/throughput work before "performance killer" can be claimed.

QUIC-native is not production-ready as default:

- broad mutation scan found weak QUIC auth/bootstrap/wire/lifecycle tests,
- live Contabo QUIC auth/handshake previously failed after bootstrap,
- forced `--bridge-transport quic-native` must keep failing clearly until live
  bootstrap, stream lifecycle, UDP, reconnect, and throughput gates pass.

## Next Work

1. Extract deterministic reducers from `data_plane/tcp.rs` and
   `agent_runtime.rs`; keep spawned task I/O thin.
2. Add golden tests for `hotpath_trace` and agent startup trace fields because
   those traces drive performance diagnosis.
3. Build fake-executor supervisor lifecycle tests for route/DNS/TUN cleanup.
4. Add focused mutation gates per subsystem instead of full-tree mutation on
   every run:
   - packet/core: `dns`, `tcp_core`, `packet_engine`,
   - agent transport: `agent_proto`, `agent_io`, `agent_window`,
     `agent_transport`, `data_plane`,
   - control-plane: `known_hosts`, `sidecar_store`, `routing`, `platform`,
     `control_plane`.
5. Keep QUIC behind explicit flags until live QUIC-native auth, TCP, DNS, UDP,
   reconnect, and 10 MiB/100 MiB repeated throughput gates are stable.
