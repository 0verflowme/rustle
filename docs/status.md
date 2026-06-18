# Rustle Status

Rustle is still pre-release. The default SSH-agent data path is the v1 product
path and is no longer just a lab prototype, but the repository should not be
called production-ready until the release-candidate gates pass on real macOS,
Linux, and Windows hosts.

## Current Maturity

| Path | Status | Notes |
| --- | --- | --- |
| `agent` | v1 product path | Default for `rustle -r host CIDR...`. Supports TCP, DNS, generic IPv4 UDP, reconnect, sidecar upload, and full-tunnel split routes. |
| `quic-native` | v2 opt-in | SSH bootstraps/authenticates the helper, then TCP/UDP/DNS use native QUIC streams. Functional and faster in the latest 100 MiB Contabo fixture, but not default-ready. |
| `quic-agent` | experiment | Carries the existing framed agent protocol over QUIC. Useful for carrier/bootstrap proof, not the final speed target. |
| `auto-quic` | hidden experiment | Probes native QUIC and falls back to agent. Functional, but observed startup decision latency is too high for default use. |
| `direct-tcpip` | lab/fallback | Useful for compatibility comparisons. It is not the product architecture because generic UDP is TCP-only SSH-incompatible. |

## What Works Now

- Compact sshuttle-style commands:

  ```sh
  sudo rustle -r contabo 10.0.0.0/8
  sudo rustle -r contabo 0.0.0.0/0
  ```

- SSH config aliases, key auth, password auth, and explicit host-key policies.
- TUN route setup and cleanup on supported platforms.
- TCP over the default agent path.
- DNS interception through `--dns`.
- Generic IPv4 UDP over the agent path.
- Remote helper sidecar upload with local/remote SHA-256 verification.
- Release-mode local verifier, rootless stress, reconnect, DNS, UDP, and
  bridge benchmarks.
- Live Contabo checks for agent TCP, full tunnel, agent UDP, native-QUIC UDP,
  and agent-vs-QUIC throughput.

## Current Blockers

1. Remote uploaded-helper cleanup is not strict enough. A live Contabo run left
   stale `/tmp/rustle-agent.*` directories with helper binaries and empty
   `.refs` directories. This is operational cleanup debt, not a plaintext or
   unauthenticated-channel issue.
2. Live bulk throughput still shows supervisor event-queue pressure. The latest
   100 MiB Contabo fixture was about `10.6 MiB/s` on `agent` and `14.6 MiB/s`
   on `quic-native`; QUIC is faster, but not yet the "superfast" target.
3. `auto-quic` startup selection is too slow for default use. The path works,
   but the latest decision trace reported about `10 s`.
4. DNS takeover must pass platform release-candidate leak and restoration
   checks in the actual target environment.
5. Windows needs native elevated TUN proof with packaged Wintun artifacts before
   the release can be called field-ready.

## Next Work

1. Make remote helper cleanup deterministic and add live remote cleanup evidence.
2. Reduce supervisor event-queue pressure in the bulk data path.
3. Tighten `auto-quic` probe accounting and fallback latency.
4. Re-run the release-candidate matrix with DNS takeover, live TCP, live UDP,
   fixture benchmarks, and sshuttle comparison enabled.
5. Promote `quic-native` only after it consistently beats `agent` on live
   latency and throughput gates.

## Product Rule

Default mode must stay boring:

```text
TUN -> packet engine -> SSH-authenticated agent helper -> remote sockets
```

QUIC should stay opt-in until it is both faster and operationally safer than the
default agent path on real networks. A temporary prototype break is acceptable
inside hidden transports; it is not acceptable for the daily command contract.
