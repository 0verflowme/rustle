# Rustle

Rustle is a pre-release, cross-platform SSH tunneling tool written in Rust. It
routes selected IPv4 traffic through a local TUN interface, handles TCP, DNS,
and UDP in user space, and carries traffic to the remote side through an
authenticated Rustle helper.

The v1 product path is the default SSH-agent data plane:

```sh
sudo rustle -r user@host 10.0.0.0/8
sudo rustle -r user@host 0.0.0.0/0
```

Rustle is designed to replace sshuttle for daily IPv4 use first, then expose an
optional QUIC data plane for higher-throughput workloads once the QUIC gates are
consistently better than the SSH-agent path on live targets.

## Features

- Cross-platform TUN-based capture for macOS, Linux, and Windows.
- Compact sshuttle-style CLI.
- IPv4 TCP tunneling through the default framed SSH-agent transport.
- Full-tunnel split-route support for `0.0.0.0/0`.
- DNS interception with `--dns`.
- Generic IPv4 UDP forwarding through the agent transport.
- Automatic remote helper startup with sidecar upload when the remote binary is
  not installed.
- Bounded queues, explicit credit, reconnect, and cleanup-oriented telemetry.
- Opt-in QUIC data planes for performance experiments.
- `direct-tcpip` compatibility mode for labs and comparisons.

## Status

Short answer: Rustle is still pre-release, but not all paths are equally
experimental.

| Area | Current posture |
| --- | --- |
| Default `agent` transport | Product path for v1. Local verifier, stress, live TCP, live UDP, and full-tunnel Contabo checks pass. |
| Remote helper upload | Functional and SHA-256 verified, but remote temp cleanup must be hardened before release. |
| DNS takeover | Implemented, but must pass the release-candidate resolver leak/restore gates on the target platform. |
| `quic-native` | Opt-in v2 path. It works and was faster than `agent` in the latest Contabo 100 MiB fixture, but is not default-ready. |
| `auto-quic` | Hidden experiment. It can select QUIC or fall back, but startup decision latency still needs work. |
| `direct-tcpip` | Lab and fallback comparison path only. |

Latest live evidence from a macOS client to the `contabo` SSH alias:

- 1 KiB fixture: `rustle-agent` p50 `163.50 ms`, sshuttle p50 `177.73 ms`.
- 100 MiB fixture: `rustle-agent` about `10.6 MiB/s`, `quic-native` about
  `14.6 MiB/s`.
- Agent and native-QUIC live UDP smokes passed.
- Full tunnel `0.0.0.0/0` over agent passed against the controlled fixture.

Remaining release blockers are tracked in [`docs/status.md`](docs/status.md)
and the hard release gates in [`docs/release.md`](docs/release.md).

IPv6 is not part of the current MVP.

## Install

Download the archive matching your platform from a Rustle release, extract it,
and put the binary on your `PATH`.

Unix and macOS:

```sh
tar -xzf rustle-<target>.tar.gz
sudo install -m 0755 rustle-<target>/rustle /usr/local/bin/rustle
rustle --help
```

Windows PowerShell:

```powershell
Expand-Archive .\rustle-<target>.zip
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\bin"
Copy-Item .\rustle-<target>\rustle.exe $env:USERPROFILE\bin\rustle.exe
rustle.exe --help
```

Windows requires an architecture-matching Wintun driver. Release Windows
binaries are intended to embed Wintun; development builds can also load it from
`RUSTLE_WINTUN_DLL`, the binary directory, or the current directory.

The remote host must accept SSH and either have `rustle` available on `PATH` or
be compatible with Rustle's automatic sidecar upload. See
[`docs/release.md`](docs/release.md) for sidecar preparation.

## Build From Source

```sh
cargo build --release
```

The resulting binary is at:

```sh
target/release/rustle
```

On Windows, Rustle needs an architecture-matching Wintun driver. See
[`docs/release.md`](docs/release.md) for packaging and driver details.

## Usage

Route one subnet through a remote SSH server:

```sh
sudo rustle -r alice@example.com 10.0.0.0/8
```

Route multiple subnets:

```sh
sudo rustle -r alice@example.com 10.0.0.0/8 172.16.0.0/12
```

Enable DNS interception:

```sh
sudo rustle --dns -r alice@example.com 10.0.0.0/8
```

Use a specific SSH identity:

```sh
sudo rustle -r alice@example.com -i ~/.ssh/id_ed25519 10.0.0.0/8
```

Full-tunnel shorthand is accepted:

```sh
sudo rustle -r alice@example.com 0/0
```

Use an OpenSSH config alias:

```sshconfig
Host contabo
  HostName 203.0.113.10
  User alice
  IdentityFile ~/.ssh/id_ed25519
```

```sh
sudo rustle -r contabo 10.0.0.0/8
```

Rustle verifies SSH host keys by default through OpenSSH `known_hosts`. To
record a new trusted host on first connection while still rejecting later key
changes, use `--accept-new-host-key`. For temporary development labs only, use
`--insecure-accept-host-key`.

For password authentication, prefer `--password` with no value for an
interactive prompt, or `--password-file /path/to/private-file` for automation.
Avoid inline `--password=...` values because local process listings and shell
history can expose them.

For operational diagnosis, see
[`docs/troubleshooting.md`](docs/troubleshooting.md).

## Development

Run the main checks:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
python3 scripts/verify-release-matrix.py
```

Run the local smoke suite:

```sh
scripts/verify-local.sh
```

Run the full macOS/Linux release-candidate verifier on a privileged host with a
real SSH target and `sshuttle` installed:

```sh
RUSTLE_LIVE_REMOTE=alice@ssh.example.com \
RUSTLE_LIVE_TARGET_CIDR=0.0.0.0/0 \
RUSTLE_LIVE_URL=https://192.168.190.45/ \
RUSTLE_FIXTURE_HOST=192.168.190.45 \
RUSTLE_LIVE_UDP_HOST=192.168.190.45 \
scripts/verify-release-candidate.sh
```

This fails on privileged/live skips, includes DNS takeover and live UDP, runs
the controlled 1 MiB / 10 MiB / 100 MiB fixture benchmarks, and compares `rustle-agent` p50 latency against sshuttle.
The same gate is available in GitHub Actions through
`.github/workflows/release-candidate.yml`; run it only on a privileged
self-hosted runner that already has SSH access and passwordless sudo.
Live UDP uses the default SSH-agent path; set
`RUSTLE_LIVE_UDP_BRIDGE_TRANSPORT=quic-native` for a separate opt-in proof that
the target allows Rustle's SSH-bootstrapped UDP/QUIC helper data plane. When
`RUSTLE_LIVE_REMOTE` is an OpenSSH `Host` alias, set
`RUSTLE_LIVE_SSH_CONFIG=$HOME/.ssh/config` so the privileged Rustle process can
resolve the same alias. For labs with a preinstalled remote Rustle binary, set
`RUSTLE_LIVE_AGENT_PATH=/opt/rustle/rustle`; live UDP can override that with
`RUSTLE_LIVE_UDP_AGENT_PATH`.

Run the rootless DNS latency benchmark:

```sh
scripts/bench-agent-dns-lab.sh
```

Run the rootless agent reconnect benchmark:

```sh
scripts/bench-agent-reconnect-lab.sh
```

Run the rootless SSH config alias smoke, which proves a `Host contabo`-style
alias can supply the SSH host, port, user, identity, and known-hosts file:

```sh
scripts/smoke-ssh-config-alias-lab.sh
```

Run the high-fanout bridge stress gate. By default this exercises 256
concurrent 1 MiB responses over the primary agent transport and the
`direct-tcpip` compatibility path:

```sh
scripts/stress-bridge-lab.sh
```

Run the experimental QUIC data-plane smoke, which authenticates through SSH and
then carries the Rustle agent protocol over UDP/QUIC:

```sh
scripts/smoke-quic-agent-lab.sh
```

Run live tunnel benchmarks, including optional sshuttle comparison:

```sh
RUSTLE_BENCH_REMOTE=alice@ssh.example.com \
RUSTLE_BENCH_TARGET_CIDR=192.168.0.0/16 \
RUSTLE_BENCH_URL=https://192.168.190.45/ \
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
scripts/bench-live-compare.sh
```

Add native-QUIC rows and make them a hard same-target comparison against the
primary agent path when the remote UDP path is reachable:

```sh
RUSTLE_BENCH_REMOTE=alice@ssh.example.com \
RUSTLE_BENCH_TARGET_CIDR=192.168.0.0/16 \
RUSTLE_BENCH_URL=https://192.168.190.45/ \
RUSTLE_BENCH_RUSTLE_TRANSPORTS="agent quic-native" \
RUSTLE_BENCH_MIN_QUIC_NATIVE_AGENT_RATIO=1.00 \
RUSTLE_BENCH_MAX_QUIC_NATIVE_AGENT_P50_RATIO=1.00 \
scripts/bench-live-compare.sh
```

Run controlled live large-response benchmarks by starting a temporary HTTP
fixture on the SSH server:

```sh
RUSTLE_FIXTURE_REMOTE=alice@ssh.example.com \
RUSTLE_FIXTURE_HOST=192.168.190.45 \
scripts/bench-live-fixture.sh
```

## Documentation

- [`docs/status.md`](docs/status.md): current maturity, blockers, and next work
- [`docs/architecture.md`](docs/architecture.md): architecture and protocol notes
- [`docs/performance.md`](docs/performance.md): benchmarking methodology
- [`docs/release.md`](docs/release.md): release and platform packaging
- [`docs/troubleshooting.md`](docs/troubleshooting.md): install, runtime, DNS,
  and performance troubleshooting

## License

MIT. See [`LICENSE`](LICENSE).
