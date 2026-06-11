# Rustle

Rustle is an experimental, cross-platform SSH network pivoting tool written in
Rust. It routes selected IPv4 traffic through a local TUN interface and carries
the traffic over SSH to a remote host.

Rustle is designed as a next-generation alternative to sshuttle, with a
user-space networking core and a framed Rustle agent protocol as the primary
transport.

## Features

- Cross-platform TUN-based capture for macOS, Linux, and Windows.
- Compact sshuttle-style CLI.
- IPv4 TCP tunneling over SSH.
- DNS interception with `--dns`.
- Generic IPv4 UDP forwarding through the Rustle agent transport.
- Bounded queues and explicit flow-control paths for load-bearing behavior.
- `direct-tcpip` compatibility mode for labs and comparisons.

## Status

Rustle is still under active development. The agent transport is the preferred
architecture, and the high-fanout TCP lifecycle path is covered by a rootless
256-flow stress gate. Live remote, DNS takeover, and cross-platform TUN proof
are still required before treating Rustle as production-ready pivoting software.

IPv6 is not part of the current MVP.

## Build

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

Rustle verifies SSH host keys by default through OpenSSH `known_hosts`. To
record a new trusted host on first connection while still rejecting later key
changes, use `--accept-new-host-key`. For temporary development labs only, use
`--insecure-accept-host-key`.

For password authentication, prefer `--password` with no value for an
interactive prompt, or `--password-file /path/to/private-file` for automation.
Avoid inline `--password=...` values because local process listings and shell
history can expose them.

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

Run the high-fanout bridge stress gate. By default this exercises 256
concurrent 1 MiB responses over the primary agent transport and the
`direct-tcpip` compatibility path:

```sh
scripts/stress-bridge-lab.sh
```

Run live tunnel benchmarks, including optional sshuttle comparison:

```sh
RUSTLE_BENCH_REMOTE=alice@ssh.example.com \
RUSTLE_BENCH_TARGET_CIDR=192.168.0.0/16 \
RUSTLE_BENCH_URL=https://192.168.190.45/ \
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
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

- [`docs/architecture.md`](docs/architecture.md): architecture and protocol notes
- [`docs/performance.md`](docs/performance.md): benchmarking methodology
- [`docs/release.md`](docs/release.md): release and platform packaging

## License

MIT. See [`LICENSE`](LICENSE).
