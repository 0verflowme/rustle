# Rustle Troubleshooting

This guide is for operators running Rustle from a release archive or from a
local build. Prefer the default `agent` transport unless you are comparing
compatibility behavior or explicitly testing the experimental QUIC carrier.

## First Checks

Confirm the local binary is the one you expect:

```sh
rustle --help
```

Confirm the remote SSH login works before adding TUN, route, or DNS state:

```sh
ssh user@host true
```

If you use an SSH config alias, test the same alias first:

```sh
ssh contabo true
sudo rustle -r contabo 10.0.0.0/8
```

For performance checks, use a release binary. Debug builds are useful for
diagnosis, but do not use them as throughput or latency evidence.

## TUN And Privileges

Rustle needs privileges to create a TUN device and install routes.

- Linux: run with `sudo` or equivalent `CAP_NET_ADMIN`. Ensure `/dev/net/tun`
  exists and `ip` from `iproute2` is installed.
- macOS: run with `sudo`; Rustle creates an `utun` device and installs routes
  with the system route tool.
- Windows: run from an elevated shell. An architecture-matching Wintun driver
  must be embedded in the release binary or available through
  `RUSTLE_WINTUN_DLL`, the binary directory, or the current directory.

If route setup fails partway through, Rustle rolls back routes it already added.
If the process is interrupted by Ctrl-C or SIGTERM, Rustle runs the same cleanup
path before exiting.

## SSH Authentication

Rustle verifies host keys by default with OpenSSH `known_hosts`.

Use trust-on-first-use only when that is the intended policy:

```sh
sudo rustle --accept-new-host-key -r user@host 10.0.0.0/8
```

Use lab-only insecure host-key bypass only for controlled temporary targets:

```sh
sudo rustle --insecure-accept-host-key -r user@host 10.0.0.0/8
```

For key authentication:

```sh
sudo rustle -r user@host -i ~/.ssh/id_ed25519 10.0.0.0/8
```

For password authentication, avoid putting the password in argv:

```sh
printf '%s\n' "$RUSTLE_PASSWORD" > /tmp/rustle-password
chmod 600 /tmp/rustle-password
sudo rustle -r user@host --password-file /tmp/rustle-password 10.0.0.0/8
```

Interactive password prompting is also supported:

```sh
sudo rustle -r user@host --password 10.0.0.0/8
```

## Remote Agent Startup

The default mode starts `rustle agent` on the remote host over SSH. If the
remote host does not already have a compatible `rustle` on `PATH`, Rustle tries
to upload a matching local sidecar helper.

To point at an installed remote binary:

```sh
sudo rustle -r user@host --agent-path /opt/rustle/rustle 10.0.0.0/8
```

To run a custom remote command:

```sh
sudo rustle -r user@host --agent-command "/opt/rustle/rustle agent" 10.0.0.0/8
```

For cross-platform upload fallback, prepare sidecars from release archives:

```sh
RUSTLE_AGENT_RELEASE_TAG=vX.Y.Z \
RUSTLE_AGENT_DIR="$HOME/.cache/rustle/agents" \
scripts/prepare-agent-sidecars.sh
```

When running Rustle through `sudo`, preserve `RUSTLE_AGENT_DIR` if the sidecar
store is not in the default location.

Expected product behavior is that helper upload is automatic: users should not
manually copy a binary for normal daily use. The engineering requirement is
stricter: uploaded helpers must also clean themselves up. If a test host keeps
stale helper directories after Rustle exits, inspect and remove them:

```sh
ssh user@host 'find /tmp -maxdepth 1 -name "rustle-agent.*" -print'
ssh user@host 'rm -rf /tmp/rustle-agent.*'
```

Treat leftover helper directories as a bug to fix before production release,
especially when they contain `rustle-agent` or `.refs` entries.

## DNS

Use `--dns` when DNS should flow through the remote side:

```sh
sudo rustle --dns -r user@host 10.0.0.0/8
```

Set a resolver explicitly when the remote environment needs one:

```sh
sudo rustle --dns --dns-remote 1.1.1.1:53 -r user@host 10.0.0.0/8
```

Linux DNS takeover uses system resolver tooling. If Rustle reports that
`resolvectl` is required, install or enable `systemd-resolved`, or run without
`--dns`.

macOS DNS takeover uses a loopback DNS proxy plus service-scoped resolver
configuration. Managed VPN or profile resolvers can override global runtime DNS;
if that happens, treat it as a DNS leak risk and verify with
`scripts/smoke-tun-dns.sh` before using `--dns` for sensitive traffic.

## Full-Tunnel Routes

Full-tunnel shorthand is accepted:

```sh
sudo rustle -r user@host 0/0
```

Rustle protects its SSH control connection before installing target routes. If
the SSH host is inside the target CIDR and route setup fails, capture the route
table and retry with a narrower target first:

```sh
sudo rustle -r user@host 10.0.0.0/8
```

On normal shutdown, target routes and DNS settings should return to their
previous state. If a host crash leaves stale state, inspect the route and DNS
tables with native tools before removing anything manually:

- Linux: `ip route`, `resolvectl status`
- macOS: `netstat -rn`, `scutil --dns`, `networksetup -getdnsservers`
- Windows: `route print`, `Get-NetRoute`, `Get-DnsClientServerAddress`

## Performance

Use the benchmark scripts from a release build:

```sh
cargo build --release
scripts/bench-bridge-lab.sh
scripts/bench-agent-dns-lab.sh
scripts/bench-agent-reconnect-lab.sh
```

For live comparison against sshuttle:

```sh
RUSTLE_BENCH_REMOTE=user@host \
RUSTLE_BENCH_TARGET_CIDR=10.0.0.0/8 \
RUSTLE_BENCH_URL=https://10.0.0.10/ \
RUSTLE_BENCH_TOOLS="rustle sshuttle" \
scripts/bench-live-compare.sh
```

If throughput is low, first compare `agent` and `direct-tcpip` rows from
`scripts/bench-bridge-lab.sh`. If latency is dominated by remote agent startup,
test a preinstalled remote `--agent-path` or a prepared sidecar store.

## Experimental QUIC Data Planes

The hidden `quic-agent` transport uses SSH for bootstrap and then carries the
Rustle agent protocol over UDP/QUIC:

```sh
scripts/smoke-quic-agent-lab.sh
RUSTLE_BENCH_BRIDGE_TRANSPORTS="quic-agent" scripts/bench-bridge-lab.sh
```

The hidden `quic-native` transport uses the same SSH-authenticated bootstrap but
maps TCP flows and UDP associations directly to QUIC streams:

```sh
sudo rustle -r user@host 10.0.0.0/8 --bridge-transport quic-native
```

QUIC requires UDP reachability from the local host to the remote helper's
advertised address and port. Firewalls, NAT, or SSH-only bastion paths can block
this mode even when the default SSH-agent transport works. QUIC helpers also
require the SSH-delivered bootstrap token; a stale or mismatched helper command
will fail closed instead of accepting unauthenticated UDP clients.

`auto-quic` is still a hidden experiment. It should fall back to the default
agent path when QUIC cannot connect, but it should not be treated as a default
until startup selection latency and fallback evidence are consistently bounded.
