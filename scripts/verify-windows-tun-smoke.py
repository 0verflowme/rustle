#!/usr/bin/env python3
"""Verify the Windows TUN smoke keeps its required behavioral assertions."""

from __future__ import annotations

import pathlib


REPO = pathlib.Path(__file__).resolve().parents[1]
WINDOWS_TUN_SMOKE = REPO / "scripts" / "smoke-windows-tun.ps1"

REQUIRED_SNIPPETS = [
    "[Security.Principal.WindowsBuiltInRole]::Administrator",
    "administrator privileges are required for the Windows TUN smoke",
    "Windows TUN smoke currently requires a /32 target CIDR",
    "Get-RouteSnapshot",
    "$routeBefore = @(Get-RouteSnapshot $TargetCidr)",
    "$routeAfter = @(Get-RouteSnapshot $TargetCidr)",
    "target route table did not return to its original state",
    "$routeDeleteNeeded = $false",
    "$routeDeleteNeeded = $true",
    "route.exe DELETE $targetIp MASK 255.255.255.255 $TunIp",
    '"tun-capture"',
    '"--target", $TargetCidr',
    '"--exit-after-packets", "1"',
    "[System.Net.Sockets.TcpClient]::new()",
    "$client.ConnectAsync($targetIp, 443)",
    "Rustle did not add the target route before timeout",
    "Rustle did not exit after capturing one packet",
    "Rustle exited with status",
    "tun: created",
    "route: added",
    "packet:",
    "capture: exit-after-packets reached",
    "route: deleted",
    "$process.Kill()",
    "RUSTLE_SMOKE_KEEP_LOGS",
    "Remove-Item -LiteralPath $tmpDir -Recurse -Force",
]


ORDERED_SNIPPETS = [
    "$routeBefore = @(Get-RouteSnapshot $TargetCidr)",
    "Smoke-Info \"starting Windows TUN capture smoke",
    "$routeDeleteNeeded = $true",
    "opening one TCP connection",
    "capture: exit-after-packets reached",
    "$routeDeleteNeeded = $false",
    "$routeAfter = @(Get-RouteSnapshot $TargetCidr)",
]


def main() -> None:
    text = WINDOWS_TUN_SMOKE.read_text(encoding="utf-8")
    missing = [snippet for snippet in REQUIRED_SNIPPETS if snippet not in text]
    if missing:
        raise SystemExit(
            "scripts/smoke-windows-tun.ps1 is missing required snippets: "
            f"{missing!r}"
        )

    last = -1
    for snippet in ORDERED_SNIPPETS:
        index = text.find(snippet, last + 1)
        if index == -1:
            raise SystemExit(
                "scripts/smoke-windows-tun.ps1 has unexpected assertion order; "
                f"could not find {snippet!r} after offset {last}"
            )
        last = index

    if text.count("route.exe DELETE $targetIp MASK 255.255.255.255 $TunIp") != 1:
        raise SystemExit("Windows TUN smoke should have exactly one fallback route delete")


if __name__ == "__main__":
    main()
