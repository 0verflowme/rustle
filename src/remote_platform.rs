use std::env;

use anyhow::{anyhow, Context, Result};
use russh::client::Handle;

use crate::remote_exec::run_remote_command_collect;
use crate::ssh_control::Client;

pub(crate) const POSIX_REMOTE_PLATFORM_PROBE_COMMAND: &str =
    "uname -s 2>/dev/null; uname -m 2>/dev/null";
pub(crate) const WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Write-Output 'Windows'; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { Write-Output 'AMD64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { Write-Output 'AMD64' } else { Write-Output $env:PROCESSOR_ARCHITECTURE }\"";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemotePlatform {
    pub(crate) os: &'static str,
    pub(crate) arch: &'static str,
}

impl RemotePlatform {
    pub(crate) fn local() -> Result<Self> {
        let os = normalize_local_os(env::consts::OS)
            .ok_or_else(|| anyhow!("local OS {} is not supported for upload", env::consts::OS))?;
        let arch = normalize_local_arch(env::consts::ARCH).ok_or_else(|| {
            anyhow!(
                "local architecture {} is not supported for upload",
                env::consts::ARCH
            )
        })?;
        Ok(Self { os, arch })
    }

    pub(crate) fn is_windows(self) -> bool {
        self.os == "windows"
    }

    pub(crate) fn label(self) -> String {
        format!("{}/{}", self.os, self.arch)
    }
}

pub(crate) async fn probe_remote_platform(handle: &Handle<Client>) -> Result<RemotePlatform> {
    match run_remote_command_collect(handle, POSIX_REMOTE_PLATFORM_PROBE_COMMAND, None).await {
        Ok(output) if output.exit_status == Some(0) => {
            if let Ok(platform) = parse_remote_platform_probe(&output.stdout) {
                return Ok(platform);
            }
        }
        _ => {}
    }

    let output = run_remote_command_collect(handle, WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND, None)
        .await
        .context("failed to probe remote platform")?;
    output.ensure_success("remote platform probe")?;
    parse_remote_platform_probe(&output.stdout)
}

pub(crate) fn parse_remote_platform_probe(stdout: &[u8]) -> Result<RemotePlatform> {
    let stdout =
        String::from_utf8(stdout.to_vec()).context("remote platform probe was not valid UTF-8")?;
    let mut lines = stdout.lines();
    let remote_os = lines
        .next()
        .and_then(normalize_remote_os)
        .ok_or_else(|| anyhow!("remote OS probe did not return a supported OS"))?;
    let remote_arch = lines
        .next()
        .and_then(normalize_remote_arch)
        .ok_or_else(|| anyhow!("remote architecture probe did not return a supported arch"))?;

    Ok(RemotePlatform {
        os: remote_os,
        arch: remote_arch,
    })
}

fn normalize_local_os(value: &str) -> Option<&'static str> {
    match value {
        "linux" => Some("linux"),
        "macos" => Some("macos"),
        "windows" => Some("windows"),
        _ => None,
    }
}

fn normalize_remote_os(value: &str) -> Option<&'static str> {
    let value = value.trim();
    match value {
        "Linux" => Some("linux"),
        "Darwin" => Some("macos"),
        "Windows" => Some("windows"),
        _ if value.starts_with("MINGW64_NT")
            || value.starts_with("MINGW32_NT")
            || value.starts_with("MSYS_NT")
            || value.starts_with("CYGWIN_NT") =>
        {
            Some("windows")
        }
        _ => None,
    }
}

fn normalize_local_arch(value: &str) -> Option<&'static str> {
    match value {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        _ => None,
    }
}

fn normalize_remote_arch(value: &str) -> Option<&'static str> {
    let value = value.trim().to_ascii_lowercase();
    match value.as_str() {
        "x86_64" | "amd64" => Some("x86_64"),
        "aarch64" | "arm64" => Some("aarch64"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_probe_normalizes_common_uname_values() {
        assert_eq!(normalize_remote_os("Linux"), Some("linux"));
        assert_eq!(normalize_remote_os("Darwin"), Some("macos"));
        assert_eq!(normalize_remote_os("Windows"), Some("windows"));
        assert_eq!(normalize_remote_os("MINGW64_NT-10.0"), Some("windows"));
        assert_eq!(normalize_remote_arch("x86_64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("amd64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("AMD64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("arm64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("ARM64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("aarch64"), Some("aarch64"));
        assert_eq!(normalize_remote_os("Plan9"), None);
        assert_eq!(normalize_remote_arch("riscv64"), None);
    }

    #[test]
    fn platform_probe_parser_accepts_unix_and_windows_outputs() {
        assert_eq!(
            parse_remote_platform_probe(b"Linux\nx86_64\n").unwrap(),
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            }
        );
        assert_eq!(
            parse_remote_platform_probe(b"Windows\r\nAMD64\r\n").unwrap(),
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            }
        );
    }

    #[test]
    fn windows_platform_probe_handles_redirected_amd64_powershell() {
        assert!(WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND.contains("PROCESSOR_ARCHITEW6432"));
        assert!(WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND.contains("-eq 'AMD64'"));
        assert_eq!(
            parse_remote_platform_probe(b"Windows\r\nx86\r\n")
                .unwrap_err()
                .to_string(),
            "remote architecture probe did not return a supported arch"
        );
        assert_eq!(
            parse_remote_platform_probe(b"Windows\r\nAMD64\r\n").unwrap(),
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            }
        );
    }
}
