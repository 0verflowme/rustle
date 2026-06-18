use std::env;

use anyhow::{anyhow, Context, Result};
use russh::client::Handle;

use crate::remote_exec::run_remote_command_collect;
use crate::ssh_control::Client;

pub(crate) const POSIX_REMOTE_PLATFORM_PROBE_COMMAND: &str =
    "uname -s 2>/dev/null; uname -m 2>/dev/null";
pub(crate) const WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Write-Output 'Windows'; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { Write-Output 'AMD64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64') { Write-Output 'AMD64' } else { Write-Output $env:PROCESSOR_ARCHITECTURE }\"";
const REMOTE_PLATFORM_PROBE_OUTPUT_LIMIT: usize = 512;

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
    let posix_failure =
        match run_remote_command_collect(handle, POSIX_REMOTE_PLATFORM_PROBE_COMMAND, None).await {
            Ok(output) => {
                if let Some(platform) = parse_successful_posix_platform_probe(&output)? {
                    return Ok(platform);
                }
                anyhow!(
                    "POSIX remote platform probe did not complete successfully ({})",
                    remote_probe_output_summary(&output)
                )
            }
            Err(err) => err.context("failed to run POSIX remote platform probe"),
        };

    let output =
        match run_remote_command_collect(handle, WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND, None).await
        {
            Ok(output) => output,
            Err(err) => {
                return Err(combine_remote_platform_probe_errors(
                    Some(posix_failure),
                    err.context("failed to run Windows remote platform probe"),
                ));
            }
        };
    if let Err(err) = output.ensure_success("Windows remote platform probe") {
        return Err(combine_remote_platform_probe_errors(
            Some(posix_failure),
            err.context(format!(
                "Windows remote platform probe did not complete successfully ({})",
                remote_probe_output_summary(&output)
            )),
        ));
    }
    parse_remote_platform_probe(&output.stdout)
        .with_context(|| {
            format!(
                "Windows remote platform probe returned unsupported output ({})",
                remote_probe_output_summary(&output)
            )
        })
        .map_err(|err| combine_remote_platform_probe_errors(Some(posix_failure), err))
}

fn parse_successful_posix_platform_probe(
    output: &crate::remote_exec::RemoteCommandOutput,
) -> Result<Option<RemotePlatform>> {
    if output.exit_status == Some(0) {
        parse_remote_platform_probe(&output.stdout)
            .with_context(|| {
                format!(
                    "POSIX remote platform probe returned unsupported output ({})",
                    remote_probe_output_summary(output)
                )
            })
            .map(Some)
    } else {
        Ok(None)
    }
}

fn combine_remote_platform_probe_errors(
    posix_failure: Option<anyhow::Error>,
    windows_failure: anyhow::Error,
) -> anyhow::Error {
    match posix_failure {
        Some(posix_failure) => anyhow!(
            "failed to probe remote platform with POSIX or Windows probes\nPOSIX probe: {posix_failure:#}\nWindows probe: {windows_failure:#}"
        ),
        None => windows_failure.context("failed to probe remote platform"),
    }
}

fn remote_probe_output_summary(output: &crate::remote_exec::RemoteCommandOutput) -> String {
    format!(
        "exit status {:?}, stdout: {}, stderr: {}",
        output.exit_status,
        trimmed_probe_output(&output.stdout),
        trimmed_probe_output(&output.stderr)
    )
}

fn trimmed_probe_output(output: &[u8]) -> String {
    let output = String::from_utf8_lossy(output);
    let output = output.trim();
    if output.is_empty() {
        return "<empty>".to_owned();
    }

    let mut excerpt: String = output
        .chars()
        .take(REMOTE_PLATFORM_PROBE_OUTPUT_LIMIT)
        .collect();
    if output.chars().count() > REMOTE_PLATFORM_PROBE_OUTPUT_LIMIT {
        excerpt.push_str("...");
    }
    excerpt
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
        assert_eq!(normalize_remote_os("MINGW32_NT-10.0"), Some("windows"));
        assert_eq!(normalize_remote_os("MSYS_NT-10.0"), Some("windows"));
        assert_eq!(normalize_remote_os("CYGWIN_NT-10.0"), Some("windows"));
        assert_eq!(normalize_remote_os(" Linux \r"), Some("linux"));
        assert_eq!(normalize_remote_arch("x86_64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("amd64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("AMD64"), Some("x86_64"));
        assert_eq!(normalize_remote_arch("arm64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("ARM64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch("aarch64"), Some("aarch64"));
        assert_eq!(normalize_remote_arch(" aarch64 \r"), Some("aarch64"));
        assert_eq!(normalize_remote_os("Plan9"), None);
        assert_eq!(normalize_remote_os("linux"), None);
        assert_eq!(normalize_remote_arch("riscv64"), None);
    }

    #[test]
    fn local_platform_normalizers_accept_only_supported_rust_targets() {
        assert_eq!(normalize_local_os("linux"), Some("linux"));
        assert_eq!(normalize_local_os("macos"), Some("macos"));
        assert_eq!(normalize_local_os("windows"), Some("windows"));
        assert_eq!(normalize_local_os("darwin"), None);
        assert_eq!(normalize_local_arch("x86_64"), Some("x86_64"));
        assert_eq!(normalize_local_arch("aarch64"), Some("aarch64"));
        assert_eq!(normalize_local_arch("amd64"), None);
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

    #[test]
    fn posix_probe_result_is_used_only_after_zero_exit_and_valid_output() {
        let successful_linux = crate::remote_exec::RemoteCommandOutput {
            stdout: b"Linux\nx86_64\n".to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
        };
        assert_eq!(
            parse_successful_posix_platform_probe(&successful_linux).unwrap(),
            Some(RemotePlatform {
                os: "linux",
                arch: "x86_64",
            })
        );

        let failed_but_parseable = crate::remote_exec::RemoteCommandOutput {
            stdout: b"Linux\nx86_64\n".to_vec(),
            stderr: b"uname unavailable\n".to_vec(),
            exit_status: Some(127),
        };
        assert_eq!(
            parse_successful_posix_platform_probe(&failed_but_parseable).unwrap(),
            None
        );

        let missing_exit_status = crate::remote_exec::RemoteCommandOutput {
            stdout: b"Linux\nx86_64\n".to_vec(),
            stderr: Vec::new(),
            exit_status: None,
        };
        assert_eq!(
            parse_successful_posix_platform_probe(&missing_exit_status).unwrap(),
            None
        );

        let successful_but_invalid = crate::remote_exec::RemoteCommandOutput {
            stdout: b"Plan9\nriscv64\n".to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
        };
        let err = parse_successful_posix_platform_probe(&successful_but_invalid)
            .expect_err("successful POSIX probe with unsupported output should be diagnostic");
        let err = format!("{err:#}");
        assert!(err.contains("POSIX remote platform probe returned unsupported output"));
        assert!(err.contains("stdout: Plan9"));
        assert!(err.contains("riscv64"));
        assert!(err.contains("remote OS probe did not return a supported OS"));
    }

    #[test]
    fn platform_probe_combined_error_reports_posix_and_windows_failures() {
        let err = combine_remote_platform_probe_errors(
            Some(anyhow!("POSIX command failed")),
            anyhow!("Windows command failed"),
        );
        let err = err.to_string();

        assert!(err.contains("failed to probe remote platform with POSIX or Windows probes"));
        assert!(err.contains("POSIX probe: POSIX command failed"));
        assert!(err.contains("Windows probe: Windows command failed"));
    }

    #[test]
    fn platform_probe_output_summary_is_trimmed_and_bounded() {
        let exact = crate::remote_exec::RemoteCommandOutput {
            stdout: vec![b'a'; REMOTE_PLATFORM_PROBE_OUTPUT_LIMIT],
            stderr: b"\n".to_vec(),
            exit_status: Some(1),
        };
        let exact_summary = remote_probe_output_summary(&exact);
        assert!(!exact_summary.contains("..."));

        let output = crate::remote_exec::RemoteCommandOutput {
            stdout: vec![b'a'; REMOTE_PLATFORM_PROBE_OUTPUT_LIMIT + 1],
            stderr: b"\n".to_vec(),
            exit_status: Some(1),
        };
        let summary = remote_probe_output_summary(&output);

        assert!(summary.contains("exit status Some(1)"));
        assert!(summary.contains("stdout: "));
        assert!(summary.contains("..."));
        assert!(summary.contains("stderr: <empty>"));
    }
}
