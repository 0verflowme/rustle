use std::env;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ring::digest;
use russh::client::Handle;
use tokio::io::AsyncReadExt;

use crate::ssh_control::Client;
use crate::transport_model::BridgeTransportKind;

pub(crate) const DEFAULT_AGENT_COMMAND: &str = "rustle agent";
pub(crate) const DEFAULT_QUIC_AGENT_COMMAND: &str = "rustle quic-agent";
pub(crate) const DEFAULT_QUIC_BRIDGE_AGENT_COMMAND: &str = "rustle quic-bridge-agent";
pub(crate) const POSIX_REMOTE_PLATFORM_PROBE_COMMAND: &str =
    "uname -s 2>/dev/null; uname -m 2>/dev/null";
pub(crate) const WINDOWS_REMOTE_PLATFORM_PROBE_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Write-Output 'Windows'; if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Write-Output 'arm64' } elseif ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { Write-Output 'arm64' } else { Write-Output $env:PROCESSOR_ARCHITECTURE }\"";
pub(crate) const POSIX_REMOTE_AGENT_UPLOAD_COMMAND: &str = "set -eu; umask 077; base=${TMPDIR:-/tmp}; dir=; cleanup() { [ -n \"$dir\" ] && rm -rf \"$dir\"; }; trap cleanup EXIT HUP INT TERM; dir=$(mktemp -d \"$base/rustle-agent.XXXXXX\"); chmod 700 \"$dir\"; p=\"$dir/rustle-agent\"; cat > \"$p\"; chmod 700 \"$p\"; trap - EXIT HUP INT TERM; printf '%s\\n' \"$p\"";
pub(crate) const WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $d=$env:TEMP; if ([string]::IsNullOrWhiteSpace($d)) { $d=$env:TMP }; if ([string]::IsNullOrWhiteSpace($d)) { $d=[IO.Path]::GetTempPath() }; $dir=Join-Path -Path $d -ChildPath ('rustle-agent-{0}-{1}' -f $PID,[Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $dir -Force | Out-Null; $p=Join-Path -Path $dir -ChildPath 'rustle-agent.exe'; $stdin=[Console]::OpenStandardInput(); try { $out=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $stdin.CopyTo($out) } finally { $out.Dispose(); $stdin.Dispose() } } catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }; [Console]::Out.WriteLine($p)\"";
pub(crate) const RUSTLE_AGENT_DIR_ENV: &str = "RUSTLE_AGENT_DIR";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelperKind {
    StdioAgent,
    QuicAgent,
    QuicBridgeNative,
}

impl HelperKind {
    pub(crate) fn subcommand(self) -> &'static str {
        helper_command_labels(self).0
    }

    pub(crate) fn default_command(self) -> &'static str {
        helper_command_labels(self).1
    }

    pub(crate) fn for_bridge_transport(transport: BridgeTransportKind) -> Self {
        match transport {
            BridgeTransportKind::QuicAgent => Self::QuicAgent,
            BridgeTransportKind::QuicNative => Self::QuicBridgeNative,
            BridgeTransportKind::Auto
            | BridgeTransportKind::DirectTcpip
            | BridgeTransportKind::Agent => Self::StdioAgent,
        }
    }
}

pub(crate) fn helper_command_labels(kind: HelperKind) -> (&'static str, &'static str) {
    match kind {
        HelperKind::StdioAgent => ("agent", DEFAULT_AGENT_COMMAND),
        HelperKind::QuicAgent => ("quic-agent", DEFAULT_QUIC_AGENT_COMMAND),
        HelperKind::QuicBridgeNative => ("quic-bridge-agent", DEFAULT_QUIC_BRIDGE_AGENT_COMMAND),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BootstrapPolicy {
    BuiltInCommandWithUploadFallback,
    ExplicitCommandNoFallback,
    ExplicitUploadAllowed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HelperCommandPlan {
    pub(crate) kind: HelperKind,
    pub(crate) command: String,
    pub(crate) policy: BootstrapPolicy,
}

impl HelperCommandPlan {
    pub(crate) fn from_command_options(
        kind: HelperKind,
        agent_command: Option<&str>,
        agent_path: Option<&str>,
    ) -> Result<Self> {
        let (command, policy) = match (agent_command, agent_path) {
            (Some(_), Some(_)) => {
                bail!("--agent-command cannot be combined with --agent-path");
            }
            (Some(command), None) => {
                if command.trim().is_empty() {
                    bail!("--agent-command must not be empty");
                }
                (
                    command.to_owned(),
                    BootstrapPolicy::ExplicitCommandNoFallback,
                )
            }
            (None, Some(path)) => {
                if path.trim().is_empty() {
                    bail!("--agent-path must not be empty");
                }
                (
                    format!("{} {}", shell_quote(path), kind.subcommand()),
                    BootstrapPolicy::ExplicitCommandNoFallback,
                )
            }
            (None, None) => (
                kind.default_command().to_owned(),
                BootstrapPolicy::BuiltInCommandWithUploadFallback,
            ),
        };

        Ok(Self {
            kind,
            command,
            policy,
        })
    }
}

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

pub(crate) fn uploaded_agent_command(remote_path: &str, platform: RemotePlatform) -> String {
    uploaded_helper_command(remote_path, platform, "agent")
}

pub(crate) fn uploaded_helper_command(
    remote_path: &str,
    platform: RemotePlatform,
    helper_subcommand: &str,
) -> String {
    if platform.is_windows() {
        uploaded_windows_helper_command(remote_path, helper_subcommand)
    } else {
        uploaded_posix_helper_command(remote_path, helper_subcommand)
    }
}

fn uploaded_posix_helper_command(remote_path: &str, helper_subcommand: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "tmp={quoted_path}; refdir=\"$tmp.refs\"; marker=\"$refdir/$$\"; owner=$$; mkdir -p \"$refdir\"; : > \"$marker\"; cleanup_parent() {{ parent=${{tmp%/*}}; base=${{parent##*/}}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac; }}; cleanup() {{ rm -f \"$marker\"; for stale in \"$refdir\"/*; do [ -e \"$stale\" ] || continue; pid=${{stale##*/}}; case \"$pid\" in *[!0-9]*) continue;; esac; kill -0 \"$pid\" 2>/dev/null || rm -f \"$stale\"; done; if rmdir \"$refdir\" 2>/dev/null; then rm -f \"$tmp\"; cleanup_parent; fi; }}; ( trap '' HUP; while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup ) </dev/null >/dev/null 2>&1 & trap cleanup EXIT HUP INT TERM; \"$tmp\" {helper_subcommand}; status=$?; trap - EXIT HUP INT TERM; cleanup; exit \"$status\""
    )
}

fn uploaded_windows_helper_command(remote_path: &str, helper_subcommand: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $tmp={quoted_path}; $refdir=$tmp+'.refs'; $marker=Join-Path -Path $refdir -ChildPath $PID; New-Item -ItemType Directory -Force -LiteralPath $refdir | Out-Null; New-Item -ItemType File -Force -LiteralPath $marker | Out-Null; function CleanupParent {{ $parent=[IO.Path]::GetDirectoryName($tmp); if ($parent -and ([IO.Path]::GetFileName($parent) -like 'rustle-agent-*')) {{ Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }} }}; function Cleanup {{ Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $refdir) {{ Get-ChildItem -LiteralPath $refdir -ErrorAction SilentlyContinue | ForEach-Object {{ $id=0; if ([int]::TryParse($_.Name,[ref]$id)) {{ if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) {{ Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }} }} }}; try {{ Remove-Item -LiteralPath $refdir -Force -ErrorAction Stop; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; CleanupParent }} catch {{}} }} }}; try {{ & $tmp {helper_subcommand}; $status=$LASTEXITCODE }} finally {{ Cleanup }}; exit $status\""
    )
}

pub(crate) async fn upload_agent_binary(
    handle: &Handle<Client>,
    local_path: &Path,
    platform: RemotePlatform,
) -> Result<String> {
    let expected_sha256 = sha256_file_hex(local_path).await?;
    let file = tokio::fs::File::open(local_path).await.with_context(|| {
        format!(
            "failed to open local Rustle binary {}",
            local_path.display()
        )
    })?;
    let output =
        run_remote_command_collect(handle, remote_agent_upload_command(platform), Some(file))
            .await
            .context("failed to upload Rustle agent binary")?;
    output.ensure_success("remote agent upload")?;
    let remote_path = String::from_utf8(output.stdout)
        .context("remote upload path was not valid UTF-8")?
        .trim()
        .to_owned();
    if remote_path.is_empty() {
        bail!("remote upload did not return a path");
    }
    if let Err(err) =
        verify_uploaded_agent_binary(handle, &remote_path, platform, &expected_sha256).await
    {
        if let Err(cleanup_err) =
            cleanup_uploaded_agent_binary(handle, &remote_path, platform).await
        {
            eprintln!(
                "agent: failed to remove unverified uploaded helper {remote_path}: {cleanup_err:#}"
            );
        }
        return Err(err).with_context(|| {
            format!("uploaded Rustle agent integrity verification failed for {remote_path}")
        });
    }
    Ok(remote_path)
}

pub(crate) fn remote_agent_upload_command(platform: RemotePlatform) -> &'static str {
    if platform.is_windows() {
        WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND
    } else {
        POSIX_REMOTE_AGENT_UPLOAD_COMMAND
    }
}

async fn verify_uploaded_agent_binary(
    handle: &Handle<Client>,
    remote_path: &str,
    platform: RemotePlatform,
    expected_sha256: &str,
) -> Result<()> {
    let command = uploaded_agent_sha256_command(remote_path, platform);
    let output = run_remote_command_collect(handle, &command, None)
        .await
        .context("failed to run remote uploaded-agent hash command")?;
    output.ensure_success("remote uploaded-agent hash")?;
    let actual = String::from_utf8(output.stdout)
        .context("remote uploaded-agent hash output was not valid UTF-8")?
        .trim()
        .to_ascii_lowercase();
    if !is_sha256_hex(&actual) {
        bail!("remote uploaded-agent hash output was not a SHA-256 digest: {actual:?}");
    }
    if actual != expected_sha256 {
        bail!("remote uploaded-agent SHA-256 mismatch: expected {expected_sha256}, got {actual}");
    }
    Ok(())
}

async fn cleanup_uploaded_agent_binary(
    handle: &Handle<Client>,
    remote_path: &str,
    platform: RemotePlatform,
) -> Result<()> {
    let command = uploaded_agent_cleanup_command(remote_path, platform);
    let output = run_remote_command_collect(handle, &command, None)
        .await
        .context("failed to run remote uploaded-agent cleanup command")?;
    output.ensure_success("remote uploaded-agent cleanup")
}

pub(crate) fn uploaded_agent_sha256_command(remote_path: &str, platform: RemotePlatform) -> String {
    if platform.is_windows() {
        uploaded_windows_agent_sha256_command(remote_path)
    } else {
        uploaded_posix_agent_sha256_command(remote_path)
    }
}

fn uploaded_posix_agent_sha256_command(remote_path: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "p={quoted_path}; if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$p\" | awk '{{print $1}}'; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 \"$p\" | awk '{{print $1}}'; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r \"$p\" | awk '{{print $1}}'; else echo 'no remote SHA-256 command found' >&2; exit 127; fi"
    )
}

fn uploaded_windows_agent_sha256_command(remote_path: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $p={quoted_path}; (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()\""
    )
}

pub(crate) fn uploaded_agent_cleanup_command(
    remote_path: &str,
    platform: RemotePlatform,
) -> String {
    if platform.is_windows() {
        uploaded_windows_agent_cleanup_command(remote_path)
    } else {
        uploaded_posix_agent_cleanup_command(remote_path)
    }
}

pub(crate) fn uploaded_posix_agent_cleanup_command(remote_path: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    format!(
        "p={quoted_path}; rm -f \"$p\"; rm -rf \"$p.refs\"; parent=${{p%/*}}; base=${{parent##*/}}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac"
    )
}

fn uploaded_windows_agent_cleanup_command(remote_path: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $p={quoted_path}; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath ($p+'.refs') -Recurse -Force -ErrorAction SilentlyContinue; $parent=[IO.Path]::GetDirectoryName($p); if ($parent -and ([IO.Path]::GetFileName($parent) -like 'rustle-agent-*')) {{ Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }}\""
    )
}

pub(crate) async fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("failed to open {} for SHA-256", path.display()))?;
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("failed to read {} for SHA-256", path.display()))?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(lower_hex(context.finish().as_ref()))
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn local_agent_binary_for_platform(
    current_exe: &Path,
    platform: RemotePlatform,
) -> Result<PathBuf> {
    let local = RemotePlatform::local()?;
    if platform == local {
        return Ok(current_exe.to_path_buf());
    }

    let candidates = local_agent_binary_candidates(current_exe, platform);
    if let Some(candidate) = candidates.iter().find(|path| path.is_file()) {
        return Ok(candidate.clone());
    }

    let candidate_list = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "no local Rustle agent binary found for remote {}; install `rustle agent` on the remote host or place a matching sidecar beside the local binary. Checked: {candidate_list}",
        platform.label()
    )
}

fn local_agent_binary_candidates(current_exe: &Path, platform: RemotePlatform) -> Vec<PathBuf> {
    dedupe_paths(agent_binary_candidates_in_dirs(
        platform,
        &local_agent_search_dirs(current_exe),
    ))
}

pub(crate) fn local_agent_search_dirs(current_exe: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(paths) = env::var_os(RUSTLE_AGENT_DIR_ENV) {
        dirs.extend(env::split_paths(&paths));
    }
    if let Some(parent) = current_exe.parent() {
        dirs.push(parent.to_path_buf());
        if let Some(package_parent) = parent.parent() {
            dirs.push(package_parent.to_path_buf());
            dirs.push(package_parent.join("rustle-agent-dir"));
        }
    }
    if let Ok(cwd) = env::current_dir() {
        dirs.push(cwd.join("target").join("rustle-agent-dir"));
        dirs.push(cwd);
    }
    dedupe_paths(dirs)
}

pub(crate) fn agent_binary_candidates_in_dirs(
    platform: RemotePlatform,
    dirs: &[PathBuf],
) -> Vec<PathBuf> {
    let suffix = if platform.is_windows() { ".exe" } else { "" };
    let binary = format!("rustle{suffix}");
    let platform_key = format!("{}-{}", platform.os, platform.arch);
    let mut candidates = Vec::new();

    for dir in dirs {
        candidates.push(dir.join(format!("rustle-agent-{platform_key}{suffix}")));
        candidates.push(dir.join(format!("rustle-{platform_key}{suffix}")));

        for triple in remote_platform_target_triples(platform) {
            candidates.push(dir.join(format!("rustle-agent-{triple}{suffix}")));
            candidates.push(dir.join(format!("rustle-{triple}{suffix}")));
            candidates.push(dir.join(format!("rustle-{triple}")).join(&binary));
            candidates.push(
                dir.join(format!("rustle-{triple}"))
                    .join(format!("rustle-agent{suffix}")),
            );
        }
    }

    dedupe_paths(candidates)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    deduped
}

pub(crate) fn remote_platform_target_triples(platform: RemotePlatform) -> &'static [&'static str] {
    match (platform.os, platform.arch) {
        ("linux", "x86_64") => &["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"],
        ("linux", "aarch64") => &["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"],
        ("macos", "x86_64") => &["x86_64-apple-darwin"],
        ("macos", "aarch64") => &["aarch64-apple-darwin"],
        ("windows", "x86_64") => &["x86_64-pc-windows-msvc"],
        ("windows", "aarch64") => &["aarch64-pc-windows-msvc"],
        _ => &[],
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

pub(crate) struct RemoteCommandOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_status: Option<u32>,
}

impl RemoteCommandOutput {
    pub(crate) fn ensure_success(&self, context: &str) -> Result<()> {
        if self.exit_status == Some(0) {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&self.stderr);
        bail!(
            "{context} failed with exit status {:?}: {}",
            self.exit_status,
            stderr.trim()
        );
    }
}

pub(crate) async fn run_remote_command_collect(
    handle: &Handle<Client>,
    command: &str,
    input: Option<tokio::fs::File>,
) -> Result<RemoteCommandOutput> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("failed to open SSH session channel")?;
    channel
        .exec(true, command.as_bytes().to_vec())
        .await
        .with_context(|| format!("failed to exec remote command: {command}"))?;

    if let Some(file) = input {
        channel
            .data(file)
            .await
            .context("failed to write remote command stdin")?;
    }
    channel
        .eof()
        .await
        .context("failed to close remote command stdin")?;

    let mut output = RemoteCommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_status: None,
    };
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => output.stdout.extend_from_slice(&data),
            russh::ChannelMsg::ExtendedData { data, .. } => {
                output.stderr.extend_from_slice(&data);
            }
            russh::ChannelMsg::ExitStatus { exit_status } => {
                output.exit_status = Some(exit_status);
            }
            _ => {}
        }
    }
    Ok(output)
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) fn effective_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    effective_remote_helper_command(agent_command, agent_path, HelperKind::StdioAgent)
}

fn effective_quic_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    effective_remote_helper_command(agent_command, agent_path, HelperKind::QuicAgent)
}

fn effective_quic_bridge_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    effective_remote_helper_command(agent_command, agent_path, HelperKind::QuicBridgeNative)
}

pub(crate) fn effective_bridge_agent_command(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    match HelperKind::for_bridge_transport(transport) {
        HelperKind::QuicAgent => effective_quic_agent_command(agent_command, agent_path),
        HelperKind::QuicBridgeNative => {
            effective_quic_bridge_agent_command(agent_command, agent_path)
        }
        HelperKind::StdioAgent => effective_agent_command(agent_command, agent_path),
    }
}

fn effective_remote_helper_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
    helper: HelperKind,
) -> Result<String> {
    Ok(HelperCommandPlan::from_command_options(helper, agent_command, agent_path)?.command)
}

pub(crate) fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn normalize_local_os(value: &str) -> Option<&'static str> {
    match value {
        "linux" => Some("linux"),
        "macos" => Some("macos"),
        "windows" => Some("windows"),
        _ => None,
    }
}

pub(crate) fn normalize_remote_os(value: &str) -> Option<&'static str> {
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

pub(crate) fn normalize_remote_arch(value: &str) -> Option<&'static str> {
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
    fn helper_kind_maps_to_subcommands_and_default_commands() {
        let cases = [
            (HelperKind::StdioAgent, "agent", DEFAULT_AGENT_COMMAND),
            (
                HelperKind::QuicAgent,
                "quic-agent",
                DEFAULT_QUIC_AGENT_COMMAND,
            ),
            (
                HelperKind::QuicBridgeNative,
                "quic-bridge-agent",
                DEFAULT_QUIC_BRIDGE_AGENT_COMMAND,
            ),
        ];

        for (kind, subcommand, default_command) in cases {
            assert_eq!(helper_command_labels(kind), (subcommand, default_command));
            assert_eq!(kind.subcommand(), subcommand);
            assert_eq!(kind.default_command(), default_command);
        }
    }

    #[test]
    fn helper_kind_maps_bridge_transports_to_helper_commands() {
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::QuicAgent),
            HelperKind::QuicAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::QuicNative),
            HelperKind::QuicBridgeNative
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::Agent),
            HelperKind::StdioAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::DirectTcpip),
            HelperKind::StdioAgent
        );
        assert_eq!(
            HelperKind::for_bridge_transport(BridgeTransportKind::Auto),
            HelperKind::StdioAgent
        );
    }

    #[test]
    fn helper_command_plan_resolves_effective_commands() {
        assert_eq!(
            HelperCommandPlan::from_command_options(HelperKind::QuicAgent, None, None)
                .expect("default command")
                .command,
            DEFAULT_QUIC_AGENT_COMMAND,
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                Some("/opt/rustle quic-agent"),
                None,
            )
            .expect("explicit command")
            .command,
            "/opt/rustle quic-agent",
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::QuicBridgeNative,
                None,
                Some("/tmp/rustle dir/rustle'bin"),
            )
            .expect("explicit path")
            .command,
            "'/tmp/rustle dir/rustle'\\''bin' quic-bridge-agent",
        );
    }

    #[test]
    fn helper_command_plan_assigns_bootstrap_policy() {
        assert_eq!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
                .expect("default policy")
                .policy,
            BootstrapPolicy::BuiltInCommandWithUploadFallback,
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                Some("rustle agent"),
                None,
            )
            .expect("explicit command policy")
            .policy,
            BootstrapPolicy::ExplicitCommandNoFallback,
        );
        assert_eq!(
            HelperCommandPlan::from_command_options(
                HelperKind::StdioAgent,
                None,
                Some("/tmp/rustle"),
            )
            .expect("explicit path policy")
            .policy,
            BootstrapPolicy::ExplicitCommandNoFallback,
        );
    }

    #[test]
    fn helper_command_plan_validates_command_options() {
        assert!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, Some(" "), None)
                .is_err()
        );
        assert!(
            HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, Some(" "))
                .is_err()
        );
        assert!(HelperCommandPlan::from_command_options(
            HelperKind::StdioAgent,
            Some("rustle agent"),
            Some("/tmp/rustle"),
        )
        .is_err());
    }
}
