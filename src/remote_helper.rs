use std::env;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
#[cfg(test)]
use std::time::{Duration, Instant as StdInstant};

use anyhow::{bail, Context, Result};
use ring::digest;
use russh::client::Handle;
use tokio::io::AsyncReadExt;

use crate::remote_exec::run_remote_command_collect;
use crate::remote_platform::{probe_remote_platform, RemotePlatform};
use crate::sidecar_store::local_helper_binary_for_platform;
use crate::ssh_control::{connect_prepared_ssh, Client, PreparedSshConnection};
use crate::transport_model::BridgeTransportKind;

pub(crate) const DEFAULT_AGENT_COMMAND: &str = "rustle agent";
pub(crate) const DEFAULT_QUIC_AGENT_COMMAND: &str = "rustle quic-agent";
pub(crate) const DEFAULT_QUIC_BRIDGE_AGENT_COMMAND: &str = "rustle quic-bridge-agent";
pub(crate) const POSIX_REMOTE_AGENT_UPLOAD_COMMAND: &str = "set -eu; umask 077; base=${TMPDIR:-/tmp}; dir=; cleanup() { [ -n \"$dir\" ] && rm -rf \"$dir\"; }; trap cleanup EXIT HUP INT TERM; dir=$(mktemp -d \"$base/rustle-agent.XXXXXX\"); chmod 700 \"$dir\"; p=\"$dir/rustle-agent\"; cat > \"$p\"; chmod 700 \"$p\"; trap - EXIT HUP INT TERM; printf '%s\\n' \"$p\"";
pub(crate) const WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $d=$env:TEMP; if ([string]::IsNullOrWhiteSpace($d)) { $d=$env:TMP }; if ([string]::IsNullOrWhiteSpace($d)) { $d=[IO.Path]::GetTempPath() }; $dir=Join-Path -Path $d -ChildPath ('rustle-agent-{0}-{1}' -f $PID,[Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $dir -Force | Out-Null; $p=Join-Path -Path $dir -ChildPath 'rustle-agent.exe'; $stdin=[Console]::OpenStandardInput(); try { $out=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $stdin.CopyTo($out) } finally { $out.Dispose(); $stdin.Dispose() } } catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }; [Console]::Out.WriteLine($p)\"";

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

    pub(crate) fn controller_log_prefix(self) -> &'static str {
        match self {
            Self::StdioAgent => "agent",
            Self::QuicAgent => "quic-agent",
            Self::QuicBridgeNative => "quic-native",
        }
    }

    fn sidecar_noun(self) -> &'static str {
        match self {
            Self::StdioAgent => "agent",
            Self::QuicAgent | Self::QuicBridgeNative => "helper",
        }
    }

    fn platform_probe_context(self) -> &'static str {
        match self {
            Self::StdioAgent => "failed to determine remote platform for Rustle agent bootstrap",
            Self::QuicAgent => {
                "failed to determine remote platform for Rustle QUIC agent bootstrap"
            }
            Self::QuicBridgeNative => {
                "failed to determine remote platform for native QUIC bridge bootstrap"
            }
        }
    }

    pub(crate) fn uploaded_start_context(self, remote_path: &str) -> String {
        match self {
            Self::StdioAgent => {
                format!("uploaded Rustle agent failed to start from {remote_path}")
            }
            Self::QuicAgent => {
                format!("uploaded Rustle QUIC agent failed to start from {remote_path}")
            }
            Self::QuicBridgeNative => {
                format!("uploaded native QUIC bridge helper failed to start from {remote_path}")
            }
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UploadedHelperCommand {
    pub(crate) kind: HelperKind,
    pub(crate) platform: RemotePlatform,
    pub(crate) local_path: PathBuf,
    pub(crate) remote_path: String,
    pub(crate) command: String,
}

impl UploadedHelperCommand {
    fn new(
        kind: HelperKind,
        platform: RemotePlatform,
        local_path: PathBuf,
        remote_path: String,
    ) -> Self {
        let command = uploaded_helper_command(&remote_path, platform, kind.subcommand());
        Self {
            kind,
            platform,
            local_path,
            remote_path,
            command,
        }
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

    pub(crate) fn allows_upload_fallback(&self) -> bool {
        self.policy.allows_upload()
    }
}

impl BootstrapPolicy {
    pub(crate) fn allows_upload(self) -> bool {
        matches!(
            self,
            Self::BuiltInCommandWithUploadFallback | Self::ExplicitUploadAllowed
        )
    }
}

pub(crate) struct BootstrappedHelper {
    pub(crate) handle: Handle<Client>,
    pub(crate) helper: UploadedHelperCommand,
}

#[cfg(test)]
pub(crate) fn uploaded_agent_command(remote_path: &str, platform: RemotePlatform) -> String {
    uploaded_helper_command(remote_path, platform, HelperKind::StdioAgent.subcommand())
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

pub(crate) async fn stage_uploaded_helper_command(
    handle: &Handle<Client>,
    kind: HelperKind,
) -> Result<UploadedHelperCommand> {
    let platform = probe_remote_platform(handle)
        .await
        .context(kind.platform_probe_context())?;
    let current_exe = env::current_exe().context("failed to locate current Rustle executable")?;
    let local_helper = local_helper_binary_for_platform(&current_exe, platform)?;
    if local_helper.is_sidecar() {
        eprintln!(
            "{}: using local {} {} sidecar {}",
            kind.controller_log_prefix(),
            platform.label(),
            kind.sidecar_noun(),
            local_helper.path.display()
        );
    }
    let remote_path = upload_agent_binary(handle, &local_helper.path, platform).await?;
    Ok(UploadedHelperCommand::new(
        kind,
        platform,
        local_helper.path,
        remote_path,
    ))
}

pub(crate) async fn bootstrap_helper(
    prepared: &PreparedSshConnection,
    plan: &HelperCommandPlan,
) -> Result<BootstrappedHelper> {
    if !plan.policy.allows_upload() {
        bail!(
            "{}: upload bootstrap is not allowed for this helper startup policy",
            plan.kind.controller_log_prefix()
        );
    }
    let handle = connect_prepared_ssh(prepared).await?;
    let helper = stage_uploaded_helper_command(&handle, plan.kind).await?;
    Ok(BootstrappedHelper { handle, helper })
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

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
pub(crate) fn effective_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    agent_command_plan(agent_command, agent_path).map(|plan| plan.command)
}

#[cfg(test)]
fn effective_quic_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::QuicAgent)
        .map(|plan| plan.command)
}

#[cfg(test)]
fn effective_quic_bridge_agent_command(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<String> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::QuicBridgeNative)
        .map(|plan| plan.command)
}

#[cfg(test)]
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

pub(crate) fn agent_command_plan(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<HelperCommandPlan> {
    remote_helper_command_plan(agent_command, agent_path, HelperKind::StdioAgent)
}

pub(crate) fn bridge_agent_command_plan(
    transport: BridgeTransportKind,
    agent_command: Option<&str>,
    agent_path: Option<&str>,
) -> Result<HelperCommandPlan> {
    remote_helper_command_plan(
        agent_command,
        agent_path,
        HelperKind::for_bridge_transport(transport),
    )
}

fn remote_helper_command_plan(
    agent_command: Option<&str>,
    agent_path: Option<&str>,
    helper: HelperKind,
) -> Result<HelperCommandPlan> {
    HelperCommandPlan::from_command_options(helper, agent_command, agent_path)
}

pub(crate) fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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
    fn helper_kind_metadata_preserves_controller_labels_and_contexts() {
        let cases = [
            (
                HelperKind::StdioAgent,
                "agent",
                "agent",
                "failed to determine remote platform for Rustle agent bootstrap",
                "uploaded Rustle agent failed to start from /tmp/rustle-agent",
            ),
            (
                HelperKind::QuicAgent,
                "quic-agent",
                "helper",
                "failed to determine remote platform for Rustle QUIC agent bootstrap",
                "uploaded Rustle QUIC agent failed to start from /tmp/rustle-agent",
            ),
            (
                HelperKind::QuicBridgeNative,
                "quic-native",
                "helper",
                "failed to determine remote platform for native QUIC bridge bootstrap",
                "uploaded native QUIC bridge helper failed to start from /tmp/rustle-agent",
            ),
        ];

        for (kind, log_prefix, sidecar_noun, probe_context, start_context) in cases {
            assert_eq!(kind.controller_log_prefix(), log_prefix);
            assert_eq!(kind.sidecar_noun(), sidecar_noun);
            assert_eq!(kind.platform_probe_context(), probe_context);
            assert_eq!(
                kind.uploaded_start_context("/tmp/rustle-agent"),
                start_context
            );
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
        let cases = [
            (
                HelperKind::StdioAgent,
                DEFAULT_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' agent",
            ),
            (
                HelperKind::QuicAgent,
                DEFAULT_QUIC_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' quic-agent",
            ),
            (
                HelperKind::QuicBridgeNative,
                DEFAULT_QUIC_BRIDGE_AGENT_COMMAND,
                "'/tmp/rustle dir/rustle'\\''bin' quic-bridge-agent",
            ),
        ];

        for (kind, default_command, path_command) in cases {
            assert_eq!(
                HelperCommandPlan::from_command_options(kind, None, None)
                    .expect("default command")
                    .command,
                default_command,
            );
            assert_eq!(
                HelperCommandPlan::from_command_options(
                    kind,
                    None,
                    Some("/tmp/rustle dir/rustle'bin"),
                )
                .expect("explicit path")
                .command,
                path_command,
            );
        }

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
    fn helper_command_plan_controls_upload_fallback() {
        let built_in = HelperCommandPlan::from_command_options(HelperKind::StdioAgent, None, None)
            .expect("built-in command plan");
        assert!(built_in.allows_upload_fallback());
        assert!(built_in.policy.allows_upload());

        let explicit_command = HelperCommandPlan::from_command_options(
            HelperKind::QuicAgent,
            Some("custom quic-agent"),
            None,
        )
        .expect("explicit command plan");
        assert!(!explicit_command.allows_upload_fallback());
        assert!(!explicit_command.policy.allows_upload());

        let explicit_path = HelperCommandPlan::from_command_options(
            HelperKind::QuicBridgeNative,
            None,
            Some("/tmp/rustle"),
        )
        .expect("explicit path plan");
        assert!(!explicit_path.allows_upload_fallback());
        assert!(!explicit_path.policy.allows_upload());

        let explicit_upload = HelperCommandPlan {
            kind: HelperKind::StdioAgent,
            command: "custom rustle agent".to_owned(),
            policy: BootstrapPolicy::ExplicitUploadAllowed,
        };
        assert!(explicit_upload.allows_upload_fallback());
        assert!(explicit_upload.policy.allows_upload());
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

    #[test]
    fn shell_quote_uses_single_quote_safe_form() {
        assert_eq!(shell_quote("/tmp/rustle-agent"), "'/tmp/rustle-agent'");
        assert_eq!(shell_quote("/tmp/rustle'agent"), "'/tmp/rustle'\\''agent'");
    }

    #[test]
    fn effective_agent_command_quotes_literal_agent_path() {
        assert_eq!(
            effective_agent_command(None, None).expect("default agent command"),
            DEFAULT_AGENT_COMMAND
        );
        assert_eq!(
            effective_agent_command(Some("/tmp/rustle agent"), None)
                .expect("raw command stays raw"),
            "/tmp/rustle agent"
        );
        assert_eq!(
            effective_agent_command(None, Some("/tmp/rustle dir/rustle'bin"))
                .expect("path command is quoted"),
            "'/tmp/rustle dir/rustle'\\''bin' agent"
        );
        assert!(effective_agent_command(Some(" "), None).is_err());
        assert!(effective_agent_command(None, Some(" ")).is_err());
        assert!(effective_agent_command(Some("rustle agent"), Some("/tmp/rustle")).is_err());
    }

    #[test]
    fn powershell_quote_uses_single_quote_safe_form() {
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle.exe"),
            "'C:\\Temp\\rustle.exe'"
        );
        assert_eq!(
            powershell_quote("C:\\Temp\\rustle'agent.exe"),
            "'C:\\Temp\\rustle''agent.exe'"
        );
    }

    #[test]
    fn uploaded_agent_command_quotes_path_and_cleans_up() {
        let command = uploaded_agent_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );

        assert!(command.contains("tmp='/tmp/rustle'\\''agent'"));
        assert!(command.contains("refdir=\"$tmp.refs\""));
        assert!(command.contains("marker=\"$refdir/$$\""));
        assert!(command.contains("owner=$$"));
        assert!(command.contains("mkdir -p \"$refdir\""));
        assert!(command.contains(": > \"$marker\""));
        assert!(command.contains("trap cleanup EXIT HUP INT TERM"));
        assert!(command.contains("\"$tmp\" agent"));
        assert!(command.contains("rm -f \"$marker\""));
        assert!(command.contains("for stale in \"$refdir\"/*"));
        assert!(command.contains("kill -0 \"$pid\" 2>/dev/null || rm -f \"$stale\""));
        assert!(command.contains("while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup"));
        assert!(command.contains("cleanup_parent()"));
        assert!(command.contains("case \"$base\" in rustle-agent.*)"));
        assert!(command
            .contains("if rmdir \"$refdir\" 2>/dev/null; then rm -f \"$tmp\"; cleanup_parent; fi"));
    }

    #[test]
    fn uploaded_agent_command_matches_stdio_uploaded_helper_command() {
        let posix = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        assert_eq!(
            uploaded_agent_command("/tmp/rustle-agent", posix),
            uploaded_helper_command(
                "/tmp/rustle-agent",
                posix,
                HelperKind::StdioAgent.subcommand()
            )
        );

        let windows = RemotePlatform {
            os: "windows",
            arch: "x86_64",
        };
        assert_eq!(
            uploaded_agent_command("C:\\Temp\\rustle-agent.exe", windows),
            uploaded_helper_command(
                "C:\\Temp\\rustle-agent.exe",
                windows,
                HelperKind::StdioAgent.subcommand()
            )
        );
    }

    #[test]
    fn uploaded_helper_command_new_constructs_metadata_and_command_for_each_kind() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let local_path = PathBuf::from("/local/rustle");

        for (kind, subcommand) in [
            (HelperKind::StdioAgent, "agent"),
            (HelperKind::QuicAgent, "quic-agent"),
            (HelperKind::QuicBridgeNative, "quic-bridge-agent"),
        ] {
            let helper = UploadedHelperCommand::new(
                kind,
                platform,
                local_path.clone(),
                "/tmp/rustle-agent".to_owned(),
            );

            assert_eq!(helper.kind, kind);
            assert_eq!(helper.platform, platform);
            assert_eq!(helper.local_path, local_path);
            assert_eq!(helper.remote_path, "/tmp/rustle-agent");
            assert!(helper.command.contains(&format!("\"$tmp\" {subcommand}")));
        }
    }

    #[test]
    fn posix_uploaded_helper_command_constructs_command_for_each_helper_kind() {
        let platform = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };

        for (kind, subcommand) in [
            (HelperKind::StdioAgent, "agent"),
            (HelperKind::QuicAgent, "quic-agent"),
            (HelperKind::QuicBridgeNative, "quic-bridge-agent"),
        ] {
            let command = uploaded_helper_command("/tmp/rustle-agent", platform, kind.subcommand());

            assert!(command.contains(&format!("\"$tmp\" {subcommand}")));
        }
    }

    #[test]
    fn windows_uploaded_agent_command_uses_powershell_and_cleans_up() {
        let platform = RemotePlatform {
            os: "windows",
            arch: "x86_64",
        };
        let command = uploaded_agent_command("C:\\Temp\\rustle'agent.exe", platform);

        assert!(command.starts_with("powershell.exe -NoProfile -NonInteractive"));
        assert!(command.contains("$tmp='C:\\Temp\\rustle''agent.exe'"));
        assert!(command.contains("$refdir=$tmp+'.refs'"));
        assert!(command.contains("$marker=Join-Path -Path $refdir -ChildPath $PID"));
        assert!(command.contains("New-Item -ItemType Directory -Force -LiteralPath $refdir"));
        assert!(command.contains("function CleanupParent"));
        assert!(command.contains("[IO.Path]::GetDirectoryName($tmp)"));
        assert!(command.contains("[IO.Path]::GetFileName($parent) -like 'rustle-agent-*'"));
        assert!(command.contains("Remove-Item -LiteralPath $marker -Force"));
        assert!(command.contains("Get-Process -Id $id -ErrorAction SilentlyContinue"));
        assert!(command.contains("Remove-Item -LiteralPath $refdir -Force"));
        assert!(command.contains("Remove-Item -LiteralPath $tmp -Force"));
        assert!(command.contains("CleanupParent"));
        assert!(command.contains("& $tmp agent"));
        assert_eq!(
            remote_agent_upload_command(platform),
            WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND
        );
    }

    #[test]
    fn windows_uploaded_helper_command_constructs_command_for_each_helper_kind() {
        let platform = RemotePlatform {
            os: "windows",
            arch: "x86_64",
        };

        for (kind, subcommand) in [
            (HelperKind::StdioAgent, "agent"),
            (HelperKind::QuicAgent, "quic-agent"),
            (HelperKind::QuicBridgeNative, "quic-bridge-agent"),
        ] {
            let command =
                uploaded_helper_command("C:\\Temp\\rustle-agent.exe", platform, kind.subcommand());

            assert!(command.contains(&format!("& $tmp {subcommand}")));
        }
    }

    #[test]
    fn posix_remote_agent_upload_command_is_used_for_unix_platforms() {
        assert_eq!(
            remote_agent_upload_command(RemotePlatform {
                os: "macos",
                arch: "aarch64",
            }),
            POSIX_REMOTE_AGENT_UPLOAD_COMMAND
        );
    }

    #[test]
    fn remote_agent_upload_commands_stage_in_private_temp_dirs() {
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("umask 077"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("mktemp -d"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("rustle-agent.XXXXXX"));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("chmod 700 \"$dir\""));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("p=\"$dir/rustle-agent\""));
        assert!(POSIX_REMOTE_AGENT_UPLOAD_COMMAND.contains("trap cleanup EXIT HUP INT TERM"));

        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("[Guid]::NewGuid()"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("New-Item -ItemType Directory"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("'rustle-agent.exe'"));
        assert!(WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("[IO.FileMode]::CreateNew"));
        assert!(
            WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND.contains("Remove-Item -LiteralPath $dir -Recurse")
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_remote_agent_upload_command_creates_private_executable_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = env::temp_dir().join(format!(
            "rustle-upload-temp-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        std::fs::create_dir(&root).expect("create upload temp root");
        let temp = TempTree { path: root };
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(POSIX_REMOTE_AGENT_UPLOAD_COMMAND)
            .env("TMPDIR", &temp.path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn POSIX upload command");
        child
            .stdin
            .as_mut()
            .expect("upload command stdin")
            .write_all(b"agent")
            .expect("write upload command stdin");
        let output = child.wait_with_output().expect("wait for upload command");
        assert!(
            output.status.success(),
            "upload command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let remote_path = PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("upload path is UTF-8")
                .trim(),
        );
        assert_eq!(remote_path.file_name().unwrap(), "rustle-agent");
        assert!(remote_path.starts_with(&temp.path));
        let parent = remote_path.parent().expect("uploaded file has parent");
        assert!(parent
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("rustle-agent."));
        assert_eq!(
            std::fs::metadata(parent)
                .expect("private upload dir exists")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&remote_path)
                .expect("uploaded helper exists")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read(&remote_path).expect("read uploaded helper"),
            b"agent"
        );

        let cleanup = Command::new("sh")
            .arg("-c")
            .arg(uploaded_posix_agent_cleanup_command(
                remote_path.to_str().expect("upload path is UTF-8"),
            ))
            .status()
            .expect("run cleanup command");
        assert!(cleanup.success(), "cleanup command failed");
        assert!(!parent.exists(), "private upload dir should be removed");
    }

    #[test]
    fn uploaded_agent_sha256_command_uses_remote_hash_tools() {
        let command = uploaded_agent_sha256_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );

        assert!(command.contains("p='/tmp/rustle'\\''agent'"));
        assert!(command.contains("command -v sha256sum"));
        assert!(command.contains("sha256sum \"$p\" | awk '{print $1}'"));
        assert!(command.contains("command -v shasum"));
        assert!(command.contains("shasum -a 256 \"$p\" | awk '{print $1}'"));
        assert!(command.contains("command -v openssl"));
        assert!(command.contains("openssl dgst -sha256 -r \"$p\" | awk '{print $1}'"));
        assert!(command.contains("no remote SHA-256 command found"));
    }

    #[test]
    fn windows_uploaded_agent_sha256_command_uses_get_file_hash() {
        let command = uploaded_agent_sha256_command(
            "C:\\Temp\\rustle'agent.exe",
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            },
        );

        assert!(command.starts_with("powershell.exe -NoProfile -NonInteractive"));
        assert!(command.contains("$p='C:\\Temp\\rustle''agent.exe'"));
        assert!(command.contains("Get-FileHash -Algorithm SHA256 -LiteralPath $p"));
        assert!(command.contains(".Hash.ToLowerInvariant()"));
    }

    #[test]
    fn uploaded_agent_cleanup_command_quotes_path_and_refs() {
        let posix = uploaded_agent_cleanup_command(
            "/tmp/rustle'agent",
            RemotePlatform {
                os: "linux",
                arch: "x86_64",
            },
        );
        assert_eq!(
            posix,
            "p='/tmp/rustle'\\''agent'; rm -f \"$p\"; rm -rf \"$p.refs\"; parent=${p%/*}; base=${parent##*/}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac"
        );

        let windows = uploaded_agent_cleanup_command(
            "C:\\Temp\\rustle'agent.exe",
            RemotePlatform {
                os: "windows",
                arch: "x86_64",
            },
        );
        assert!(windows.contains("$p='C:\\Temp\\rustle''agent.exe'"));
        assert!(windows.contains("Remove-Item -LiteralPath $p -Force"));
        assert!(windows.contains("Remove-Item -LiteralPath ($p+'.refs') -Recurse -Force"));
        assert!(windows.contains("[IO.Path]::GetDirectoryName($p)"));
        assert!(windows.contains("[IO.Path]::GetFileName($parent) -like 'rustle-agent-*'"));
        assert!(windows.contains("Remove-Item -LiteralPath $parent -Recurse -Force"));
    }

    #[cfg(unix)]
    #[test]
    fn uploaded_agent_cleanup_removes_unverified_posix_staging_tree() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let parent = env::temp_dir().join(format!(
            "rustle-agent.cleanup-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree {
            path: parent.clone(),
        };
        std::fs::create_dir(&temp.path).expect("create private staging dir");

        let agent_path = temp.path.join("rustle-agent");
        let refdir = PathBuf::from(format!("{}.refs", agent_path.display()));
        std::fs::write(&agent_path, b"unverified").expect("write unverified helper");
        std::fs::create_dir(&refdir).expect("create refs dir");
        std::fs::write(refdir.join("12345"), b"stale lane marker").expect("write refs marker");

        let cleanup = Command::new("sh")
            .arg("-c")
            .arg(uploaded_posix_agent_cleanup_command(
                agent_path.to_str().expect("staging path is UTF-8"),
            ))
            .status()
            .expect("run POSIX cleanup command");
        assert!(cleanup.success(), "cleanup command failed");

        assert!(!agent_path.exists(), "unverified helper should be removed");
        assert!(!refdir.exists(), "refs directory should be removed");
        assert!(!parent.exists(), "private staging dir should be removed");
    }

    #[test]
    fn sha256_hex_validation_accepts_only_complete_digests() {
        assert!(is_sha256_hex(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ));
        assert!(is_sha256_hex(
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
        ));
        assert!(!is_sha256_hex("9f86d081"));
        assert!(!is_sha256_hex(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a0z"
        ));
    }

    #[tokio::test]
    async fn sha256_file_hex_hashes_local_file() {
        struct TempFile {
            path: PathBuf,
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        let path = env::temp_dir().join(format!(
            "rustle-sha256-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempFile { path };
        tokio::fs::write(&temp.path, b"test")
            .await
            .expect("write test file");

        assert_eq!(
            sha256_file_hex(&temp.path).await.expect("hash test file"),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uploaded_helper_command_keeps_staged_binary_until_last_lane_exits_for_each_kind() {
        use std::os::unix::fs::PermissionsExt;

        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        struct ChildGuard {
            children: Vec<std::process::Child>,
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                for child in &mut self.children {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        fn wait_for_files(dir: &Path, wanted: usize) -> Vec<PathBuf> {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                let mut files = std::fs::read_dir(dir)
                    .expect("read wait directory")
                    .map(|entry| entry.expect("read wait entry").path())
                    .collect::<Vec<_>>();
                files.sort();
                if files.len() >= wanted {
                    return files;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for {wanted} files in {}",
                    dir.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_any_child_exit(children: &mut [std::process::Child]) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if children
                    .iter_mut()
                    .any(|child| child.try_wait().expect("poll child").is_some())
                {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for one uploaded-agent wrapper to exit"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_all_children_exit(children: &mut [std::process::Child]) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if children
                    .iter_mut()
                    .all(|child| child.try_wait().expect("poll child").is_some())
                {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for uploaded-agent wrappers to exit"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_absent(path: &Path) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if !path.exists() {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for {} to be removed",
                    path.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn dir_entry_count(path: &Path) -> usize {
            std::fs::read_dir(path)
                .map(|entries| entries.filter_map(Result::ok).count())
                .unwrap_or(0)
        }

        fn assert_refcounted_cleanup_for_kind(kind: HelperKind) {
            let root = env::temp_dir().join(format!(
                "rustle-uploaded-{}-test-{}-{:?}",
                kind.subcommand(),
                std::process::id(),
                StdInstant::now()
            ));
            let temp = TempTree { path: root };
            std::fs::create_dir_all(&temp.path).expect("create temp tree");
            let ready_dir = temp.path.join("ready");
            let release_dir = temp.path.join("release");
            std::fs::create_dir(&ready_dir).expect("create ready dir");
            std::fs::create_dir(&release_dir).expect("create release dir");

            let agent_path = temp.path.join("rustle-agent");
            std::fs::write(
                &agent_path,
                "#!/bin/sh\n\
                 set -eu\n\
                 if [ \"${1:-}\" != \"$RUSTLE_FAKE_HELPER_SUBCOMMAND\" ]; then exit 64; fi\n\
                 : > \"$RUSTLE_FAKE_AGENT_READY_DIR/$$\"\n\
                 while [ ! -f \"$RUSTLE_FAKE_AGENT_RELEASE_DIR/$$\" ]; do sleep 0.05; done\n",
            )
            .expect("write fake uploaded helper");
            let mut perms = std::fs::metadata(&agent_path)
                .expect("fake helper metadata")
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&agent_path, perms).expect("chmod fake helper");

            let command = uploaded_helper_command(
                agent_path.to_str().expect("utf-8 temp path"),
                RemotePlatform {
                    os: "linux",
                    arch: "x86_64",
                },
                kind.subcommand(),
            );
            let mut children = ChildGuard {
                children: (0..2)
                    .map(|_| {
                        Command::new("sh")
                            .arg("-c")
                            .arg(&command)
                            .env("RUSTLE_FAKE_HELPER_SUBCOMMAND", kind.subcommand())
                            .env("RUSTLE_FAKE_AGENT_READY_DIR", &ready_dir)
                            .env("RUSTLE_FAKE_AGENT_RELEASE_DIR", &release_dir)
                            .spawn()
                            .expect("spawn uploaded-helper wrapper")
                    })
                    .collect(),
            };
            let refdir = PathBuf::from(format!("{}.refs", agent_path.display()));

            let ready = wait_for_files(&ready_dir, 2);
            assert!(agent_path.exists(), "staged helper disappeared early");
            assert!(refdir.exists(), "refdir should exist while lanes run");
            assert_eq!(dir_entry_count(&refdir), 2);

            let first_release = release_dir.join(ready[0].file_name().expect("ready file name"));
            std::fs::write(first_release, b"").expect("release one fake helper");
            wait_for_any_child_exit(&mut children.children);
            assert!(
                agent_path.exists(),
                "staged helper should remain while another lane is active"
            );
            assert_eq!(dir_entry_count(&refdir), 1);

            for ready_file in &ready[1..] {
                std::fs::write(
                    release_dir.join(ready_file.file_name().expect("ready file name")),
                    b"",
                )
                .expect("release remaining fake helper");
            }
            wait_for_all_children_exit(&mut children.children);
            wait_for_absent(&agent_path);
            wait_for_absent(&refdir);
        }

        for kind in [
            HelperKind::StdioAgent,
            HelperKind::QuicAgent,
            HelperKind::QuicBridgeNative,
        ] {
            assert_refcounted_cleanup_for_kind(kind);
        }
    }
}
