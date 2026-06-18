use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use russh::client::Handle;

use crate::remote_exec::run_remote_command_collect;
use crate::remote_platform::{probe_remote_platform, RemotePlatform};
use crate::sidecar_store::local_helper_binary_for_platform;
use crate::ssh_control::Client;

use super::integrity::{sha256_file_hex, verify_uploaded_agent_binary};
use super::kind::HelperKind;
use super::upload_command::{
    remote_agent_upload_command, uploaded_agent_cleanup_command, uploaded_helper_command,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UploadedHelperCommand {
    pub(super) kind: HelperKind,
    pub(super) platform: RemotePlatform,
    pub(super) local_path: PathBuf,
    pub(super) remote_path: String,
    pub(super) command: String,
}

impl UploadedHelperCommand {
    fn new(
        kind: HelperKind,
        platform: RemotePlatform,
        local_path: PathBuf,
        remote_path: String,
    ) -> Self {
        let command = uploaded_helper_command(&remote_path, platform, kind);
        Self {
            kind,
            platform,
            local_path,
            remote_path,
            command,
        }
    }
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

pub(super) async fn stage_uploaded_helper_command(
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

pub(super) async fn cleanup_uploaded_agent_binary(
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
