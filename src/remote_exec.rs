use anyhow::{bail, Context, Result};
use russh::client::Handle;

use crate::ssh_control::Client;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_command_output_success_and_failure_context_are_stable() {
        let ok = RemoteCommandOutput {
            stdout: b"done\n".to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
        };
        ok.ensure_success("remote probe")
            .expect("zero exit status succeeds");

        let err = RemoteCommandOutput {
            stdout: Vec::new(),
            stderr: b"bad things\n".to_vec(),
            exit_status: Some(127),
        }
        .ensure_success("remote probe")
        .expect_err("nonzero exit status fails")
        .to_string();

        assert_eq!(
            err,
            "remote probe failed with exit status Some(127): bad things"
        );
    }
}
