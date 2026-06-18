use std::path::Path;

use anyhow::{bail, Context, Result};
use ring::digest;
use russh::client::Handle;
use tokio::io::AsyncReadExt;

use crate::remote_exec::run_remote_command_collect;
use crate::remote_platform::RemotePlatform;
use crate::ssh_control::Client;

use super::command::{powershell_quote, shell_quote};

pub(super) async fn verify_uploaded_agent_binary(
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::time::Instant as StdInstant;

    use super::*;

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
}
