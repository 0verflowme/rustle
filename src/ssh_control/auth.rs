use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use russh::client::{AuthResult, Handle};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{Algorithm, HashAlg, PrivateKey};

use crate::SshArgs;

use super::config::PreparedSshConnection;
use super::session::Client;

const SSH_PASSWORD_FILE_ENV: &str = "RUSTLE_SSH_PASSWORD_FILE";

pub(crate) fn resolve_ssh_password(args: &SshArgs) -> Result<Option<String>> {
    if args.password.is_some() && args.password_file.is_some() {
        bail!("--password-file cannot be combined with --password");
    }
    match (&args.password, &args.password_file) {
        (_, Some(path)) => read_password_file(path).map(Some),
        (Some(Some(value)), None) => {
            eprintln!(
                "ssh: warning: inline --password values may be visible to other local users; prefer --password-file or an interactive prompt"
            );
            Ok(Some(value.clone()))
        }
        (Some(None), None) => {
            let password = match read_password_file_from_env()? {
                Some(value) => value,
                None => rpassword::prompt_password("SSH password: ")
                    .context("failed to read password from terminal")?,
            };
            Ok(Some(password))
        }
        (None, None) => Ok(None),
    }
}

pub(crate) fn read_password_file_from_env() -> Result<Option<String>> {
    let Some(path) = env::var_os(SSH_PASSWORD_FILE_ENV) else {
        return Ok(None);
    };
    read_password_file(Path::new(&path)).map(Some)
}

pub(crate) fn read_password_file(path: &Path) -> Result<String> {
    let mut password = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read SSH password file {}", path.display()))?;
    while matches!(password.as_bytes().last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    Ok(password)
}

pub(super) async fn authenticate(
    handle: &mut Handle<Client>,
    user: &str,
    prepared: &PreparedSshConnection,
) -> Result<()> {
    for identity in &prepared.identity_files {
        let key = load_private_key(identity)?;
        let result = handle
            .authenticate_publickey(user.to_owned(), key)
            .await
            .with_context(|| {
                format!(
                    "public-key authentication failed for {}",
                    identity.display()
                )
            })?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    if let Some(password) = &prepared.password {
        let result = handle
            .authenticate_password(user.to_owned(), password.clone())
            .await
            .context("password authentication failed")?;
        if matches!(result, AuthResult::Success) {
            return Ok(());
        }
    }

    bail!("authentication failed; provide --identity, --password, or both")
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyWithHashAlg> {
    let key_data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    let key = PrivateKey::from_openssh(&key_data)
        .with_context(|| format!("failed to parse private key {}", path.display()))?;
    let hash_alg = match key.algorithm() {
        Algorithm::Rsa { .. } => Some(HashAlg::Sha512),
        _ => None,
    };

    Ok(PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::time::Instant as StdInstant;

    use clap::Parser;

    use super::*;
    use crate::cli::Cli;

    #[test]
    fn password_file_reader_strips_shell_newlines_only() {
        let path = env::temp_dir().join(format!(
            "rustle-password-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, " secret value \r\n").unwrap();

        let password = read_password_file(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        assert_eq!(password, " secret value ");
    }

    #[test]
    fn ssh_password_file_option_reads_password_without_argv_secret() {
        let path = env::temp_dir().join(format!(
            "rustle-password-file-option-test-{}-{}",
            std::process::id(),
            StdInstant::now().elapsed().as_nanos()
        ));
        std::fs::write(&path, "file secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "rustle",
            "-r",
            "alice@example.com",
            "--password-file",
            path.to_str().expect("password path is UTF-8"),
            "10.0.0.0/8",
        ])
        .expect("compact CLI with password file");

        assert_eq!(cli.compact.ssh.password, None);
        assert_eq!(
            cli.compact.ssh.password_file.as_deref(),
            Some(path.as_path())
        );
        assert_eq!(
            resolve_ssh_password(&cli.compact.ssh).expect("read password file"),
            Some("file secret".to_owned())
        );

        std::fs::remove_file(&path).unwrap();
    }
}
