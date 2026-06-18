use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ring::hmac;
use russh::keys::PublicKey;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};

#[derive(Clone, Debug)]
pub(crate) struct HostKeyVerifier {
    host: String,
    port: u16,
    known_hosts: Option<PathBuf>,
    insecure_accept: bool,
    accept_new: bool,
}

impl HostKeyVerifier {
    pub(crate) fn new(
        host: String,
        port: u16,
        known_hosts: Option<PathBuf>,
        insecure_accept: bool,
        accept_new: bool,
    ) -> Self {
        Self {
            host,
            port,
            known_hosts,
            insecure_accept,
            accept_new,
        }
    }

    pub(crate) fn verify(&self, server_public_key: &PublicKey) -> Result<bool> {
        if self.insecure_accept {
            eprintln!(
                "ssh: insecurely accepting host key for {} ({})",
                self.known_hosts_hostport(),
                server_public_key.fingerprint(Default::default())
            );
            return Ok(true);
        }

        let path = self.known_hosts_path()?;
        let input = match std::fs::read_to_string(&path) {
            Ok(input) => input,
            Err(err) if self.accept_new && err.kind() == std::io::ErrorKind::NotFound => {
                String::new()
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read known_hosts file {}", path.display()))
            }
        };
        let candidates = self.host_match_candidates();
        let mut host_matched = false;
        let mut key_mismatch = false;

        for entry in KnownHosts::new(&input) {
            let entry = entry.with_context(|| format!("failed to parse {}", path.display()))?;
            if !known_hosts_entry_matches(entry.host_patterns(), &candidates) {
                continue;
            }

            host_matched = true;
            let key_matches = entry.public_key().key_data() == server_public_key.key_data();
            if matches!(entry.marker(), Some(Marker::Revoked)) && key_matches {
                bail!(
                    "SSH host key for {} is marked revoked in {}",
                    self.known_hosts_hostport(),
                    path.display()
                );
            }

            if key_matches && entry.marker().is_none() {
                return Ok(true);
            }
            if key_matches && matches!(entry.marker(), Some(Marker::CertAuthority)) {
                continue;
            }
            key_mismatch = true;
        }

        let fingerprint = server_public_key.fingerprint(Default::default());
        if key_mismatch {
            bail!(
                "SSH host key mismatch for {}; presented fingerprint {}; update {} only if the server key changed intentionally",
                self.known_hosts_hostport(),
                fingerprint,
                path.display()
            );
        }
        if host_matched {
            bail!(
                "SSH host entry for {} exists in {}, but no usable plain host-key entry matched fingerprint {}",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
        }

        if self.accept_new {
            self.append_known_host(&path, server_public_key)?;
            eprintln!(
                "ssh: recorded new host key for {} in {} ({})",
                self.known_hosts_hostport(),
                path.display(),
                fingerprint
            );
            return Ok(true);
        }

        bail!(
            "SSH host {} is not in {}; verify the fingerprint {}, then add it with ssh-keyscan, use --accept-new-host-key to trust and record this first key, or use --insecure-accept-host-key only for a controlled lab",
            self.known_hosts_hostport(),
            path.display(),
            fingerprint
        )
    }

    fn append_known_host(&self, path: &Path, server_public_key: &PublicKey) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_known_hosts_parent_dir(parent)?;
            }
        }

        let key = server_public_key
            .to_openssh()
            .context("failed to encode SSH server public key")?;
        let entry = format!("{} {}\n", self.known_hosts_hostport(), key);
        append_known_hosts_entry(path, &entry)
            .with_context(|| format!("failed to append host key to {}", path.display()))
    }

    fn known_hosts_path(&self) -> Result<PathBuf> {
        if let Some(path) = &self.known_hosts {
            return Ok(path.clone());
        }
        default_known_hosts_path()
            .ok_or_else(|| anyhow!("could not locate home directory for ~/.ssh/known_hosts"))
    }

    fn known_hosts_hostport(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }

    fn host_match_candidates(&self) -> Vec<String> {
        let mut candidates = Vec::new();
        candidates.push(self.known_hosts_hostport());
        if self.port == 22 {
            candidates.push(self.host.clone());
        }
        let lowercase_host = self.host.to_ascii_lowercase();
        if lowercase_host != self.host {
            if self.port == 22 {
                candidates.push(lowercase_host.clone());
            } else {
                candidates.push(format!("[{lowercase_host}]:{}", self.port));
            }
        }
        dedupe_strings(candidates)
    }
}

fn default_known_hosts_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .map(|home| home.join(".ssh").join("known_hosts"))
}

fn create_known_hosts_parent_dir(path: &Path) -> Result<()> {
    let existed = path.exists();
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create known_hosts directory {}", path.display()))?;
    if existed {
        Ok(())
    } else {
        set_known_hosts_parent_permissions(path)
    }
}

#[cfg(unix)]
fn set_known_hosts_parent_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_parent_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn append_known_hosts_entry(path: &Path, entry: &str) -> Result<()> {
    let needs_separator = known_hosts_needs_leading_newline(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    if needs_separator {
        file.write_all(b"\n")?;
    }
    file.write_all(entry.as_bytes())?;
    file.sync_all()?;
    set_known_hosts_file_permissions(path)
}

fn known_hosts_needs_leading_newline(path: &Path) -> Result<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(false);
    }
    use std::io::{Read, Seek};
    file.seek(std::io::SeekFrom::End(-1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    Ok(byte[0] != b'\n')
}

#[cfg(unix)]
fn set_known_hosts_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_known_hosts_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn known_hosts_entry_matches(patterns: &HostPatterns, candidates: &[String]) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => patterns_match(patterns, candidates),
        HostPatterns::HashedName { salt, hash } => candidates.iter().any(|candidate| {
            hashed_known_host_matches(salt, hash, candidate)
                || hashed_known_host_matches(salt, hash, &candidate.to_ascii_lowercase())
        }),
    }
}

pub(crate) fn patterns_match(patterns: &[String], candidates: &[String]) -> bool {
    let mut matched_positive = false;
    for pattern in patterns {
        let (negated, pattern) = if let Some(pattern) = pattern.strip_prefix('!') {
            (true, pattern)
        } else {
            (false, pattern.as_str())
        };
        let matched = candidates
            .iter()
            .any(|candidate| glob_match_case_insensitive(pattern, candidate));
        if matched && negated {
            return false;
        }
        matched_positive |= matched;
    }
    matched_positive
}

fn glob_match_case_insensitive(pattern: &str, candidate: &str) -> bool {
    glob_match(
        pattern.to_ascii_lowercase().as_bytes(),
        candidate.to_ascii_lowercase().as_bytes(),
    )
}

fn glob_match(pattern: &[u8], candidate: &[u8]) -> bool {
    let (mut p, mut c) = (0, 0);
    let mut star = None;
    let mut star_candidate = 0;

    while c < candidate.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == candidate[c]) {
            p += 1;
            c += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_candidate = c;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_candidate += 1;
            c = star_candidate;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn hashed_known_host_matches(salt: &[u8], expected_hash: &[u8; 20], candidate: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let tag = hmac::sign(&key, candidate.as_bytes());
    tag.as_ref() == expected_hash
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.iter().any(|existing| existing == &value) {
            unique.push(value);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use russh::keys::PublicKey;
    use ssh_key::known_hosts::HostPatterns;

    const TEST_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";
    const OTHER_ED25519_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";

    #[test]
    fn known_hosts_patterns_support_wildcards_ports_and_negation() {
        assert!(patterns_match(
            &["*.example.com".to_owned()],
            &["api.example.com".to_owned()]
        ));
        assert!(patterns_match(
            &["[*.example.com]:2222".to_owned()],
            &["[api.example.com]:2222".to_owned()]
        ));
        assert!(!patterns_match(
            &["*.example.com".to_owned(), "!bad.example.com".to_owned()],
            &["bad.example.com".to_owned()]
        ));
    }

    #[test]
    fn known_hosts_hashed_name_matches_hmac_sha1_candidate() {
        let salt = b"01234567890123456789";
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&key, b"example.com");
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(tag.as_ref());

        assert!(known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["example.com".to_owned()]
        ));
        assert!(!known_hosts_entry_matches(
            &HostPatterns::HashedName {
                salt: salt.to_vec(),
                hash,
            },
            &["other.example.com".to_owned()]
        ));
    }

    #[test]
    fn host_key_verifier_accepts_matching_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_mismatched_known_hosts_entry() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("mismatch must fail");
        assert!(err.to_string().contains("mismatch"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accepts_bracketed_non_default_port() {
        let path = write_temp_known_hosts(&format!("[test.example.com]:2222 {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            2222,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_rejects_revoked_key() {
        let path =
            write_temp_known_hosts(&format!("@revoked test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier.verify(&key).expect_err("revoked key must fail");
        assert!(err.to_string().contains("revoked"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_records_missing_host_key() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let root = unique_temp_path("rustle-known-hosts-accept-new");
        let temp = TempTree { path: root };
        let path = temp.path.join(".ssh").join("known_hosts");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was created");
        assert_eq!(recorded, format!("test.example.com {TEST_ED25519_KEY}\n"));

        let strict = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        assert!(strict.verify(&key).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .expect("known_hosts parent metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("known_hosts metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn host_key_verifier_accept_new_preserves_existing_line_without_newline() {
        let path = write_temp_known_hosts(&format!("other.example.com {OTHER_ED25519_KEY}"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        assert!(verifier.verify(&key).unwrap());
        let recorded = std::fs::read_to_string(&path).expect("known_hosts was updated");
        assert_eq!(
            recorded,
            format!("other.example.com {OTHER_ED25519_KEY}\ntest.example.com {TEST_ED25519_KEY}\n")
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_accept_new_rejects_changed_known_host() {
        let path = write_temp_known_hosts(&format!("test.example.com {TEST_ED25519_KEY}\n"));
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            true,
        );
        let key = OTHER_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("accept-new must reject changed keys");
        assert!(err.to_string().contains("mismatch"));
        let recorded = std::fs::read_to_string(&path).expect("known_hosts still readable");
        assert!(!recorded.contains(OTHER_ED25519_KEY));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn host_key_verifier_unknown_host_error_mentions_accept_new() {
        let path = write_temp_known_hosts("");
        let verifier = HostKeyVerifier::new(
            "test.example.com".to_owned(),
            22,
            Some(path.clone()),
            false,
            false,
        );
        let key = TEST_ED25519_KEY.parse::<PublicKey>().unwrap();

        let err = verifier
            .verify(&key)
            .expect_err("unknown host must fail in strict mode");
        let message = err.to_string();
        assert!(message.contains("--accept-new-host-key"));
        assert!(message.contains("--insecure-accept-host-key"));
        assert!(message.contains("SHA256:"));
        std::fs::remove_file(path).ok();
    }

    fn write_temp_known_hosts(contents: &str) -> PathBuf {
        let path = unique_temp_path("rustle-known-hosts").with_extension("tmp");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn unique_temp_path(prefix: &str) -> PathBuf {
        static NEXT_TEMP_PATH: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_TEMP_PATH.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{sequence}-{now}", std::process::id()))
    }
}
