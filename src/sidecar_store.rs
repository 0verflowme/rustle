use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::remote_platform::RemotePlatform;

pub(crate) const RUSTLE_AGENT_DIR_ENV: &str = "RUSTLE_AGENT_DIR";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalHelperBinary {
    pub(crate) path: PathBuf,
    source: LocalHelperBinarySource,
}

impl LocalHelperBinary {
    fn current_executable(path: PathBuf) -> Self {
        Self {
            path,
            source: LocalHelperBinarySource::CurrentExecutable,
        }
    }

    fn sidecar(path: PathBuf) -> Self {
        Self {
            path,
            source: LocalHelperBinarySource::Sidecar,
        }
    }

    pub(crate) fn is_sidecar(&self) -> bool {
        self.source == LocalHelperBinarySource::Sidecar
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalHelperBinarySource {
    CurrentExecutable,
    Sidecar,
}

pub(crate) fn local_helper_binary_for_platform(
    current_exe: &Path,
    platform: RemotePlatform,
) -> Result<LocalHelperBinary> {
    local_helper_binary_for_platform_with_explicit_dirs(
        current_exe,
        platform,
        &explicit_agent_search_dirs(),
    )
}

fn local_helper_binary_for_platform_with_explicit_dirs(
    current_exe: &Path,
    platform: RemotePlatform,
    explicit_dirs: &[PathBuf],
) -> Result<LocalHelperBinary> {
    let local = RemotePlatform::local()?;
    if platform == local {
        if let Some(candidate) =
            explicit_portable_linux_agent_binary_for_platform(platform, explicit_dirs)
        {
            return Ok(LocalHelperBinary::sidecar(candidate));
        }
        return Ok(LocalHelperBinary::current_executable(
            current_exe.to_path_buf(),
        ));
    }

    let candidates =
        local_agent_binary_candidates_with_explicit_dirs(current_exe, platform, explicit_dirs);
    if let Some(candidate) = candidates.iter().find(|path| path.is_file()) {
        return Ok(LocalHelperBinary::sidecar(candidate.clone()));
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

fn explicit_portable_linux_agent_binary_for_platform(
    platform: RemotePlatform,
    explicit_dirs: &[PathBuf],
) -> Option<PathBuf> {
    if platform.os != "linux" {
        return None;
    }
    portable_linux_agent_binary_candidates_in_dirs(platform, explicit_dirs)
        .into_iter()
        .find(|path| path.is_file())
}

fn local_agent_binary_candidates_with_explicit_dirs(
    current_exe: &Path,
    platform: RemotePlatform,
    explicit_dirs: &[PathBuf],
) -> Vec<PathBuf> {
    dedupe_paths(agent_binary_candidates_in_dirs(
        platform,
        &local_agent_search_dirs_with_explicit_dirs(current_exe, explicit_dirs),
    ))
}

#[cfg(test)]
pub(crate) fn local_agent_search_dirs(current_exe: &Path) -> Vec<PathBuf> {
    local_agent_search_dirs_with_explicit_dirs(current_exe, &explicit_agent_search_dirs())
}

fn explicit_agent_search_dirs() -> Vec<PathBuf> {
    env::var_os(RUSTLE_AGENT_DIR_ENV)
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

fn local_agent_search_dirs_with_explicit_dirs(
    current_exe: &Path,
    explicit_dirs: &[PathBuf],
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.extend(explicit_dirs.iter().cloned());
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

fn portable_linux_agent_binary_candidates_in_dirs(
    platform: RemotePlatform,
    dirs: &[PathBuf],
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for dir in dirs {
        for triple in remote_platform_target_triples(platform)
            .iter()
            .copied()
            .filter(|triple| triple.ends_with("-unknown-linux-musl"))
        {
            candidates.push(dir.join(format!("rustle-agent-{triple}")));
            candidates.push(dir.join(format!("rustle-{triple}")));
            candidates.push(dir.join(format!("rustle-{triple}")).join("rustle"));
            candidates.push(dir.join(format!("rustle-{triple}")).join("rustle-agent"));
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant as StdInstant;

    #[test]
    fn local_agent_selection_marks_current_binary_for_matching_platform() {
        let current_exe = PathBuf::from(if cfg!(windows) {
            "C:\\rustle\\rustle.exe"
        } else {
            "/tmp/rustle"
        });
        let local = RemotePlatform::local().expect("local platform is supported");
        let helper = local_helper_binary_for_platform(&current_exe, local)
            .expect("current binary works for matching platform");

        assert_eq!(helper.path, current_exe);
        assert!(!helper.is_sidecar());
    }

    #[test]
    fn linux_local_agent_selection_marks_explicit_packaged_sidecar() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let local = RemotePlatform::local().expect("local platform is supported");
        if local.os != "linux" {
            return;
        }

        let root = env::temp_dir().join(format!(
            "rustle-linux-local-sidecar-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let bin_dir = temp.path.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create sidecar test bin dir");

        let current_exe = bin_dir.join("rustle");
        std::fs::write(&current_exe, "current gnu controller").expect("write fake current binary");

        let triple = remote_platform_target_triples(local)
            .first()
            .expect("local Linux platform has a release target");
        let package_dir = bin_dir.join(format!("rustle-{triple}"));
        std::fs::create_dir(&package_dir).expect("create sidecar package dir");
        let sidecar = package_dir.join("rustle");
        std::fs::write(&sidecar, "portable sidecar").expect("write fake sidecar");

        let helper = local_helper_binary_for_platform_with_explicit_dirs(
            &current_exe,
            local,
            std::slice::from_ref(&bin_dir),
        )
        .expect("select local Linux helper");

        assert_eq!(helper.path, sidecar);
        assert!(helper.is_sidecar());
    }

    #[test]
    fn explicit_portable_sidecar_selection_is_limited_to_linux_musl() {
        let dir = PathBuf::from("/opt/rustle");
        let linux_x64 = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let macos_x64 = RemotePlatform {
            os: "macos",
            arch: "x86_64",
        };
        let linux_candidates =
            portable_linux_agent_binary_candidates_in_dirs(linux_x64, std::slice::from_ref(&dir));

        assert!(
            linux_candidates.contains(&dir.join("rustle-x86_64-unknown-linux-musl").join("rustle"))
        );
        assert!(!linux_candidates
            .iter()
            .any(|candidate| candidate.display().to_string().contains("linux-gnu")));
        assert!(portable_linux_agent_binary_candidates_in_dirs(
            macos_x64,
            std::slice::from_ref(&dir),
        )
        .is_empty());
    }

    #[test]
    fn cross_platform_agent_candidates_include_release_package_shapes() {
        let dir = PathBuf::from("/opt/rustle");
        let linux = RemotePlatform {
            os: "linux",
            arch: "x86_64",
        };
        let linux_candidates = agent_binary_candidates_in_dirs(linux, std::slice::from_ref(&dir));

        assert_eq!(
            linux_candidates.first(),
            Some(&dir.join("rustle-agent-linux-x86_64"))
        );
        let musl = dir.join("rustle-x86_64-unknown-linux-musl").join("rustle");
        let gnu = dir.join("rustle-x86_64-unknown-linux-gnu").join("rustle");
        let musl_index = linux_candidates
            .iter()
            .position(|candidate| candidate == &musl)
            .expect("Linux musl release package shape is a candidate");
        let gnu_index = linux_candidates
            .iter()
            .position(|candidate| candidate == &gnu)
            .expect("Linux gnu release package shape is a candidate");
        assert!(musl_index < gnu_index, "static Linux sidecar is preferred");

        let windows = RemotePlatform {
            os: "windows",
            arch: "aarch64",
        };
        let windows_candidates =
            agent_binary_candidates_in_dirs(windows, std::slice::from_ref(&dir));
        assert!(windows_candidates.contains(
            &dir.join("rustle-aarch64-pc-windows-msvc")
                .join("rustle.exe")
        ));
    }

    #[test]
    fn cross_platform_release_package_shape_is_a_sidecar_candidate() {
        struct TempTree {
            path: PathBuf,
        }

        impl Drop for TempTree {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        fn nonlocal_platform() -> RemotePlatform {
            let local = RemotePlatform::local().expect("local platform is supported");
            [
                RemotePlatform {
                    os: "linux",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "linux",
                    arch: "aarch64",
                },
                RemotePlatform {
                    os: "macos",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "macos",
                    arch: "aarch64",
                },
                RemotePlatform {
                    os: "windows",
                    arch: "x86_64",
                },
                RemotePlatform {
                    os: "windows",
                    arch: "aarch64",
                },
            ]
            .into_iter()
            .find(|platform| *platform != local)
            .expect("at least one nonlocal supported platform")
        }

        let root = env::temp_dir().join(format!(
            "rustle-agent-sidecar-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        let bin_dir = temp.path.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create sidecar test bin dir");

        let current_exe = bin_dir.join(if cfg!(windows) {
            "rustle-current.exe"
        } else {
            "rustle-current"
        });
        std::fs::write(&current_exe, "local").expect("write fake current binary");

        let remote = nonlocal_platform();
        let triple = remote_platform_target_triples(remote)
            .first()
            .expect("remote platform has a release target");
        let package_dir = bin_dir.join(format!("rustle-{triple}"));
        std::fs::create_dir(&package_dir).expect("create sidecar package dir");
        let sidecar = package_dir.join(if remote.is_windows() {
            "rustle.exe"
        } else {
            "rustle"
        });
        std::fs::write(&sidecar, "agent").expect("write fake sidecar");

        let candidates = agent_binary_candidates_in_dirs(remote, std::slice::from_ref(&bin_dir));
        let selected = candidates
            .iter()
            .find(|path| path.is_file())
            .expect("matching sidecar should be a selectable candidate");
        assert_eq!(selected, &sidecar);
    }

    #[test]
    fn local_agent_search_dirs_include_release_package_parent() {
        let current_exe = PathBuf::from("/opt/rustle/rustle-aarch64-apple-darwin/rustle");
        let dirs = local_agent_search_dirs(&current_exe);

        assert!(dirs.contains(&PathBuf::from("/opt/rustle/rustle-aarch64-apple-darwin")));
        assert!(dirs.contains(&PathBuf::from("/opt/rustle")));
        assert!(dirs.contains(&PathBuf::from("/opt/rustle/rustle-agent-dir")));
    }

    #[test]
    fn local_agent_search_dirs_include_target_agent_dir_for_dev_builds() {
        let current_exe = PathBuf::from("/work/rustle/target/debug/rustle");
        let dirs = local_agent_search_dirs(&current_exe);

        assert!(dirs.contains(&PathBuf::from("/work/rustle/target/rustle-agent-dir")));
    }

    #[test]
    fn cross_platform_agent_candidates_support_env_style_agent_dirs() {
        let agent_dir = PathBuf::from("/var/lib/rustle-agents");
        let linux = RemotePlatform {
            os: "linux",
            arch: "aarch64",
        };
        let candidates = agent_binary_candidates_in_dirs(linux, std::slice::from_ref(&agent_dir));

        assert!(candidates.contains(
            &agent_dir
                .join("rustle-aarch64-unknown-linux-musl")
                .join("rustle")
        ));
        assert!(candidates.contains(&agent_dir.join("rustle-agent-linux-aarch64")));
    }
}
