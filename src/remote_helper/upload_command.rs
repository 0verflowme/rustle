use crate::remote_platform::RemotePlatform;

use super::command::{powershell_quote, shell_quote};
use super::kind::HelperKind;

pub(crate) const POSIX_REMOTE_AGENT_UPLOAD_COMMAND: &str = "set -eu; umask 077; base=${TMPDIR:-/tmp}; dir=; cleanup() { [ -n \"$dir\" ] && rm -rf \"$dir\"; }; trap cleanup EXIT HUP INT TERM; dir=$(mktemp -d \"$base/rustle-agent.XXXXXX\"); chmod 700 \"$dir\"; p=\"$dir/rustle-agent\"; cat > \"$p\"; chmod 700 \"$p\"; trap - EXIT HUP INT TERM; printf '%s\\n' \"$p\"";
pub(crate) const WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND: &str = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $d=$env:TEMP; if ([string]::IsNullOrWhiteSpace($d)) { $d=$env:TMP }; if ([string]::IsNullOrWhiteSpace($d)) { $d=[IO.Path]::GetTempPath() }; $dir=Join-Path -Path $d -ChildPath ('rustle-agent-{0}-{1}' -f $PID,[Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $dir -Force | Out-Null; $p=Join-Path -Path $dir -ChildPath 'rustle-agent.exe'; $stdin=[Console]::OpenStandardInput(); try { $out=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $stdin.CopyTo($out) } finally { $out.Dispose(); $stdin.Dispose() } } catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }; [Console]::Out.WriteLine($p)\"";

#[cfg(test)]
pub(crate) fn uploaded_agent_command(remote_path: &str, platform: RemotePlatform) -> String {
    uploaded_helper_command(remote_path, platform, HelperKind::StdioAgent)
}

pub(crate) fn uploaded_helper_command(
    remote_path: &str,
    platform: RemotePlatform,
    kind: HelperKind,
) -> String {
    let helper_subcommand = kind.subcommand();
    if platform.is_windows() {
        uploaded_windows_helper_command(remote_path, helper_subcommand)
    } else {
        uploaded_posix_helper_command(remote_path, helper_subcommand)
    }
}

fn uploaded_posix_helper_command(remote_path: &str, helper_subcommand: &str) -> String {
    let quoted_path = shell_quote(remote_path);
    let runner = if helper_subcommand == HelperKind::StdioAgent.subcommand() {
        format!(
            "( trap '' HUP; while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup_refs ) </dev/null >/dev/null 2>&1 & trap cleanup EXIT HUP INT TERM; \"$tmp\" {helper_subcommand}; status=$?; trap - EXIT HUP INT TERM; cleanup; exit \"$status\""
        )
    } else {
        format!(
            "child=; owner_watcher=; stdin_watcher=; cleanup() {{ exec 3<&- 2>/dev/null || true; if [ -n \"${{owner_watcher:-}}\" ]; then kill \"$owner_watcher\" 2>/dev/null || true; fi; if [ -n \"${{stdin_watcher:-}}\" ]; then kill \"$stdin_watcher\" 2>/dev/null || true; fi; if [ -n \"${{child:-}}\" ] && kill -0 \"$child\" 2>/dev/null; then kill \"$child\" 2>/dev/null || true; wait \"$child\" 2>/dev/null || true; fi; cleanup_refs; }}; trap cleanup EXIT HUP INT TERM; exec 3<&0; \"$tmp\" {helper_subcommand} & child=$!; ( trap '' HUP; while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; kill \"$child\" 2>/dev/null || true; cleanup_refs ) </dev/null >/dev/null 2>&1 & owner_watcher=$!; ( trap '' HUP; while IFS= read -r _; do :; done; kill \"$child\" 2>/dev/null || true ) <&3 >/dev/null 2>&1 & stdin_watcher=$!; exec 3<&-; wait \"$child\"; status=$?; trap - EXIT HUP INT TERM; kill \"$owner_watcher\" 2>/dev/null || true; kill \"$stdin_watcher\" 2>/dev/null || true; wait \"$owner_watcher\" 2>/dev/null || true; wait \"$stdin_watcher\" 2>/dev/null || true; cleanup_refs; exit \"$status\""
        )
    };
    format!(
        "tmp={quoted_path}; refdir=\"$tmp.refs\"; marker=\"$refdir/$$\"; owner=$$; mkdir -p \"$refdir\"; : > \"$marker\"; cleanup_parent() {{ parent=${{tmp%/*}}; base=${{parent##*/}}; case \"$base\" in rustle-agent.*) rmdir \"$parent\" 2>/dev/null || true;; esac; }}; cleanup_refs() {{ rm -f \"$marker\"; for stale in \"$refdir\"/*; do [ -e \"$stale\" ] || continue; pid=${{stale##*/}}; case \"$pid\" in *[!0-9]*) continue;; esac; kill -0 \"$pid\" 2>/dev/null || rm -f \"$stale\"; done; if rmdir \"$refdir\" 2>/dev/null; then rm -f \"$tmp\"; cleanup_parent; fi; }}; cleanup() {{ cleanup_refs; }}; {runner}"
    )
}

fn uploaded_windows_helper_command(remote_path: &str, helper_subcommand: &str) -> String {
    let quoted_path = powershell_quote(remote_path);
    format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$ErrorActionPreference='Stop'; $tmp={quoted_path}; $refdir=$tmp+'.refs'; $marker=Join-Path -Path $refdir -ChildPath $PID; New-Item -ItemType Directory -Force -LiteralPath $refdir | Out-Null; New-Item -ItemType File -Force -LiteralPath $marker | Out-Null; function CleanupParent {{ $parent=[IO.Path]::GetDirectoryName($tmp); if ($parent -and ([IO.Path]::GetFileName($parent) -like 'rustle-agent-*')) {{ Remove-Item -LiteralPath $parent -Recurse -Force -ErrorAction SilentlyContinue }} }}; function Cleanup {{ Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $refdir) {{ Get-ChildItem -LiteralPath $refdir -ErrorAction SilentlyContinue | ForEach-Object {{ $id=0; if ([int]::TryParse($_.Name,[ref]$id)) {{ if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) {{ Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }} }} }}; try {{ Remove-Item -LiteralPath $refdir -Force -ErrorAction Stop; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; CleanupParent }} catch {{}} }} }}; try {{ & $tmp {helper_subcommand}; $status=$LASTEXITCODE }} finally {{ Cleanup }}; exit $status\""
    )
}

pub(crate) fn remote_agent_upload_command(platform: RemotePlatform) -> &'static str {
    if platform.is_windows() {
        WINDOWS_REMOTE_AGENT_UPLOAD_COMMAND
    } else {
        POSIX_REMOTE_AGENT_UPLOAD_COMMAND
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant as StdInstant};

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
        assert!(command
            .contains("while kill -0 \"$owner\" 2>/dev/null; do sleep 1; done; cleanup_refs"));
        assert!(!command.contains("stdin_watcher"));
        assert!(command.contains("cleanup_parent()"));
        assert!(command.contains("cleanup_refs()"));
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
            uploaded_helper_command("/tmp/rustle-agent", posix, HelperKind::StdioAgent)
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
                HelperKind::StdioAgent
            )
        );
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
            let command = uploaded_helper_command("/tmp/rustle-agent", platform, kind);

            assert!(command.contains(&format!("\"$tmp\" {subcommand}")));
            if kind == HelperKind::StdioAgent {
                assert!(!command.contains("stdin_watcher"));
            } else {
                assert!(command.contains("stdin_watcher"));
                assert!(command.contains(&format!("\"$tmp\" {subcommand} & child=$!")));
                assert!(command.contains("while IFS= read -r _; do :; done; kill \"$child\""));
            }
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
            let command = uploaded_helper_command("C:\\Temp\\rustle-agent.exe", platform, kind);

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
                kind,
            );
            let mut children = ChildGuard {
                children: (0..2)
                    .map(|_| {
                        Command::new("sh")
                            .arg("-c")
                            .arg(&command)
                            .stdin(std::process::Stdio::piped())
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

    #[cfg(unix)]
    #[test]
    fn uploaded_quic_helper_command_kills_child_when_stdin_closes() {
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
            child: Option<std::process::Child>,
        }

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(child) = &mut self.child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        fn wait_for_one_file(dir: &Path) -> PathBuf {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                let files = std::fs::read_dir(dir)
                    .expect("read wait directory")
                    .map(|entry| entry.expect("read wait entry").path())
                    .collect::<Vec<_>>();
                if let Some(path) = files.into_iter().next() {
                    return path;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for one file in {}",
                    dir.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_for_child_exit(child: &mut std::process::Child) {
            let deadline = StdInstant::now() + Duration::from_secs(3);
            loop {
                if child.try_wait().expect("poll child").is_some() {
                    return;
                }
                assert!(
                    StdInstant::now() < deadline,
                    "timed out waiting for uploaded QUIC helper wrapper to exit"
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

        let root = env::temp_dir().join(format!(
            "rustle-uploaded-quic-stdin-test-{}-{:?}",
            std::process::id(),
            StdInstant::now()
        ));
        let temp = TempTree { path: root };
        std::fs::create_dir_all(&temp.path).expect("create temp tree");
        let ready_dir = temp.path.join("ready");
        std::fs::create_dir(&ready_dir).expect("create ready dir");

        let agent_path = temp.path.join("rustle-agent");
        std::fs::write(
            &agent_path,
            "#!/bin/sh\n\
             set -eu\n\
             if [ \"${1:-}\" != quic-bridge-agent ]; then exit 64; fi\n\
             : > \"$RUSTLE_FAKE_AGENT_READY_DIR/$$\"\n\
             trap 'exit 0' TERM HUP INT\n\
             while :; do sleep 0.05; done\n",
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
            HelperKind::QuicBridgeNative,
        );
        let mut wrapper = ChildGuard {
            child: Some(
                Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .stdin(std::process::Stdio::piped())
                    .env("RUSTLE_FAKE_AGENT_READY_DIR", &ready_dir)
                    .spawn()
                    .expect("spawn uploaded QUIC helper wrapper"),
            ),
        };

        let refdir = PathBuf::from(format!("{}.refs", agent_path.display()));
        let _ready = wait_for_one_file(&ready_dir);
        assert!(agent_path.exists(), "staged helper disappeared early");
        assert!(refdir.exists(), "refdir should exist while helper runs");

        let child = wrapper.child.as_mut().expect("wrapper child");
        drop(child.stdin.take());
        wait_for_child_exit(child);
        wait_for_absent(&agent_path);
        wait_for_absent(&refdir);
        wrapper.child.take();
    }
}
