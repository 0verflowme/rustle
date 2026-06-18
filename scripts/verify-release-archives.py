#!/usr/bin/env python3
"""Verify assembled Rustle release archives and SHA-256 checksums."""

from __future__ import annotations

import hashlib
import io
import pathlib
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass


DOC_FILES = [
    "README.md",
    "ARCHITECTURE.md",
    "RELEASE.md",
    "STATUS.md",
    "TROUBLESHOOTING.md",
]


@dataclass(frozen=True)
class ReleaseArchive:
    target: str
    archive: str
    windows: bool = False

    @property
    def package(self) -> str:
        return f"rustle-{self.target}"

    @property
    def binary(self) -> str:
        return "rustle.exe" if self.windows else "rustle"

    @property
    def expected_files(self) -> set[str]:
        return {f"{self.package}/{self.binary}"} | {
            f"{self.package}/{name}" for name in DOC_FILES
        }


EXPECTED = [
    ReleaseArchive(
        "x86_64-unknown-linux-gnu",
        "rustle-x86_64-unknown-linux-gnu.tar.gz",
    ),
    ReleaseArchive(
        "x86_64-unknown-linux-musl",
        "rustle-x86_64-unknown-linux-musl.tar.gz",
    ),
    ReleaseArchive(
        "aarch64-unknown-linux-gnu",
        "rustle-aarch64-unknown-linux-gnu.tar.gz",
    ),
    ReleaseArchive(
        "aarch64-unknown-linux-musl",
        "rustle-aarch64-unknown-linux-musl.tar.gz",
    ),
    ReleaseArchive(
        "x86_64-apple-darwin",
        "rustle-x86_64-apple-darwin.tar.gz",
    ),
    ReleaseArchive(
        "aarch64-apple-darwin",
        "rustle-aarch64-apple-darwin.tar.gz",
    ),
    ReleaseArchive(
        "x86_64-pc-windows-msvc",
        "rustle-x86_64-pc-windows-msvc.zip",
        windows=True,
    ),
    ReleaseArchive(
        "aarch64-pc-windows-msvc",
        "rustle-aarch64-pc-windows-msvc.zip",
        windows=True,
    ),
]


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_basename(path: pathlib.Path) -> str:
    return path.name


def reject_unsafe_member(name: str, archive: pathlib.Path) -> None:
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise SystemExit(f"{archive.name} contains unsafe archive member {name!r}")


def validate_file_set(
    archive: pathlib.Path,
    release: ReleaseArchive,
    files: set[str],
) -> None:
    expected = release.expected_files
    missing = sorted(expected - files)
    if missing:
        raise SystemExit(f"{archive.name} is missing expected files: {missing}")

    if release.windows:
        wintun = sorted(
            path for path in files if pathlib.PurePosixPath(path).name.lower() == "wintun.dll"
        )
        if wintun:
            raise SystemExit(
                f"{archive.name} must not ship wintun.dll beside rustle.exe: {wintun}"
            )

    allowed = expected | {release.package}
    unexpected = sorted(files - allowed)
    if unexpected:
        raise SystemExit(f"{archive.name} contains unexpected files: {unexpected}")


def verify_tar_archive(path: pathlib.Path, release: ReleaseArchive) -> None:
    files: set[str] = set()
    executable = False
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            reject_unsafe_member(member.name, path)
            normalized = member.name.rstrip("/")
            if member.isfile():
                files.add(normalized)
                if normalized == f"{release.package}/{release.binary}":
                    executable = bool(member.mode & stat.S_IXUSR)
            elif member.isdir():
                files.add(normalized)
            else:
                raise SystemExit(
                    f"{path.name} contains unsupported archive member {member.name!r}"
                )

    validate_file_set(path, release, files)
    if not executable:
        raise SystemExit(f"{path.name} does not mark {release.binary} executable")


def zip_entry_is_directory(info: zipfile.ZipInfo) -> bool:
    return info.is_dir() or info.filename.endswith("/")


def verify_zip_archive(path: pathlib.Path, release: ReleaseArchive) -> None:
    files: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            reject_unsafe_member(info.filename, path)
            normalized = info.filename.rstrip("/")
            if zip_entry_is_directory(info):
                files.add(normalized)
            else:
                files.add(normalized)

    validate_file_set(path, release, files)


def find_release_archives(root: pathlib.Path) -> dict[str, pathlib.Path]:
    archives: dict[str, pathlib.Path] = {}
    duplicates: dict[str, list[pathlib.Path]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if not (path.name.endswith(".tar.gz") or path.name.endswith(".zip")):
            continue
        name = archive_basename(path)
        if name in archives:
            duplicates.setdefault(name, [archives[name]]).append(path)
            continue
        archives[name] = path

    if duplicates:
        details = {
            name: [str(path) for path in paths] for name, paths in sorted(duplicates.items())
        }
        raise SystemExit(f"duplicate release archive names: {details}")

    expected = {release.archive for release in EXPECTED}
    actual = set(archives)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise SystemExit(
            f"release archive set mismatch: missing={missing} unexpected={unexpected}"
        )

    return archives


def parse_checksums(path: pathlib.Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    duplicates: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise SystemExit(f"invalid checksum line {line_number}: {line!r}")
        digest, filename = parts
        if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
            raise SystemExit(f"invalid SHA-256 digest on line {line_number}: {digest!r}")
        name = pathlib.PurePosixPath(filename.replace("\\", "/")).name
        if name in checksums:
            duplicates.add(name)
        checksums[name] = digest.lower()

    if duplicates:
        raise SystemExit(f"duplicate checksum entries: {sorted(duplicates)}")

    expected = {release.archive for release in EXPECTED}
    actual = set(checksums)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise SystemExit(
            f"checksum archive set mismatch: missing={missing} unexpected={unexpected}"
        )

    return checksums


def verify(root: pathlib.Path, checksum_path: pathlib.Path) -> None:
    archives = find_release_archives(root)
    checksums = parse_checksums(checksum_path)

    for release in EXPECTED:
        path = archives[release.archive]
        actual = sha256_file(path)
        expected = checksums[release.archive]
        if actual != expected:
            raise SystemExit(
                f"checksum mismatch for {release.archive}: expected {expected}, got {actual}"
            )

        if release.windows:
            verify_zip_archive(path, release)
        else:
            verify_tar_archive(path, release)


def add_tar_file(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def make_tar_archive(path: pathlib.Path, release: ReleaseArchive) -> None:
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo(release.package)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        add_tar_file(
            archive,
            f"{release.package}/{release.binary}",
            b"fake rustle binary\n",
            0o755,
        )
        for doc in DOC_FILES:
            add_tar_file(
                archive,
                f"{release.package}/{doc}",
                f"{doc}\n".encode("utf-8"),
                0o644,
            )


def make_zip_archive(
    path: pathlib.Path,
    release: ReleaseArchive,
    *,
    include_wintun: bool = False,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{release.package}/", b"")
        archive.writestr(f"{release.package}/{release.binary}", b"fake rustle binary\n")
        for doc in DOC_FILES:
            archive.writestr(f"{release.package}/{doc}", f"{doc}\n")
        if include_wintun:
            archive.writestr(f"{release.package}/wintun.dll", b"driver\n")


def write_fake_release_set(root: pathlib.Path, *, bad_windows_wintun: bool = False) -> None:
    for release in EXPECTED:
        path = root / release.archive
        if release.windows:
            make_zip_archive(path, release, include_wintun=bad_windows_wintun)
        else:
            make_tar_archive(path, release)

    checksums = []
    for release in EXPECTED:
        archive = root / release.archive
        checksums.append(f"{sha256_file(archive)}  {archive.name}\n")
    (root / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")


def assert_rejects(root: pathlib.Path, expected_message: str) -> None:
    try:
        verify(root, root / "SHA256SUMS")
    except SystemExit as exc:
        message = str(exc)
        if expected_message not in message:
            raise AssertionError(
                f"expected {expected_message!r} in rejection, got {message!r}"
            ) from exc
    else:
        raise AssertionError("expected release archive verification to reject sample")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        write_fake_release_set(root)
        verify(root, root / "SHA256SUMS")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        write_fake_release_set(root)
        lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        digest, name = lines[0].split()
        lines[0] = f"{'0' if digest[0] != '0' else '1'}{digest[1:]}  {name}"
        (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert_rejects(root, "checksum mismatch")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        write_fake_release_set(root, bad_windows_wintun=True)
        checksums = []
        for release in EXPECTED:
            archive = root / release.archive
            checksums.append(f"{sha256_file(archive)}  {archive.name}\n")
        (root / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
        assert_rejects(root, "must not ship wintun.dll")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        write_fake_release_set(root)
        (root / EXPECTED[0].archive).unlink()
        assert_rejects(root, "release archive set mismatch")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: verify-release-archives.py DIST_DIR SHA256SUMS\n"
            "       verify-release-archives.py --self-test"
        )

    verify(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))


if __name__ == "__main__":
    main()
