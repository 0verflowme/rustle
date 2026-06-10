#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

smoke_require tar

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rustle-agent-sidecars.XXXXXX")"
cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

ARCHIVE_DIR="${TMP_ROOT}/archives"
SRC_DIR="${TMP_ROOT}/src"
AGENT_DIR="${TMP_ROOT}/agents"
mkdir -p "$ARCHIVE_DIR" "$SRC_DIR" "$AGENT_DIR"

make_unix_archive() {
  local target="$1"
  local marker="$2"
  local package="rustle-${target}"
  local package_dir="${SRC_DIR}/${package}"

  rm -rf "$package_dir"
  mkdir -p "$package_dir"
  printf '%s\n' "$marker" >"${package_dir}/rustle"
  chmod +x "${package_dir}/rustle"
  tar -czf "${ARCHIVE_DIR}/${package}.tar.gz" -C "$SRC_DIR" "$package"
}

make_windows_archive() {
  local target="$1"
  local marker="$2"
  local package="rustle-${target}"
  local package_dir="${SRC_DIR}/${package}"
  local py

  py="$(smoke_python)"
  rm -rf "$package_dir"
  mkdir -p "$package_dir"
  printf '%s\n' "$marker" >"${package_dir}/rustle.exe"

  "$py" - "${ARCHIVE_DIR}/${package}.zip" "$package_dir" "$package" <<'PY'
import pathlib
import sys
import zipfile

archive = pathlib.Path(sys.argv[1])
package_dir = pathlib.Path(sys.argv[2])
package = sys.argv[3]

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in package_dir.rglob("*"):
        if path.is_file():
            arcname = pathlib.PurePosixPath(package) / path.relative_to(package_dir).as_posix()
            zf.write(path, str(arcname))
PY
}

make_checksums() {
  local archive_root
  local archive_base
  archive_root="$(dirname "$ARCHIVE_DIR")"
  archive_base="$(basename "$ARCHIVE_DIR")"
  (
    cd "$archive_root"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${archive_base}"/rustle-* >"${ARCHIVE_DIR}/SHA256SUMS"
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "${archive_base}"/rustle-* >"${ARCHIVE_DIR}/SHA256SUMS"
    else
      smoke_die "missing required command: sha256sum or shasum"
    fi
  )
}

targets="x86_64-unknown-linux-musl x86_64-unknown-linux-gnu aarch64-unknown-linux-musl aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
make_unix_archive x86_64-unknown-linux-musl linux-x64-musl-sidecar
make_unix_archive x86_64-unknown-linux-gnu linux-x64-gnu-sidecar
make_unix_archive aarch64-unknown-linux-musl linux-arm64-musl-sidecar
make_unix_archive aarch64-unknown-linux-gnu linux-arm64-gnu-sidecar
make_unix_archive x86_64-apple-darwin macos-x64-sidecar
make_unix_archive aarch64-apple-darwin macos-arm64-sidecar

if command -v unzip >/dev/null 2>&1; then
  targets="${targets} x86_64-pc-windows-msvc aarch64-pc-windows-msvc"
  make_windows_archive x86_64-pc-windows-msvc windows-x64-sidecar
  make_windows_archive aarch64-pc-windows-msvc windows-arm-sidecar
else
  smoke_info "unzip unavailable; Windows sidecar archive extraction check skipped"
fi

make_checksums

RUSTLE_AGENT_ARCHIVE_DIR="$ARCHIVE_DIR" \
RUSTLE_AGENT_DIR="$AGENT_DIR" \
RUSTLE_AGENT_TARGETS="$targets" \
RUSTLE_AGENT_REQUIRE_ALL=1 \
RUSTLE_AGENT_FORCE=1 \
  "${SCRIPT_DIR}/prepare-agent-sidecars.sh" >"${TMP_ROOT}/prepare.out"

grep -q "^RUSTLE_AGENT_DIR=${AGENT_DIR}$" "${TMP_ROOT}/prepare.out"
test -x "${AGENT_DIR}/rustle-x86_64-unknown-linux-musl/rustle"
test -x "${AGENT_DIR}/rustle-x86_64-unknown-linux-gnu/rustle"
test -x "${AGENT_DIR}/rustle-aarch64-unknown-linux-musl/rustle"
test -x "${AGENT_DIR}/rustle-aarch64-unknown-linux-gnu/rustle"
test -x "${AGENT_DIR}/rustle-x86_64-apple-darwin/rustle"
test -x "${AGENT_DIR}/rustle-aarch64-apple-darwin/rustle"
test -f "${AGENT_DIR}/rustle-agent-x86_64-unknown-linux-musl"
test -f "${AGENT_DIR}/rustle-agent-x86_64-unknown-linux-gnu"
test -f "${AGENT_DIR}/rustle-agent-aarch64-unknown-linux-musl"
test -f "${AGENT_DIR}/rustle-agent-aarch64-unknown-linux-gnu"
test -f "${AGENT_DIR}/rustle-agent-x86_64-apple-darwin"
test -f "${AGENT_DIR}/rustle-agent-aarch64-apple-darwin"
grep -q 'linux-x64-musl-sidecar' "${AGENT_DIR}/rustle-agent-linux-x86_64"
grep -q 'linux-x64-musl-sidecar' "${AGENT_DIR}/rustle-linux-x86_64"
grep -q 'linux-arm64-musl-sidecar' "${AGENT_DIR}/rustle-agent-linux-aarch64"
grep -q 'linux-arm64-musl-sidecar' "${AGENT_DIR}/rustle-linux-aarch64"
grep -q 'macos-x64-sidecar' "${AGENT_DIR}/rustle-agent-macos-x86_64"
grep -q 'macos-arm64-sidecar' "${AGENT_DIR}/rustle-agent-macos-aarch64"

if [[ "$targets" == *aarch64-pc-windows-msvc* ]]; then
  test -f "${AGENT_DIR}/rustle-x86_64-pc-windows-msvc/rustle.exe"
  test -f "${AGENT_DIR}/rustle-aarch64-pc-windows-msvc/rustle.exe"
  test -f "${AGENT_DIR}/rustle-agent-windows-x86_64.exe"
  test -f "${AGENT_DIR}/rustle-agent-windows-aarch64.exe"
  grep -q 'windows-x64-sidecar' "${AGENT_DIR}/rustle-agent-windows-x86_64.exe"
  grep -q 'windows-arm-sidecar' "${AGENT_DIR}/rustle-agent-windows-aarch64.exe"
fi

smoke_info "agent sidecar preparation smoke passed"
