#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

TARGETS="${RUSTLE_AGENT_BUILD_TARGETS:-x86_64-unknown-linux-musl}"
ARCHIVE_DIR="${RUSTLE_AGENT_ARCHIVE_DIR:-${REPO_ROOT}/dist}"
AGENT_DIR="${RUSTLE_AGENT_DIR:-${REPO_ROOT}/target/rustle-agent-dir}"
USE_ZIG="${RUSTLE_AGENT_BUILD_USE_ZIG:-auto}"
BUILD_PROFILE="${RUSTLE_AGENT_BUILD_PROFILE:-release}"

case "$USE_ZIG" in
  auto | 0 | 1) ;;
  *) smoke_die "RUSTLE_AGENT_BUILD_USE_ZIG must be auto, 0, or 1" ;;
esac
case "$BUILD_PROFILE" in
  release) ;;
  *) smoke_die "RUSTLE_AGENT_BUILD_PROFILE currently supports only release" ;;
esac

if [[ -n "${RUSTLE_AGENT_BUILD_ZIG:-}" ]]; then
  [[ -x "$RUSTLE_AGENT_BUILD_ZIG" ]] || smoke_die "RUSTLE_AGENT_BUILD_ZIG is not executable: $RUSTLE_AGENT_BUILD_ZIG"
  PATH="$(cd -- "$(dirname -- "$RUSTLE_AGENT_BUILD_ZIG")" && pwd):$PATH"
  export PATH
fi

mkdir -p "$ARCHIVE_DIR" "$AGENT_DIR"

archive_name() {
  local target="$1"
  if [[ "$target" == *windows* ]]; then
    printf 'rustle-%s.zip\n' "$target"
  else
    printf 'rustle-%s.tar.gz\n' "$target"
  fi
}

binary_name() {
  if [[ "$1" == *windows* ]]; then
    printf 'rustle.exe\n'
  else
    printf 'rustle\n'
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    smoke_die "missing required command: sha256sum or shasum"
  fi
}

should_use_zig_for_target() {
  local target="$1"
  case "$USE_ZIG" in
    1)
      return 0
      ;;
    0)
      return 1
      ;;
    auto)
      if command -v cargo-zigbuild >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
        case "$(uname -s):$target" in
          Darwin:*unknown-linux*) return 0 ;;
        esac
      fi
      return 1
      ;;
  esac
}

build_target() {
  local target="$1"
  if should_use_zig_for_target "$target"; then
    smoke_info "building ${target} with cargo zigbuild"
    cargo zigbuild --locked --release --target "$target"
  else
    smoke_info "building ${target} with cargo build"
    cargo build --locked --release --target "$target"
  fi
}

package_target() {
  local target="$1"
  local package="rustle-${target}"
  local binary
  binary="$(binary_name "$target")"
  local built="${REPO_ROOT}/target/${target}/release/${binary}"
  [[ -x "$built" ]] || smoke_die "missing built binary for ${target}: $built"

  local stage="${ARCHIVE_DIR}/.${package}.stage.$$"
  rm -rf "$stage"
  mkdir -p "${stage}/${package}"
  cp "$built" "${stage}/${package}/${binary}"
  cp "${REPO_ROOT}/README.md" "${stage}/${package}/"
  cp "${REPO_ROOT}/docs/architecture.md" "${stage}/${package}/ARCHITECTURE.md"
  cp "${REPO_ROOT}/docs/release.md" "${stage}/${package}/RELEASE.md"
  cp "${REPO_ROOT}/docs/status.md" "${stage}/${package}/STATUS.md"
  cp "${REPO_ROOT}/docs/troubleshooting.md" "${stage}/${package}/TROUBLESHOOTING.md"

  local archive="${ARCHIVE_DIR}/$(archive_name "$target")"
  rm -f "$archive"
  if [[ "$archive" == *.zip ]]; then
    smoke_require zip
    (cd "$stage" && zip -qr "$archive" "$package")
  else
    tar -czf "$archive" -C "$stage" "$package"
  fi
  rm -rf "$stage"
  smoke_info "packaged $(basename "$archive") sha256=$(sha256_file "$archive")"
}

write_checksums() {
  local checksum_file="${ARCHIVE_DIR}/SHA256SUMS"
  : >"$checksum_file"
  local archive
  for archive in "$ARCHIVE_DIR"/rustle-*.tar.gz "$ARCHIVE_DIR"/rustle-*.zip; do
    [[ -f "$archive" ]] || continue
    printf '%s  %s\n' "$(sha256_file "$archive")" "$(basename "$archive")" >>"$checksum_file"
  done
  [[ -s "$checksum_file" ]] || smoke_die "no sidecar archives were produced under ${ARCHIVE_DIR}"
}

for target in $TARGETS; do
  build_target "$target"
  package_target "$target"
done

write_checksums

RUSTLE_AGENT_ARCHIVE_DIR="$ARCHIVE_DIR" \
RUSTLE_AGENT_DIR="$AGENT_DIR" \
RUSTLE_AGENT_TARGETS="$TARGETS" \
RUSTLE_AGENT_REQUIRE_ALL=1 \
RUSTLE_AGENT_FORCE=1 \
  "${SCRIPT_DIR}/prepare-agent-sidecars.sh"
