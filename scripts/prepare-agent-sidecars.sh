#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/smoke-lib.sh"

DEFAULT_TARGETS=(
  x86_64-unknown-linux-musl
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
  aarch64-pc-windows-msvc
)

RELEASE_TAG="${RUSTLE_AGENT_RELEASE_TAG:-}"
RELEASE_REPO="${RUSTLE_AGENT_RELEASE_REPO:-0verflowme/rustle}"
TARGETS="${RUSTLE_AGENT_TARGETS:-${DEFAULT_TARGETS[*]}}"
OUT_DIR="${RUSTLE_AGENT_DIR:-${RUSTLE_AGENT_OUTPUT_DIR:-${REPO_ROOT}/target/rustle-agent-dir}}"
ARCHIVE_DIR="${RUSTLE_AGENT_ARCHIVE_DIR:-}"
FORCE="${RUSTLE_AGENT_FORCE:-0}"
REQUIRE_ALL="${RUSTLE_AGENT_REQUIRE_ALL:-}"
SKIP_CHECKSUMS="${RUSTLE_AGENT_SKIP_CHECKSUMS:-0}"

if [[ -z "$ARCHIVE_DIR" ]]; then
  if [[ -n "$RELEASE_TAG" ]]; then
    ARCHIVE_DIR="${REPO_ROOT}/target/rustle-agent-downloads/${RELEASE_TAG}"
  else
    ARCHIVE_DIR="${REPO_ROOT}/dist"
  fi
fi
if [[ -z "$REQUIRE_ALL" ]]; then
  if [[ -n "$RELEASE_TAG" ]]; then
    REQUIRE_ALL=1
  else
    REQUIRE_ALL=0
  fi
fi

case "$FORCE" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_AGENT_FORCE must be 0 or 1" ;;
esac
case "$REQUIRE_ALL" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_AGENT_REQUIRE_ALL must be 0 or 1" ;;
esac
case "$SKIP_CHECKSUMS" in
  0 | 1) ;;
  *) smoke_die "RUSTLE_AGENT_SKIP_CHECKSUMS must be 0 or 1" ;;
esac

mkdir -p "$ARCHIVE_DIR" "$OUT_DIR"

archive_name() {
  local target="$1"
  if [[ "$target" == *windows* ]]; then
    printf 'rustle-%s.zip\n' "$target"
  else
    printf 'rustle-%s.tar.gz\n' "$target"
  fi
}

package_name() {
  printf 'rustle-%s\n' "$1"
}

binary_name() {
  if [[ "$1" == *windows* ]]; then
    printf 'rustle.exe\n'
  else
    printf 'rustle\n'
  fi
}

platform_key() {
  case "$1" in
    x86_64-unknown-linux-* ) printf 'linux-x86_64\n' ;;
    aarch64-unknown-linux-* ) printf 'linux-aarch64\n' ;;
    x86_64-apple-darwin ) printf 'macos-x86_64\n' ;;
    aarch64-apple-darwin ) printf 'macos-aarch64\n' ;;
    x86_64-pc-windows-msvc ) printf 'windows-x86_64\n' ;;
    aarch64-pc-windows-msvc ) printf 'windows-aarch64\n' ;;
    *) smoke_die "unsupported Rustle agent target: $1" ;;
  esac
}

target_suffix() {
  if [[ "$1" == *windows* ]]; then
    printf '.exe\n'
  else
    printf '\n'
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

checksum_entry() {
  local checksum_file="$1"
  local archive="$2"
  local archive_base
  archive_base="$(basename "$archive")"
  awk -v name="$archive_base" '{
    path = $2
    sub(/^.*\//, "", path)
    if (path == name) {
      print $1
      exit
    }
  }' "$checksum_file"
}

verify_archive_checksum() {
  local archive="$1"
  local checksum_file="${RUSTLE_AGENT_CHECKSUMS:-${ARCHIVE_DIR}/SHA256SUMS}"
  [[ "$SKIP_CHECKSUMS" == "0" ]] || return 0
  [[ -f "$checksum_file" ]] || return 0

  local expected
  expected="$(checksum_entry "$checksum_file" "$archive")"
  if [[ -z "$expected" ]]; then
    smoke_die "checksum file ${checksum_file} has no entry for $(basename "$archive")"
  fi

  local actual
  actual="$(sha256_file "$archive")"
  if [[ "$actual" != "$expected" ]]; then
    smoke_die "checksum mismatch for $(basename "$archive"): expected ${expected}, got ${actual}"
  fi
}

download_release_assets() {
  [[ -n "$RELEASE_TAG" ]] || return 0
  smoke_require curl
  local base_url="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_TAG}"

  if [[ "$SKIP_CHECKSUMS" == "0" && ! -f "${ARCHIVE_DIR}/SHA256SUMS" ]]; then
    smoke_info "downloading SHA256SUMS for ${RELEASE_REPO}@${RELEASE_TAG}"
    curl -fsSL -o "${ARCHIVE_DIR}/SHA256SUMS" "${base_url}/SHA256SUMS"
  fi

  local target
  for target in $TARGETS; do
    local archive="${ARCHIVE_DIR}/$(archive_name "$target")"
    if [[ -f "$archive" && "$FORCE" != "1" ]]; then
      continue
    fi
    smoke_info "downloading $(basename "$archive") from ${RELEASE_REPO}@${RELEASE_TAG}"
    curl -fsSL -o "$archive" "${base_url}/$(basename "$archive")"
  done
}

extract_archive() {
  local target="$1"
  local archive="$2"
  local package
  package="$(package_name "$target")"
  local dest="${OUT_DIR}/${package}"

  if [[ -d "$dest" && "$FORCE" != "1" ]]; then
    return 0
  fi

  local tmp="${OUT_DIR}/.${package}.tmp.$$"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  case "$archive" in
    *.tar.gz)
      tar -xzf "$archive" -C "$tmp"
      ;;
    *.zip)
      smoke_require unzip
      unzip -q "$archive" -d "$tmp"
      ;;
    *)
      smoke_die "unsupported release archive extension: $archive"
      ;;
  esac

  if [[ ! -d "${tmp}/${package}" ]]; then
    rm -rf "$tmp"
    smoke_die "archive $(basename "$archive") did not contain ${package}/"
  fi

  rm -rf "$dest"
  mv "${tmp}/${package}" "$dest"
  rm -rf "$tmp"
}

copy_existing_package() {
  local target="$1"
  local source="${ARCHIVE_DIR}/$(package_name "$target")"
  local dest="${OUT_DIR}/$(package_name "$target")"
  [[ -d "$source" ]] || return 1
  if [[ "$source" == "$dest" ]]; then
    return 0
  fi
  if [[ -d "$dest" && "$FORCE" != "1" ]]; then
    return 0
  fi
  rm -rf "$dest"
  cp -R "$source" "$OUT_DIR/"
}

create_alias() {
  local alias_path="$1"
  local target_path="$2"
  [[ -f "$target_path" ]] || smoke_die "cannot create alias for missing sidecar: $target_path"
  if [[ -d "$alias_path" ]]; then
    return 0
  fi
  if [[ ( -e "$alias_path" || -L "$alias_path" ) && "$FORCE" != "1" ]]; then
    return 0
  fi
  rm -f "$alias_path"
  ln -s "$target_path" "$alias_path" 2>/dev/null || cp "$target_path" "$alias_path"
  chmod +x "$alias_path" 2>/dev/null || true
}

create_alias_if_missing() {
  local alias_path="$1"
  local target_path="$2"
  if [[ -e "$alias_path" || -L "$alias_path" ]]; then
    return 0
  fi
  create_alias "$alias_path" "$target_path"
}

create_aliases_for_target() {
  local target="$1"
  local package
  package="$(package_name "$target")"
  local binary
  binary="$(binary_name "$target")"
  local sidecar="${OUT_DIR}/${package}/${binary}"
  [[ -f "$sidecar" ]] || return 1
  chmod +x "$sidecar" 2>/dev/null || true

  local suffix
  suffix="$(target_suffix "$target")"
  create_alias "${OUT_DIR}/rustle-agent-${target}${suffix}" "$sidecar"
  create_alias "${OUT_DIR}/rustle-${target}${suffix}" "$sidecar"

  local platform
  platform="$(platform_key "$target")"
  create_alias_if_missing "${OUT_DIR}/rustle-agent-${platform}${suffix}" "$sidecar"
  create_alias_if_missing "${OUT_DIR}/rustle-${platform}${suffix}" "$sidecar"
}

download_release_assets

prepared=0
for target in $TARGETS; do
  archive="${ARCHIVE_DIR}/$(archive_name "$target")"
  package="$(package_name "$target")"
  if [[ -f "$archive" ]]; then
    verify_archive_checksum "$archive"
    extract_archive "$target" "$archive"
  elif ! copy_existing_package "$target"; then
    if [[ "$REQUIRE_ALL" == "1" ]]; then
      smoke_die "missing release archive or package for ${target} under ${ARCHIVE_DIR}"
    fi
    smoke_info "skipping ${target}; no archive or package under ${ARCHIVE_DIR}"
    continue
  fi

  if create_aliases_for_target "$target"; then
    prepared=$((prepared + 1))
    smoke_info "prepared ${package} in ${OUT_DIR}"
  else
    smoke_die "prepared package ${package} is missing its Rustle binary"
  fi
done

if [[ "$prepared" -eq 0 ]]; then
  smoke_die "no Rustle agent sidecars were prepared from ${ARCHIVE_DIR}"
fi

smoke_info "Rustle agent sidecars ready: ${OUT_DIR}"
printf 'RUSTLE_AGENT_DIR=%s\n' "$OUT_DIR"
