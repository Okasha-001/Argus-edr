#!/usr/bin/env bash
# Regenerate bpf/vmlinux.h from the running kernel's BTF. This is the CO-RE type
# header; it is machine-specific and therefore git-ignored, regenerated locally.
#
# Usage:
#   ./scripts/gen-vmlinux.sh              # default: dump from running kernel BTF
#   ./scripts/gen-vmlinux.sh --ci         # CI mode: download pre-built header
#   ./scripts/gen-vmlinux.sh <output>     # specify output path
#   ./scripts/gen-vmlinux.sh --ci <out>   # CI mode with custom output path
set -euo pipefail

CI_MODE=false
out="bpf/vmlinux.h"

# Parse arguments: --ci flag and optional output path.
for arg in "$@"; do
  case "$arg" in
    --ci) CI_MODE=true ;;
    *)    out="$arg" ;;
  esac
done

# ---------------------------------------------------------------------------
# CI fallback: download a reference vmlinux.h from the libbpf/vmlinux.h repo.
# This is sufficient for compile-only checks (clang syntax/type verification)
# but NOT for runtime loading — the verifier runs in kernel-matrix.yml VMs
# that have real BTF kernels.
# ---------------------------------------------------------------------------
ci_download() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86" ;;
    aarch64|arm64) arch="aarch64" ;;
  esac
  local base_url="https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/${arch}"
  local url="${base_url}/vmlinux.h"
  echo "CI mode: downloading pre-built vmlinux.h for ${arch}…" >&2
  
  local tmp_out
  tmp_out="$(mktemp)"
  
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$tmp_out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp_out" "$url"
  else
    echo "error: neither curl nor wget is available." >&2
    rm -f "$tmp_out"
    exit 1
  fi

  # Resolve Git symlink if the content is just a filename pointing to a versioned header
  local target
  target="$(tr -d '\r\n' < "$tmp_out" | xargs)"
  if [[ "$target" =~ ^vmlinux_[0-9].*\.h$ ]]; then
    echo "CI mode: resolving symlink target ${target}…" >&2
    local resolved_url="${base_url}/${target}"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --retry 3 -o "$out" "$resolved_url"
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$out" "$resolved_url"
    fi
  else
    mv "$tmp_out" "$out"
  fi
  rm -f "$tmp_out" || true
  echo "wrote $out ($(wc -l < "$out") lines) [CI pre-built]"
}

if $CI_MODE; then
  ci_download
  exit 0
fi

# ---------------------------------------------------------------------------
# Local mode: dump from the running kernel's BTF (the default).
# ---------------------------------------------------------------------------
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "error: /sys/kernel/btf/vmlinux is missing — this kernel lacks BTF." >&2
  echo "       CO-RE needs BTF (kernel 5.2+ built with CONFIG_DEBUG_INFO_BTF)." >&2
  echo "       Hint: pass --ci to download a pre-built header for compile checks." >&2
  exit 1
fi

# Try to find a working bpftool binary. The linux-tools wrapper often fails on CI when
# the packaged tools don't match the running kernel; prefer a real binary on disk.
find_bpftool() {
  local candidate
  for candidate in \
    "$(command -v bpftool 2>/dev/null || true)" \
    /usr/sbin/bpftool \
    /usr/bin/bpftool \
    $(find /usr/lib/linux-tools /usr/lib/linux-tools-* -name bpftool -type f -executable 2>/dev/null); do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    if "$candidate" --version >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

BPFTOOL=""
if BPFTOOL="$(find_bpftool)"; then
  :
else
  echo "error: bpftool not found or not working — install bpftool or linux-tools." >&2
  echo "       e.g. sudo apt-get install -y bpftool linux-tools-common" >&2
  echo "       Hint: pass --ci to download a pre-built header for compile checks." >&2
  exit 1
fi

"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
