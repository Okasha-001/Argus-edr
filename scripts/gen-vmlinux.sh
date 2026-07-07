#!/usr/bin/env bash
# Regenerate bpf/vmlinux.h from the running kernel's BTF. This is the CO-RE type
# header; it is machine-specific and therefore git-ignored, regenerated locally.
set -euo pipefail

out="${1:-bpf/vmlinux.h}"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "error: /sys/kernel/btf/vmlinux is missing — this kernel lacks BTF." >&2
  echo "       CO-RE needs BTF (kernel 5.2+ built with CONFIG_DEBUG_INFO_BTF)." >&2
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
  exit 1
fi

"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
