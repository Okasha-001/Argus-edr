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

# Try to find a working bpftool binary. The default wrapper might fail if there's a kernel version mismatch.
BPFTOOL=""
if command -v bpftool >/dev/null 2>&1 && bpftool --version >/dev/null 2>&1; then
  BPFTOOL="bpftool"
else
  # Search for any installed bpftool binary directly in the linux-tools directories
  # to bypass the broken wrapper script.
  candidate=$(find /usr/lib/linux-tools /usr/lib/linux-tools-* -name bpftool -type f -executable 2>/dev/null | head -n 1)
  if [[ -n "$candidate" ]]; then
    BPFTOOL="$candidate"
  fi
fi

if [[ -z "$BPFTOOL" ]]; then
  echo "error: bpftool not found or not working — install linux-tools for your kernel." >&2
  exit 1
fi

"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
