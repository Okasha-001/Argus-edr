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

if ! command -v bpftool >/dev/null 2>&1; then
  echo "error: bpftool not found — install linux-tools for your kernel." >&2
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
