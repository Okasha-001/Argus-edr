#!/usr/bin/env bash
# Install the toolchain needed to build ARGUS on a Debian/Ubuntu host:
# the eBPF compiler (clang/llvm), bpftool, and Go. Requires sudo.
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This helper targets Debian/Ubuntu. On other distros install the" >&2
  echo "equivalents of: clang llvm bpftool go (1.24+)." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  clang llvm libbpf-dev build-essential \
  "linux-headers-$(uname -r)" || true
sudo apt-get install -y "linux-tools-$(uname -r)" || sudo apt-get install -y linux-tools-generic || true

if ! command -v go >/dev/null 2>&1; then
  echo
  echo "Go was not found. Install Go 1.24+ from https://go.dev/dl/ and put it on PATH."
fi

echo
echo "Verifying BTF (required for CO-RE):"
ls -l /sys/kernel/btf/vmlinux || echo "  WARNING: no BTF — see scripts/gen-vmlinux.sh"
echo
echo "Next: make all && make replay"
