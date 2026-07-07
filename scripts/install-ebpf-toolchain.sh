#!/usr/bin/env bash
# Install the clang/llvm/bpftool stack needed to compile CO-RE eBPF objects in CI
# and on a fresh Ubuntu/Debian host. Requires sudo for apt.
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "install-ebpf-toolchain.sh targets Debian/Ubuntu (apt-get)." >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common
# Ubuntu 24.04+ ships a standalone bpftool package; prefer it over the kernel-versioned
# linux-tools wrapper, which often breaks on GitHub runners.
sudo apt-get install -y bpftool || true
sudo apt-get install -y "linux-tools-$(uname -r)" || sudo apt-get install -y linux-tools-generic || true

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "warning: /sys/kernel/btf/vmlinux is missing — CO-RE needs BTF (kernel 5.2+)." >&2
fi
