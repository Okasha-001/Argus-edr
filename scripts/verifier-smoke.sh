#!/usr/bin/env bash
# Load the compiled eBPF objects and confirm the kernel verifier accepts them.
# This is the per-kernel portability gate: a program that uses a helper or a loop
# shape an older kernel rejects fails here, not in production. Run it under the
# kernel-version matrix (scripts run inside each VM); locally: sudo make verifier-smoke.
#
# The sensor object is required — a rejection fails the run. The LSM object is
# best-effort: loading a BPF-LSM program needs CONFIG_BPF_LSM, which not every
# target kernel ships, so a load failure there is a warning, not a hard error.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
BPFTOOL="${BPFTOOL:-bpftool}"
PIN_BASE="/sys/fs/bpf/argus-smoke"

if [ "$(id -u)" -ne 0 ]; then
    echo "verifier-smoke must run as root (loading eBPF needs privileges)" >&2
    exit 2
fi
if ! command -v "$BPFTOOL" >/dev/null 2>&1; then
    echo "bpftool not found on PATH" >&2
    exit 2
fi
mount | grep -q ' /sys/fs/bpf ' || mount -t bpf bpf /sys/fs/bpf

# load OBJ {required|optional} — loadall runs the verifier on every program in the
# object as it pins them; a clean exit means the verifier accepted them all.
load() {
    local obj="$1" mode="$2"
    local pin="$PIN_BASE/$(basename "$obj" .bpf.o)"
    if [ ! -f "$obj" ]; then
        echo "MISSING: $obj (run 'make bpf' first)" >&2
        [ "$mode" = required ] && exit 1 || return 0
    fi
    rm -rf "$pin"
    mkdir -p "$pin"
    if "$BPFTOOL" prog loadall "$obj" "$pin"; then
        echo "OK: verifier accepted $(basename "$obj")"
        rm -rf "$pin"
        return 0
    fi
    rm -rf "$pin"
    if [ "$mode" = required ]; then
        echo "FAIL: verifier rejected $(basename "$obj") on $(uname -r)" >&2
        exit 1
    fi
    echo "WARN: $(basename "$obj") did not load on $(uname -r) (optional — needs CONFIG_BPF_LSM)"
}

load "$BUILD_DIR/edr.bpf.o" required
load "$BUILD_DIR/edr_lsm.bpf.o" optional
echo "verifier smoke passed on kernel $(uname -r)"
