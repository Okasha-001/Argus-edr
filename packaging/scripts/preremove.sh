#!/bin/sh
# Runs before the package is removed: stop and disable the agent so removal does
# not leave a running service pointed at deleted binaries.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now argus >/dev/null 2>&1 || true
fi
