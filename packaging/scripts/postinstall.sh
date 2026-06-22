#!/bin/sh
# Runs after the deb/rpm unpacks the files. Enforcement stays OFF until the
# operator edits /etc/argus/config.yaml — installing the package never arms the
# agent. We only register the unit and ensure the log directory exists.
set -e

mkdir -p /var/log/argus

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    echo "ARGUS installed. Review /etc/argus/config.yaml, then: systemctl enable --now argus"
fi
