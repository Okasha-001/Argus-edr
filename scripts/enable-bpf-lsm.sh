#!/usr/bin/env bash
# Enable the BPF LSM so the enforcement programs can load. Most distros
# (Ubuntu included) do not enable it by default — it must be added to the
# kernel's lsm= boot parameter. Requires root and a reboot.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (it edits GRUB and requires a reboot)." >&2
  exit 1
fi

current="$(cat /sys/kernel/security/lsm 2>/dev/null || echo '')"
echo "current LSMs: ${current:-unknown}"

if [[ ",${current}," == *",bpf,"* ]]; then
  echo "BPF LSM is already active. Nothing to do."
  exit 0
fi

grub=/etc/default/grub
if [[ ! -f "$grub" ]]; then
  echo "error: $grub not found; add 'lsm=...,bpf' to your bootloader manually." >&2
  exit 1
fi

cp "$grub" "${grub}.argus.bak"
echo "backed up $grub to ${grub}.argus.bak"

# Append bpf to the existing lsm= list, or add a full list if none is set.
if grep -q 'lsm=' "$grub"; then
  sed -i 's/\(lsm=[a-z0-9,_-]*\)/\1,bpf/' "$grub"
else
  sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf"/' "$grub"
fi

update-grub
echo
echo "Done. Reboot, then verify with:  cat /sys/kernel/security/lsm   (expect ...,bpf)"
