#!/bin/bash
# setup-sandbox.sh — filesystem sandbox for Cowrie and OpenCanary (part of Huginn, AGPL-3.0-or-later).
# Run by install-honeypot.sh and update-honeypot.sh as root. Safe to run again. Someone who gets out of a fake service
# can then only write in that service's own folder. If a service does not start this way, its drop-in is removed again.
set -euo pipefail

sandbox() {  # sandbox UNIT DIR
  local unit="$1" dir="$2" d f want
  [ -f "/etc/systemd/system/$unit.service" ] || return 0
  d="/etc/systemd/system/$unit.service.d"; f="$d/huginn-sandbox.conf"
  want="# Written by Huginn: this service may write only in its own folder.
[Service]
ProtectSystem=strict
ReadWritePaths=$dir
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet="
  if [ -f "$f" ] && [ "$(cat "$f")" = "$want" ]; then echo "    ok $unit already sandboxed"; return 0; fi
  install -d "$d"
  printf '%s\n' "$want" > "$f"
  systemctl daemon-reload
  systemctl restart "$unit" || true
  sleep 5
  if systemctl is-active --quiet "$unit"; then
    echo "    ok $unit sandboxed"
  else
    rm -f "$f"
    systemctl daemon-reload
    systemctl restart "$unit" || true
    echo "    ! $unit did not start in the sandbox, so it runs without it"
  fi
}

sandbox cowrie /home/cowrie
sandbox cowrie-camera /home/cowrie
sandbox opencanary /home/opencanary
