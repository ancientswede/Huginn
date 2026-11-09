#!/bin/bash
# setup-identity.sh — the rotating web identity for the honeypot (part of Huginn, AGPL-3.0-or-later).
# Run by install-honeypot.sh and update-honeypot.sh (as root, from the repository folder). Safe to run again.
#   - hp-identity + a daily timer that changes the web trap every ROTATE_DAYS (21 by default, 0 = never)
#   - the first time: a real identity instead of OpenCanary's default banner
# Does nothing when OpenCanary is not installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ -f /home/opencanary/.opencanary.conf ] || exit 0

install -m 755 "$HERE/honeypot/hp-identity" /usr/local/sbin/hp-identity
install -m 644 "$HERE/systemd/hp-identity.service" /etc/systemd/system/hp-identity.service
install -m 644 "$HERE/systemd/hp-identity.timer" /etc/systemd/system/hp-identity.timer
install -d -m 755 /usr/local/share/hp-identity
install -d -m 755 /usr/local/share/hp-identity/skins
install -d -m 700 /var/lib/hp-identity
[ -e /etc/default/hp-identity ] || echo "ROTATE_DAYS=21" > /etc/default/hp-identity
systemctl daemon-reload

# Keep the device it already pretends to be, now with a matching Server header and certificate.
[ -s /var/lib/hp-identity/history ] || /usr/local/sbin/hp-identity set synology
systemctl enable --now hp-identity.timer >/dev/null 2>&1 || true
