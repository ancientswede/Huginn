#!/bin/bash
# setup-housekeeping.sh — disk housekeeping for the honeypot (part of Huginn, AGPL-3.0-or-later).
# Run by install-honeypot.sh and update-honeypot.sh (as root, from the repository folder). Safe to run again.
#   - hp-logclean + a daily timer: gzip Cowrie's rotated logs, delete them and old recordings after 30 days
#   - logrotate for OpenCanary: daily, compressed, 30 days
#   - the systemd journal is capped at 200 MB
# Huginn copies everything within minutes and keeps it, so the honeypot only needs a short history.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"

install -m 755 "$HERE/honeypot/hp-logclean" /usr/local/bin/hp-logclean
install -m 644 "$HERE/systemd/hp-logclean.service" /etc/systemd/system/hp-logclean.service
install -m 644 "$HERE/systemd/hp-logclean.timer" /etc/systemd/system/hp-logclean.timer

# Defaults (kept if you changed them).
touch /etc/default/hp-export
for kv in LOG_KEEP_DAYS=30 TTY_KEEP_DAYS=30 DOWNLOAD_KEEP_DAYS=0; do
  grep -q "^${kv%%=*}=" /etc/default/hp-export || echo "$kv" >> /etc/default/hp-export
done

if [ -d /home/opencanary ]; then
  cat > /etc/logrotate.d/opencanary <<'LR'
# Written by Huginn: daily, compressed after a day (hp-export reads the uncompressed files), 30 days kept.
/home/opencanary/opencanary.log {
    daily
    rotate 30
    dateext
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su opencanary opencanary
}
LR
fi

install -d /etc/systemd/journald.conf.d
if [ ! -f /etc/systemd/journald.conf.d/huginn-honeypot.conf ]; then
  printf '# Written by Huginn: the honeypot logs a lot and its disk is small.\n[Journal]\nSystemMaxUse=200M\n' \
    > /etc/systemd/journald.conf.d/huginn-honeypot.conf
  systemctl restart systemd-journald
fi

systemctl daemon-reload
systemctl enable --now hp-logclean.timer >/dev/null 2>&1
echo "    ok housekeeping: hp-logclean daily, logs kept 30 days, journal max 200 MB"
