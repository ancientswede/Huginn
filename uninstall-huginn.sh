#!/bin/bash
# uninstall-huginn.sh — remove Huginn from this machine (part of Huginn, AGPL-3.0-or-later).
#
#   ./uninstall-huginn.sh            remove Huginn; the collected data is kept in /root/huginn-data-<date>
#   ./uninstall-huginn.sh --purge    remove the collected data too
#
# Afterwards, also delete Huginn's key on the honeypot (uninstall-honeypot.sh does that), or run there:
#   sed -i '/command="\/usr\/local\/bin\/hp-export"/d' /root/.ssh/authorized_keys
set -euo pipefail

DIR="${HUGINN_DIR:-/opt/huginn}"
SVC="${HUGINN_SERVICE:-huginn}"
USR="${HUGINN_USER:-huginn}"
PURGE=0
YES=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n 2,9p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."
[ -d "$DIR" ] || [ -f "/etc/systemd/system/$SVC.service" ] || die "Huginn is not installed here ($DIR)."

echo
echo "    This removes Huginn: the service, $DIR, the '$USR' service user and its SSH key."
if [ "$PURGE" = 1 ]; then echo "    --purge: the collected attacker data is deleted as well."
else echo "    The collected data (database) is kept in /root/huginn-data-<date>."; fi
if [ "$YES" != 1 ]; then
  read -r -p "    Type 'remove' to continue: " a </dev/tty || a=""
  [ "$a" = remove ] || { echo "    Nothing was changed."; exit 0; }
fi

say "Stopping Huginn"
systemctl disable --now "$SVC" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/$SVC.service"
rm -rf "/etc/systemd/system/$SVC.service.d"
systemctl daemon-reload
ok "service removed"

if [ "$PURGE" != 1 ] && [ -d "$DIR/data" ]; then
  KEEP="/root/huginn-data-$(date +%Y%m%d-%H%M%S)"
  mv "$DIR/data" "$KEEP"
  chown -R root:root "$KEEP"; chmod 700 "$KEEP"
  ok "data kept in $KEEP"
fi

say "Removing files"
rm -rf -- "$DIR"
ok "removed $DIR (code, settings, SSH key, backups)"
if id "$USR" >/dev/null 2>&1; then
  userdel "$USR" 2>/dev/null || true
  ok "removed user $USR"
fi

say "Done"
echo "    Remember Huginn's key on the honeypot: uninstall-honeypot.sh removes it, or delete the"
echo "    line with command=\"/usr/local/bin/hp-export\" in the honeypot's /root/.ssh/authorized_keys."
echo "    Firewalls that fetch Huginn's blocklist feeds will keep their last copy: remove those jobs too."
