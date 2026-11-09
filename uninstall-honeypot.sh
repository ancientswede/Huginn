#!/bin/bash
# uninstall-honeypot.sh — remove what install-honeypot.sh set up (part of Huginn, AGPL-3.0-or-later).
#
#   ./uninstall-honeypot.sh                  stop the honeypot: port redirects, services, export, Huginn's key, personas
#   ./uninstall-honeypot.sh --purge          also delete Cowrie, OpenCanary, their users, all logs and captured files,
#                                            and the endlessh package
#   ./uninstall-honeypot.sh --restore-ssh    also put admin SSH back on port 22 only (the extra admin port goes away)
#
# The port redirects are removed FIRST, so nothing on the internet reaches a half-removed honeypot.
# Remember to delete the port forwards in your router as well. Run as root.
set -euo pipefail

PURGE=0
RESTORE_SSH=0
YES=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    --restore-ssh) RESTORE_SSH=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n 2,11p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."
# Also accept what an earlier run without --purge / --restore-ssh leaves behind, so those can be run later.
[ -e /usr/local/bin/hp-export ] || [ -e /etc/huginn-honeypot.nft ] || [ -e /etc/systemd/system/cowrie.service ] \
  || id cowrie >/dev/null 2>&1 || id opencanary >/dev/null 2>&1 || [ -e /etc/ssh/sshd_config.d/10-huginn-admin.conf ] \
  || grep -qs "Written by Huginn" /etc/endlessh/config \
  || die "The Huginn honeypot does not seem to be installed here."

ADMIN_CONF=/etc/ssh/sshd_config.d/10-huginn-admin.conf
ADMIN_PORT=$(sed -nE 's/^Port ([0-9]+)$/\1/p' "$ADMIN_CONF" 2>/dev/null | grep -vx 22 | head -1 || true)

echo
echo "    This removes the honeypot: port redirects, Cowrie (all personas), OpenCanary, endlessh, hp-traps,"
echo "    the export for Huginn, Huginn's SSH key and the personas/bait in /etc/huginn-honeypot."
if [ "$PURGE" = 1 ]; then echo "    --purge: Cowrie/OpenCanary, their users, logs and captured files are deleted too."
else echo "    Logs and captured files are kept in /home/cowrie, /home/opencanary and /var/log/hp-traps."; fi
if [ "$RESTORE_SSH" = 1 ]; then echo "    --restore-ssh: admin SSH goes back to port 22 only (port ${ADMIN_PORT:-?} stops working)."
elif [ -n "$ADMIN_PORT" ]; then echo "    Your admin SSH stays on port $ADMIN_PORT, and port 22 is the real sshd again."; fi
if [ "$YES" != 1 ]; then
  read -r -p "    Type 'remove' to continue: " a </dev/tty || a=""
  [ "$a" = remove ] || { echo "    Nothing was changed."; exit 0; }
fi

# ------------------------------------------------------------------ 1. port redirects first
say "Port redirects"
nft delete table ip huginn_honeypot 2>/dev/null && ok "redirect rules unloaded" || ok "no redirect rules loaded"
if [ -f /etc/nftables.conf ] && grep -q 'include "/etc/huginn-honeypot.nft"' /etc/nftables.conf; then
  cp -p /etc/nftables.conf "/etc/nftables.conf.bak-uninstall-$(date +%s)"
  sed -i '\#include "/etc/huginn-honeypot.nft"#d' /etc/nftables.conf
  ok "removed the include from /etc/nftables.conf (backup next to it)"
fi
rm -f /etc/huginn-honeypot.nft

# ------------------------------------------------------------------ 2. services
say "Services"
# First: a web identity change under way would otherwise restart OpenCanary, or write its history, after everything is gone.
systemctl disable --now hp-identity.timer >/dev/null 2>&1 || true
systemctl stop hp-identity.service >/dev/null 2>&1 || true
UNITS=$(systemctl list-unit-files --no-legend 'cowrie*.service' 2>/dev/null | awk '{print $1}' || true)   # none left: not an error
for u in $UNITS opencanary.service hp-traps.service; do
  if [ -f "/etc/systemd/system/$u" ]; then
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$u"
    ok "removed $u"
  fi
done
if [ -f /etc/systemd/system/endlessh.service.d/huginn.conf ]; then
  rm -f /etc/systemd/system/endlessh.service.d/huginn.conf
  rmdir /etc/systemd/system/endlessh.service.d 2>/dev/null || true
  systemctl disable --now endlessh >/dev/null 2>&1 || true
  ok "stopped endlessh"
fi
# Only purge endlessh if the installer set it up (its config carries our header), never someone's own endlessh.
if [ "$PURGE" = 1 ] && grep -qs "Written by Huginn" /etc/endlessh/config; then
  systemctl disable --now endlessh >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq endlessh >/dev/null 2>&1 || true
  rm -rf /etc/endlessh
  ok "removed the endlessh package"
fi
rm -rf /etc/systemd/system/hp-traps.service.d
systemctl disable --now hp-logclean.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/hp-identity.service /etc/systemd/system/hp-identity.timer /usr/local/sbin/hp-identity /etc/default/hp-identity
rm -rf /usr/local/share/hp-identity /var/lib/hp-identity
rm -f /etc/systemd/system/hp-logclean.service /etc/systemd/system/hp-logclean.timer /etc/systemd/journald.conf.d/huginn-honeypot.conf
systemctl daemon-reload
rm -f /etc/logrotate.d/opencanary

# ------------------------------------------------------------------ 3. export, key, personas, hp-traps
say "Export for Huginn"
if [ -f /root/.ssh/authorized_keys ] && grep -q 'command="/usr/local/bin/hp-export"' /root/.ssh/authorized_keys; then
  cp -p /root/.ssh/authorized_keys "/root/.ssh/authorized_keys.bak-uninstall-$(date +%s)"
  sed -i '\#command="/usr/local/bin/hp-export"#d' /root/.ssh/authorized_keys
  ok "removed Huginn's key from /root/.ssh/authorized_keys"
fi
rm -f /usr/local/bin/hp-export /usr/local/bin/hp-fileinfo /usr/local/bin/hp-logclean /usr/local/sbin/hp-add-huginn-key /etc/default/hp-export
rm -rf /var/lib/hp-export /opt/hp-traps /etc/huginn-honeypot
ok "removed hp-export, hp-fileinfo, hp-traps and the personas/bait"

# ------------------------------------------------------------------ 4. purge
if [ "$PURGE" = 1 ]; then
  say "Purge"
  for u in cowrie opencanary; do
    if id "$u" >/dev/null 2>&1; then
      pkill -u "$u" 2>/dev/null || true
      userdel -r "$u" >/dev/null 2>&1 || { userdel "$u" 2>/dev/null || true; rm -rf "/home/${u:?}"; }
      ok "removed user $u and /home/$u"
    fi
  done
  rm -rf /var/log/hp-traps /root/huginn-honeypot-backups
  ok "removed logs and backups"
fi

# ------------------------------------------------------------------ 5. admin SSH
if [ "$RESTORE_SSH" = 1 ] && [ -f "$ADMIN_CONF" ]; then
  say "Admin SSH"
  rm -f "$ADMIN_CONF"
  sshd -t || die "sshd config test failed after removing $ADMIN_CONF — check sshd before you log out."
  systemctl restart ssh.service
  ok "sshd listens on port 22 only (existing sessions stay open)"
fi

say "Done"
echo "    Delete the port forwards to this machine in your router."
[ "$PURGE" = 1 ] || echo "    Logs and captured files are still in /home/cowrie, /home/opencanary and /var/log/hp-traps (--purge removes them)."
if [ "$RESTORE_SSH" != 1 ] && [ -n "$ADMIN_PORT" ]; then
  echo "    Admin SSH stays on port $ADMIN_PORT. --restore-ssh moves it back to port 22."
fi
