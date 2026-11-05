#!/bin/bash
# update-honeypot.sh — update the honeypot side of Huginn from this repository folder (part of Huginn, AGPL-3.0-or-later).
#
#   cd Huginn && git pull && ./update-honeypot.sh                  hp-export, hp-fileinfo, hp-traps
#   ./update-honeypot.sh --cowrie --opencanary                     ...and upgrade Cowrie / OpenCanary too
#
# Configs, personas, bait, logs and keys are never replaced. Huginn's small patches to Cowrie and
# OpenCanary are put back after an upgrade. Run as root. Your admin SSH port is not touched.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
UP_COWRIE=0
UP_CANARY=0
for a in "$@"; do
  case "$a" in
    --cowrie) UP_COWRIE=1 ;;
    --opencanary) UP_CANARY=1 ;;
    -h|--help) sed -n 2,9p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."
[ -x /usr/local/bin/hp-export ] || die "hp-export is not installed — run install-honeypot.sh first."
for f in honeypot/hp-export honeypot/hp-fileinfo honeypot/hp-traps.py honeypot/patches.py; do
  [ -f "$HERE/$f" ] || die "Missing $f — run this from the Huginn repository folder."
done

COWRIE_DIRS="/home/cowrie/cowrie"
[ -r /etc/default/hp-export ] && . /etc/default/hp-export
C="${COWRIE_DIRS%% *}"
O=/home/opencanary
PATCH="python3 $HERE/honeypot/patches.py"

restart_ok() {  # restart_ok UNIT
  systemctl restart "$1"; sleep 4
  systemctl is-active --quiet "$1" && ok "$1 is running" || { journalctl -u "$1" -n 15 --no-pager -o cat | sed 's/^/      /'; warn "$1 did not start (log above)"; FAILED=1; }
}
FAILED=0

say "Backup"
B="/root/huginn-honeypot-backups/$(date +%Y%m%d-%H%M%S)"
install -d -m 700 "$B"
cp -p /usr/local/bin/hp-export /usr/local/bin/hp-fileinfo "$B/" 2>/dev/null || true
[ -f /opt/hp-traps/hp-traps.py ] && cp -p /opt/hp-traps/hp-traps.py "$B/"
ok "$B"
ls -1dt /root/huginn-honeypot-backups/*/ 2>/dev/null | tail -n +6 | while read -r old; do rm -rf -- "$old"; done

say "Huginn's honeypot scripts"
for f in hp-export hp-fileinfo; do
  if cmp -s "$HERE/honeypot/$f" "/usr/local/bin/$f"; then ok "$f unchanged"; else install -m 755 "$HERE/honeypot/$f" "/usr/local/bin/$f"; ok "$f updated"; fi
done
if [ -d /opt/hp-traps ]; then
  if cmp -s "$HERE/honeypot/hp-traps.py" /opt/hp-traps/hp-traps.py; then ok "hp-traps unchanged"
  else install -m 644 "$HERE/honeypot/hp-traps.py" /opt/hp-traps/hp-traps.py; ok "hp-traps updated"; restart_ok hp-traps; fi
fi

if [ "$UP_COWRIE" = 1 ]; then
  say "Cowrie"
  [ -d "$C/.git" ] || die "$C is not a git checkout of Cowrie."
  FREE="$C/src/cowrie/commands/free.py"
  # Put Cowrie's own free.py back so git can update it, then patch the new version again.
  runuser -u cowrie -- git -C "$C" checkout -- src/cowrie/commands/free.py 2>/dev/null || true
  BEFORE=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  runuser -u cowrie -- git -C "$C" pull -q --ff-only || die "git pull failed in $C (local changes?) — Cowrie was not updated."
  AFTER=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  runuser -u cowrie -- bash -c "cd '$C' && cowrie-env/bin/pip install -q -e ."
  ok "Cowrie $BEFORE -> $AFTER"
  rc=0; $PATCH cowrie-free "$FREE" || rc=$?
  case $rc in 0|3) ok "free.py patch in place" ;; *) warn "free.py patch no longer fits the new Cowrie (harmless: free shows the host's memory)" ;; esac
  for u in $(systemctl list-units --type=service --all --no-legend 'cowrie*' | awk '{print $1}'); do restart_ok "$u"; done
fi

if [ "$UP_CANARY" = 1 ]; then
  say "OpenCanary"
  [ -x "$O/oc-env/bin/pip" ] || die "OpenCanary is not installed in $O."
  BEFORE=$(runuser -u opencanary -- "$O/oc-env/bin/pip" show opencanary 2>/dev/null | sed -n 's/^Version: //p')
  runuser -u opencanary -- "$O/oc-env/bin/pip" install -q -U opencanary
  AFTER=$(runuser -u opencanary -- "$O/oc-env/bin/pip" show opencanary 2>/dev/null | sed -n 's/^Version: //p')
  ok "OpenCanary $BEFORE -> $AFTER"
  HTTPPY=$(find "$O/oc-env" -path "*opencanary/modules/http.py" | head -1)
  rc=0; [ -n "$HTTPPY" ] && $PATCH opencanary-http "$HTTPPY" || rc=$?
  case $rc in 0|3) ok "web logging patch in place" ;; *) warn "web logging patch no longer fits the new OpenCanary (only start-page visits are logged)" ;; esac
  $PATCH opencanary-ports "$O/.opencanary.conf" || true
  restart_ok opencanary
fi

say "Check"
N=$(sleep 30 | timeout 60 /usr/local/bin/hp-export | grep -c '^##' || true)
[ "$N" -ge 7 ] && ok "hp-export works ($N sections)" || { warn "hp-export printed $N sections (expected 7)"; FAILED=1; }
[ "$FAILED" = 0 ] && echo -e "\n    Done. Previous files are in $B" || die "Something needs a look (see above). Previous files are in $B"
