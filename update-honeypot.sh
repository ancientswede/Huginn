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
for f in honeypot/hp-export honeypot/hp-fileinfo honeypot/hp-traps.py honeypot/patches.py honeypot/webreply.py honeypot/hp-logclean honeypot/hp-identity honeypot/setup-identity.sh honeypot/setup-housekeeping.sh honeypot/setup-sandbox.sh; do
  [ -f "$HERE/$f" ] || die "Missing $f — run this from the Huginn repository folder."
done

COWRIE_DIRS="/home/cowrie/cowrie"
[ -r /etc/default/hp-export ] && . /etc/default/hp-export
C="${COWRIE_DIRS%% *}"
O=/home/opencanary
patch_as() { local u="$1"; shift; runuser -u "$u" -- python3 -I - "$@" < "$HERE/honeypot/patches.py"; }   # as the file's owner, never root

restart_ok() {  # restart_ok UNIT
  systemctl restart "$1" || true; sleep 4
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

say "Disk housekeeping"
bash "$HERE/honeypot/setup-housekeeping.sh"

say "Filesystem sandbox for Cowrie and OpenCanary"
bash "$HERE/honeypot/setup-sandbox.sh"

if [ "$UP_COWRIE" = 1 ]; then
  say "Cowrie"
  [ -d "$C/.git" ] || die "$C is not a git checkout of Cowrie."
  FREE="$C/src/cowrie/commands/free.py"
  # Put Cowrie's own free.py back so git can update it, then patch the new version again.
  runuser -u cowrie -- git -C "$C" checkout -- src/cowrie/commands/free.py src/cowrie/ssh/forwarding.py 2>/dev/null || true
  BEFORE=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  runuser -u cowrie -- git -C "$C" pull -q --ff-only || die "git pull failed in $C (local changes?) — Cowrie was not updated."
  AFTER=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  runuser -u cowrie -- bash -c "cd '$C' && cowrie-env/bin/pip install -q -e ."
  ok "Cowrie $BEFORE -> $AFTER"
  rc=0; patch_as cowrie cowrie-free "$FREE" || rc=$?
  case $rc in 0|3) ok "free.py patch in place" ;; *) warn "free.py patch no longer fits the new Cowrie (harmless: free shows the host's memory)" ;; esac
  rc=0; patch_as cowrie cowrie-forward "$C/src/cowrie/ssh/forwarding.py" || rc=$?
  case $rc in 0|3) ok "proxy reply patch in place" ;; *) warn "proxy reply patch no longer fits the new Cowrie (harmless: proxy checks are refused as before)" ;; esac
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
  rc=0; [ -n "$HTTPPY" ] && patch_as opencanary opencanary-http "$HTTPPY" || rc=$?
  case $rc in 0|3) ok "web reply/logging patch in place" ;; *) warn "web reply/logging patch no longer fits the new OpenCanary (only start-page visits are logged)"; FAILED=1 ;; esac
  patch_as opencanary opencanary-ports "$O/.opencanary.conf" || true
  restart_ok opencanary
fi

# Apply local reply changes even without --opencanary (which upgrades the package).
if [ "$UP_CANARY" = 0 ] && [ -x "$O/oc-env/bin/python3" ]; then
  HTTPPY=$(find "$O/oc-env" -path '*opencanary/modules/http.py' | head -1)
  rc=0
  if [ -n "$HTTPPY" ]; then patch_as opencanary opencanary-http "$HTTPPY" || rc=$?; else rc=1; fi
  case $rc in
    0) ok "web reply/logging patch updated"; restart_ok opencanary ;;
    3) ok "web reply/logging patch in place" ;;
    *) warn "web reply patch did not fit; no files changed"; FAILED=1 ;;
  esac
fi

# Same for Cowrie's fake proxy (--cowrie patches it after the upgrade instead).
FWD="$C/src/cowrie/ssh/forwarding.py"
if [ "$UP_COWRIE" = 0 ] && [ -f "$FWD" ]; then
  rc=0; patch_as cowrie cowrie-forward "$FWD" || rc=$?
  case $rc in
    0) ok "Cowrie answers proxy checks now"
       for u in $(systemctl list-units --type=service --all --no-legend 'cowrie*' | awk '{print $1}'); do restart_ok "$u"; done ;;
    3) ok "proxy reply patch in place" ;;
    *) warn "proxy reply patch did not fit this Cowrie; no files changed (proxy checks are refused as before)" ;;
  esac
fi

say "Web identity"
# Last, after any upgrade you asked for. A problem here must not stop those.
if bash "$HERE/honeypot/setup-identity.sh"; then
  [ -x /usr/local/sbin/hp-identity ] && /usr/local/sbin/hp-identity status | sed 's/^/    /' || true
else
  warn "web identity not set up (the rest of the update is done)"; FAILED=1
fi

say "Check"
N=$(sleep 30 | timeout 60 /usr/local/bin/hp-export | grep -c '^##' || true)
[ "$N" -ge 7 ] && ok "hp-export works ($N sections)" || { warn "hp-export printed $N sections (expected 7)"; FAILED=1; }
[ "$FAILED" = 0 ] && echo -e "\n    Done. Previous files are in $B" || die "Something needs a look (see above). Previous files are in $B"
