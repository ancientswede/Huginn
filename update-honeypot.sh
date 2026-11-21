#!/bin/bash
# update-honeypot.sh — update the honeypot side of Huginn from this repository folder (part of Huginn, AGPL-3.0-or-later).
#
#   cd Huginn && git pull && ./update-honeypot.sh                  hp-export, hp-fileinfo, hp-traps
#   ./update-honeypot.sh --cowrie --opencanary                     ...and upgrade Cowrie / OpenCanary too
#   ./update-honeypot.sh --goodbye-on | --goodbye-off              only turn the logout note on or off (nothing else changes)
#   ./update-honeypot.sh --suricata-on | --suricata-off            only turn the Suricata IDS on or off (about 500 MB of memory)
#   ./update-honeypot.sh --suricata-rules emerging.rules.tar.gz    load ET Open rules downloaded elsewhere (no internet here)
#
# Configs, personas, bait, logs and keys are never replaced. Huginn's small patches to Cowrie and
# OpenCanary are put back after an upgrade. Run as root. Your admin SSH port is not touched.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
UP_COWRIE=0
UP_CANARY=0
GOODBYE=""
SURICATA=""
SURICATA_RULES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cowrie) UP_COWRIE=1 ;;
    --opencanary) UP_CANARY=1 ;;
    --goodbye-on) GOODBYE=on ;;
    --goodbye-off) GOODBYE=off ;;
    --suricata-on) SURICATA=on ;;
    --suricata-off) SURICATA=off ;;
    --suricata-rules) SURICATA=rules; SURICATA_RULES="${2:-}"; [ $# -ge 2 ] && shift ;;
    -h|--help) sed -n 2,12p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."

# The logout note (honeypot/patches.py hp_goodbye): a root-owned flag file Cowrie only checks for. Read at every logout,
# so no restart. Only this when asked for: the note is a choice, not part of an update.
if [ -n "$GOODBYE" ]; then
  if [ "$GOODBYE" = on ]; then
    [ ! -L /etc/huginn-goodbye ] || die "/etc/huginn-goodbye is a symlink; remove it first."
    install -m 644 -o root -g root /dev/null /etc/huginn-goodbye
    printf '    \033[32mok\033[0m %s\n' "logout note on: a real login that types exit or logout gets a short goodbye"
  else
    rm -f /etc/huginn-goodbye
    printf '    \033[32mok\033[0m %s\n' "logout note off"
  fi
  exit 0
fi
[ -x /usr/local/bin/hp-export ] || die "hp-export is not installed — run install-honeypot.sh first."
for f in honeypot/hp-export honeypot/hp-fileinfo honeypot/hp-sample-zip honeypot/hp-readlogs honeypot/hp-traps.py honeypot/patches.py honeypot/webreply.py honeypot/hp-logclean honeypot/hp-identity honeypot/setup-identity.sh honeypot/setup-housekeeping.sh honeypot/setup-sandbox.sh honeypot/setup-suricata.sh systemd/hp-suricata-rules.service systemd/hp-suricata-rules.timer; do
  [ -f "$HERE/$f" ] || die "Missing $f — run this from the Huginn repository folder."
done

# Suricata (honeypot/setup-suricata.sh): only this when asked for. hp-export is updated first, so Huginn gets the alerts.
if [ -n "$SURICATA" ]; then
  # hp-readlogs first: the new hp-export needs it, and a honeypot from before 0.50 does not have it yet.
  for f in hp-readlogs hp-export; do
    cmp -s "$HERE/honeypot/$f" "/usr/local/bin/$f" || install -m 755 "$HERE/honeypot/$f" "/usr/local/bin/$f"
  done
  case "$SURICATA" in
    on) bash "$HERE/honeypot/setup-suricata.sh" on ;;
    off) bash "$HERE/honeypot/setup-suricata.sh" off ;;
    rules) bash "$HERE/honeypot/setup-suricata.sh" rules "$SURICATA_RULES" ;;
  esac
  exit 0
fi

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
cp -p /usr/local/bin/hp-export /usr/local/bin/hp-fileinfo /usr/local/bin/hp-sample-zip /usr/local/bin/hp-readlogs "$B/" 2>/dev/null || true
[ -f /opt/hp-traps/hp-traps.py ] && cp -p /opt/hp-traps/hp-traps.py "$B/"
ok "$B"
ls -1dt /root/huginn-honeypot-backups/*/ 2>/dev/null | tail -n +6 | while read -r old; do rm -rf -- "$old"; done

say "Huginn's honeypot scripts"
for f in hp-readlogs hp-export hp-fileinfo hp-sample-zip; do
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
cowrie_patches() {  # every Huginn patch on the Cowrie source in $C (after an upgrade, or after a failed one); counts misses in PFAIL
    PFAIL=0
    rc=0; patch_as cowrie cowrie-free "$FREE" || rc=$?
    case $rc in 0|3) ok "free.py patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "free.py patch no longer fits the new Cowrie (harmless: free shows the host's memory)" ;; esac
    rc=0; patch_as cowrie cowrie-forward "$C/src/cowrie/ssh/forwarding.py" || rc=$?
    case $rc in 0|3) ok "proxy reply patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "proxy reply patch no longer fits the new Cowrie (harmless: proxy checks are refused as before)" ;; esac
    rc=0; patch_as cowrie cowrie-ping "$C/src/cowrie/commands/ping.py" || rc=$?
    case $rc in 0|3) ok "ping patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "ping patch no longer fits the new Cowrie (harmless: ping -c fails as upstream)" ;; esac
    rc=0; patch_as cowrie cowrie-upload "$C/src/cowrie" || rc=$?
    case $rc in 0|3) ok "upload patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "upload patch no longer fits the new Cowrie (harmless: uploads vanish as upstream)" ;; esac
    rc=0; patch_as cowrie cowrie-wget "$C/src/cowrie/commands/wget.py" || rc=$?
    case $rc in 0|3) ok "wget patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "wget patch no longer fits the new Cowrie (harmless: GNU wget text everywhere)" ;; esac
    rc=0; patch_as cowrie cowrie-exec "$C/src/cowrie/shell/protocol.py" || rc=$?
    case $rc in 0|3) ok "exec patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "exec patch no longer fits the new Cowrie (harmless: Exec format error as upstream)" ;; esac
    rc=0; patch_as cowrie cowrie-goodbye "$C/src/cowrie" || rc=$?
    case $rc in 0|3) ok "goodbye patch in place" ;; *) PFAIL=$((PFAIL+1)); warn "goodbye patch no longer fits the new Cowrie (harmless: no logout note)" ;; esac
}
  # Put Cowrie's own free.py back so git can update it, then patch the new version again.
  runuser -u cowrie -- git -C "$C" checkout -- src/cowrie/commands/free.py src/cowrie/ssh/forwarding.py src/cowrie/commands/ping.py \
    src/cowrie/shell/server.py src/cowrie/shell/session.py src/cowrie/shell/filetransfer.py \
    src/cowrie/commands/scp.py src/cowrie/shell/fs.py src/cowrie/commands/wget.py src/cowrie/shell/protocol.py \
    src/cowrie/commands/bash.py 2>/dev/null || true
  BEFORE=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  BEFORE_FULL=$(runuser -u cowrie -- git -C "$C" rev-parse HEAD)
  back_or_die() {  # put the patches back on whatever source is there now, then stop with an honest message
    cowrie_patches
    if [ "$PFAIL" = 0 ]; then die "$1 Huginn's patches are back on the source in $C; restart Cowrie only after checking it."
    else die "$1 $PFAIL Huginn patch(es) could not be put back (see the warnings above); do not restart Cowrie before fixing $C."; fi
  }
  # Back to the exact version that ran before, source AND packages, so a failed upgrade never leaves a mix of the two
  # (Codex 049 M16). Nothing is restarted until the patches are checked.
  go_back() {
    warn "$1 — going back to Cowrie $BEFORE"
    runuser -u cowrie -- git -C "$C" reset -q --hard "$BEFORE_FULL" \
      && runuser -u cowrie -- bash -c "cd '$C' && cowrie-env/bin/pip install -q -e ." \
      || back_or_die "$1, and going back to $BEFORE failed too."
    PFAIL=0; cowrie_patches
    [ "$PFAIL" = 0 ] || back_or_die "$1; back on $BEFORE, but"
    for u in $(systemctl list-units --type=service --all --no-legend 'cowrie*' | awk '{print $1}'); do restart_ok "$u"; done
    die "$1 Cowrie $BEFORE with Huginn's patches is running again."
  }
  runuser -u cowrie -- git -C "$C" pull -q --ff-only || back_or_die "git pull failed in $C (local changes?) — Cowrie was not updated."
  AFTER=$(runuser -u cowrie -- git -C "$C" rev-parse --short HEAD)
  runuser -u cowrie -- bash -c "cd '$C' && cowrie-env/bin/pip install -q -e ." || go_back "pip install failed in $C after the update"
  ok "Cowrie $BEFORE -> $AFTER"
  PFAIL=0
  cowrie_patches
  # A patch that protects the honeypot (sandbox-like: free, proxy, upload) no longer fitting is a reason to stay on the old version.
  [ "$PFAIL" = 0 ] || [ "$BEFORE" = "$AFTER" ] || go_back "$PFAIL Huginn patch(es) do not fit Cowrie $AFTER"
  for u in $(systemctl list-units --type=service --all --no-legend 'cowrie*' | awk '{print $1}'); do restart_ok "$u"; done
fi

if [ "$UP_CANARY" = 1 ]; then
  say "OpenCanary"
  [ -x "$O/oc-env/bin/pip" ] || die "OpenCanary is not installed in $O."
  BEFORE=$(runuser -u opencanary -- "$O/oc-env/bin/pip" show opencanary 2>/dev/null | sed -n 's/^Version: //p')
  oc_back() {  # the version that ran before, if the upgrade or the patch on it failed (Codex 049 M16)
    warn "$1 — going back to OpenCanary $BEFORE"
    [[ "$BEFORE" =~ ^[0-9A-Za-z.+-]+$ ]] && runuser -u opencanary -- "$O/oc-env/bin/pip" install -q "opencanary==$BEFORE" \
      || die "$1, and going back to $BEFORE failed too: do not restart OpenCanary before fixing $O/oc-env."
  }
  runuser -u opencanary -- "$O/oc-env/bin/pip" install -q -U opencanary || oc_back "the upgrade failed"
  AFTER=$(runuser -u opencanary -- "$O/oc-env/bin/pip" show opencanary 2>/dev/null | sed -n 's/^Version: //p')
  ok "OpenCanary $BEFORE -> $AFTER"
  HTTPPY=$(find "$O/oc-env" -path "*opencanary/modules/http.py" | head -1)
  rc=0; [ -n "$HTTPPY" ] && patch_as opencanary opencanary-http "$HTTPPY" || rc=$?
  if [ "$rc" != 0 ] && [ "$rc" != 3 ] && [ "$BEFORE" != "$AFTER" ]; then
    oc_back "the web reply patch does not fit OpenCanary $AFTER"
    HTTPPY=$(find "$O/oc-env" -path "*opencanary/modules/http.py" | head -1)
    rc=0; [ -n "$HTTPPY" ] && patch_as opencanary opencanary-http "$HTTPPY" || rc=$?
  fi
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

# Same for Cowrie's own patches (--cowrie patches them after the upgrade instead). Restart once if any changed.
FWD="$C/src/cowrie/ssh/forwarding.py"
if [ "$UP_COWRIE" = 0 ] && [ -f "$FWD" ]; then
  CHANGED=0
  rc=0; patch_as cowrie cowrie-forward "$FWD" || rc=$?
  case $rc in
    0) ok "Cowrie answers proxy checks now"; CHANGED=1 ;;
    3) ok "proxy reply patch in place" ;;
    *) warn "proxy reply patch did not fit this Cowrie; no files changed (proxy checks are refused as before)" ;;
  esac
  rc=0; patch_as cowrie cowrie-ping "$C/src/cowrie/commands/ping.py" || rc=$?
  case $rc in
    0) ok "ping accepts -c now"; CHANGED=1 ;;
    3) ok "ping patch in place" ;;
    *) warn "ping patch did not fit this Cowrie; no files changed" ;;
  esac
  rc=0; patch_as cowrie cowrie-upload "$C/src/cowrie" || rc=$?
  case $rc in
    0) ok "uploaded files stay for the next command now"; CHANGED=1 ;;
    3) ok "upload patch in place" ;;
    *) warn "upload patch did not fit this Cowrie; no files changed" ;;
  esac
  rc=0; patch_as cowrie cowrie-wget "$C/src/cowrie/commands/wget.py" || rc=$?
  case $rc in
    0) ok "wget answers like the persona's own wget now"; CHANGED=1 ;;
    3) ok "wget patch in place" ;;
    *) warn "wget patch did not fit this Cowrie; no files changed" ;;
  esac
  rc=0; patch_as cowrie cowrie-exec "$C/src/cowrie/shell/protocol.py" || rc=$?
  case $rc in
    0) ok "uploaded programs run silently now (simulated, logged)"; CHANGED=1 ;;
    3) ok "exec patch in place" ;;
    *) warn "exec patch did not fit this Cowrie; no files changed" ;;
  esac
  rc=0; patch_as cowrie cowrie-goodbye "$C/src/cowrie" || rc=$?
  case $rc in
    0) ok "logout note ready now ($( [ -f /etc/huginn-goodbye ] && echo on || echo 'off; turn on with --goodbye-on' ))"; CHANGED=1 ;;
    3) ok "goodbye patch in place" ;;
    *) warn "goodbye patch did not fit this Cowrie; no files changed" ;;
  esac
  if [ "$CHANGED" = 1 ]; then
    for u in $(systemctl list-units --type=service --all --no-legend 'cowrie*' | awk '{print $1}'); do restart_ok "$u"; done
  fi
fi

if [ -f /etc/huginn-honeypot/suricata ]; then
  say "Suricata"
  bash "$HERE/honeypot/setup-suricata.sh" refresh || { warn "Suricata needs a look (the rest of the update is done)"; FAILED=1; }
fi

say "Web identity"
# Last, after any upgrade you asked for. A problem here must not stop those.
if bash "$HERE/honeypot/setup-identity.sh"; then
  [ -x /usr/local/sbin/hp-identity ] && /usr/local/sbin/hp-identity status | sed 's/^/    /' || true
else
  warn "web identity not set up (the rest of the update is done)"; FAILED=1
fi

say "Check"
# A whole export: it must end with ##END and exit 0, the same test Huginn's collector uses (Codex 049 L1).
OUT=$(sleep 30 | timeout 60 /usr/local/bin/hp-export) && RC=0 || RC=$?
N=$(printf '%s\n' "$OUT" | grep -c '^##' || true)
if [ "$RC" = 0 ] && [ "$N" -ge 7 ] && printf '%s\n' "$OUT" | grep -qx '##END'; then ok "hp-export works ($N sections)"
else warn "hp-export did not finish cleanly (exit $RC, $N sections, end marker $(printf '%s\n' "$OUT" | grep -qx '##END' && echo found || echo missing))"; FAILED=1; fi
[ "$FAILED" = 0 ] && echo -e "\n    Done. Previous files are in $B" || die "Something needs a look (see above). Previous files are in $B"
