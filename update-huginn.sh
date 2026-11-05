#!/bin/bash
# update-huginn.sh — update an installed Huginn from this repository folder (part of Huginn, AGPL-3.0-or-later).
#
#   cd Huginn && git pull && ./update-huginn.sh     update (backup first, rolls back by itself if it fails)
#   ./update-huginn.sh --rollback                   go back to the version before the last update
#
# Your settings (.env), key, login and collected data are never replaced. Run as root.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="${HUGINN_DIR:-/opt/huginn}"
SVC="${HUGINN_SERVICE:-huginn}"
BK="$DIR/backups"
KEEP=3
FORCE=0
ROLLBACK=0

for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --rollback) ROLLBACK=1 ;;
    -h|--help) sed -n 2,8p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."
[ -f "$DIR/app.py" ] || die "Huginn is not installed in $DIR — run install-huginn.sh first."

ver() { sed -nE 's/^HUGINN_VERSION = "([^"]+)".*/\1/p' "$1" | head -1; }
PORT=$(sed -nE 's/^HUGINN_PORT=([0-9]+).*/\1/p' "$DIR/.env" 2>/dev/null | head -1); PORT="${PORT:-8095}"

running_version() {
  python3 - "$PORT" <<'PY'
import json, sys, urllib.request, urllib.error
try:
    print(json.load(urllib.request.urlopen("http://127.0.0.1:%s/healthz" % sys.argv[1], timeout=5))["version"])
except urllib.error.HTTPError as e:      # 503 = running but the last honeypot sync is old: still a version answer
    try:
        print(json.loads(e.read())["version"])
    except Exception:
        pass
except Exception:
    pass
PY
}

wait_for() {  # wait_for VERSION -> 0 when Huginn answers with that version
  for _ in $(seq 1 20); do
    [ "$(running_version)" = "$1" ] && return 0
    sleep 2
  done
  return 1
}

restore() {  # restore BACKUPDIR: put the code from a backup back and restart (data is left alone)
  install -m 644 "$1/app.py" "$DIR/app.py"
  if [ -d "$1/static" ]; then rm -rf "$DIR/static"; cp -a "$1/static" "$DIR/static"; fi
  [ -f "$1/huginn.service" ] && install -m 644 "$1/huginn.service" "/etc/systemd/system/$SVC.service"
  systemctl daemon-reload
  systemctl restart "$SVC"
}

# ------------------------------------------------------------------ rollback
if [ "$ROLLBACK" = 1 ]; then
  LAST=$(ls -1dt "$BK"/*/ 2>/dev/null | head -1)
  [ -n "$LAST" ] || die "No backup found in $BK."
  OLDV=$(ver "$LAST/app.py")
  say "Rolling back to $OLDV"
  restore "$LAST"
  wait_for "$OLDV" || die "Huginn did not come up as $OLDV — see: journalctl -u $SVC -n 30"
  ok "running $OLDV again"
  echo "    The database was not touched. Its copy from before the update is $LAST""huginn.db if you ever need it."
  exit 0
fi

# ------------------------------------------------------------------ update
OLD=$(ver "$DIR/app.py")
NEW=$(ver "$HERE/app.py")
[ -n "$NEW" ] || die "Run this from the Huginn repository folder."
if [ "$OLD" = "$NEW" ] && [ "$FORCE" != 1 ]; then
  ok "Huginn $OLD is already the newest version in this folder (did you run git pull?)"
  exit 0
fi
if [ "$FORCE" != 1 ] && python3 -c "import sys; a,b=[tuple(int(x) for x in v.split('.')) for v in sys.argv[1:]]; sys.exit(0 if b < a else 1)" "$OLD" "$NEW"; then
  die "This folder has $NEW, which is older than the installed $OLD. Use --rollback to go back, or --force."
fi
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$HERE/app.py" || die "The new app.py does not parse — nothing was changed."

say "Backup of $OLD"
B="$BK/$OLD-$(date +%Y%m%d-%H%M%S)"
install -d -m 700 "$BK" "$B"
cp -p "$DIR/app.py" "$B/app.py"
[ -d "$DIR/static" ] && cp -a "$DIR/static" "$B/static"
cp -p "/etc/systemd/system/$SVC.service" "$B/huginn.service" 2>/dev/null || true
if [ -f "$DIR/data/huginn.db" ]; then
  python3 - "$DIR/data/huginn.db" "$B/huginn.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2])
src.backup(dst)          # consistent copy while Huginn keeps running
dst.close(); src.close()
PY
  chmod 600 "$B/huginn.db"
  # Only the newest backup keeps a database copy: the database grows, the code backups stay tiny.
  for old in "$BK"/*/; do [ "${old%/}" = "$B" ] || rm -f "$old/huginn.db"; done
fi
ok "saved in $B"

say "Installing $NEW"
install -m 644 "$HERE/app.py" "$DIR/app.py"
if [ -d "$HERE/static" ]; then install -d -m 755 "$DIR/static"; install -m 644 "$HERE"/static/* "$DIR/static/"; fi
if ! cmp -s "$HERE/systemd/huginn.service" "/etc/systemd/system/$SVC.service"; then
  install -m 644 "$HERE/systemd/huginn.service" "/etc/systemd/system/$SVC.service"
  ok "updated the systemd service"
fi
systemctl daemon-reload
systemctl restart "$SVC"
if wait_for "$NEW"; then
  ok "Huginn $NEW is running"
else
  warn "Huginn $NEW did not come up — rolling back to $OLD"
  journalctl -u "$SVC" -n 15 --no-pager -o cat | sed 's/^/      /'
  restore "$B"
  wait_for "$OLD" && die "Update failed; $OLD is running again (nothing lost). Please report the log above." \
                  || die "Update failed and $OLD did not come back either — see: journalctl -u $SVC -n 50"
fi

# keep the newest $KEEP backups
ls -1dt "$BK"/*/ 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do rm -rf -- "$old"; done

say "What is new since $OLD"
python3 - "$HERE/app.py" "$OLD" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
log = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CHANGELOG")
old = tuple(int(x) for x in sys.argv[2].split("."))
for v, d, text in log:
    if tuple(int(x) for x in v.split(".")) > old:
        print("    %s  %s" % (v, text))
PY
echo
