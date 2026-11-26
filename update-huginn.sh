#!/bin/bash
# update-huginn.sh — update an installed Huginn from this repository folder (part of Huginn, AGPL-3.0-or-later).
#
#   cd Huginn && git pull && ./update-huginn.sh     update (backup first, rolls back by itself if it fails)
#   ./update-huginn.sh --rollback                   go back to the version before the last update (code only)
#   ./update-huginn.sh --rollback --with-db         ... and put back the database copy from before that update
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
WITHDB=0

for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    --rollback) ROLLBACK=1 ;;
    --with-db) WITHDB=1 ;;
    -h|--help) sed -n 2,9p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root."
[ -f "$DIR/app.py" ] || die "RavenTrap is not installed in $DIR — run install-huginn.sh first."
[ "$WITHDB" = 0 ] || [ "$ROLLBACK" = 1 ] || die "--with-db only goes with --rollback."
# The database lives under HUGINN_BASE (default: the install folder), as the service sees it (Codex rc2 M18).
BASE=$(sed -nE 's/^HUGINN_BASE=//p' "$DIR/.env" 2>/dev/null | tail -1 | tr -d "\"'"); BASE="${BASE:-$DIR}"
DB="$BASE/data/huginn.db"

# Backups are folders named <version>-<YYYYmmdd-HHMMSS>: sort by that name, never by file times (which change
# when an old backup's database copy is removed).
backups_newest_first() {
  local d
  for d in "$BK"/*/; do [ -d "$d" ] && echo "${d%/}"; done | awk -F- '{print $(NF-1) $NF "\t" $0}' | sort -r | cut -f2
}

ver() { sed -nE 's/^HUGINN_VERSION = "([^"]+)".*/\1/p' "$1" | head -1; }
PORT=$(sed -nE 's/^HUGINN_PORT=([0-9]+).*/\1/p' "$DIR/.env" 2>/dev/null | head -1); PORT="${PORT:-8095}"
BINDADDR=$(sed -nE 's/^HUGINN_BIND=//p' "$DIR/.env" 2>/dev/null | tail -1 | tr -d "\"' "); BINDADDR="${BINDADDR:-0.0.0.0}"

running_version() {
  python3 - "$PORT" "$BINDADDR" <<'PY'
import json, sys, urllib.request, urllib.error
port, bind = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
# Ask where RavenTrap listens (HUGINN_BIND): any-address -> loopback; a set address -> that one (Codex rc2 M19).
host = {"": "127.0.0.1", "0.0.0.0": "127.0.0.1", "::": "::1"}.get(bind, bind)
url = "http://%s:%s/healthz" % ("[%s]" % host if ":" in host else host, port)
req = urllib.request.Request(url, headers={"Host": "localhost:%s" % port})   # loopback names always get the version
try:
    print(json.load(urllib.request.urlopen(req, timeout=5))["version"])
except urllib.error.HTTPError as e:      # 503 = running but the last honeypot sync is old: still a version answer
    try:
        print(json.loads(e.read())["version"])
    except Exception:
        pass
except Exception:
    pass
PY
}

wait_for() {  # wait_for VERSION -> 0 when RavenTrap answers with that version
  for _ in $(seq 1 20); do
    [ "$(running_version)" = "$1" ] && return 0
    sleep 2
  done
  return 1
}

restore() {  # restore BACKUPDIR: put the code from a backup back and restart (data is left alone)
  # Every step checks its own result and the files are compared afterwards: called as "restore || ...", set -e does not
  # apply in here, so a failed copy must not be hidden by a successful restart (Codex 049 M15).
  local bad=0
  install -m 644 "$1/app.py" "$DIR/app.py" || bad=1
  if [ -d "$1/static" ]; then
    rm -rf "$DIR/static.restore" && cp -a "$1/static" "$DIR/static.restore" && rm -rf "$DIR/static" \
      && mv "$DIR/static.restore" "$DIR/static" || bad=1
  fi
  if [ -f "$1/huginn.service" ]; then install -m 644 "$1/huginn.service" "/etc/systemd/system/$SVC.service" || bad=1; fi
  cmp -s "$1/app.py" "$DIR/app.py" || bad=1
  [ ! -d "$1/static" ] || diff -rq "$1/static" "$DIR/static" >/dev/null || bad=1
  [ ! -f "$1/huginn.service" ] || cmp -s "$1/huginn.service" "/etc/systemd/system/$SVC.service" || bad=1
  systemctl daemon-reload || bad=1
  systemctl restart "$SVC" || bad=1
  [ "$bad" = 0 ] || { warn "the restore from $1 was not complete: compare $1 with $DIR by hand"; return 1; }
}

restore_db() {  # restore_db BACKUPDIR: put that backup's database copy back (the service must be stopped)
  local f="" t owner
  for f in "$1/huginn.db.gz" "$1/huginn.db"; do [ -f "$f" ] && break; f=""; done
  [ -n "$f" ] || { warn "no database copy in $1"; return 1; }
  owner=$(stat -c %U "$BASE/data")
  # The backup folder is root's (700); hand the service user a copy it can read, then let RavenTrap's own restore-db
  # check it and swap it in (it keeps the current database next to it as huginn.db.before-restore-...).
  # The folder stays root's (0711: the user can open a file it knows the name of, not list or change anything), so
  # nothing can be swapped in before the hand-over; chown -h never follows a link.
  t=$(mktemp -d) && chmod 711 "$t" && cp "$f" "$t/copy.db" && chown -h "$owner" "$t/copy.db" && chmod 600 "$t/copy.db" \
    || { rm -rf "$t"; return 1; }
  systemd-run --quiet --wait --pipe --collect --uid="$owner" --gid="$(id -gn "$owner")" -p EnvironmentFile=-"$DIR/.env" -p UMask=0027 \
    /usr/bin/python3 "$DIR/app.py" restore-db "$t/copy.db"
  local rc=$?
  rm -rf "$t"
  return $rc
}

# ------------------------------------------------------------------ rollback
if [ "$ROLLBACK" = 1 ]; then
  LAST=$(backups_newest_first | head -1)
  [ -n "$LAST" ] || die "No backup found in $BK."
  OLDV=$(ver "$LAST/app.py")
  say "Rolling back to $OLDV"
  restore "$LAST"
  if [ "$WITHDB" = 1 ]; then
    systemctl stop "$SVC"
    restore_db "$LAST" || { systemctl start "$SVC"; die "The database copy could not be put back; $OLDV runs on the current database."; }
    systemctl start "$SVC"
    ok "database put back to the copy from before that update (the one it replaced is kept next to it)"
  fi
  wait_for "$OLDV" || die "RavenTrap did not come up as $OLDV — see: journalctl -u $SVC -n 30"
  ok "running $OLDV again"
  if [ "$WITHDB" = 0 ]; then
    if ls "$LAST"/huginn.db* >/dev/null 2>&1; then
      echo "    The database was not touched. To also go back to the copy from before that update (events since then"
      echo "    come back from the honeypot's export only if it still has them): ./update-huginn.sh --rollback --with-db"
    else
      echo "    The database was not touched (this backup has no database copy; only the newest one keeps it)."
    fi
  fi
  exit 0
fi

# ------------------------------------------------------------------ update
# Version order: 1.0.0-rc1 comes after every 0.x and before 1.0.0 (same rule as vtuple in app.py).
VKEY='import re, sys
def vkey(v):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?", v.strip())
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 10 ** 6) if m else (0,)'
OLD=$(ver "$DIR/app.py")
NEW=$(ver "$HERE/app.py")
[ -n "$NEW" ] || die "Run this from the Huginn repository folder."
if [ "$OLD" = "$NEW" ] && [ "$FORCE" != 1 ]; then
  ok "RavenTrap $OLD is already the newest version in this folder (did you run git pull?)"
  exit 0
fi
if [ "$FORCE" != 1 ] && python3 -c "$VKEY
a,b=[vkey(v) for v in sys.argv[1:]]; sys.exit(0 if b < a else 1)" "$OLD" "$NEW"; then
  die "This folder has $NEW, which is older than the installed $OLD. Use --rollback to go back, or --force."
fi
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$HERE/app.py" || die "The new app.py does not parse — nothing was changed."

say "Backup of $OLD"
B="$BK/$OLD-$(date +%Y%m%d-%H%M%S)"
install -d -m 700 "$BK" "$B"
cp -p "$DIR/app.py" "$B/app.py"
[ -d "$DIR/static" ] && cp -a "$DIR/static" "$B/static"
cp -p "/etc/systemd/system/$SVC.service" "$B/huginn.service" 2>/dev/null || true
if [ -f "$DB" ]; then
  # As the database's owner: root must not open files in a folder the service user controls. The copy is streamed out,
  # compressed like RavenTrap's own daily copies, so app.py restore-db reads it.
  OWNER=$(stat -c %U "$BASE/data")
  T=$(mktemp -d)
  chown "$OWNER" "$T"
  runuser -u "$OWNER" -- python3 -I - "$DB" "$T/huginn.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2])
src.backup(dst)          # consistent copy while RavenTrap keeps running
dst.close(); src.close()
PY
  runuser -u "$OWNER" -- cat "$T/huginn.db" | gzip -1 > "$B/huginn.db.gz"
  chmod 600 "$B/huginn.db.gz"
  rm -rf "$T"
fi
ok "saved in $B"

say "Installing $NEW"
install_new() {  # everything that can leave a half-finished update: any failure goes to the rollback below
  install -m 644 "$HERE/app.py" "$DIR/app.py" || return 1
  if [ -d "$HERE/static" ]; then
    install -d -m 755 "$DIR/static" && install -m 644 "$HERE"/static/* "$DIR/static/" || return 1
  fi
  if ! cmp -s "$HERE/systemd/huginn.service" "/etc/systemd/system/$SVC.service"; then
    install -m 644 "$HERE/systemd/huginn.service" "/etc/systemd/system/$SVC.service" || return 1
    ok "updated the systemd service"
  fi
  systemctl daemon-reload || return 1
  systemctl restart "$SVC" || return 1
}
if install_new && wait_for "$NEW"; then
  ok "RavenTrap $NEW is running"
else
  warn "RavenTrap $NEW did not come up — rolling back to $OLD"
  journalctl -u "$SVC" -n 15 --no-pager -o cat 2>/dev/null | sed 's/^/      /' || true
  restore "$B" || warn "the rollback had errors, see above"
  # The new version may have changed the database before it failed: put the copy from just before the update back too.
  if [ -f "$B/huginn.db.gz" ]; then
    systemctl stop "$SVC"
    if restore_db "$B"; then DBMSG="database put back to the copy from just before the update"
    else DBMSG="the database copy could NOT be put back (it is in $B)"; fi
    systemctl start "$SVC"
  else DBMSG="there was no database yet"; fi
  if wait_for "$OLD"; then
    die "Update failed; $OLD is running again, $DBMSG. Please report the log above."
  fi
  die "Update failed and $OLD did not come back either — see: journalctl -u $SVC -n 50"
fi

# keep the newest $KEEP backups, and a database copy only in the newest one (the database grows, the code stays tiny)
backups_newest_first | tail -n +$((KEEP + 1)) | while read -r old; do rm -rf -- "$old"; done
backups_newest_first | tail -n +2 | while read -r old; do rm -f -- "$old/huginn.db" "$old/huginn.db.gz"; done

# Only when going up: after --force to an older version there is nothing new to list.
NEWS=$(python3 - "$HERE/app.py" "$OLD" "$VKEY" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1]).read())
log = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CHANGELOG")
exec(sys.argv[3])
old = vkey(sys.argv[2])
for v, d, text in log:
    if vkey(v) > old:
        head, *rest = text.split("\n")
        print("    %s  %s" % (v, head))
        for line in rest:
            print("            %s" % line)
PY
)
if [ -n "$NEWS" ]; then
  say "What is new since $OLD"
  printf '%s\n\n' "$NEWS"
fi
