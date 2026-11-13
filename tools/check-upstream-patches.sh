#!/bin/bash
# check-upstream-patches.sh — do Huginn's small patches still fit the newest Cowrie and OpenCanary? (part of Huginn, AGPL-3.0-or-later)
# Downloads both into a temporary folder (nothing is installed), patches them and checks that the result compiles.
# Run by CI every week, so an upstream change is noticed before an update-honeypot.sh run on a real honeypot.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
FAIL=0

check() {  # check NAME FILE COMMAND
  local rc=0
  python3 "$HERE/honeypot/patches.py" "$3" "$2" || rc=$?
  if [ "$rc" = 0 ] && python3 -m py_compile "$2"; then echo "ok    $1"; else echo "FAIL  $1 (patches.py exit $rc)"; FAIL=1; fi
}

git clone -q --depth 1 https://github.com/cowrie/cowrie "$W/cowrie"
echo "Cowrie $(git -C "$W/cowrie" log -1 --format='%h %cs')"
check "Cowrie free.py" "$W/cowrie/src/cowrie/commands/free.py" cowrie-free
check "Cowrie forwarding.py" "$W/cowrie/src/cowrie/ssh/forwarding.py" cowrie-forward
check "Cowrie ping.py" "$W/cowrie/src/cowrie/commands/ping.py" cowrie-ping
check "Cowrie wget.py" "$W/cowrie/src/cowrie/commands/wget.py" cowrie-wget
check "Cowrie protocol.py (exec)" "$W/cowrie/src/cowrie/shell/protocol.py" cowrie-exec
# The upload patch changes several files at once (all or none).
rc=0
python3 "$HERE/honeypot/patches.py" cowrie-upload "$W/cowrie/src/cowrie" || rc=$?
if [ "$rc" = 0 ] && (cd "$W/cowrie/src/cowrie" && python3 -m py_compile shell/server.py shell/session.py shell/fs.py shell/filetransfer.py commands/scp.py); then
  echo "ok    Cowrie upload (server, session, fs, filetransfer, scp)"
else
  echo "FAIL  Cowrie upload (patches.py exit $rc)"; FAIL=1
fi

python3 -m pip download -q --no-deps --no-binary :none: -d "$W/oc" opencanary >/dev/null
WHL=$(ls "$W"/oc/opencanary-*.whl 2>/dev/null | head -1 || true)
if [ -n "$WHL" ]; then
  python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$WHL" "$W/oc/x"
else
  tar -xzf "$W"/oc/opencanary-*.tar.gz -C "$W/oc" && mkdir -p "$W/oc/x" && cp -r "$W"/oc/opencanary-*/opencanary "$W/oc/x/"
fi
echo "OpenCanary $(basename "$(ls "$W"/oc/opencanary-* | head -1)")"
check "OpenCanary http.py" "$W/oc/x/opencanary/modules/http.py" opencanary-http
exit $FAIL
