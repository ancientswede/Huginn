#!/bin/bash
# check-isolation.sh — run ON THE HONEYPOT to check it cannot reach your other networks (part of Huginn, AGPL-3.0-or-later).
#
#   ./tools/check-isolation.sh 192.168.1.10 192.168.1.20:445 nas.lan:5000 ...
#
# Give it a few machines from your LAN (host or host:port; port 22 if none). Every one must be BLOCKED.
# It also tests the honeypot's own gateway: routers often isolate VLANs from each other but still let every VLAN reach
# the router itself (SSH, web admin). Only TCP connects and pings; nothing is sent beyond that. Exit code 1 if anything
# that should be blocked answers.
set -u
FAIL=0
tcp() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
row() { printf '  %-8s %-24s %s\n' "$1" "$2" "$3"; }
bad() { row "OPEN" "$1" "$2  <-- should be blocked"; FAIL=1; }

GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
echo "Honeypot: $(hostname -I 2>/dev/null | awk '{print $1}')   gateway: ${GW:-none}"

if [ -n "$GW" ]; then
  echo; echo "The gateway itself (router admin must be closed):"
  for p in 22 23 80 443 8080 8443 9443 10443; do
    if tcp "$GW" "$p"; then bad "$GW:$p" "router service"; else row "blocked" "$GW:$p" ""; fi
  done
  if tcp "$GW" 53; then row "info" "$GW:53" "DNS answers (fine if you want DNS; it may hand out your internal names)"; fi
fi

if [ $# -gt 0 ]; then
  echo; echo "Your LAN (must all be blocked):"
  for t in "$@"; do
    h="${t%%:*}"; p="${t##*:}"; [ "$p" = "$t" ] && p=22
    if tcp "$h" "$p"; then bad "$h:$p" "LAN"; else row "blocked" "$h:$p" ""; fi
    if ping -c1 -W2 "$h" >/dev/null 2>&1; then row "info" "$h" "answers ping"; fi
  done
else
  echo; echo "  (no LAN machines given: add a few, e.g. ./tools/check-isolation.sh 192.168.1.10 192.168.1.20:445)"
fi

echo; echo "Internet (your choice: blocked is safer, open lets Cowrie capture malware):"
if tcp 1.1.1.1 443; then row "open" "1.1.1.1:443" ""; else row "blocked" "1.1.1.1:443" ""; fi

echo
if [ "$FAIL" = 0 ]; then echo "OK: nothing that should be blocked answered."; else echo "NOT ISOLATED: fix the rules above before you open any ports."; fi
exit $FAIL
