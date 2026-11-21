#!/bin/bash
# check-isolation.sh — run ON THE HONEYPOT to check it cannot reach your other networks (part of Huginn, AGPL-3.0-or-later).
#
#   ./tools/check-isolation.sh 192.168.1.10 192.168.1.20:445 nas.lan:5000 fd00::10 [fd00::20]:445 ...
#
# Give it a few machines from your LAN (host, host:port, an IPv6 address or [IPv6]:port; port 22 if none), and include
# IPv6 ones if your LAN has IPv6. Every one must be BLOCKED. A name that does not resolve counts as NOT TESTED.
# It also tests the honeypot's own gateway: routers often isolate VLANs from each other but still let every VLAN reach
# the router itself (SSH, web admin). Only TCP connects and pings; nothing is sent beyond that. Exit code 1 if anything
# that should be blocked answers.
set -u
FAIL=0
UNTESTED=0
# The host and port are passed as arguments, never pasted into the shell code (a name could hold shell syntax).
tcp() { timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' tcp "$1" "$2" 2>/dev/null; }
row() { printf '  %-8s %-28s %s\n' "$1" "$2" "$3"; }
bad() { row "OPEN" "$1" "$2  <-- should be blocked"; FAIL=1; }
untested() { row "UNTESTED" "$1" "$2"; UNTESTED=1; }
command -v timeout >/dev/null || { echo "This needs the timeout command (coreutils)."; exit 2; }

GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
GW6=$(ip -6 route show default 2>/dev/null | awk '{print $3; exit}')
echo "Honeypot: $(hostname -I 2>/dev/null | awk '{print $1}')   gateway: ${GW:-none}   IPv6 gateway: ${GW6:-none}"

for g in $GW $GW6; do
  echo; echo "The gateway $g itself (router admin must be closed):"
  case "$g" in fe80:*|FE80:*) g6="$g%$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"; ;; *) g6="$g" ;; esac
  for p in 22 23 80 443 8080 8443 9443 10443; do
    l="$g:$p"; [[ "$g" == *:* ]] && l="[$g]:$p"
    if tcp "$g6" "$p"; then bad "$l" "router service"; else row "blocked" "$l" ""; fi
  done
  if tcp "$g6" 53; then row "info" "$g port 53" "DNS answers (fine if you want DNS; it may hand out your internal names)"; fi
done

if [ $# -gt 0 ]; then
  echo; echo "Your LAN (must all be blocked):"
  for t in "$@"; do
    if [[ "$t" =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$ ]]; then h="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[2]}"
    elif [[ "$t" =~ ^\[([0-9A-Fa-f:.]+)\]$ ]] || [[ "$t" =~ ^([0-9A-Fa-f]*:[0-9A-Fa-f:.]*)$ ]]; then h="${BASH_REMATCH[1]}"; p=22
    elif [[ "$t" =~ ^([A-Za-z0-9._-]+):([0-9]{1,5})$ ]]; then h="${BASH_REMATCH[1]}"; p="${BASH_REMATCH[2]}"
    elif [[ "$t" =~ ^([A-Za-z0-9._-]+)$ ]]; then h="${BASH_REMATCH[1]}"; p=22
    else untested "$t" "not a host, host:port or [IPv6]:port"; continue
    fi
    if ! getent ahosts "$h" >/dev/null 2>&1; then untested "$h" "the name does not resolve here, so nothing was tried"; continue; fi
    l="$h:$p"; [[ "$h" == *:* ]] && l="[$h]:$p"
    if tcp "$h" "$p"; then bad "$l" "LAN"; else row "blocked" "$l" ""; fi
    if ping -c1 -W2 "$h" >/dev/null 2>&1; then row "info" "$h" "answers ping"; fi
  done
else
  echo; echo "  (no LAN machines given: add a few, e.g. ./tools/check-isolation.sh 192.168.1.10 192.168.1.20:445)"
fi

echo; echo "Internet (your choice: blocked is safer, open lets Cowrie capture malware):"
if tcp 1.1.1.1 443; then row "open" "1.1.1.1:443" ""; else row "blocked" "1.1.1.1:443" ""; fi

echo
if [ "$FAIL" != 0 ]; then echo "NOT ISOLATED: fix the rules above before you open any ports."; exit 1; fi
if [ "$UNTESTED" != 0 ]; then echo "NOT DONE: some targets were not tested (see UNTESTED above). Use addresses, or fix the names."; exit 1; fi
if [ -n "$GW6" ] && ! printf '%s\n' "$@" | grep -q ':.*:'; then
  echo "OK for what was tested, but this machine has IPv6 and no IPv6 LAN address was given: add one if your LAN has IPv6."
  exit 0
fi
echo "OK: nothing that should be blocked answered."
exit 0
