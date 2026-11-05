#!/bin/bash
# install-huginn.sh — install Huginn on a LAN machine (part of Huginn, AGPL-3.0-or-later).
#
# Run as root on Debian 12/13 (VM or LXC) on your normal LAN, AFTER install-honeypot.sh:
#   git clone https://github.com/ancientswede/Huginn.git && cd Huginn && ./install-huginn.sh --honeypot 192.0.2.10
#
# It installs Huginn, creates a key, shows the one command to run on the honeypot,
# waits until the honeypot answers, starts the service and asks for a login password.
# Safe to run again: an existing .env, key and database are kept.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HP_HOST=""
HP_PORT=""
WEB_PORT=8095
TZ_NAME=""
NTFY=""
NTFY_TOKEN=""
NO_NTFY=0
YES=0
NO_PASSWORD=0
WAIT_MIN=15

usage() {
  cat <<EOF
Usage: $0 --honeypot HOST [options]
  --honeypot HOST       honeypot address (required)
  --honeypot-port N     the honeypot's admin SSH port chosen in install-honeypot.sh (asked if not given; default 22022)
  --port N              Huginn web port (default $WEB_PORT)
  --tz ZONE             time zone, e.g. Europe/Stockholm (default: this machine's)
  --ntfy URL            ntfy topic URL for alerts, e.g. http://ntfy.lan:2586/huginn (asked if not given)
  --ntfy-token TOKEN    access token for an ntfy server with access control (tk_...)
  --no-ntfy             do not ask about notifications
  --no-password         do not ask for the login password now (set it later with app.py set-password)
  --yes                 no questions; trust the honeypot host key on first contact
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --honeypot) HP_HOST="$2"; shift ;;
    --honeypot-port) HP_PORT="$2"; shift ;;
    --port) WEB_PORT="$2"; shift ;;
    --tz) TZ_NAME="$2"; shift ;;
    --ntfy) NTFY="$2"; shift ;;
    --ntfy-token) NTFY_TOKEN="$2"; shift ;;
    --no-ntfy) NO_NTFY=1 ;;
    --no-password) NO_PASSWORD=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
  shift
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
ask() {
  local q="$1" d="$2" a
  if [ "$YES" = 1 ]; then [ "$d" = yes ]; return; fi
  read -r -p "    $q [$([ "$d" = yes ] && echo Y/n || echo y/N)] " a </dev/tty || a=""
  a="${a:-$d}"; [[ "$a" =~ ^[YyJj] ]]
}

[ "$(id -u)" = 0 ] || die "Run as root."
[ -r /etc/debian_version ] || die "This script supports Debian 12/13 (and derivatives) only."
[ -f "$HERE/app.py" ] && [ -f "$HERE/systemd/huginn.service" ] || die "Run this from the Huginn repository folder."
if [ -z "$HP_HOST" ]; then
  [ "$YES" = 1 ] && die "--honeypot HOST is required."
  read -r -p "    Honeypot address (IP or hostname): " HP_HOST </dev/tty
fi
[[ "$HP_HOST" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid honeypot address."
if [ -z "$HP_PORT" ]; then
  if [ "$YES" = 1 ]; then HP_PORT=22022; else
    read -r -p "    The honeypot's admin SSH port (chosen in install-honeypot.sh) [22022]: " HP_PORT </dev/tty || true
    HP_PORT="${HP_PORT:-22022}"
  fi
fi
[[ "$HP_PORT$WEB_PORT" =~ ^[0-9]+$ ]] || die "Ports must be numbers."
if [ -z "$TZ_NAME" ]; then
  TZ_NAME="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)"
fi

# ------------------------------------------------------------------ notifications (optional)
if [ -z "$NTFY" ] && [ "$YES" != 1 ] && [ "$NO_NTFY" != 1 ] && ! grep -q "^HUGINN_NTFY_URL=." /opt/huginn/.env 2>/dev/null; then
  echo
  echo "    Huginn can push a short summary to ntfy (phone app) when something notable happens:"
  echo "    bait taken, new malware, a human-like session, an exploit. At most one message per hour."
  if ask "Set up ntfy notifications?" no; then
    SUGGEST="huginn-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d " \n")"
    echo "    Your own ntfy server:   http://ntfy.lan:2586/$SUGGEST"
    echo "    Public ntfy.sh:         https://ntfy.sh/$SUGGEST"
    echo "    (On ntfy.sh anyone who guesses the topic name can read it — keep a random name like this one.)"
    read -r -p "    Topic URL: " NTFY </dev/tty || NTFY=""
    if [ -n "$NTFY" ]; then
      read -r -s -p "    Access token (empty if your topic is open): " NTFY_TOKEN </dev/tty || NTFY_TOKEN=""; echo
    fi
  fi
fi
if [ -n "$NTFY" ]; then
  [[ "$NTFY" =~ ^https?://[A-Za-z0-9._:-]+/[A-Za-z0-9_-]{1,64}$ ]] || die "ntfy URL must look like http(s)://server/topic"
  [ -z "$NTFY_TOKEN" ] || [[ "$NTFY_TOKEN" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || die "That access token does not look right."
  if NTFY_URL="$NTFY" NTFY_TOKEN="$NTFY_TOKEN" python3 - <<'PY'
import os, urllib.request
h = {"Title": "Huginn: test", "Tags": "honey_pot"}
if os.environ.get("NTFY_TOKEN"):
    h["Authorization"] = "Bearer " + os.environ["NTFY_TOKEN"]
urllib.request.urlopen(urllib.request.Request(os.environ["NTFY_URL"], data=b"Huginn is being installed. Notifications work.", headers=h, method="POST"), timeout=10).read()
PY
  then ok "test notification sent — check your phone"
  else warn "could not send to $NTFY — check the URL/token; you can change HUGINN_NTFY_URL in /opt/huginn/.env later"
  fi
fi

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 openssh-client ca-certificates >/dev/null
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Python 3.10 or newer is required."
ok "python $(python3 -V | cut -d' ' -f2)"

say "Huginn files"
id huginn >/dev/null 2>&1 || useradd --system --home-dir /opt/huginn --shell /usr/sbin/nologin huginn
install -d -m 755 /opt/huginn
install -d -m 750 -o huginn -g huginn /opt/huginn/data
install -d -m 700 -o huginn -g huginn /opt/huginn/.ssh
install -m 644 "$HERE/app.py" /opt/huginn/app.py
install -d -m 755 /opt/huginn/static
install -m 644 "$HERE"/static/* /opt/huginn/static/
install -m 644 "$HERE/systemd/huginn.service" /etc/systemd/system/huginn.service
if [ ! -f /opt/huginn/.env ]; then
  cat > /opt/huginn/.env <<EOF
# Huginn settings (read by systemd). See .env.example in the repository for all options.
HUGINN_HP_HOST=$HP_HOST
HUGINN_HP_PORT=$HP_PORT
HUGINN_PORT=$WEB_PORT
HUGINN_TZ=$TZ_NAME
EOF
  chmod 600 /opt/huginn/.env
  ok "wrote /opt/huginn/.env"
else
  ok "keeping existing /opt/huginn/.env"
fi
if [ -n "$NTFY" ] && ! grep -q "^HUGINN_NTFY_URL=." /opt/huginn/.env; then
  {
    echo "HUGINN_NTFY_URL=$NTFY"
    [ -n "$NTFY_TOKEN" ] && echo "HUGINN_NTFY_TOKEN=$NTFY_TOKEN"
    grep -q "^HUGINN_PUBLIC_URL=." /opt/huginn/.env || echo "HUGINN_PUBLIC_URL=http://$(hostname -I | awk '{print $1}'):$WEB_PORT"
  } >> /opt/huginn/.env
  ok "ntfy notifications on (HUGINN_NTFY_URL in /opt/huginn/.env)"
fi
if [ ! -f /opt/huginn/.ssh/honeypot_ro ]; then
  runuser -u huginn -- ssh-keygen -q -t ed25519 -N "" -C "huginn@$(hostname)" -f /opt/huginn/.ssh/honeypot_ro
  ok "created key /opt/huginn/.ssh/honeypot_ro"
fi

say "Honeypot host key"
KNOWN=/opt/huginn/.ssh/known_hosts
if ! runuser -u huginn -- ssh-keygen -F "[$HP_HOST]:$HP_PORT" -f "$KNOWN" >/dev/null 2>&1; then
  SCAN=$(ssh-keyscan -T 10 -t ed25519 -p "$HP_PORT" "$HP_HOST" 2>/dev/null | grep -v '^#' || true)
  [ -n "$SCAN" ] || die "No SSH answer from $HP_HOST:$HP_PORT. Is install-honeypot.sh done, and may this machine reach that port?"
  echo "    The honeypot's key fingerprint is:"
  echo "$SCAN" | ssh-keygen -lf - | sed 's/^/      /'
  echo "    Compare on the honeypot with:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
  ask "Trust this key?" yes || die "Stopped."
  echo "$SCAN" >> "$KNOWN"
  chown huginn:huginn "$KNOWN"; chmod 644 "$KNOWN"
  ok "saved"
else
  ok "already known"
fi

test_export() {
  runuser -u huginn -- ssh -T -i /opt/huginn/.ssh/honeypot_ro -p "$HP_PORT" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN" "root@$HP_HOST" </dev/null 2>/dev/null \
    | grep -c '^##' || true
}

say "Connect Huginn to the honeypot"
N=$(test_export)
if [ "${N:-0}" -lt 7 ]; then
  cat <<EOF

    Run this ONE command on the honeypot (as root):

      hp-add-huginn-key '$(cat /opt/huginn/.ssh/honeypot_ro.pub)'

    It allows this key to run the read-only log export and nothing else.
    Waiting for it (up to $WAIT_MIN minutes)...
EOF
  END=$(( $(date +%s) + WAIT_MIN * 60 ))
  while [ "$(date +%s)" -lt "$END" ]; do
    sleep 5
    N=$(test_export)
    [ "${N:-0}" -ge 7 ] && break
  done
  [ "${N:-0}" -ge 7 ] || die "The honeypot did not accept the key in time. Add it and run this script again."
fi
ok "the honeypot export answers ($N sections)"

say "Starting Huginn"
systemctl daemon-reload
systemctl enable huginn >/dev/null 2>&1
systemctl restart huginn
sleep 4
systemctl is-active --quiet huginn || { journalctl -u huginn -n 20 --no-pager; die "huginn did not start."; }
ok "huginn is running"

HAS_PW=$(runuser -u huginn -- python3 -c "import sqlite3; c=sqlite3.connect('/opt/huginn/data/huginn.db'); print(1 if c.execute(\"SELECT 1 FROM meta WHERE k='pw'\").fetchone() else 0)" 2>/dev/null || echo 0)
if [ "$HAS_PW" = 1 ]; then
  ok "a login password is already set"
elif [ "$NO_PASSWORD" = 1 ] || [ ! -t 0 ]; then
  warn "no login password yet — set it with: runuser -u huginn -- python3 /opt/huginn/app.py set-password"
else
  say "Choose the login password for the web page"
  runuser -u huginn -- python3 /opt/huginn/app.py set-password </dev/tty
fi

cat <<EOF

  Huginn is ready:  http://$(hostname -I | awk '{print $1}'):$WEB_PORT
  The first sync runs within two minutes. Keep this page on your LAN or VPN.
EOF
