#!/bin/bash
# install-honeypot.sh — set up the honeypot side for Huginn (part of Huginn, AGPL-3.0-or-later).
#
# Run as root on a fresh Debian 12/13 VM or LXC that sits on an ISOLATED network (no route to your LAN):
#   git clone https://github.com/ancientswede/Huginn.git && cd Huginn && ./install-honeypot.sh
#
# What it does (each optional part asks first, or use the flags):
#   1. Moves your admin SSH to another port (default 22022) — checked BEFORE anything takes port 22
#   2. Installs Cowrie (fake SSH on 22, fake Telnet on 23)
#   3. Optional: OpenCanary (fake FTP/HTTP/MySQL/Redis/VNC), endlessh (SSH tarpit on 2222),
#      hp-traps (fake SMTP relay/POP3/IMAP/PostgreSQL/SOCKS5)
#   4. Redirects the public ports to the honeypot services with nftables
#   5. Installs hp-export (the read-only export Huginn pulls) and hp-add-huginn-key
# Safe to run again: existing installs and configs are kept.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ADMIN_PORT=""
PERSONA_HOSTNAME="srv01"
WITH_CANARY=ask
WITH_TARPIT=ask
WITH_TRAPS=ask
COWRIE_REF=""
YES=0

# Internal ports (the public port -> internal port mapping lives in nftables)
COWRIE_SSH=2225
COWRIE_TELNET=2323
TARPIT=2224
CANARY_FTP=2121
CANARY_HTTP=8080
CANARY_HTTPS=8443

usage() {
  cat <<EOF
Usage: $0 [options]
  --admin-port N        your admin SSH port after install (asked if not given; suggestion 22022)
  --hostname NAME       hostname the fake shell shows (default $PERSONA_HOSTNAME)
  --opencanary | --no-opencanary
  --tarpit     | --no-tarpit       (endlessh on public port 2222)
  --traps      | --no-traps        (hp-traps: SMTP 25/587, POP3 110, IMAP 143, PostgreSQL 5432, SOCKS5 1080)
  --cowrie-ref REF      git branch/tag of Cowrie to install (default: its default branch)
  --yes                 no questions: optional parts default to yes, admin-port check is automatic
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-port) ADMIN_PORT="$2"; shift ;;
    --hostname) PERSONA_HOSTNAME="$2"; shift ;;
    --opencanary) WITH_CANARY=yes ;; --no-opencanary) WITH_CANARY=no ;;
    --tarpit) WITH_TARPIT=yes ;; --no-tarpit) WITH_TARPIT=no ;;
    --traps) WITH_TRAPS=yes ;; --no-traps) WITH_TRAPS=no ;;
    --cowrie-ref) COWRIE_REF="$2"; shift ;;
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
ask() {  # ask "question" default(yes|no) -> 0 for yes
  local q="$1" d="$2" a
  if [ "$YES" = 1 ]; then [ "$d" = yes ]; return; fi
  read -r -p "    $q [$([ "$d" = yes ] && echo Y/n || echo y/N)] " a </dev/tty || a=""
  a="${a:-$d}"; [[ "$a" =~ ^[YyJj] ]]
}
decide() {  # decide VAR "question"
  local v="${!1}"
  if [ "$v" = ask ]; then if ask "$2" yes; then printf -v "$1" yes; else printf -v "$1" no; fi; fi
}

start_svc() {  # start_svc unit -> enable, restart and verify it stays up
  systemctl daemon-reload
  systemctl enable "$1" >/dev/null 2>&1
  systemctl restart "$1"
  sleep 4
  if systemctl is-active --quiet "$1"; then ok "$1 is running"; else
    journalctl -u "$1" -n 15 --no-pager -o cat | sed 's/^/      /'
    die "$1 did not start (log above). Fix it and run the script again — finished steps are kept."
  fi
}

[ "$(id -u)" = 0 ] || die "Run as root."
if [ -z "$ADMIN_PORT" ]; then
  if [ "$YES" = 1 ]; then ADMIN_PORT=22022; else
    echo
    echo "    Port 22 will belong to the honeypot, so your own (admin) SSH needs another port."
    read -r -p "    Admin SSH port [22022]: " ADMIN_PORT </dev/tty || true
    ADMIN_PORT="${ADMIN_PORT:-22022}"
  fi
fi
[ -r /etc/debian_version ] || die "This script supports Debian 12/13 (and derivatives) only."
command -v systemctl >/dev/null || die "systemd is required."
[[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] && [ "$ADMIN_PORT" -gt 1024 ] && [ "$ADMIN_PORT" -lt 65536 ] || die "--admin-port must be 1025-65535."
for p in 22 23 2222 25 587 110 143 21 80 443 8080 5432 1080 $COWRIE_SSH $COWRIE_TELNET $TARPIT $CANARY_FTP $CANARY_HTTP $CANARY_HTTPS; do
  [ "$p" = "$ADMIN_PORT" ] && die "--admin-port $ADMIN_PORT collides with a honeypot port."
done
for f in honeypot/hp-export honeypot/hp-fileinfo honeypot/hp-traps.py honeypot/patches.py systemd/hp-traps.service; do
  [ -f "$HERE/$f" ] || die "Missing $f — run this from the Huginn repository folder."
done

cat <<EOF

  Huginn honeypot installer
  -------------------------
  This machine will be ATTACKED on purpose. It must sit on an isolated network/VLAN
  with no route to your LAN. Your admin SSH moves to port $ADMIN_PORT.
EOF
ask "Continue?" yes || exit 0
decide WITH_CANARY "Install OpenCanary (fake FTP, HTTP/HTTPS, MySQL, Redis, VNC)?"
decide WITH_TARPIT "Install endlessh (SSH tarpit on public port 2222)?"
decide WITH_TRAPS  "Install hp-traps (fake SMTP relay, POP3, IMAP, PostgreSQL, SOCKS5)?"

# ------------------------------------------------------------------ packages
say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3 python3-venv python3-dev build-essential libssl-dev libffi-dev \
  nftables openssh-server util-linux ca-certificates >/dev/null
ok "base packages"

# ------------------------------------------------------------------ 1. admin SSH port
say "Admin SSH on port $ADMIN_PORT"
if ss -ltnH "sport = :$ADMIN_PORT" | grep -q .; then
  ok "something already listens on $ADMIN_PORT (assuming it is sshd)"
else
  install -d /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/10-huginn-admin.conf <<EOF
# Added by Huginn install-honeypot.sh: admin SSH. Public port 22 is redirected to the Cowrie honeypot.
Port 22
Port $ADMIN_PORT
EOF
  sshd -t || die "sshd config test failed (see above); nothing was changed on port 22."
  # Debian 13 starts sshd through ssh.socket, which ignores Port lines: switch to the plain service.
  if systemctl is-enabled ssh.socket >/dev/null 2>&1 || systemctl is-active ssh.socket >/dev/null 2>&1; then
    systemctl disable --now ssh.socket >/dev/null 2>&1 || true
    systemctl enable ssh.service >/dev/null 2>&1 || true
  fi
  systemctl restart ssh.service
  sleep 2
  ss -ltnH "sport = :$ADMIN_PORT" | grep -q . || die "sshd does not listen on $ADMIN_PORT. Port 22 is untouched; fix sshd and run again."
  ok "sshd listens on 22 and $ADMIN_PORT (existing sessions stay open)"
fi
ssh-keyscan -T 5 -p "$ADMIN_PORT" 127.0.0.1 2>/dev/null | grep -q ssh- || die "sshd on $ADMIN_PORT does not answer."
ok "sshd answers on $ADMIN_PORT"
if [ "$YES" != 1 ]; then
  echo
  echo "    Open a NEW terminal now and log in with:  ssh -p $ADMIN_PORT root@<this machine>"
  echo "    Only continue when that works — after the next steps, port 22 belongs to the honeypot."
  ask "Did the login on port $ADMIN_PORT work?" no || die "Stopped. Port 22 still goes to your real sshd."
fi

# ------------------------------------------------------------------ 2. Cowrie
say "Cowrie (fake SSH/Telnet)"
id cowrie >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/cowrie --shell /usr/sbin/nologin cowrie
C=/home/cowrie/cowrie
if [ ! -d "$C/.git" ]; then
  runuser -u cowrie -- git clone -q --depth 1 ${COWRIE_REF:+--branch "$COWRIE_REF"} https://github.com/cowrie/cowrie "$C"
  ok "cloned Cowrie"
else
  ok "Cowrie already cloned ($C)"
fi
if [ ! -x "$C/cowrie-env/bin/cowrie" ]; then
  runuser -u cowrie -- python3 -m venv "$C/cowrie-env"
  runuser -u cowrie -- "$C/cowrie-env/bin/pip" install -q --upgrade pip
  runuser -u cowrie -- bash -c "cd '$C' && cowrie-env/bin/pip install -q -e ."
  ok "installed Cowrie into a venv"
else
  ok "Cowrie venv exists"
fi
if [ ! -f "$C/etc/cowrie.cfg" ]; then
  cat > "$C/etc/cowrie.cfg" <<EOF
# Written by Huginn install-honeypot.sh. Full list of settings: src/cowrie/data/etc/cowrie.cfg.dist
[honeypot]
hostname = $PERSONA_HOSTNAME
# Let attackers in after 2-5 tries (like a weak real device), remember each IP's password
auth_class = AuthRandom
auth_class_parameters = 2, 5, 10

[ssh]
listen_endpoints = tcp:$COWRIE_SSH:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:$COWRIE_TELNET:interface=0.0.0.0
EOF
  chown cowrie:cowrie "$C/etc/cowrie.cfg"
  ok "wrote $C/etc/cowrie.cfg"
else
  ok "keeping existing $C/etc/cowrie.cfg"
fi
# Cowrie's "free" reads the host's real /proc/meminfo, which gives the honeypot away: read the fake one first.
FREE="$C/src/cowrie/commands/free.py"
if [ -f "$FREE" ]; then
  rc=0; python3 "$HERE/honeypot/patches.py" cowrie-free "$FREE" || rc=$?
  case $rc in 0) ok "patched free.py to read the fake /proc/meminfo" ;; 3) ok "free.py already patched" ;; *) warn "free.py not patched (Cowrie changed); harmless" ;; esac
fi
cat > /etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH/Telnet honeypot
After=network.target

[Service]
User=cowrie
Group=cowrie
WorkingDirectory=$C
Environment=PATH=$C/cowrie-env/bin:/usr/bin:/bin
ExecStart=$C/cowrie-env/bin/cowrie start -- -n
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
start_svc cowrie

# ------------------------------------------------------------------ 3a. endlessh
if [ "$WITH_TARPIT" = yes ]; then
  say "endlessh (tarpit)"
  apt-get install -y -qq endlessh >/dev/null
  install -d /etc/endlessh
  cat > /etc/endlessh/config <<EOF
# Written by Huginn install-honeypot.sh. Public port 2222 is redirected here.
Port $TARPIT
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
BindFamily 4
EOF
  install -d /etc/systemd/system/endlessh.service.d
  cat > /etc/systemd/system/endlessh.service.d/huginn.conf <<'EOF'
[Service]
# Works in unprivileged LXC too; the port is above 1024 so no capabilities are needed.
PrivateUsers=no
User=nobody
Group=nogroup
EOF
  start_svc endlessh
fi

# ------------------------------------------------------------------ 3b. OpenCanary
if [ "$WITH_CANARY" = yes ]; then
  say "OpenCanary (fake FTP/HTTP/MySQL/Redis/VNC)"
  id opencanary >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/opencanary --shell /usr/sbin/nologin opencanary
  O=/home/opencanary
  if [ ! -x "$O/oc-env/bin/opencanaryd" ]; then
    runuser -u opencanary -- python3 -m venv "$O/oc-env"
    runuser -u opencanary -- "$O/oc-env/bin/pip" install -q --upgrade pip
    runuser -u opencanary -- "$O/oc-env/bin/pip" install -q opencanary
    ok "installed OpenCanary into a venv"
  fi
  if [ ! -f "$O/.opencanary.conf" ]; then
    DEFAULT=$(find "$O/oc-env" -path "*opencanary/data/settings.json" | head -1)
    [ -n "$DEFAULT" ] || die "OpenCanary default settings.json not found."
    python3 - "$DEFAULT" "$O/.opencanary.conf" "$CANARY_FTP" "$CANARY_HTTP" "$(hostname)" <<'PY'
import json, sys
src, dst, ftp, http, host = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
c = json.load(open(src))
for k in list(c):
    if k.endswith(".enabled"):
        c[k] = False
c["device.node_id"] = host
c.update({"ftp.enabled": True, "ftp.port": ftp, "http.enabled": True, "http.port": http, "http.skin": "nasLogin",
          "http.banner": "Apache/2.4.41 (Ubuntu)", "http.log_redirect_request": True,
          "https.enabled": True, "https.port": 8443, "https.skin": "nasLogin",
          "https.certificate": "/home/opencanary/https.pem", "https.key": "/home/opencanary/https.key",
          "mysql.enabled": True, "mysql.port": 3306, "redis.enabled": True, "redis.port": 6379,
          "vnc.enabled": True, "vnc.port": 5900})
c["logger"] = {"class": "PyLogger", "kwargs": {"formatters": {"plain": {"format": "%(message)s"}},
               "handlers": {"file": {"class": "logging.FileHandler", "filename": "/home/opencanary/opencanary.log"}}}}
json.dump(c, open(dst, "w"), indent=2)
PY
    chown opencanary:opencanary "$O/.opencanary.conf"
    ok "wrote $O/.opencanary.conf"
  fi
  # OpenCanary refuses to start if two modules share a port, even when one is disabled: move disabled ones away.
  python3 "$HERE/honeypot/patches.py" opencanary-ports "$O/.opencanary.conf" || true
  cat > /etc/systemd/system/opencanary.service <<EOF
[Unit]
Description=OpenCanary honeypot
After=network.target

[Service]
User=opencanary
Group=opencanary
WorkingDirectory=$O
Environment=PATH=$O/oc-env/bin:/usr/bin:/bin
ExecStart=$O/oc-env/bin/twistd -noy $O/oc-env/bin/opencanary.tac --pidfile $O/oc.pid
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  # Self-signed certificate with a generic NAS name — never your real certificate (it would link your IP to your domain).
  if [ ! -f "$O/https.key" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=DiskStation" -addext "subjectAltName=DNS:DiskStation" \
      -keyout "$O/https.key" -out "$O/https.pem" 2>/dev/null
    chown opencanary:opencanary "$O/https.key" "$O/https.pem"; chmod 600 "$O/https.key"
    ok "self-signed certificate CN=DiskStation"
  fi
  # OpenCanary answers unknown paths with 404 and never logs them, so most scanner traffic is invisible: log them.
  HTTPPY=$(find "$O/oc-env" -path "*opencanary/modules/http.py" | head -1)
  if [ -n "$HTTPPY" ]; then
    rc=0; python3 "$HERE/honeypot/patches.py" opencanary-http "$HTTPPY" || rc=$?
    case $rc in 0) ok "OpenCanary logs every probed web path" ;; 3) ok "OpenCanary web logging already patched" ;; *) warn "OpenCanary 404 logging not patched (OpenCanary changed); harmless" ;; esac
  fi
  # OpenCanary never rotates its log: rotate daily, uncompressed so hp-export can still read every file.
  cat > /etc/logrotate.d/opencanary <<EOF
$O/opencanary.log {
    daily
    rotate 14
    dateext
    missingok
    notifempty
    nocompress
    copytruncate
    su opencanary opencanary
}
EOF
  start_svc opencanary
fi

# ------------------------------------------------------------------ 3c. hp-traps
if [ "$WITH_TRAPS" = yes ]; then
  say "hp-traps (fake SMTP relay, POP3, IMAP, PostgreSQL, SOCKS5)"
  install -d -m 755 /opt/hp-traps
  install -m 644 "$HERE/honeypot/hp-traps.py" /opt/hp-traps/hp-traps.py
  [ -f /etc/systemd/system/hp-traps.service ] || install -m 644 "$HERE/systemd/hp-traps.service" /etc/systemd/system/hp-traps.service
  start_svc hp-traps
fi

# ------------------------------------------------------------------ 4. nftables redirects
say "Port redirects (nftables)"
RULES="    tcp dport 22 counter redirect to :$COWRIE_SSH
    tcp dport 23 counter redirect to :$COWRIE_TELNET"
[ "$WITH_TARPIT" = yes ] && RULES="$RULES
    tcp dport 2222 counter redirect to :$TARPIT"
[ "$WITH_CANARY" = yes ] && RULES="$RULES
    tcp dport 21 counter redirect to :$CANARY_FTP
    tcp dport 80 counter redirect to :$CANARY_HTTP
    tcp dport 443 counter redirect to :$CANARY_HTTPS"
[ "$WITH_TRAPS" = yes ] && RULES="$RULES
    tcp dport 25 counter redirect to :2525
    tcp dport 587 counter redirect to :2587
    tcp dport 110 counter redirect to :2110
    tcp dport 143 counter redirect to :2143"
cat > /etc/huginn-honeypot.nft <<EOF
# Written by Huginn install-honeypot.sh — public honeypot ports -> local honeypot services.
# Admin SSH ($ADMIN_PORT) is NOT redirected.
table ip huginn_honeypot
delete table ip huginn_honeypot
table ip huginn_honeypot {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
$RULES
  }
}
EOF
[ -f /etc/nftables.conf ] || printf '#!/usr/sbin/nft -f\nflush ruleset\n' > /etc/nftables.conf
if ! grep -q 'include "/etc/huginn-honeypot.nft"' /etc/nftables.conf; then
  cp -p /etc/nftables.conf "/etc/nftables.conf.bak-huginn-$(date +%s)"
  printf '\ninclude "/etc/huginn-honeypot.nft"\n' >> /etc/nftables.conf
fi
nft -c -f /etc/nftables.conf || die "nftables check failed — no rules were loaded."
nft -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1
ok "port 22 -> Cowrie from now on (admin: port $ADMIN_PORT)"

# ------------------------------------------------------------------ 5. export for Huginn
say "Export for Huginn"
install -m 755 "$HERE/honeypot/hp-export" /usr/local/bin/hp-export
install -m 755 "$HERE/honeypot/hp-fileinfo" /usr/local/bin/hp-fileinfo
if [ ! -f /etc/default/hp-export ]; then
  cat > /etc/default/hp-export <<EOF
# hp-export settings (read by /usr/local/bin/hp-export). Several Cowrie dirs = several personas.
COWRIE_DIRS="$C"
OPENCANARY_LOG="/home/opencanary/opencanary.log"
ENDLESSH_UNIT="endlessh"
TRAPS_LOG_DIR="/var/log/hp-traps"
FILEINFO_USER="cowrie"
EOF
fi
cat > /usr/local/sbin/hp-add-huginn-key <<'EOF'
#!/bin/bash
# Adds Huginn's public key to root's authorized_keys, locked to the read-only export.
# Usage: hp-add-huginn-key 'ssh-ed25519 AAAA... huginn'
set -euo pipefail
key="$*"
[[ "$key" =~ ^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa)\ [A-Za-z0-9+/=]{40,}(\ [A-Za-z0-9@._:-]{1,64})?$ ]] || { echo "That does not look like one SSH public key line." >&2; exit 1; }
blob="$(echo "$key" | awk '{print $2}')"
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
if grep -qF "$blob" /root/.ssh/authorized_keys; then echo "Key is already present."; exit 0; fi
cp -p /root/.ssh/authorized_keys "/root/.ssh/authorized_keys.bak-$(date +%s)"
echo "restrict,command=\"/usr/local/bin/hp-export\" $key" >> /root/.ssh/authorized_keys
echo "Added. This key can only run /usr/local/bin/hp-export (no shell, no forwarding)."
EOF
chmod 755 /usr/local/sbin/hp-add-huginn-key
SECTIONS=$(sleep 30 | timeout 60 /usr/local/bin/hp-export | grep -c '^##' || true)
[ "$SECTIONS" -ge 7 ] && ok "hp-export works ($SECTIONS sections)" || warn "hp-export printed $SECTIONS sections (expected 7)"

# ------------------------------------------------------------------ summary
say "Done"
sleep 3
for s in cowrie $( [ "$WITH_TARPIT" = yes ] && echo endlessh ) $( [ "$WITH_CANARY" = yes ] && echo opencanary ) $( [ "$WITH_TRAPS" = yes ] && echo hp-traps ); do
  printf '    %-11s %s\n' "$s" "$(systemctl is-active "$s")"
done
FWD="22, 23"
[ "$WITH_TARPIT" = yes ] && FWD="$FWD, 2222"
[ "$WITH_CANARY" = yes ] && FWD="$FWD, 21, 80, 443, 8080, 3306, 5900, 6379"
[ "$WITH_TRAPS" = yes ] && FWD="$FWD, 25, 587, 110, 143, 1080, 5432"
cat <<EOF

  Admin SSH from now on:   ssh -p $ADMIN_PORT root@$(hostname -I | awk '{print $1}')

  Next:
  1. On your Huginn machine run ./install-huginn.sh — it prints a key line.
  2. Back here:  hp-add-huginn-key '<that line>'
  3. FIRST prove this machine is isolated: from here, these must all FAIL:
       ping -c1 <a LAN machine>   /   nc -zv -w3 <your router> 80
     Read "Read this before you open any ports" in README.md.
  4. Only then, in your router, forward these TCP ports from the internet to this machine:
       $FWD
     (never forward $ADMIN_PORT)
EOF
