#!/bin/bash
# setup-suricata.sh — optional Suricata IDS on the honeypot (part of Huginn, AGPL-3.0-or-later).
# Run by install-honeypot.sh --suricata and update-honeypot.sh --suricata-on|--suricata-off|--suricata-rules (as root).
#
#   setup-suricata.sh on              install Suricata, write Huginn's config, fetch the ET Open rules, start it
#   setup-suricata.sh refresh         rewrite the config if Suricata is on (run by every update-honeypot.sh)
#   setup-suricata.sh rules FILE      load ET Open rules from a downloaded emerging.rules.tar.gz (honeypot without internet)
#   setup-suricata.sh update          fetch new rules (the daily timer runs this as /usr/local/sbin/hp-suricata update)
#   setup-suricata.sh off             stop and disable it (the package and rules stay)
#
# Suricata only listens: it reads a copy of the packets on the honeypot's own network card and writes an alert line
# when one matches a rule. It never blocks or changes traffic, and it needs nothing on your router. Only the alerts are
# written (no flows, no payloads); hp-export passes them to Huginn with the rest. Traffic to and from your admin SSH
# port on this machine is left out. Suricata starts as root to open the network card, then runs as the user
# hp-suricata, keeping only the network capabilities packet capture needs. Its log folder stays root's: it may only
# append to its two log files, which root creates for it.
# New rules are tested with the installed Suricata before they are used, and the previous set is kept: if Suricata
# does not start with the new ones, the old ones go back.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FLAG=/etc/huginn-honeypot/suricata
CONF=/etc/huginn-honeypot/suricata.yaml
DISABLE=/etc/huginn-honeypot/suricata-disable.conf
RULEDIR=/var/lib/suricata/rules
RULES=$RULEDIR/suricata.rules
PREV=/var/lib/suricata/rules.prev
SURI_USER=hp-suricata
LOG=/var/log/suricata/suricata.log
MIN_RULES=1000            # a rule set with fewer rules than this is not ET Open: refused
LOGDIR=/var/log/suricata
MAX_ADDRS=16; MAX_PORTS=8 # the capture filter grows with addresses x admin ports: refused beyond this

ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "Run as root."
# One change at a time (a manual run and the daily timer must not both swap the rules).
exec 9>/run/hp-suricata.lock
flock -w 900 9 || die "another hp-suricata run did not finish within 15 minutes."

# Private scratch space for logs and tests (never fixed names in /tmp), removed on exit.
WORK=$(mktemp -d)
STAGE=""
TESTDIR=""
cleanup() { rm -rf "$WORK"; [ -n "$STAGE" ] && rm -rf "$STAGE"; [ -n "$TESTDIR" ] && rm -rf "$TESTDIR"; return 0; }
trap cleanup EXIT

limited() {  # limited MEM SECS cmd... : a time limit, and a memory limit of its own when systemd can give one
  local mem="$1" secs="$2"; shift 2
  if command -v systemd-run >/dev/null && [ -d /run/systemd/system ]; then
    systemd-run --scope --quiet -p MemoryMax="$mem" -p CPUWeight=50 timeout "$secs" "$@"
  else
    timeout "$secs" "$@"
  fi
}

rules_url() {  # where the ET Open rules for this Suricata version are, for the message when there is no internet
  local v; v=$(suricata -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  echo "https://rules.emergingthreats.net/open/suricata-${v:-7.0.10}/emerging.rules.tar.gz"
}

ensure_user() {
  # Suricata drops root after opening the network card. The log folder stays root's (so Suricata cannot swap files
  # in it for links or FIFOs that root later opens); root makes the two files it writes and hands only those over.
  id "$SURI_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SURI_USER"
  [ ! -L "$LOGDIR" ] || die "$LOGDIR is a symlink."
  install -d -m 755 -o root -g root "$LOGDIR"
  chown root:root "$LOGDIR" && chmod 755 "$LOGDIR"
  python3 -I - "$LOGDIR" "$SURI_USER" <<'PY' || die "could not prepare Suricata's log files (see above)."
import os, pwd, stat, sys
d, user = sys.argv[1], sys.argv[2]
pw = pwd.getpwnam(user)
for name in ("eve.json", "suricata.log"):
    p = os.path.join(d, name)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o640)
    except OSError as e:
        sys.exit("%s: %s (remove it and run again)" % (p, e))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            sys.exit("%s is not a regular file (remove it and run again)" % p)
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
PY
}

log_size() {  # bytes in Suricata's log now; root opens it only as a regular file, never a link or FIFO
  python3 -I -c 'import os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
except OSError:
    print(0); sys.exit()
st = os.fstat(fd); print(st.st_size if stat.S_ISREG(st.st_mode) else 0)' "$LOG"
}

log_since() {  # log_since BYTES: at most 1 MB of the log written after that point (all of it if the log was rotated)
  python3 -I -c 'import os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
except OSError:
    sys.exit()
with os.fdopen(fd, "rb") as fh:
    st = os.fstat(fh.fileno())
    if not stat.S_ISREG(st.st_mode):
        sys.exit()
    start = int(sys.argv[2])
    fh.seek(start if start <= st.st_size else 0)
    sys.stdout.buffer.write(fh.read(1 << 20))' "$LOG" "$1"
}

write_conf() {
  # Huginn's own complete config, made from the package's suricata.yaml so it follows the installed version.
  local iface ips ports
  iface=$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')
  [ -n "$iface" ] || iface=$(ip -o link show | awk -F': ' '$2 != "lo" {sub(/@.*/, "", $2); print $2; exit}')
  [ -n "$iface" ] || die "found no network card for Suricata."
  ips=$(ip -o addr show dev "$iface" scope global | awk '{sub(/\/.*/, "", $4); print $4}' | paste -sd, -)
  [ -n "$ips" ] || die "$iface has no address."
  # Every port the real sshd listens on, from Port and from ListenAddress (which may name its own port). Port 22 is
  # the honeypot's (redirected to Cowrie), so it is watched.
  # If sshd cannot tell (a broken config on disk), keep the config there is: never drop the admin exclusion silently.
  local sshd_t
  if ! sshd_t=$(sshd -T 2>"$WORK/sshd.err"); then
    sed 's/^/      /' "$WORK/sshd.err" | tail -3
    if [ -f "$CONF" ]; then warn "sshd -T failed: Suricata's config is left as it was"; return 0; fi
    die "sshd -T failed, so the admin SSH port to leave out is unknown (fix sshd's config and run again)."
  fi
  ports=$(printf '%s\n' "$sshd_t" | awk '$1 == "port" {print $2} $1 == "listenaddress" {n = split($2, a, ":"); print a[n]}' \
          | grep -E '^[0-9]{1,5}$' | grep -vx 22 | sort -un | paste -sd, - || true)
  install -d -m 755 /etc/huginn-honeypot
  python3 -I - "$iface" "$ips" "$ports" "$CONF" "$SURI_USER" "$MAX_ADDRS" "$MAX_PORTS" <<'PY'
import ipaddress, re, sys, yaml
iface, ips, ports, out, user = sys.argv[1:6]
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface):
    sys.exit("odd network card name: %r" % iface)
addrs = [str(ipaddress.ip_address(a)) for a in ips.split(",") if a]
ports = sorted({int(p) for p in ports.split(",") if p and 0 < int(p) < 65536})
if len(addrs) > int(sys.argv[6]) or len(ports) > int(sys.argv[7]):
    sys.exit("%d addresses and %d admin ports: too many for the capture filter" % (len(addrs), len(ports)))
src = open("/etc/suricata/suricata.yaml").read()
body = src.split("\n---\n", 1)[1] if src.startswith("%YAML") else src
c = yaml.safe_load(body)
c["vars"]["address-groups"]["HOME_NET"] = "[%s]" % ",".join(addrs)
c["vars"]["address-groups"]["EXTERNAL_NET"] = "!$HOME_NET"
cap = {"interface": iface, "cluster-id": 99, "cluster-type": "cluster_flow", "defrag": True, "tpacket-v3": True}
if ports:
    # Only the admin SSH itself: this machine's address AND its port, in each direction. An attacker who connects
    # FROM the same port number to a honeypot service is still watched.
    terms = ["(dst host %s and tcp dst port %d) or (src host %s and tcp src port %d)" % (a, p, a, p) for a in addrs for p in ports]
    cap["bpf-filter"] = "not (%s)" % " or ".join(terms)
c["af-packet"] = [cap, {"interface": "default"}]
# Alerts only: no flows, DNS, TLS or payloads, so nothing an attacker sends is copied into the export.
c["outputs"] = [{"eve-log": {"enabled": True, "filetype": "regular", "filename": "eve.json",
                 "types": [{"alert": {"payload": False, "payload-printable": False, "packet": False, "metadata": False,
                                      "http-body": False, "http-body-printable": False, "tagged-packets": False}}]}}]
c["stats"] = {"enabled": False}
c["logging"]["outputs"] = [{"console": {"enabled": False}},
                           {"file": {"enabled": True, "level": "notice", "filename": "/var/log/suricata/suricata.log"}}]
c["default-rule-path"] = "/var/lib/suricata/rules"
c["rule-files"] = ["suricata.rules"]
c["run-as"] = {"user": user, "group": user}       # root only while the network card is opened
c["unix-command"] = {"enabled": False}             # no control socket: Huginn restarts, never reloads
new = "%YAML 1.1\n---\n# Written by Huginn (honeypot/setup-suricata.sh). Rewritten by update-honeypot.sh: change the script, not this file.\n" \
      + yaml.safe_dump(c, sort_keys=False)
try:
    old = open(out).read()
except OSError:
    old = ""
if old != new:
    with open(out + ".new", "w") as fh:
        fh.write(new)
    import os
    os.replace(out + ".new", out)
    print("changed")
PY
}

write_disable() {
  # IP reputation lists (an alert for every packet from a listed address) say nothing about what an attacker did and
  # cost memory. Huginn makes its own lists from what they actually do.
  [ -f "$DISABLE" ] && return 0
  cat > "$DISABLE" <<'D'
# Written by Huginn: rule groups Suricata leaves out on the honeypot (edit freely; kept on update).
group:ciarmy.rules
group:compromised.rules
group:drop.rules
group:dshield.rules
group:tor.rules
group:botcc.rules
group:botcc.portgrouped.rules
D
}

write_unit() {
  install -d /etc/systemd/system/suricata.service.d
  cat > /etc/systemd/system/suricata.service.d/huginn.conf.new <<EOF
# Written by Huginn: Huginn's config, a sandbox, and limits so Suricata cannot take the honeypot's memory or CPU.
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D --af-packet -c $CONF --pidfile /run/suricata.pid
# No control socket (see the config): stop and restart with signals.
ExecReload=
ExecStop=
MemoryHigh=700M
MemoryMax=900M
Nice=10
CPUWeight=50
Restart=on-failure
RestartSec=30
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
EOF
  if cmp -s /etc/systemd/system/suricata.service.d/huginn.conf.new /etc/systemd/system/suricata.service.d/huginn.conf; then
    rm -f /etc/systemd/system/suricata.service.d/huginn.conf.new; return 1
  fi
  mv /etc/systemd/system/suricata.service.d/huginn.conf.new /etc/systemd/system/suricata.service.d/huginn.conf
  systemctl daemon-reload
}

write_timer() {
  install -m 755 "$HERE/honeypot/setup-suricata.sh" /usr/local/sbin/hp-suricata
  install -m 644 "$HERE/systemd/hp-suricata-rules.service" /etc/systemd/system/hp-suricata-rules.service
  install -m 644 "$HERE/systemd/hp-suricata-rules.timer" /etc/systemd/system/hp-suricata-rules.timer
  systemctl daemon-reload
  systemctl enable --now hp-suricata-rules.timer >/dev/null 2>&1
}

check_archive() {  # check_archive FILE: a plain ET Open archive, within limits, before anything reads it further
  local size
  size=$(stat -c %s "$1")
  [ "$size" -le 157286400 ] || die "$1 is over 150 MB: not an ET Open rules archive."
  [ -f "$1" ] && [ ! -L "$1" ] || die "$1 is not a regular file."
  limited 300M 120 python3 -I - "$1" <<'PY' || die "$1 is not an ET Open rules archive (see above)."
import os, sys, tarfile
members, total, rules = 0, 0, 0
try:
    with tarfile.open(sys.argv[1], "r:gz") as tf:
        for m in tf:
            members += 1
            parts = m.name.split("/")
            if members > 5000 or m.name.startswith("/") or ".." in parts or not (m.isfile() or m.isdir()):
                sys.exit("refused member: %r" % m.name[:200])
            total += m.size
            if total > 400 * 1048576:
                sys.exit("unpacks to over 400 MB")
            rules += m.isfile() and m.name.endswith(".rules")
except (tarfile.TarError, OSError, EOFError) as e:
    sys.exit("not a gzipped tar: %s" % e)
if not rules:
    sys.exit("no .rules files in it")
PY
}

engine_ready() {  # engine_ready BYTES: did Suricata finish loading since that point of its log? Waits up to 3 minutes.
  local from="$1" n
  for _ in $(seq 1 45); do
    sleep 4
    n=$(log_since "$from" | grep -c "Engine started" || true)      # grep -c reads it all: no early exit under pipefail
    [ "${n:-0}" -gt 0 ] && systemctl is-active --quiet suricata && return 0
    systemctl is-active --quiet suricata || return 1
  done
  return 1
}

restart_engine() {  # restart Suricata and wait until it really inspects traffic; 1 if it did not
  local n0
  ensure_user
  n0=$(log_size)
  systemctl enable suricata >/dev/null 2>&1
  systemctl restart suricata || return 1
  engine_ready "$n0"
}

start_check() {
  if restart_engine; then
    ok "Suricata is running ($(( $(systemctl show suricata -p MemoryCurrent --value 2>/dev/null || echo 0) / 1048576 )) MB)"
  else
    journalctl -u suricata -n 10 --no-pager -o cat | sed 's/^/      /'
    log_since $(( $(log_size) > 2000 ? $(log_size) - 2000 : 0 )) | tail -n 5 | sed 's/^/      /'
    die "Suricata did not start, or did not finish loading its rules within 3 minutes (log above)."
  fi
}

update_rules() {  # update_rules [URL] -> fetch into a staging folder, test, then use; 1 if nothing new could be used
  # Called as a condition, so set -e does not apply in here: every step checks its own result.
  local args n
  STAGE=$(mktemp -d /var/lib/suricata/rules.stage.XXXXXX) || return 1
  chmod 755 "$STAGE" || return 1           # Suricata reads its rules after it has dropped root, the test too
  args=(--no-test --no-reload -q --disable-conf "$DISABLE" -o "$STAGE")
  [ -n "${1:-}" ] && args+=(--url "$1")
  if ! limited 700M 900 suricata-update "${args[@]}" >"$WORK/update.log" 2>&1; then
    sed 's/^/      /' "$WORK/update.log" | tail -5; return 1
  fi
  n=$(grep -c '^alert' "$STAGE/suricata.rules" 2>/dev/null || true)
  [ "${n:-0}" -ge "$MIN_RULES" ] || { warn "the new rule set has ${n:-0} rules: not used"; return 1; }
  # The installed Suricata must accept them, with Huginn's config, before they replace the working set. The test
  # drops to the Suricata user like the real thing, so it gets a folder of that user's own and its own log.
  ensure_user
  TESTDIR=$(mktemp -d) || return 1
  chown "$SURI_USER:$SURI_USER" "$TESTDIR" || return 1
  if ! limited 900M 600 suricata -T -c "$CONF" -S "$STAGE/suricata.rules" -l "$TESTDIR" \
         --set logging.outputs.1.file.filename="$TESTDIR/test.log" >"$WORK/test.out" 2>&1; then
    # test.log belongs to the Suricata user: read it only as a regular file, and only its end
    { cat "$WORK/test.out"; LOG="$TESTDIR/test.log" log_since 0; } | grep -iE "error|fail" | tail -5 | sed 's/^/      /'
    warn "the new rules did not pass Suricata's own test: not used"; return 1
  fi
  # Publish by renaming whole folders: the working set is either the old one or the new one, never a mix. The old
  # one becomes rules.prev only once the new one is in place.
  rm -rf "$RULEDIR.next" "$RULEDIR.old" || return 1
  mv "$STAGE" "$RULEDIR.next" || return 1
  STAGE=""
  if [ -d "$RULEDIR" ]; then mv "$RULEDIR" "$RULEDIR.old" || return 1; fi
  if ! mv "$RULEDIR.next" "$RULEDIR"; then
    [ -d "$RULEDIR.old" ] && mv "$RULEDIR.old" "$RULEDIR"
    warn "could not put the new rules in place: the old ones are still in use"; return 1
  fi
  if [ -d "$RULEDIR.old" ]; then
    rm -rf "$PREV" && mv "$RULEDIR.old" "$PREV" || warn "the previous rules could not be kept as $PREV"
  fi
  ok "rules: $n from ET Open, tested"
}

use_new_rules() {  # restart with the new rules; if that fails, put the previous set back and start with it
  [ -f "$FLAG" ] || return 0
  if restart_engine; then
    ok "Suricata is running with the new rules"
    return 0
  fi
  if [ ! -d "$PREV" ]; then
    warn "Suricata did not start with the new rules, and there is no previous set to go back to"; return 1
  fi
  warn "Suricata did not start with the new rules: going back to the previous set"
  rm -rf "$RULEDIR.bad"
  if mv "$RULEDIR" "$RULEDIR.bad" && mv "$PREV" "$RULEDIR"; then
    if restart_engine; then ok "Suricata is running with the previous rules"; else warn "Suricata did not start with the previous rules either"; fi
  else
    warn "could not put the previous rules back (see $RULEDIR, $RULEDIR.bad and $PREV)"
  fi
  return 1
}

case "${1:-}" in
  on)
    mem=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
    [ "$mem" -ge 1500 ] || warn "this machine has ${mem} MB of memory; Suricata with the ET Open rules uses about 500 MB"
    if ! command -v suricata >/dev/null || ! command -v suricata-update >/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq suricata suricata-update >"$WORK/apt.log" 2>&1 || {
        tail -5 "$WORK/apt.log" | sed 's/^/      /'
        die "could not install Suricata (no internet on this machine?). Install the packages suricata and suricata-update some other way, then run this again."; }
      # The package starts Suricata with its own config right away: stop it until Huginn's config is written.
      systemctl stop suricata 2>/dev/null || true
    fi
    ok "$(suricata -V 2>/dev/null | head -1)"
    ensure_user
    write_conf >/dev/null
    write_disable
    write_unit || true
    install -m 644 /dev/null "$FLAG"
    if [ ! -s "$RULES" ] && ! update_rules; then
      warn "no rules yet (no internet on this machine?). Download $(rules_url)"
      warn "elsewhere, copy it here and run: ./update-honeypot.sh --suricata-rules emerging.rules.tar.gz"
    fi
    write_timer
    if [ -s "$RULES" ]; then start_check; else systemctl enable suricata >/dev/null 2>&1; warn "Suricata starts once it has rules"; fi
    ;;
  refresh)
    [ -f "$FLAG" ] || exit 0
    command -v suricata >/dev/null || { warn "Suricata is on in Huginn but not installed: run ./update-honeypot.sh --suricata-on"; exit 1; }
    ensure_user
    changed=0
    out=$(write_conf) || exit 1
    [ -n "$out" ] && changed=1
    write_unit && changed=1
    write_disable
    write_timer
    if [ ! -s "$RULES" ]; then warn "Suricata has no rules yet: ./update-honeypot.sh --suricata-rules emerging.rules.tar.gz"
    elif [ "$changed" = 1 ] || ! systemctl is-active --quiet suricata; then start_check
    else ok "Suricata running, config unchanged"; fi
    ;;
  rules)
    f="${2:-}"
    [ -f "$f" ] && [ ! -L "$f" ] || die "give the path to emerging.rules.tar.gz (download: $(rules_url))"
    command -v suricata-update >/dev/null || die "Suricata is not installed: run ./update-honeypot.sh --suricata-on first."
    # A private copy: the file given may be in a folder others can write, and must not change after it was checked.
    cp --no-preserve=all -- "$f" "$WORK/rules.tar.gz" || die "could not copy $f."
    check_archive "$WORK/rules.tar.gz"
    write_disable
    [ -f "$FLAG" ] && { ensure_user; write_conf >/dev/null; write_unit || true; }
    [ -f "$CONF" ] || die "run ./update-honeypot.sh --suricata-on first."
    update_rules "file://$WORK/rules.tar.gz" || die "could not load the rules from $f; the previous rules are still in use."
    use_new_rules || die "Suricata needs a look (log above)."
    ;;
  update)
    # The daily timer. Without internet this fails here and the rules in use stay as they are.
    [ -f "$FLAG" ] || exit 0
    update_rules || exit 1
    use_new_rules
    ;;
  off)
    rm -f "$FLAG"
    systemctl disable --now hp-suricata-rules.timer >/dev/null 2>&1 || true
    if systemctl list-unit-files suricata.service >/dev/null 2>&1; then
      systemctl disable --now suricata >/dev/null 2>&1 || true
    fi
    ok "Suricata off (the package and the rules are kept; --suricata-on starts it again)"
    ;;
  *)
    sed -n 4,9p "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
