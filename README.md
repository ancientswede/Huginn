# Huginn

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-support-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/ancientswede)

**Attacker intelligence for a homelab honeypot.** Huginn pulls the logs from your honeypot, keeps the history, shows everything about every attacker IP on its own page, and turns it into blocklists your firewalls can fetch.

In Norse myth Huginn is one of Odin's ravens. It flies out over the world every day and comes back to tell what it saw.

```
                 internet
                    │  port forwards (22, 23, 25, ...)
                    ▼
   ┌───────────────────────────────┐        isolated VLAN, no route to your LAN
   │ Honeypot                      │
   │  Cowrie (fake SSH/Telnet)     │
   │  OpenCanary (fake FTP/HTTP/…) │
   │  endlessh (tarpit)            │
   │  hp-traps (fake mail/DB/proxy)│
   │  hp-export  ◄─────────────────┼──┐  SSH, key locked to one read-only command
   └───────────────────────────────┘  │  (Huginn pulls; the honeypot never connects out)
                                      │
   ┌───────────────────────────────┐  │
   │ Huginn  (your LAN)            │──┘
   │  SQLite history, web UI,      │
   │  blocklist feeds, ntfy alerts │──►  firewalls fetch /feed/<token>/…
   └───────────────────────────────┘
```

## What you get

- **Overview:** attackers per day, top attackers, latest shell sessions, top passwords, countries, how many took the bait, and **time wasted** (hours attackers spent stuck in the tarpit and in the fake shells, and who is stuck right now).
- **A page per attacker IP:**
  - country, network, reverse DNS, open ports and known CVEs (from Shodan InternetDB)
  - every password they tried
  - every session as a terminal log, plus a **replay** that plays the session back exactly as they saw it
  - files they dropped, decoy services they touched and time spent in the tarpit
  - **related attackers** (same SSH client fingerprint, same command script, same file, same /24)
  - an "always block" / "never block" switch
- **Campaigns:** IPs grouped by identical command scripts and SSH client fingerprints (HASSH), so one botnet shows up as one group.
- **Files:** everything attackers uploaded or downloaded. Each file is analysed statically on the honeypot: type, CPU architecture, UPX packing, and the IP addresses and URLs embedded in it. Nothing is ever executed.
- **Credentials:** top usernames, passwords and pairs across SSH, Telnet, FTP, HTTP, MySQL, Redis, SMTP, POP3, IMAP, PostgreSQL and SOCKS5.
- **Bait detection:** put fake credentials in the honeypot's files. Huginn tags anyone who reads them (`read-bait`) or later tries one of them anywhere (`took-bait`).
- **Blocklists** as plain text, nftables, ipset, MikroTik or CSV, filtered by score and age. There is also a separate **C2 list**: the servers attackers download from and the addresses found inside their malware.
- **ntfy alerts:** at most one summary per hour, sent only when something worth a look happened (bait taken, new file, human-like session, exploit attempt).

Huginn uses only the Python standard library and SQLite. There are no dependencies, no build step and no JavaScript framework. It runs comfortably in a 1 core / 512 MB LXC.

## Requirements

- **A honeypot host:** a VM or LXC on an isolated network or VLAN that can **not** reach your LAN. It needs:
  - [Cowrie](https://github.com/cowrie/cowrie), required
  - [OpenCanary](https://github.com/thinkst/opencanary), optional
  - [endlessh](https://github.com/skeeto/endlessh), optional
  - hp-traps from this repo, optional
- **A Huginn host** on your LAN with Python 3.11+ and `ssh`. Debian 12/13 works out of the box.
- Your router or firewall forwarding the ports you want attacked to the honeypot.

## Install

### 1. On the honeypot

Install Cowrie (and optionally OpenCanary and endlessh) following their own documentation. Then add the export script and its file analyser:

```bash
install -m 755 honeypot/hp-export   /usr/local/bin/hp-export
install -m 755 honeypot/hp-fileinfo /usr/local/bin/hp-fileinfo
```

If your paths differ from the defaults, create `/etc/default/hp-export`. Several Cowrie directories mean several personas:

```bash
COWRIE_DIRS="/home/cowrie/cowrie"
OPENCANARY_LOG="/home/opencanary/opencanary.log"
ENDLESSH_UNIT="endlessh"
TRAPS_LOG_DIR="/var/log/hp-traps"
FILEINFO_USER="cowrie"   # captured files are analysed as this user, never as root
```

Run `hp-export | grep '^##'` once. It should print `##COWRIE ##CANARY ##ENDLESSH ##NFT ##TRAPS ##FILES ##END`.

**Optional: hp-traps.** These are fake mail, database and proxy services. They capture logins and spam-relay attempts and never send or forward anything.

```bash
install -d /opt/hp-traps && install -m 644 honeypot/hp-traps.py /opt/hp-traps/
install -m 644 systemd/hp-traps.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now hp-traps
# It listens on 2525 (SMTP), 2587 (submission), 2110 (POP3), 2143 (IMAP), 5432 (PostgreSQL), 1080 (SOCKS5).
# Map the real ports with nftables, for example:
#   tcp dport 25 redirect to :2525 ; tcp dport 587 redirect to :2587
#   tcp dport 110 redirect to :2110 ; tcp dport 143 redirect to :2143
```

**Your admin SSH must not use port 22**, because that is Cowrie's port. Move sshd to another port (for example 22022) before redirecting 22 to Cowrie. On Debian 13, sshd is started through `ssh.socket`, so set the port with a drop-in for `ssh.socket` (`ListenStream=`).

### 2. On the Huginn host

```bash
useradd --system --home-dir /opt/huginn --shell /usr/sbin/nologin huginn
install -d -o huginn -g huginn /opt/huginn/data
install -d -m 700 -o huginn -g huginn /opt/huginn/.ssh
install -m 644 app.py /opt/huginn/app.py
install -m 644 systemd/huginn.service /etc/systemd/system/
cp .env.example /opt/huginn/.env && chmod 600 /opt/huginn/.env   # then edit HUGINN_HP_HOST etc.

# A key that only exists for this
runuser -u huginn -- ssh-keygen -t ed25519 -N "" -C huginn -f /opt/huginn/.ssh/honeypot_ro
cat /opt/huginn/.ssh/honeypot_ro.pub
```

### 3. Lock the key to the export on the honeypot

Add **one line** to `/root/.ssh/authorized_keys` on the honeypot. `restrict` turns off shells, port forwarding and the rest, and `command=` means the key can only run hp-export, whatever the client asks for:

```
restrict,command="/usr/local/bin/hp-export" ssh-ed25519 AAAA...your-key... huginn
```

Then accept the honeypot's host key once and start Huginn:

```bash
runuser -u huginn -- ssh -i /opt/huginn/.ssh/honeypot_ro -p 22022 \
  -o UserKnownHostsFile=/opt/huginn/.ssh/known_hosts root@HONEYPOT | grep -c '^##'   # prints 7
systemctl daemon-reload && systemctl enable --now huginn
runuser -u huginn -- python3 /opt/huginn/app.py set-password
```

Open `http://huginn-host:8095` and log in. The first sync runs within two minutes.

**History from before Huginn:** copy old `cowrie.json.*` and `opencanary.log*` files to the Huginn host and run `runuser -u huginn -- python3 /opt/huginn/app.py import FILE...`. Lines Huginn already has are skipped, so you can run it again at any time, for example after Huginn has been down for a while. The export only covers the latest lines, so a long gap otherwise leaves a hole.

## Using the blocklists

The **Blocklist** page builds feed URLs from your filters (minimum score, how recently seen, include research scanners or not). The feed URLs contain a secret token instead of a login, so firewalls can fetch them. Keep them on your LAN. You can rotate the token on the page.

| Format | Use with |
|---|---|
| `txt` | OPNsense/pfSense URL Table alias, pfBlockerNG, `cscli decisions import --format values` (CrowdSec) |
| `nft` | `curl -fsS URL -o /etc/huginn.nft && nft -f /etc/huginn.nft` (complete table with drop rules) |
| `ipset` | `curl -fsS URL \| ipset restore -exist`, then `iptables -I INPUT -m set --match-set huginn4 src -j DROP` |
| `mikrotik` | `/tool fetch url=URL dst-path=huginn.rsc; /import huginn.rsc` |
| `csv` | IP with score, last seen, country and tags (CrowdSec `cscli decisions import -i`) |
| `c2` | Malware download hosts and addresses embedded in captured malware |

**Score:**
- connection: 1
- tried to log in: +2
- brute force: +2
- per command: +½, up to 10
- dropped a file: +15
- used the honeypot as a proxy: +10
- exploit attempt: +10
- each other decoy service: +3
- read bait: +5
- took bait: +20

**Before you block anything:**
- Most attackers are infected home routers and cheap VPSs whose addresses change hands. That is why the feeds only include IPs seen in the last N days.
- Research scanners (Shodan, Censys and others) are detected from reverse DNS and network names and left out by default.
- "Never block" always wins.

## Making the honeypot more convincing

Huginn works with any Cowrie setup, but you learn more when attackers stay longer. Ideas that paid off here:

- **Two personas.** Run a second Cowrie instance with its own `etc/cowrie.cfg` (`hostname`, `kernel_version`, `hardware_platform`, `arch`, a `filesystem` pickle and `honeyfs`) and list it in `COWRIE_DIRS`. For example, put an x86 "database server" on SSH and an ARM "IP camera" on Telnet. Tell Huginn the internal ports with `HUGINN_PERSONAS`.
- **Realistic logins.** Use `auth_class = AuthRandom` with `auth_class_parameters = 2, 5, 10`: attackers get in after 2–5 tries, and the honeypot remembers each IP.
- **Bait.** Put fake `.bash_history`, `.my.cnf`, `.env` and `.aws/credentials` files in `honeyfs`, and add them to the filesystem pickle so `ls` shows them. Use unique random values, never real ones, and list the same values in `bait.json` (see `examples/bait.example.json`).
- **Consistency.** `uname`, `nproc`, `/proc/cpuinfo` and `free` should tell the same story. Note that Cowrie's `free` reads the *host's* `/proc/meminfo`, which gives away the real machine. Patch it to read the persona's file.
- Never publish your own persona and bait files. They are exactly what someone would use to recognise your honeypot.

## Configuration

All settings are environment variables in `/opt/huginn/.env`. See [`.env.example`](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `HUGINN_HP_HOST` | – | Honeypot address (required) |
| `HUGINN_HP_PORT` | `22022` | Honeypot admin SSH port |
| `HUGINN_PORT` / `HUGINN_BIND` | `8095` / `0.0.0.0` | Web UI |
| `HUGINN_TZ` | `UTC` | Time zone for the UI and per-day charts |
| `HUGINN_POLL` | `120` | Seconds between syncs |
| `HUGINN_RETENTION_DAYS` | `180` | History kept |
| `HUGINN_ENRICH` | `1` | Look up attacker IPs at ipwho.is and Shodan InternetDB |
| `HUGINN_PERSONAS` | – | `port=name,...` for several Cowrie instances |
| `HUGINN_BAIT_FILE` | `/opt/huginn/bait.json` | Bait values to watch for |
| `HUGINN_NTFY_URL` / `HUGINN_PUBLIC_URL` | – | ntfy topic URL and the link in notifications |
| `HUGINN_TRUSTED_PROXIES` | – | Reverse proxy IPs allowed to set `X-Forwarded-*` |

## Security model

- **The honeypot stays isolated.** Huginn connects *to* the honeypot. The honeypot needs no route to your LAN, and the key can only print logs. If the honeypot is ever fully compromised, the attacker gets that log export and nothing else.
- **Attacker data is untrusted.** Everything attackers typed is escaped. The UI has a strict Content-Security-Policy (no inline scripts).
- **Logins:** one password (scrypt), HttpOnly SameSite=Strict cookies, at most 5 failed logins per 15 minutes per IP, same-origin checks on every form.
- **Do not expose Huginn to the internet.** Keep it on your LAN or VPN, or behind a reverse proxy with an IP allow-list.
- **Captured files never leave the honeypot.** Only their analysis (type, architecture, embedded IPs and URLs) is exported.
- **Enrichment** sends attacker IPs, and nothing else, to ipwho.is and internetdb.shodan.io. Set `HUGINN_ENRICH=0` to turn it off.

**Privacy:** IP addresses count as personal data in many jurisdictions, also when they belong to attackers. Huginn deletes history older than `HUGINN_RETENTION_DAYS`. Pick a retention you can justify.

## Commands

```
app.py serve                 # run the web UI and the collector (what systemd runs)
app.py set-password          # set or reset the login password (logs out every session)
app.py ingest-once           # one sync, for testing
app.py import FILE...        # import full cowrie.json* / opencanary.log* files
```

## Support

If Huginn is useful in your homelab, you can [buy me a coffee](https://buymeacoffee.com/ancientswede). ☕

## License

[AGPL-3.0-or-later](LICENSE). You may use, change and share Huginn. If you share a modified version, or run one as a service for others, you must publish your changes under the same license.
