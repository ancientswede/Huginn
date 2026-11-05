# Huginn

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-support-FFDD00?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/ancientswede)

**Attacker intelligence for a homelab honeypot.** Huginn pulls the logs from your honeypot, keeps the history, shows everything about every attacker IP on its own page, and turns it into blocklists your firewalls can fetch.

**[See the live demo →](https://ancientswede.se/huginn/)** (made-up data, read-only)

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

## ⚠️ Read this before you open any ports

A honeypot **invites attacks on purpose**. Port forwarding from the internet into your home network is not something to try just to see what happens. Done wrong, you give strangers a way into the network your family's laptops, phones, NAS and cameras live on. **If you are not sure what the steps below mean, stop here and read up first.**

Only open ports when **all** of this is true:

- **The honeypot is truly isolated.** Use its own VLAN (best) or the hypervisor's firewall (see [How to isolate the honeypot](#how-to-isolate-the-honeypot)), so it cannot open connections to your LAN, your router's admin page, your NAS or your other VLANs. A correct port forward alone is not isolation, and neither is a different subnet. **Test it** from the honeypot. Every one of these must fail:
  ```bash
  ping -c1 <a LAN machine>      # must time out
  nc -zv -w3 <your router> 80   # must fail
  nc -zv -w3 <your NAS> 445     # must fail
  ```
- **You forward only to the honeypot**, and only the ports the installer lists. Never forward its admin SSH port. Never forward anything to Huginn: Huginn stays on your LAN or VPN.
- **You keep it up to date.** Patch the honeypot (`apt upgrade`) and Cowrie (`git pull`). Rebuild it if anything looks wrong. Consider blocking its outbound internet once it is installed.
- **You are allowed to.** Some internet providers forbid running servers or block port 25. In many countries, IP addresses are personal data (GDPR), so keep the retention short.
- **You accept the risk.** Huginn comes with **no warranty** (see sections 15–16 of the [license](LICENSE)). You are responsible for your own network.

### How to isolate the honeypot

Getting the port forward right in your router only controls what comes **in**. Isolation is about what a successful attacker can reach **from** the honeypot. Pick one of these:

| | How | Verdict |
|---|---|---|
| **1. Own VLAN** | Put the honeypot on its own VLAN (UniFi, OPNsense, pfSense, MikroTik, most managed switches). Add firewall rules: honeypot VLAN → LAN/other VLANs/router = **block**, LAN → honeypot = allow only Huginn to the admin port. | **Best.** The network itself keeps it apart. |
| **2. Hypervisor firewall** | No VLAN-capable gear? Keep the honeypot on your normal network, but block it from your LAN with the firewall of the *host* it runs on (Proxmox example below). Rules inside the honeypot itself do not count: an attacker with root just turns them off. | **Acceptable.** It is still on your LAN segment, so get the rules right and test them. |
| **3. Nothing** | Honeypot on the same network as everything else, only a port forward. | **Don't.** One escape from the fake shell and the attacker is inside your home network. |

**Proxmox firewall example (option 2).** Turn on the firewall under Datacenter → Firewall, and on the container's network device (`firewall=1`). Then create `/etc/pve/firewall/<CTID>.fw` on the Proxmox host. Replace `192.168.1.0/24` with your LAN, `192.168.1.50` with Huginn's address and `22022` with your admin port:

```
[OPTIONS]
enable: 1
policy_in: ACCEPT
policy_out: ACCEPT

[RULES]
IN ACCEPT -source 192.168.1.50 -p tcp -dport 22022   # Huginn may pull the export
IN DROP -p tcp -dport 22022                           # nobody else reaches admin SSH
OUT DROP -dest 10.0.0.0/8                              # no private networks at all...
OUT DROP -dest 172.16.0.0/12
OUT DROP -dest 192.168.0.0/16                          # ...including your router's admin page
```

Replies to connections that were made *to* the honeypot still work, because the firewall tracks them. Internet traffic still goes out through your router: it is the router's address as a *destination* that is blocked, not its use as gateway. Give the honeypot a **static IP address** and a public DNS server (for example `1.1.1.1`) instead of your router. With DHCP, the lease renewal to your router would be blocked too, and the honeypot would drop off the network after a while. Then run the isolation test above.

**About the blocklists:**
- They only help where you **apply** them, on the firewall in front of your *real* services.
- They do not make it safe to expose services you could keep private. A VPN (WireGuard and the like) is still the better answer.
- Many attacking addresses are shared or recycled: home routers, CGNAT, cloud servers. Start with a short window (7–30 days), and use "Never block" when a real user gets caught.

## What you get

- **Overview:** attackers per day, top attackers, latest shell sessions, top passwords, countries as a world map or a list (click a country to see its attackers), how many took the bait, and **time wasted** (hours attackers spent stuck in the tarpit and in the fake shells, and who is stuck right now).
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
- **Your way:** light, dark or automatic theme, six accent colours, a compact layout, a 12- or 24-hour clock, the columns and overview cards you want, and countries or networks you never want to see (they are still blocklisted). Every attacker can be exported as JSON or CSV. Keyboard shortcuts: press `?`.

Huginn uses only the Python standard library and SQLite. There are no dependencies, no build step and no JavaScript framework. It runs comfortably in a 1 core / 512 MB LXC.

## Requirements

You need **two machines**, VMs or LXC containers. That is on purpose: the honeypot will be broken into sooner or later. If Huginn, with your history and your blocklists, ran on the same machine, an attacker who escaped the fake shell would get both.

| | Honeypot | Huginn |
|---|---|---|
| OS | Debian 12 or 13 | Debian 12 or 13 |
| CPU / RAM / disk | 1 core, 1–2 GB, 8 GB | 1 core, 512 MB–1 GB, 8 GB |
| Network | **isolated**: own VLAN (best) or blocked from your LAN by the hypervisor firewall, see [How to isolate](#how-to-isolate-the-honeypot); internet ports forwarded to it | your normal LAN |
| Reaches | the internet while installing | the honeypot's admin SSH port |

**Proxmox:** use unprivileged LXC containers from the Debian template, with **nesting enabled** (the default in recent versions). The services use systemd sandboxing, which needs it.

**Outbound internet for the honeypot:** the installer needs it. Afterwards you choose:
- **Blocked** (recommended): attackers' downloads fail, so you only see the URLs they tried.
- **Allowed:** Cowrie captures the malware itself. Never allow traffic to your LAN either way.

## Quick start (about 10 minutes)

Run each script as root from a clone of this repository. Both scripts can be run again safely, and they keep what is already done.

**1. On the honeypot machine**

```bash
apt-get install -y git && git clone https://github.com/ancientswede/Huginn.git && cd Huginn
./install-honeypot.sh
```

The script asks before each optional part: OpenCanary, the endlessh tarpit and hp-traps. Then it:
- Asks which port your own admin SSH should move to (suggests 22022, any free port above 1024 works), and asks you to prove you can log in there **before** port 22 goes to the honeypot, so you cannot lock yourself out.
- Installs Cowrie and redirects the public ports to the honeypot services.
- Ends with the list of ports to forward in your router.

From now on, log in with `ssh -p <your admin port> root@honeypot`.

**2. On the Huginn machine**

```bash
apt-get install -y git && git clone https://github.com/ancientswede/Huginn.git && cd Huginn
./install-huginn.sh --honeypot <honeypot IP>     # add --honeypot-port N if you did not use 22022
```

The script:
1. Shows the honeypot's key fingerprint and asks you to compare it.
2. Prints **one line** to run on the honeypot:
   ```bash
   hp-add-huginn-key 'ssh-ed25519 AAAA... huginn@...'
   ```
3. Waits until the honeypot accepts the key, starts Huginn and asks for the password for the web page.

**3. Forward the ports**, but only after you have read [the warning above](#️-read-this-before-you-open-any-ports) and **tested the isolation**. Forward the ports listed at the end of step 1 from the internet to the honeypot. Never forward the admin port. Then open `http://<huginn IP>:8095`. The first data shows up within two minutes, after the first sync.

**Test it before you open the ports.** Add `HUGINN_ALLOW_PRIVATE=1` to `/opt/huginn/.env` and run `systemctl restart huginn`. Then attack the honeypot from your own LAN: `ssh root@<honeypot>` and try a few passwords, the fake shell lets you in after 2–5 tries. Your session shows up in Huginn. Remove the line again afterwards, so your own addresses are never recorded. LAN addresses never end up in the blocklists, even in test mode.

## Manual install (what the scripts do)

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

## Notifications (optional)

Huginn can push a short summary to [ntfy](https://ntfy.sh), the phone app, when something worth a look happens: bait taken, new malware, a human-like session or an exploit attempt. It sends at most one message per hour, and nothing at all if this is not set up.

- **During install:** `install-huginn.sh` asks whether you want ntfy, suggests a random topic name and sends a test notification.
- **Later:** add `HUGINN_NTFY_URL` to `/opt/huginn/.env` (and `HUGINN_NTFY_TOKEN` if your server uses access control), then run `systemctl restart huginn`.
- **Choose which events** you get, or send a test, on the **Settings** page.
- **Your own ntfy server** in the homelab is the most private option. On the public `ntfy.sh`, anyone who guesses the topic name can read your messages, so use a long random name like the one the installer suggests. The messages only contain counts and attacker IPs, never your own addresses.

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
- Research scanners (Censys, Shadowserver, BinaryEdge and others) are detected from reverse DNS and network names and left out by default. Anyone who logged in, ran commands, dropped files or tried an exploit is always blocklisted, research network or not.
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
| `HUGINN_NTFY_TOKEN` | – | Access token (`tk_...`) for an ntfy server with access control |
| `HUGINN_TRUSTED_PROXIES` | – | Reverse proxy IPs allowed to set `X-Forwarded-*` |
| `HUGINN_MASK` | – | Your own public IPs/domains, replaced with `[self]` in everything stored (attackers often echo the address they target) |
| `HUGINN_ALLOW_PRIVATE` | `0` | `1` = also record LAN source addresses (testing only; never blocklisted) |

## Security model

- **The honeypot stays isolated.** Huginn connects *to* the honeypot. The honeypot needs no route to your LAN, and the key can only print logs. If the honeypot is ever fully compromised, the attacker gets that log export and nothing else.
- **Attacker data is untrusted.** Everything attackers typed is escaped. The UI has a strict Content-Security-Policy (no inline scripts).
- **Logins:** one password (scrypt), HttpOnly SameSite=Strict cookies, at most 5 failed logins per 15 minutes per IP, same-origin checks on every form.
- **Do not expose Huginn to the internet.** Keep it on your LAN or VPN, or behind a reverse proxy with an IP allow-list.
- **Captured files never leave the honeypot.** Only their analysis (type, architecture, embedded IPs and URLs) is exported.
- **Enrichment** sends attacker IPs, and nothing else, to ipwho.is and internetdb.shodan.io. Set `HUGINN_ENRICH=0` to turn it off.

**Privacy:** IP addresses count as personal data in many jurisdictions, also when they belong to attackers. Huginn deletes history older than `HUGINN_RETENTION_DAYS`. Pick a retention you can justify.

## Uninstall

- **Huginn:** `systemctl disable --now huginn`, then `rm -rf /opt/huginn /etc/systemd/system/huginn.service`, then `userdel huginn`.
- **Honeypot:** `systemctl disable --now cowrie opencanary endlessh hp-traps`. Remove the `include "/etc/huginn-honeypot.nft"` line from `/etc/nftables.conf`, then `nft -f /etc/nftables.conf`. Delete the `restrict,command="/usr/local/bin/hp-export"` line in `/root/.ssh/authorized_keys`.

## Try it without a honeypot

`tools/make_demo.py` builds a static, read-only copy of Huginn with made-up data. Every address, network and AS number comes from the ranges reserved for documentation, so none of it belongs to anyone real:

```bash
python3 tools/make_demo.py ./demo --base /
cd demo && python3 -m http.server 8000   # then open http://127.0.0.1:8000/
```

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

[AGPL-3.0-or-later](LICENSE). The world map in `static/world-map.json` is a simplified version of [@svg-maps/world](https://github.com/VictorCazanave/svg-maps) by Victor Cazanave, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (see `static/world-map.LICENSE.md`).

You may use, change and share Huginn. If you share a modified version, or run one as a service for others, you must publish your changes under the same license.
