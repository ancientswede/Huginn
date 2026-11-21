# Install

[← Back to the README](../README.md)

## Requirements

You need **two machines**, VMs or LXC containers. That is on purpose: the honeypot will be broken into sooner or later. If Huginn, with your history and your blocklists, ran on the same machine, an attacker who escaped the fake shell would get both.

| | Honeypot | Huginn |
|---|---|---|
| OS | Debian 12 or 13 | Debian 12 or 13 |
| CPU / RAM / disk | 1 core, 1–2 GB (2 GB with Suricata), 8 GB | 1 core, 512 MB–1 GB, 8 GB |
| Network | **isolated**: own VLAN (best) or blocked from your LAN by the hypervisor firewall, see [How to isolate](isolation.md#how-to-isolate-the-honeypot); internet ports forwarded to it | your normal LAN |
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

The script asks before each optional part: OpenCanary, the endlessh tarpit, hp-traps and the Suricata IDS (the only one that defaults to no). Then it:
- Asks which port your own admin SSH should move to (suggests 22022, any free port above 1024 works), and asks you to prove you can log in there **before** port 22 goes to the honeypot, so you cannot lock yourself out.
- Asks what SSH should pretend to be (a **server** or a **file server**) and whether Telnet should be an **IP camera**. Each install gets its own random hostname, network, hardware and planted bait (see [Personas and bait](honeypot.md#personas-and-bait)).
- Installs Cowrie and redirects the public ports to the honeypot services.
- Ends with the list of ports to forward in your router.

From now on, log in with `ssh -p <your admin port> root@honeypot`.

**2. On the Huginn machine** (or use the [Debian package](#install-with-the-debian-package) or [Docker](#run-huginn-in-docker), neither needs a clone)

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

**3. Forward the ports**, but only after you have read [Read this before you open any ports](isolation.md) and **tested the isolation**. Forward the ports in [Ports to forward](#ports-to-forward) (also listed at the end of step 1) from the internet to the honeypot. Never forward the admin port. Then open `http://<huginn IP>:8095`. The first data shows up within two minutes, after the first sync.

**Test it before you open the ports.** Add `HUGINN_ALLOW_PRIVATE=1` to `/opt/huginn/.env` and run `systemctl restart huginn`. Then attack the honeypot from your own LAN: `ssh root@<honeypot>` and try a few passwords, the fake shell lets you in after 2–5 tries. Your session shows up in Huginn. Remove the line again afterwards, so your own addresses are never recorded. LAN addresses never end up in the blocklists, even in test mode.

## Install with the Debian package

Every [release](https://github.com/ancientswede/Huginn/releases) has a package for the Huginn side, on Debian 12/13 and derivatives. The honeypot is still set up with `install-honeypot.sh`, because each install has to get its own random identity.

```bash
wget https://github.com/ancientswede/Huginn/releases/latest/download/huginn_all.deb
apt install ./huginn_all.deb
huginn-setup                  # asks for the honeypot address, then the same steps as install-huginn.sh
```

- **Update:** download the new package and run `apt install ./huginn_all.deb` again. It backs up first and goes back to the old version by itself if the new one does not start.
- **Go back:** `huginn-rollback`.
- **Remove:** `apt remove huginn` stops Huginn and keeps your settings and data in `/opt/huginn`. `apt purge huginn` deletes them too.
- A machine installed with the scripts can switch by installing the package. Settings and data are kept.

**Check a download** (optional, from 1.0): release files and the Docker image are signed by the GitHub workflow that built them, with no key of mine involved. With the [GitHub CLI](https://cli.github.com):

```bash
gh attestation verify huginn_all.deb -R ancientswede/Huginn
gh attestation verify oci://ghcr.io/ancientswede/huginn:latest -R ancientswede/Huginn
```

It confirms the file was built from this repository by its release workflow, and not changed afterwards. `SHA256SUMS` lists the checksums too.

## Run Huginn in Docker

The Huginn side also runs as a container. **The honeypot does not:** it needs its own isolated VM or LXC with port redirects, set up with `install-honeypot.sh` as above. Never run the honeypot next to your other containers.

```bash
mkdir huginn && cd huginn
wget https://github.com/ancientswede/Huginn/releases/latest/download/docker-compose.yml
wget -O .env https://github.com/ancientswede/Huginn/releases/latest/download/huginn.env.example
nano .env                            # set HUGINN_HP_HOST (and HUGINN_HP_PORT if not 22022)
docker compose up -d
docker compose logs huginn           # shows the honeypot's key fingerprint and the line to run on the honeypot
```

1. Compare the fingerprint in the log with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the honeypot.
2. On the honeypot, run the `hp-add-huginn-key '...'` line from the log, once.
3. Set the login password: `docker compose exec -it huginn huginn set-password`
4. Open `http://<docker host>:8095`. The first data shows up within two minutes.

Everything Huginn keeps lives in the `huginn-data` volume: the database, session recordings, its SSH key and the honeypot's host key. The container runs as an unprivileged user with a read-only file system and no capabilities.

- **Image:** `ghcr.io/ancientswede/huginn` for amd64 and arm64, built from each release. To build it yourself, clone the repository, use its `docker-compose.yml` and run `docker compose up -d --build`. Pin a version with `HUGINN_TAG=0.13.0` in `.env`.
- **Update:** `docker compose pull && docker compose up -d`. The volume is kept.
- **Extra bait values:** `docker compose cp bait.json huginn:/data/bait.json`, then `docker compose restart huginn`.
- **Honeypot reinstalled** (new host key): `docker compose exec huginn rm /data/.ssh/known_hosts`, then `docker compose restart huginn` and compare the new fingerprint.
- **Back up** the volume, for example: `docker run --rm -v huginn_huginn-data:/data -v "$PWD":/backup alpine tar czf /backup/huginn-data.tgz -C /data .`
- **Remove:** `docker compose down` keeps the data; `docker compose down -v` deletes it too.

## Manual install (what the scripts do)

### 1. On the honeypot

Install Cowrie (and optionally OpenCanary and endlessh) following their own documentation. Then add the export script and its file analyser:

```bash
install -m 755 honeypot/hp-export   /usr/local/bin/hp-export
install -m 755 honeypot/hp-fileinfo /usr/local/bin/hp-fileinfo
install -m 755 honeypot/hp-sample-zip /usr/local/bin/hp-sample-zip
install -m 755 honeypot/hp-readlogs /usr/local/bin/hp-readlogs
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

## Ports to forward

Forward these **TCP** ports from the internet to the honeypot, and only the rows for the parts you installed. The installer prints the same list at the end. Inside the honeypot, nftables passes each port on to the service that pretends to be there.

| Public port | Pretends to be | Part | Inside the honeypot |
|---|---|---|---|
| 22 | SSH (server or file-server persona) | Cowrie, always | 2225 |
| 23 | Telnet (IP camera persona) | Cowrie, always | 2323 |
| 2222 | SSH tarpit: keeps scanners stuck for hours | endlessh | 2224 |
| 21 | FTP | OpenCanary | 2121 |
| 80 | Web login page (a NAS) | OpenCanary | 8080 |
| 443 | The same over HTTPS (self-signed, generic name) | OpenCanary | 8443 |
| 8080 | Web, alternative port | OpenCanary | 8080 |
| 3306 | MySQL | OpenCanary | 3306 |
| 5900 | VNC | OpenCanary | 5900 |
| 6379 | Redis | OpenCanary | 6379 |
| 25 | SMTP mail server (open-relay bait, never sends) | hp-traps | 2525 |
| 587 | Mail submission | hp-traps | 2587 |
| 110 | POP3 | hp-traps | 2110 |
| 143 | IMAP | hp-traps | 2143 |
| 5432 | PostgreSQL | hp-traps | 5432 |
| 1080 | SOCKS5 proxy (always refuses) | hp-traps | 1080 |

**Never forward** the honeypot's admin SSH port (22022 by default), and never forward anything to Huginn. Forward a port to the same port number on the honeypot (22 → 22, not 22 → 2225): the redirects inside take care of the rest. Some providers block port 25; the rest still works. All of this is TCP; UDP is not needed.

### Router security features can hide the attacks

Many routers and firewalls inspect incoming traffic and silently drop what looks like an attack: an **IPS** (intrusion prevention), "threat management" or "active protection". For a honeypot, that is exactly the traffic you want. Typical sign: the encrypted or less common ports (443, VNC, MySQL) still get visits, but SSH (22, 2222) and plain HTTP (80, 8080) go quiet, even though the port forwards are right.

**Exclude the honeypot's network (VLAN) or address from the IPS**, or set it to detect only, never block. Leave the IPS on for the rest of your network.

- **UniFi:** Settings → Security → Threat Management: add the honeypot's network or IP as an exclusion. With prevention on, the router can block SSH and web probes before they ever reach the honeypot.
- **OPNsense / pfSense with Suricata or Snort in blocking mode:** add the honeypot's address to a pass list, or don't run blocking mode on that interface.
- **Others** (Firewalla, consumer routers with "security" or "threat protection" add-ons): look for an exclusion per device or network.

Some routers also have a **built-in honeypot**. It is unrelated to this one and only watches your own networks. Leave it as it is; it does not need to be on the honeypot's VLAN.

To test from outside: turn off Wi-Fi and VPN on your phone and open `http://<your public IP>/`. You should see the fake NAS login page, and the visit shows up in Huginn within two minutes. Then mark your phone's address as "never block" on its Huginn page.
