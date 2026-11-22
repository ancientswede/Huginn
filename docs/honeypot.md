# Personas, bait and the web trap

[← Back to the README](../README.md)

## Personas and bait

Attackers stay longer, and show more of what they want, on a machine that looks real and worth something. `install-honeypot.sh` sets this up for you:

| Persona | Port | Looks like | Bait planted in |
|---|---|---|---|
| `server` | SSH 22 | Ubuntu server with a web app, MySQL, Redis and backups to S3 | `.bash_history`, `.my.cnf`, `.aws/credentials`, the app's `.env`, `backup.sh` |
| `nas` | SSH 22 | Debian file server with Samba, rsync and Nextcloud | `.bash_history`, `.smbcredentials`, `rsyncd.secrets`, `rclone.conf`, Nextcloud's `config.php` |
| `camera` | Telnet 23 | Cheap ARM IP camera | `Account1`, `network.conf`, `wpa_supplicant.conf` |

- **Different on every install.** The hostname, internal network, users, CPU, memory, kernel and every bait value are random, so two Huginn honeypots never look alike, and nobody can recognise them all by one fixed detail.
- **Consistent.** `hostname`, `uname`, `nproc`, `lscpu`, `/proc/cpuinfo`, `free`, `/etc/passwd` and the home folders tell the same story. Cowrie's `free` normally shows the *real* machine's memory; Huginn patches it.
- **Realistic logins.** Attackers get in after 2–5 tries (Cowrie's `AuthRandom`), and the honeypot remembers each IP's password.
- **A proxy that seems to work.** Many bots log in only to use the box as an SSH proxy and test it first (`GET yahoo.com/`, `google.com`, `yandex.ru`). Plain Cowrie refuses, so they leave. Huginn patches Cowrie to answer such a plain HTTP check with an empty `200` page and to hold TLS silently for up to 30 s (at most 64 at a time). **Nothing is ever forwarded or connected**; anything else is refused as before. The attacker page and Campaigns › Proxy use show what was answered.
- **Uploaded programs "run".** A program uploaded for the persona's CPU exits silently instead of failing with "Exec format error", so bots go on to their next step; the run, its arguments and the file's hash are logged. Nothing is ever executed (`patches.py cowrie-exec`). `wget` prints what the persona's own wget would: BusyBox text on the camera, and no "connected" before a connection fails (`cowrie-wget`).
- **Timeline and ATT&CK.** The attacker page opens with a timeline of the last 30 days across every service, one step per kind of activity, each with a phase. Commands are labelled with MITRE ATT&CK techniques (simple patterns: what a command tried, not proof that it worked).
- **Protection report.** The export lists the honeypot's own protection (sandbox and memory/file limits per service, running services, every Huginn patch). Account shows it, and Huginn alerts when something goes missing. A service that will not start with its sandbox or limits is left stopped with them in place, never started without them: the installer says so, and Huginn alerts that it is not running.
- **Collection health.** Huginn alerts (ntfy) when no sync has worked for 30 minutes or a source is quiet for longer than its own longest silence last week, and again when it is back. Account lists every source with its newest data; `/healthz` adds `collection_problems`.
- **Repeated tries are counted, not all stored.** Decoy services keep the first 2,000 events per IP, service and day (`HUGINN_DECOY_CAP`, 0 keeps everything); the rest are only counted, so scores and totals stay right. Account shows how fast the data folder grows and when the disk would be full.
- **Two Cowrie fixes.** Cowrie's `ping` never accepted `-c N`, so the usual network check `ping -c 1 8.8.8.8` failed, and a bot that checks the network that way left there. And a file uploaded over SFTP or `scp` vanished before the next command, so the bot's `chmod +x` failed and it never ran the file. Huginn patches both (`patches.py cowrie-ping`, `cowrie-upload`); an uploaded file now stays for the whole connection. Uploads are capped at 10 MB, and `setup-sandbox.sh` gives Cowrie and OpenCanary a memory cap and a 128 MB limit per file, so one huge upload cannot fill the disk or take the honeypot down.
- **Slow replies.** The fake mail server waits 1 to 2.5 s before it says a message is queued. The message is already logged by then, so nothing is lost. A session takes at most 50 messages and 10 minutes, and mail may use at most half of hp-traps' connections. The web trap sends the robots-only backup file in small parts over about 5 s (at most 32 at a time, 2 per IP). The `.env` file and other first replies stay fast. Both log how the visit ended, and Campaigns › Slow replies sums up the last 7 days.
- **An optional goodbye (off by default).** Turn it on with `update-honeypot.sh --goodbye-on`: when someone who really logged in types `exit` or `logout`, they get a short note with how long they stayed, how many lines they typed, and that all of it is logged along with their address. Only at the very end, and never for `sh -c`, scripts, nested shells or bots that just disconnect, so the session is fully logged before it shows. It does tell whoever reads it that this is a honeypot, and a bot that logs in and types `exit` can learn to recognise yours and skip it next time. That is why it is off unless you choose it (`patches.py cowrie-goodbye`, flag file `/etc/huginn-goodbye`, no restart needed). The session log shows who got it.
- **Attackers that come back.** An address seen again after 7 or more days with nothing at all from it is tagged `returned`. If it then gets further than ever before (only knocked first, later logs in and runs commands, leaves files or uses the honeypot as a proxy) it is also tagged `stepped-up` (+5) and an ntfy alert says so, once per return. A home connection is worth most to attackers as a proxy, and the first quick checks are often followed later by real work; this is where that shows. The quiet spell (7 days) is set under Settings, Views & defaults; saving it checks every stored attacker again.
- **Bait detection works by itself.** The honeypot tells Huginn its personas and bait values through the export. Huginn tags anyone who reads a bait file (`read-bait`) and anyone who later uses one of the values anywhere, on any service (`took-bait`).

Everything lives in `/etc/huginn-honeypot/` on the honeypot (root only). **Never publish it**: it is exactly what would let someone recognise your honeypot. Want a new identity? Delete that folder and Cowrie's `etc/cowrie.cfg`, then run the installer again.

You can still build your own: put files in a Cowrie instance's `honeyfs`, add them with `honeypot/personas.py fs`, and list extra bait values in `bait.json` next to `app.py` (see `examples/bait.example.json`). Set `HUGINN_PERSONAS` to override the persona names the honeypot announces.

## The web trap's identity

Ports 80 and 443 pretend to be a NAS or a router, and change by themselves every few weeks. `hp-identity` on the honeypot picks from 19 devices (8 NAS brands, 11 routers) and changes the login page, the `Server` header and the certificate together. Only OpenCanary restarts; the SSH and telnet personas are not touched.

```bash
hp-identity list              # the devices it can pretend to be
hp-identity status            # what it is now
hp-identity set mikrotik      # change now (or: set random)
```

`ROTATE_DAYS=21` in `/etc/default/hp-identity` sets how often it changes, `0` turns it off. Do not make it very short: a machine that keeps changing what it is on one address looks odd by itself, and scanners keep history. The login pages are written from scratch for Huginn, with product names as plain text and no logos or code from any vendor.

**Fake replies.** For the files scanners hunt most, the trap answers 200 with believable fake content instead of 404: `.env` and its variants, `.git/config` and `HEAD`, `.aws/credentials` and `config`, phpinfo, `/etc/passwd` through path traversal, PHPUnit's `eval-stdin.php`, Spring `/actuator/env` and MCP servers (`/mcp`, `/sse`, with `initialize` and `tools/list`). Every secret in them is a bait value from `/etc/huginn-honeypot/bait.json`, the same for every request, so Huginn tags anyone who later uses one `took-bait`, and the request itself `read-bait`. Without a `bait.json` the trap answers 404 as before. Replies are plain text or JSON, small, and sent with a sandboxing `Content-Security-Policy`.

**robots.txt trap.** Each identity gets a `robots.txt` with four `Disallow:` paths that exist nowhere else and stay the same for that identity. Only someone who reads robots.txt and goes looking finds them; Huginn tags them `robots-trap` (+5).

Huginn only reads the history (through `hp-export`) and shows it on **Personas**: hits per day for each device, since each one runs for a different time. It cannot change the identity: nothing ever connects to the honeypot to control it.
