# Notifications, IDS, DNS and metrics

[← Back to the README](../README.md)

## Notifications (optional)

Huginn can push a short summary to [ntfy](https://ntfy.sh), the phone app, when something worth a look happens: bait taken, new malware, a human-like session or an exploit attempt. It sends at most one message per hour, and nothing at all if this is not set up.

- **During install:** `install-huginn.sh` asks whether you want ntfy, suggests a random topic name and sends a test notification.
- **Later:** add `HUGINN_NTFY_URL` to `/opt/huginn/.env` (and `HUGINN_NTFY_TOKEN` if your server uses access control), then run `systemctl restart huginn`.
- **Choose which events** you get, or send a test, on the **Settings** page.
- **Your own ntfy server** in the homelab is the most private option. On the public `ntfy.sh`, anyone who guesses the topic name can read your messages, so use a long random name like the one the installer suggests. The messages only contain counts and attacker IPs, never your own addresses.

## Suricata IDS (optional)

Cowrie and OpenCanary show what attackers *do*. [Suricata](https://suricata.io) adds what their traffic *is*: it matches every packet to the honeypot against the [Emerging Threats Open](https://rules.emergingthreats.net) rules (about 45,000, free) and names known exploits, scanners and tools, often with the CVE.

```bash
./update-honeypot.sh --suricata-on      # on the honeypot, from the repository folder (or install-honeypot.sh --suricata)
```

That is all. The script installs Debian's `suricata` package, writes Huginn's config, fetches the rules, starts it and checks that it runs. Huginn picks the alerts up with the next sync; there is nothing to change on the Huginn machine or in your router.

After that, **Settings › Honeypot** has a button to turn Suricata off and on again. Like the logout note, it is a fixed command to the locked export key (`ids on` / `ids off`): it only starts or stops a Suricata that is already set up, and never installs or configures anything.

- **It only listens.** Suricata reads a copy of the packets on the honeypot's own network card. It never blocks, changes or forwards anything, and needs no mirror port or router feature. Traffic to and from your admin SSH on this machine (every port sshd listens on, and with it Huginn's own fetches) is left out; an attacker who connects *from* that port number to a honeypot service is still watched.
- **It does not run as root.** Suricata starts as root only to open the network card, then runs as the user `hp-suricata`, keeping only the capabilities packet capture needs (`NET_RAW`, `NET_ADMIN`, plus `SYS_NICE`), in a systemd sandbox that cannot see `/home` (where Cowrie lives). Its log folder stays root's: Suricata can only append to the two log files root made for it, so it cannot plant links or other files there for root to open.
- **Only alerts are exported**, as a few fixed fields: time, address, port, protocol, rule number, severity, rule name and class. No payloads, flows or DNS. The honeypot's own fake replies also match rules (a planted `/etc/passwd` looks like a leak), so only alerts on traffic *to* the honeypot count.
- **Where it shows:** the attacker page (card **IDS alerts**), **Campaigns > IDS alerts** with a page per rule and the addresses that tripped it, and **Settings > Honeypot** (on or off, running, how old the rules are, last 7 days). Addresses that only tripped a rule, without touching a service, are listed on the rule's page but get no attacker page of their own.
- **Score:** a rule of severity 1 (attacks: exploits, privilege gain, trojans, web application attacks) adds 3 and tags the attacker `ids-alert`. Severity 2 (mostly scans and recon, which nearly every attacker does), 3 and 4 are shown but not scored.
- **Memory:** about 500 MB with the rules loaded, capped at 900 MB by systemd so it cannot starve Cowrie. Give the honeypot 2 GB. Rule groups that are only IP reputation lists (CINS, DShield, Spamhaus DROP, Tor and so on) are left out: they cost memory and say nothing about what the address did. Edit `/etc/huginn-honeypot/suricata-disable.conf` to change that.
- **Rules are updated once a day** by a timer (`hp-suricata-rules.timer`), which needs internet on the honeypot. New rules are fetched into a staging folder with a memory limit of their own, tested with the installed Suricata, and only then swapped in as a whole folder; the previous set is kept, and if Suricata does not start with the new rules it goes back to the old ones. One run at a time (a lock), so a manual update and the timer cannot overlap.
- **A flood is reported, not hidden.** Each sync takes the newest 20,000 alerts to the honeypot. If eve.json holds more since the last rotation, Settings says how many were not counted. **No internet there** (recommended, see [Requirements](install.md#requirements)): install the packages while you set the honeypot up, or copy them over, then download the rules on another machine and load them:
  ```bash
  # on a machine with internet (the version must match: suricata -V on the honeypot)
  curl -LO https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz
  scp -P 22022 emerging.rules.tar.gz root@honeypot:
  # on the honeypot
  ./update-honeypot.sh --suricata-rules ~/emerging.rules.tar.gz
  ```
  The archive is checked first (size, number of files, no paths outside it, only plain files), then tested like the daily update. Settings shows a note when the rules are over two weeks old.
- **Off again:** `./update-honeypot.sh --suricata-off` stops it (the package and rules stay). `uninstall-honeypot.sh --purge` removes the package too. The alerts already in Huginn stay, like all other history.

Suricata parses hostile traffic on the honeypot. That is the machine that is already assumed to be broken into one day, which is why it sits on an isolated network, and why Suricata drops root and runs sandboxed.

## Own DNS resolver (optional)

Huginn's DNS lookups (Project Honey Pot, Team Cymru, Abusix, DroneBL, Spamhaus) can go through any resolver. Your own one is the best choice:

- **Privacy:** no public resolver sees which addresses you look up; the questions go straight to each list's servers.
- **It passes the lists' answers:** Pi-hole and many routers drop answers in 127.0.0.0/8 (DNS rebinding protection), which is exactly how these lists answer.
- **Spamhaus needs it:** Spamhaus refuses questions that come through Cloudflare, Quad9, Google and other public resolvers.

[Unbound](https://www.nlnetlabs.nl/projects/unbound/about/) on the Huginn machine, answering only Huginn:

```sh
apt install unbound
cat > /etc/unbound/unbound.conf.d/huginn.conf <<'CONF'
server:
    interface: 127.0.0.1
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
CONF
systemctl restart unbound
```

Then pick **Own resolver on this machine (127.0.0.1)** in each lookup on Settings, Lookups. The machine's own name resolution (`/etc/resolv.conf`) does not have to change. A resolver elsewhere on your LAN works too: type its address in the field next to the list.

## Metrics and Grafana (optional)

Huginn can serve counts for [Prometheus](https://prometheus.io) on `/metrics`, for a Grafana dashboard next to the rest of your homelab. It is **off** until you turn it on, and then only answers requests with the right token.

1. **Settings > Metrics > Turn on.** Huginn makes a token and shows the address, the token and a ready Prometheus job (or set `HUGINN_METRICS_TOKEN` in `.env`, 16+ characters, for automated setups).
2. Add the job to `prometheus.yml` (example: [`examples/prometheus-huginn.yml`](../examples/prometheus-huginn.yml)) and reload Prometheus.
3. In Grafana: **Dashboards > New > Import**, enter the id **26093** ([Huginn on grafana.com](https://grafana.com/grafana/dashboards/26093-huginn/)) or upload [`examples/grafana/huginn-dashboard.json`](../examples/grafana/huginn-dashboard.json), then pick your Prometheus data source. The dashboard is built by `tools/grafana-dashboard.py`: change the script, not the JSON.

What is in it: events per source, kind and decoy service (a counter for `rate()`, and the last 24 hours), active and new attackers, SSH/Telnet sessions and logins, captured files, blocklist size, repeated decoy tries not stored, sync time and errors, collection problems, lookup allowances used and paused, database size and the last backup. **Never addresses, usernames, passwords or commands**: one label per attacker would also give Prometheus a new time series for every address. Details stay in Huginn. **New token** in Settings stops the old one at once.

### JSON logs for log tools

Huginn logs to stderr (the systemd journal, or `docker logs`). With `HUGINN_LOG_FORMAT=json` each line is one JSON object, so a log tool such as Grafana Loki, Graylog or Elasticsearch (fed by Alloy, Promtail, Vector, Fluent Bit or similar) can filter on its fields, for example every `login_failed`, or alert on `collection_problem`:

```json
{"ts": "2026-11-14T12:00:00.123Z", "level": "info", "app": "huginn", "event": "sync", "new": 41, "rows": 41, "files": 0, "secs": 1.2}
```

Events: `start`, `sync`, `collection_problem` / `collection_back`, `login` / `login_failed` / `login_locked` (with the client address of whoever logged in to Huginn, not attackers), `metrics_refused`, `backup_failed`, `http_error`, and every new error Huginn shows on its pages (`last_error`, `vt_error`, `gn_error` …). `HUGINN_LOG_LEVEL` (`debug`, `info`, `warning`, `error`) sets how much: `info` for JSON, `warning` for plain text, so the default journal stays quiet. Attack data itself is not logged; it is in the database and on `/metrics`.
