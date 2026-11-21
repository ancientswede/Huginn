# Configuration

[← Back to the README](../README.md)

All settings are environment variables in `/opt/huginn/.env`. See [`.env.example`](../.env.example). Only systemd reads that file, so commands you run by hand need it too: see [Commands](operations.md#commands).

| Variable | Default | Meaning |
|---|---|---|
| `HUGINN_HP_HOST` | – | Honeypot address (required) |
| `HUGINN_HP_PORT` | `22022` | Honeypot admin SSH port |
| `HUGINN_PORT` / `HUGINN_BIND` | `8095` / `0.0.0.0` | Web UI |
| `HUGINN_TZ` | `UTC` | Time zone for the UI and per-day charts |
| `HUGINN_POLL` | `120` | Seconds between syncs, at least `30` |
| `HUGINN_RETENTION_DAYS` | `180` | Days of history kept, at least `7` (1–6 count as 7); `0` or a negative number keeps everything forever. The Account page shows the value in use |
| `HUGINN_DECOY_CAP` | `2000` | Decoy-service events stored per IP, service and day; the rest are only counted. `0` stores everything |
| `HUGINN_RETURN_DAYS` | `7` | Starting value for the quiet days before an address counts as `returned`; change it under Settings |
| `HUGINN_DB_BACKUPS` | `3` | Automatic copies of the database to keep; `0` turns them off |
| `HUGINN_DB_BACKUP_HOURS` | `24` | Hours between those copies |
| `HUGINN_ENRICH` | `1` | Look up attacker IPs at ipwho.is and Shodan InternetDB |
| `HUGINN_PERSONAS` | announced by the honeypot | `port=name,...` for several Cowrie instances |
| `HUGINN_MALWAREBAZAAR_KEY` | – | Look captured files up on MalwareBazaar by SHA-256 (only the hash is sent). Can also be pasted on the Settings page (Lookups), where it is tested and never shown again. Free key at [auth.abuse.ch](https://auth.abuse.ch) |
| `HUGINN_VIRUSTOTAL_KEY` | – | VirusTotal verdicts for captured files: how many engines flag a file, or *novel* if VirusTotal has never seen it (only the SHA-256 is sent). Can also be pasted on the Settings page, where it is tested and never shown again. Free key at [virustotal.com](https://www.virustotal.com) |
| `HUGINN_VIRUSTOTAL_DAILY` | `400` | Most VirusTotal lookups a day (the free key allows 500, and 4 a minute) |
| `HUGINN_GREYNOISE_DAILY` | `20` / `40` | Most GreyNoise community lookups a day (20 without a key, 40 with one), top attackers first; `0` = off. Benign mass scanners count as research unless they logged in or ran something |
| `HUGINN_GREYNOISE_KEY` | – | Optional free GreyNoise key for a larger allowance. Can also be pasted on the Settings page (Lookups), where it is tested without using a lookup and never shown again. Free key at [viz.greynoise.io](https://viz.greynoise.io) |
| `HUGINN_HTTPBL_KEY` | – | Project Honey Pot http:BL access key (12 letters): is an attacker a known web spammer, e-mail harvester or suspicious visitor? One DNS question per IPv4 address. Can also be pasted on the Settings page (Lookups), where it is tested on Project Honey Pot's test address and never shown again. Free key at [projecthoneypot.org](https://www.projecthoneypot.org) |
| `HUGINN_HTTPBL_DNS` | system | DNS server for http:BL: `system` or an IPv4 address such as `1.1.1.1`. Pi-hole and many routers drop answers in 127.0.0.0/8 (DNS rebinding protection), and http:BL always answers there, so a public server is often needed. Can be changed on the Settings page |
| `HUGINN_HTTPBL_DAILY` | `300` | Most http:BL lookups a day, top attackers first, each again after a week; `0` = off |
| `HUGINN_DRONEBL_DAILY` | `2000` | Most DroneBL lookups a day (DNS, no key, IPv4 only), newest attackers first (seen in the last 30 days), each again after a week; `0` = off. Turn it off or pick a DNS server on the Settings page (Lookups). DroneBL answers in 127.0.0.x, which Pi-hole and many routers drop, so the server is tested first; until you choose one, the server chosen for Project Honey Pot is used |
| `HUGINN_SPAMHAUS_DAILY` | `500` | Most Spamhaus ZEN lookups a day (IPv4, attackers seen in the last 30 days), each address again after a week; `0` = off. Only through your own resolver: Spamhaus refuses public ones. The free mirrors are for non-commercial use at low volumes |
| `HUGINN_ABUSIX_DAILY` | `2000` | Most abuse contact lookups a day (Abusix Abuse Contact DB over DNS, no key, attackers seen in the last 30 days), each address again after 30 days; `0` = off. On or off together with netblocks on the Settings page |
| `HUGINN_NETBLOCK_DAILY` | `5000` | Most netblock lookups a day (Team Cymru IP-to-ASN over DNS, no key): the announced block, its AS, owner, registry and allocation date, each address again after 30 days; `0` = off. Turn it off or pick a DNS server on the Settings page (Lookups). The question is plain DNS, so the address can be read on the way |
| `HUGINN_METRICS_TOKEN` | – | Turns on `/metrics` with this bearer token (16+ characters). Otherwise turn metrics on in Settings |
| `HUGINN_LOG_FORMAT` | `text` | `json` for one JSON object per log line, for log tools such as Grafana Loki, Graylog or Elasticsearch |
| `HUGINN_LOG_LEVEL` | `warning` / `info` | `debug`, `info`, `warning` or `error`; the default is `info` with JSON logs |
| `HUGINN_C2_EXCLUDE` | (empty) | Addresses that never go on the C2 list, separated by commas (your DNS, VPN, ...) |
| `HUGINN_ALLOWED_HOSTS` | (empty) | Host names the web page answers to, separated by commas, with the port if it is not 80/443 (`huginn.lan:8095`). Empty = any. Stops DNS rebinding |
| `HUGINN_BAIT_FILE` | `/opt/huginn/bait.json` | Extra bait values to watch for (the honeypot's own are announced) |
| `HUGINN_NTFY_URL` / `HUGINN_PUBLIC_URL` | – | ntfy topic URL and the link in notifications |
| `HUGINN_NTFY_TOKEN` | – | Access token (`tk_...`) for an ntfy server with access control |
| `HUGINN_TRUSTED_PROXIES` | – | Reverse proxy IPs allowed to set `X-Forwarded-*` |
| `HUGINN_MASK` | – | Your own public IPs/domains, replaced with `[self]` in everything stored (attackers often echo the address they target) |
| `HUGINN_UPDATE_CHECK` | `1` | Daily check for a newer version (reads GitHub's public tag list) |
| `HUGINN_ALLOW_PRIVATE` | `0` | `1` = also record LAN source addresses (testing only; never blocklisted) |
