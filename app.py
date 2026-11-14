#!/usr/bin/env python3
# Huginn — attacker intelligence for a homelab honeypot.
# Pulls logs (Cowrie, OpenCanary, endlessh, hp-traps) over SSH with a key that is locked to
# hp-export on the honeypot (read-only, pull-only: the honeypot never connects to Huginn),
# keeps history in SQLite, shows a page per attacker IP and serves firewall blocklists.
# Python standard library only. Copyright (C) 2026 Ancientswede. License: AGPL-3.0-or-later (see LICENSE).

HUGINN_VERSION = "0.32.0"
CHANGELOG = [
    ("0.32.0", "2026-11-14", "New Engagement page: sessions that got in, day by day, with what they did after the login (left at once, proxy only, ran commands, went for a payload), how many were typed by hand, the median stay and new against returning attackers. Pick a release to compare the whole days before it with the days after it. Huginn now also stores the terminal size a client asks for: it shows on each session and in a table on the Engagement page."),
    ("0.31.0", "2026-11-13", "The attacker page starts with a timeline of the last 30 days across every service: web requests, tarpit, decoy logins, SSH and Telnet sessions, files and programs run, with the same kind of activity within 30 minutes as one step and a phase for each (Recon, Access, Commands, Payload, Exploit). Commands are labelled with MITRE ATT&CK techniques (for example T1105 tool transfer, T1098.004 SSH keys, T1496 mining), linked to MITRE, on the timeline and on every session."),
    ("0.30.0", "2026-11-13", "The attacker page folds its sessions: the same command script is shown once with \"×N like this\" and the repeats under it, and sessions that only connected or only tried to log in are two folded groups at the end. Chips filter the list to sessions with commands or with logins. The honeypot now reports its own protection in the export (sandbox and memory/file limits per service, whether each service runs, every Huginn patch); Account shows it and Huginn alerts when something is missing, for example a limit removed because a service would not start with it, or a patch that no longer fits after a Cowrie upgrade. Update the honeypot too (update-honeypot.sh)."),
    ("0.29.0", "2026-11-13", "Huginn tells you when collection stops: no sync from the honeypot for 30 minutes, or a source (each Cowrie port, OpenCanary, hp-traps, endlessh) quiet for longer than its own longest silence last week. One phone alert per problem and one when it is back; Account lists every source with its newest data, and /healthz names the problems. On the honeypot, wget now prints what the persona's own wget would (BusyBox on the camera, no \"connected\" before a connection fails, no name lookup for an address), and an uploaded program for the persona's CPU \"runs\" silently instead of failing with \"Exec format error\". Nothing is ever executed; the run, its arguments and the file's hash show in the session log and in the phone alert. Update the honeypot too (update-honeypot.sh)."),
    ("0.28.0", "2026-11-13", "Repeated tries on the decoy services are counted but no longer all stored: the first 2,000 per IP, service and day are kept (HUGINN_DECOY_CAP). One VNC brute forcer alone was nearly a fifth of the database; existing history is trimmed once on update, and every page still counts all tries. Account shows how fast the data folder grows and when the disk would be full. Web exploits recognised by the rules (with their CVE) now trigger the phone alert. Wider screens get three columns on the Overview and two on Campaigns. Campaigns shows IPs in the last 7 days and has an Active filter; Files has a chip per malware family. The Blocklist explains the whole scoring, empty Overview cards say so, the Attackers list marks its sort column, charts have a text for screen readers, and keyboard focus is visible everywhere."),
    ("0.27.3", "2026-11-12", "The Overview banner is a new raven with a soft beam of light from its eye, in a dark and a light version that follow the theme."),
    ("0.27.2", "2026-11-12", "A new raven banner on the Overview, in a dark and a light version that follow the theme (Auto, Light or Dark), with the text colour to match."),
    ("0.27.1", "2026-11-12", "Two Cowrie bugs that ended many attacks early are patched on the honeypot. ping never accepted \"-c N\", so \"ping -c 1 8.8.8.8\" always failed; most telnet bots check the network that way and left (about 1,500 of 2,500 telnet sessions with commands ended there). And a file uploaded over SFTP or scp vanished before the next command, so \"chmod +x\" failed and the bot never ran it; now it stays for the whole connection. Security and robustness after a review: uploads are capped at 10 MB (also a write far past the end of a file), Cowrie and OpenCanary get memory and file-size limits, a mail session really ends after 10 minutes (also while a message is being sent), a held TLS proxy check frees its slot as soon as the client leaves and later data on it is not logged again, scp refuses file names with a slash, and the honeypot patches are written all at once or not at all. Campaigns says \"sent in full\" instead of \"read to the end\" (the honeypot cannot see whether the client read it), and the proxy table covers the last 7 days like its heading. Update the honeypot (update-honeypot.sh)."),
    ("0.27.0", "2026-11-12", "Slow replies: the fake mail server waits 1 to 2.5 seconds before it says a message is queued (after the message is logged), with a cap of 50 messages and 10 minutes per session and half the trap connections for mail. The web trap sends the robots-only backup file slowly, over about 5 seconds (at most 32 at a time, 2 per IP). Both log how the visit ended, and Campaigns has a Slow replies summary for the last 7 days, to see whether bots stay longer and still go on. Update the honeypot too (hp-traps and the OpenCanary patch)."),
    ("0.26.0", "2026-11-11", "Proxy that seems to work: most bots that log in to the SSH honeypot only want to use it as a proxy, test it with a plain web request and leave when Cowrie refuses. The honeypot now answers such a check with an empty 200 page and holds TLS for up to 30 seconds; nothing is ever forwarded. The attacker page shows each answered check, and Campaigns has a Proxy use table with proxy sessions and requests per session for the last 7 days, to compare before and after."),
    ("0.25.0", "2026-11-11", "Web attacks: every request to the web trap is matched against about 3,100 rules from Krawl (MIT), so CVE exploits, path traversal, webshells, .env and .git hunting, scanners and MCP server probes have a name. Exploits tag the attacker web-exploit (+8), probes web-probe (+3). The attacker page lists them, Campaigns groups them with a page per attack and a link to the CVE, Search finds them by CVE, and the Board shows them in the raw data. A plain GET only counts as a probe. The web trap now answers .env, .git, AWS, phpinfo, traversal, PHPUnit, actuator and MCP probes with fake files holding bait values (read-bait), and serves a robots.txt with paths found nowhere else (robots-trap, +5). Synology now uses a generated login page like the other identities."),
    ("0.24.1", "2026-11-11", "VNC passwords count as logins: on Credentials, in the password check, the exports and the Board. VNC only reveals a password when it is on OpenCanary's list of common ones, so tries with an unknown password stay plain hits. The mail relay trap keeps every recipient, the HELO name, the size and the start of each message (on the attacker's page, recipients also in Search). Campaigns groups mail clients by HELO name."),
    ("0.24.0", "2026-11-11", "Overview has a second layout, Board: every service side by side with IPs, hits, logins and accepted logins, attacker IPs and login attempts on the same time axis, top attackers and the latest raw data, for the last 24 hours or 7 days and one service or all. Switch between Cards and Board at the top of the Overview; the choice is remembered."),
    ("0.23.1", "2026-11-09", "Security and bug hunt. Fixed: a specially crafted command line could freeze Huginn for minutes, web requests were counted as logins on the password lists, a failed update of New left permanent holes, backup and restore could collide, restore accepted a database that was not Huginn's, one huge captured file could stop all file analysis, firewall feeds did not clear IPv6 when the list became empty, a reverse DNS name containing a word like research could keep an attacker off the blocklist, and the database file was readable by other users on the machine."),
    ("0.23.0", "2026-11-09", "The web trap can pretend to be many NAS and router brands and changes by itself every few weeks (hp-identity on the honeypot, ROTATE_DAYS sets how often, 0 turns it off). Personas shows which device drew the most attention, per day, because each one runs for a different time."),
    ("0.22.0", "2026-11-09", "A visual pass: the attacker page is headed by its address, phones get shorter lists with paging at the top and readable rows, campaigns and New lead with the commands instead of a hash, rare finds (bait, files, exploits) have their own warm colour, Replay looks like a terminal and has a timeline, Personas shows how far attackers got as bars, and empty sections no longer draw empty tables. Two small extras: the raven in the header reacts once to a new file or used bait, and Time wasted has a receipt."),
    ("0.21.2", "2026-11-08", "Releases now include a Debian package, plus Docker files that work without cloning the repository."),
    ("0.21.1", "2026-11-08", "Session logs are easier to read: download and permission commands stand out, addresses link to Search (never to the attacker's server) and captured files link to their file page."),
    ("0.21.0", "2026-11-08", "New page, Search: commands, file hashes and names, addresses inside malware, failed downloads, decoy service data, sessions and attacker IPs across the whole history. Press / on any page without a filter to get there."),
    ("0.20.0", "2026-11-08", "New page, Personas: how far attackers get on each fake machine, where sessions with several lines stop with no download seen, and which single lines hit it. A hint about what may give the honeypot away, not proof."),
    ("0.19.1", "2026-11-08", "Overview: the banner is back to its full size on computers. It stays low on phones."),
    ("0.19.0", "2026-11-08", "Campaigns: scripts that differ only in addresses, numbers or random markers are now one campaign (old links to a script campaign stop working). Attacker page: a one-line summary, sessions first with the facts in a side column on wide screens, related attackers as a count and the five latest. Sync gaps: the day charts and the Account page show when Huginn did not collect."),
    ("0.18.0", "2026-11-08", "New page: everything Huginn has never seen before since you last reviewed (files, scripts, commands, password patterns, SSH clients), with Mark all reviewed and Undo. Overview: a low banner so more fits on the first screen, today's unfinished bar is striped, rare events stand out, a change against the prior 7 days. Files: steady columns and two IOCs with the rest behind Show more. Attacker page: what the score is made of. Phone: three key numbers first, sync status back, larger touch targets. Replay: short sessions no longer leave an empty terminal."),
    ("0.17.0", "2026-11-07", "Automatic database backups: once a day Huginn saves a checked, compressed copy of its database in data/backups and keeps the last 3 (HUGINN_DB_BACKUPS, HUGINN_DB_BACKUP_HOURS). A damaged database never pushes out the good copies, you get a warning on the Account page and through ntfy. Bring one back with: app.py restore-db."),
    ("0.16.2", "2026-11-06", "More security and reliability fixes from a deep review. Honeypot: root no longer changes or writes files the honeypot users control (update it, this one matters), Cowrie and OpenCanary run in a filesystem sandbox, the real sshd leaves port 22 on new installs. Huginn: addresses with an IPv6 scope are refused and can no longer add lines to a feed. The C2 list only has addresses seen from at least 2 attackers, never from failed downloads (HUGINN_C2_EXCLUDE removes more): treat it as advice. A bad file, port or recording can no longer stop the sync or a thread. update-huginn.sh rolls back when the restart itself fails. Optional HUGINN_ALLOWED_HOSTS."),
    ("0.16.1", "2026-11-06", "Security fixes: text sent to a decoy service could add fake lines to the honeypot export and break pages. The export is now split on real line ends only, impossible times and durations are refused, and pages tolerate bad values. The web server has a time limit and a cap on connections, the login limit holds under parallel requests, and an unread request body closes the connection. Update the honeypot too (hp-traps)."),
    ("0.16.0", "2026-11-06", "SSHole detection (CVE-2026-123158): an SSH login with a password of 257-1024 bytes tags the attacker sshole-probe (+10 score), stands out in the session log and counts as an exploit attempt in ntfy. Attackers already in the database are tagged at the first start."),
    ("0.15.0", "2026-11-05", "Overview: a banner with the raven and what Huginn has seen so far (since when, attackers, countries, login attempts, last sync). It is a card like the others: switch it off in Settings."),
    ("0.14.3", "2026-11-05", "Security review: data from ipwho.is, Shodan and reverse DNS is validated, the CSV blocklist uses real CSV quoting, a negative Content-Length can no longer hang a request, extra security headers, harder systemd sandbox, hp-export never follows symlinks, hp-logclean runs as the cowrie user. New tests plant HTML/JS in every attacker-controlled field."),
    ("0.14.2", "2026-11-05", "Session replays are easy to find: a Replay button on every recorded shell session of an attacker (no need to open it first) and in Latest shell sessions on the overview."),
    ("0.14.1", "2026-11-05", "Malware families from real honeypot data: loaders hidden as \\x escapes or base64 are decoded (their C2 addresses show up too), more dropper shapes (busybox wget, wget -O- | sh, ftpget), \"competitor killer\" scripts, SSH keys written to authorized_keys."),
    ("0.14.0", "2026-11-05", "Malware families: captured files are recognised as Mirai, Gafgyt, Mozi, Tsunami, XMRig and other miners, SSH-key backdoors or dropper scripts (strings in the file, its name or URL, optionally MalwareBazaar with HUGINN_MALWAREBAZAAR_KEY). Overview: New this week, and When they attack (a heat map per hour of the week). Weekly ntfy summary on Sunday evening."),
    ("0.13.0", "2026-11-05", "Huginn runs in Docker: Dockerfile and docker-compose.yml (one volume for everything, unprivileged, read-only, health check), the container makes its SSH key and learns the honeypot's host key on first start. Image for amd64 and arm64 at ghcr.io/ancientswede/huginn from each release."),
    ("0.12.4", "2026-11-05", "Fix: the bars in the charts were gone in 0.12.2-0.12.3 (only the numbers showed). Their heights were inline styles, which Huginn's own Content-Security-Policy blocks."),
    ("0.12.3", "2026-11-05", "Huginn has a logo: the raven as tab icon, next to the name in the header and on the login page. README banner."),
    ("0.12.2", "2026-11-05", "The bar charts show the number above each bar (no need to hover), sharp at any screen size."),
    ("0.12.1", "2026-11-05", "Fix: copying session recordings in batches stopped at the first batch (bytes vs. text)."),
    ("0.12.0", "2026-11-05", "Disk housekeeping. Honeypot: hp-logclean gzips Cowrie's logs and keeps 30 days, OpenCanary's log is rotated compressed, the journal is capped. Huginn: copies every session recording in the background and keeps it compressed, HUGINN_RETENTION_DAYS=0 keeps the whole history forever, the Account page shows database size and free disk, updates keep only one database backup."),
    ("0.11.2", "2026-11-05", "Long cards scroll inside instead of growing the page: the four Credentials cards (now with a filter box each and more rows), Related attackers and Sessions on an attacker's page."),
    ("0.11.1", "2026-11-05", "The fake mail server (hp-traps) greets with a name that fits the persona instead of mail.example.com. README: a table of the ports to forward. install-honeypot.sh can be run again on a honeypot without internet (apt only runs when a package is missing)."),
    ("0.11.0", "2026-11-05", "Credentials: \"Is my password in here?\" checks a password against everything attackers tried, in the browser (only 4 characters of its SHA-256 hash are sent). Search all usernames and passwords, and export them as word lists or a CSV of every attempt."),
    ("0.10.1", "2026-11-05", "Personas look more real: CPU count fits the CPU model, the tools in the bash history exist (and fail like a real network problem), the camera shows a BusyBox banner. Huginn remembers bait from earlier honeypot identities, so old attackers keep their took-bait tag. New uninstall-huginn.sh and uninstall-honeypot.sh."),
    ("0.10.0", "2026-11-05", "Ready-made personas with planted bait: the honeypot installer makes SSH a server or file server and Telnet an IP camera, with a random hostname, network, hardware and bait values for every install. The honeypot announces its personas and bait to Huginn, so bait detection works without setup. Tests and CI."),
    ("0.9.1", "2026-11-05", "Footer on every page: copyright, license (AGPL-3.0, no warranty) and a link to the source code, as the AGPL asks of network software."),
    ("0.9.0", "2026-11-05", "Updates: update-huginn.sh (backup, health check, automatic rollback, --rollback) and update-honeypot.sh (also upgrades Cowrie/OpenCanary and re-applies Huginn's patches). Huginn shows when a newer version is out."),
    ("0.8.4", "2026-11-05", "ntfy servers with access control: HUGINN_NTFY_TOKEN. The installer asks about ntfy and sends a test notification."),
    ("0.8.3", "2026-11-05", "Web decoy: HTTPS port and readable web requests (method, path, status). The address the attacker connected to is no longer stored, and HUGINN_MASK hides your own IPs/domains in everything stored."),
    ("0.8.2", "2026-11-05", "Clicking a country on the map shows exactly that country (new country filter on the Attackers list)."),
    ("0.8.1", "2026-11-05", "Map and chart cards line up."),
    ("0.8.0", "2026-11-05", "Countries card: switch between a world map and the list. Click a country to see its attackers."),
    ("0.7.0", "2026-11-05", "12/24-hour clock, choose the columns of the Attackers list, hide countries/networks from the views (never from the blocklist), export everything about an IP as JSON or CSV, keyboard shortcuts (press ?)."),
    ("0.6.1", "2026-11-05", "Fix: Shodan's \"scanner\" tag no longer marks attackers as research scanners, and anyone who logged in, ran commands or dropped files is always blocklisted. Header wraps on phones."),
    ("0.6.0", "2026-11-05", "Settings page: light/dark/auto theme (quick toggle in the header), accent colour, compact layout, page title, overview cards, list and blocklist defaults, notification events and a test notification."),
    ("0.5.0", "2026-11-05", "Install scripts for the honeypot and Huginn. HUGINN_ALLOW_PRIVATE=1 for testing from your own LAN."),
    ("0.4.1", "2026-11-04", "Hardening: size caps on everything read from the honeypot, one bad file record no longer stops the sync."),
    ("0.4.0", "2026-11-04", "Time wasted: tarpit and fake-shell time per attacker, who is stuck right now. All site-specific settings moved to environment variables."),
    ("0.3.1", "2026-11-04", "Reads hp-traps (fake SMTP relay, POP3, IMAP, PostgreSQL, SOCKS5) as decoy services."),
    ("0.3.0", "2026-11-04", "Session replay, file analysis with IOCs and a C2 blocklist feed, bait detection (read/took the bait), persona per session (server/camera), ntfy alerts."),
    ("0.2.1", "2026-11-04", "One-off import of full honeypot log files (history before Huginn started)."),
    ("0.2.0", "2026-11-04", "Account page: change password, see and end other login sessions, system status and changelog."),
    ("0.1.1", "2026-11-04", "Fix: login and other forms returned Forbidden (browsers sent Origin: null under the no-referrer policy)."),
    ("0.1.0", "2026-11-04", "First version: honeypot ingest, IP profiles, sessions, files, credentials, campaigns, blocklist feeds."),
]

import base64
import fcntl
import getpass
import gzip
import hashlib
import hmac
import html
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

BASE = os.environ.get("HUGINN_BASE", "/opt/huginn")
DATA = os.path.join(BASE, "data")
DB_PATH = os.path.join(DATA, "huginn.db")
PORT = int(os.environ.get("HUGINN_PORT", "8095"))
BIND = os.environ.get("HUGINN_BIND", "0.0.0.0")
HP_HOST = os.environ.get("HUGINN_HP_HOST", "")
HP_PORT = os.environ.get("HUGINN_HP_PORT", "22022")
HP_KEY = os.environ.get("HUGINN_HP_KEY", os.path.join(BASE, ".ssh", "honeypot_ro"))
HP_KNOWN = os.environ.get("HUGINN_HP_KNOWN", os.path.join(BASE, ".ssh", "known_hosts"))
POLL = max(30, int(os.environ.get("HUGINN_POLL", "120")))
_ret = int(os.environ.get("HUGINN_RETENTION_DAYS", "180") or 0)
RETENTION_DAYS = 0 if _ret <= 0 else max(7, _ret)       # 0 = keep everything forever
# Decoy services (OpenCanary, hp-traps): keep at most this many events per IP, service and UTC day; the rest are only counted.
# One VNC brute forcer sent ~16,000 tries a day, nearly a fifth of the whole database. 0 = keep everything.
try:
    DECOY_CAP = max(0, int(os.environ.get("HUGINN_DECOY_CAP", "2000")))
except ValueError:
    DECOY_CAP = 2000
ENRICH = os.environ.get("HUGINN_ENRICH", "1") == "1"
ENRICH_TTL = 14 * 86400
# Your own public IPs / domain names: replaced with "[self]" in everything stored (attackers often echo the target address).
MASK = [x.strip() for x in os.environ.get("HUGINN_MASK", "").split(",") if x.strip()]
# Testing only: also record private/LAN source addresses (normally dropped so you never block yourself).
ALLOW_PRIVATE = os.environ.get("HUGINN_ALLOW_PRIVATE", "0") == "1"
# Demo only (tools/make_demo.py): the documentation ranges used for made-up attackers count as public addresses.
DEMO_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
DEMO = os.environ.get("HUGINN_DEMO", "0") == "1"


def is_public(a):
    return a.is_global or (DEMO and any(a in n for n in DEMO_NETS))
ALLOWED_HOSTS = {x.strip().lower() for x in os.environ.get("HUGINN_ALLOWED_HOSTS", "").split(",") if x.strip()}  # empty = any Host
C2_EXCLUDE = {x.strip() for x in os.environ.get("HUGINN_C2_EXCLUDE", "").split(",") if x.strip()}
C2_MIN_SOURCES = 2      # attackers choose what they download: one attacker alone never puts an address on the C2 list
TRUSTED_PROXIES = {x.strip() for x in os.environ.get("HUGINN_TRUSTED_PROXIES", "").split(",") if x.strip()}
TZ = ZoneInfo(os.environ.get("HUGINN_TZ", "UTC"))
os.environ["TZ"] = os.environ.get("HUGINN_TZ", "UTC")  # SQLite "localtime" (per-day grouping) follows the process TZ
time.tzset()
UA = "huginn/" + HUGINN_VERSION + " (homelab honeypot)"
SESSION_DAYS = 14
# The honeypot may be fully compromised one day: never read more than this from it.
MAX_EXPORT = int(os.environ.get("HUGINN_MAX_EXPORT_MB", "256")) * 1024 * 1024
MAX_TTY = 64 * 1024 * 1024
# Update check: once a day, read the public list of version tags on GitHub (sends nothing about you). 0 = off.
UPDATE_CHECK = os.environ.get("HUGINN_UPDATE_CHECK", "1") == "1"
REPO = os.environ.get("HUGINN_REPO", "ancientswede/Huginn")
NTFY_URL = os.environ.get("HUGINN_NTFY_URL", "")          # e.g. http://ntfy.lan:2586/huginn — empty = no notifications
NTFY_TOKEN = os.environ.get("HUGINN_NTFY_TOKEN", "")      # access token (tk_...) for ntfy servers with access control
# Optional: look captured files up on MalwareBazaar (abuse.ch) by SHA-256. Sends only the hash. Free key: auth.abuse.ch
MB_KEY = os.environ.get("HUGINN_MALWAREBAZAAR_KEY", "")


def ntfy_post(body, title, prio=3):
    # One place that talks to ntfy (alerts and the test button). Never logs the token.
    h = {"Title": title, "Priority": str(prio), "Tags": "honey_pot", "User-Agent": UA}
    if PUBLIC_URL:
        h["Click"] = PUBLIC_URL.rstrip("/") + "/"
    if NTFY_TOKEN:
        h["Authorization"] = "Bearer " + NTFY_TOKEN
    req = urllib.request.Request(NTFY_URL, data=body.encode("utf-8"), method="POST", headers=h)
    urllib.request.urlopen(req, timeout=10).read()
PUBLIC_URL = os.environ.get("HUGINN_PUBLIC_URL", "")      # link in the notifications
NOTIFY_EVERY = 3600
# Automatic copies of the database: how many to keep (0 = off) and how often. See "Database backups" in README.md.
BACKUP_KEEP = max(0, min(30, int(os.environ.get("HUGINN_DB_BACKUPS", "3"))))
BACKUP_HOURS = max(1, int(os.environ.get("HUGINN_DB_BACKUP_HOURS", "24")))
BACKUP_RETRY = 6 * 3600                  # after a failure, try again this much later
TTY_DIR = os.path.join(DATA, "tty")
BACKUP_DIR = os.path.join(DATA, "backups")
BACKUP_RE = re.compile(r"huginn-\d{8}-\d{6}\.db\.gz")
STATIC_DIR = os.environ.get("HUGINN_STATIC", os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))
# Persona per internal Cowrie port, e.g. HUGINN_PERSONAS="2225=server,2323=camera" (several Cowrie instances).
# Without the setting, Huginn uses what the honeypot announces in its export (##PERSONAS, written by install-honeypot.sh).
PERSONA_RE = re.compile(r"^\s*(\d{1,5})\s*=\s*([A-Za-z0-9_.-]{1,20})\s*$")


def parse_personas(items):
    out = {}
    for x in items:
        m = PERSONA_RE.match(x or "")
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


PERSONA_ENV = parse_personas(os.environ.get("HUGINN_PERSONAS", "").split(","))
PERSONA = dict(PERSONA_ENV)


# Bait: fake credentials that only exist in the honeypot's bait files. From bait.json next to app.py (optional) plus
# the values the honeypot announces in its export (##BAIT). Treated as untrusted data: only strings, sane lengths.
def bait_values(d, limit=100):
    if not isinstance(d, dict):
        return []
    return sorted({v for v in list(d.values())[:limit] if isinstance(v, str) and 8 <= len(v) <= 200})


try:
    BAIT_LOCAL = bait_values(json.load(open(os.environ.get("HUGINN_BAIT_FILE", os.path.join(BASE, "bait.json")))))
except Exception:
    BAIT_LOCAL = []
BAIT = list(BAIT_LOCAL)
BAIT_FILES_RE = re.compile(r"\.env\b|\.my\.cnf|\.aws/credentials|\.bash_history|backup\.sh|Account1|network\.conf|wpa_supplicant|\.ssh/config"
                           r"|rsyncd\.secrets|\.smbcredentials|rclone\.conf|nextcloud/config/config\.php|nextcloud-admin\.txt")
# Common harmless addresses found in malware (connectivity checks, docs) — never put on the C2 list.
BENIGN_IOC = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.222.222", "208.67.220.220", "4.2.2.2"}

PORTNAME = {22: "ssh", 2222: "ssh", 2223: "ssh", 23: "telnet", 2323: "telnet", 21: "ftp", 2121: "ftp",
            80: "http", 8080: "http", 443: "https", 8443: "https", 3306: "mysql", 6379: "redis", 5900: "vnc"}

# Known research/internet scanners (rDNS/org/tags). Left out of the blocklist by default.
RESEARCH_RE = re.compile(
    r"shodan|censys|binaryedge|shadowserver|internet-measurement|stretchoid|onyphe|criminalip|leakix|"
    r"netsystemsresearch|recyber|alphastrike|bitsight|paloaltonetworks|expanse|driftnet|rapid7|"
    r"internettl|quadmetrics|intrinsec|zoomeye|natlas|ipip\.net|academic|research|"
    r"probe-?net|projectdiscovery|modat|hadrian|cyber\.casa|securitytrails|fofa", re.I)
# Whoever controls an address chooses its reverse DNS, so a name only counts when it ends in a known scanner's domain.
RESEARCH_DOMAINS = ("shodan.io", "censys-scanner.com", "censys.io", "binaryedge.ninja", "binaryedge.io", "shadowserver.org", "shadowserver.io", "academyforinternetresearch.org", "gatech.edu", "mpg.de", "tu-dresden.de", "internet-measurement.com",
                    "stretchoid.com", "onyphe.net", "onyphe.io", "criminalip.io", "criminalip.com", "leakix.net", "netsystemsresearch.com", "recyber.net",
                    "alphastrike.io", "bitsight.com", "bitsighttech.com", "paloaltonetworks.com", "expanseinc.com", "driftnet.io", "rapid7.com", "internettl.org",
                    "quadmetrics.com", "intrinsec.com", "zoomeye.org", "ipip.net", "projectdiscovery.io", "modat.io", "hadrian.io", "cyber.casa",
                    "securitytrails.com", "fofa.info", "probe-net.net")


def research_flag(rdns, org, isp, hostnames, rdns_ok=None):
    # rdns_ok: 1 the name points back to this address, anything else it has not been shown to. This is an exception from
    # blocking, so unknown does not count. `hostnames` is not checked at all, so it cannot grant anything.
    if rdns_ok == 1:
        n = str(rdns or "").strip().lower().rstrip(".")
        if any(n == d or n.endswith("." + d) for d in RESEARCH_DOMAINS):
            return 1
    return 1 if RESEARCH_RE.search(" ".join(str(v) for v in (org, isp) if v)) else 0

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(h TEXT PRIMARY KEY, ts REAL, ip TEXT, src TEXT, kind TEXT, session TEXT, a TEXT, b TEXT);
CREATE INDEX IF NOT EXISTS ev_ip ON events(ip, ts);
CREATE INDEX IF NOT EXISTS ev_sess ON events(session);
CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, ts);
CREATE TABLE IF NOT EXISTS capped(ip TEXT, svc TEXT, day TEXT, kept INTEGER, dropped INTEGER, upto REAL, PRIMARY KEY(ip, svc, day));
CREATE TABLE IF NOT EXISTS sessions(session TEXT PRIMARY KEY, ip TEXT, start REAL, end REAL, proto TEXT, port INTEGER,
  version TEXT, hassh TEXT, duration REAL, logins_ok INTEGER, logins_fail INTEGER, cmds INTEGER, files INTEGER,
  tcpip INTEGER, exploits INTEGER, cmdhash TEXT);
CREATE INDEX IF NOT EXISTS se_ip ON sessions(ip, start);
CREATE INDEX IF NOT EXISTS se_start ON sessions(start);
CREATE INDEX IF NOT EXISTS se_hassh ON sessions(hassh);
CREATE INDEX IF NOT EXISTS se_cmdhash ON sessions(cmdhash);
CREATE TABLE IF NOT EXISTS ips(ip TEXT PRIMARY KEY, first REAL, last REAL, sessions INTEGER, logins_ok INTEGER,
  logins_fail INTEGER, cmds INTEGER, files INTEGER, tcpip INTEGER, exploits INTEGER, canary INTEGER, canary_svcs TEXT,
  tarpit_s REAL, protos TEXT, score INTEGER, tags TEXT);
CREATE INDEX IF NOT EXISTS ips_last ON ips(last);
CREATE TABLE IF NOT EXISTS enrich(ip TEXT PRIMARY KEY, fetched REAL, ok INTEGER, cc TEXT, country TEXT, city TEXT,
  asn TEXT, org TEXT, isp TEXT, rdns TEXT, ports TEXT, tags TEXT, vulns TEXT, hostnames TEXT, research INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS flags(ip TEXT PRIMARY KEY, flag TEXT, note TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS logins(token_hash TEXT PRIMARY KEY, expires REAL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS files(sha TEXT PRIMARY KEY, src TEXT, size INTEGER, type TEXT, arch TEXT, packed INTEGER,
  iocs TEXT, mtime REAL, updated REAL);
CREATE TABLE IF NOT EXISTS seen(kind TEXT, key TEXT, observed REAL, ip TEXT, session TEXT, ex TEXT, n INTEGER DEFAULT 1,
  PRIMARY KEY(kind, key));
CREATE INDEX IF NOT EXISTS seen_obs ON seen(observed);
CREATE TABLE IF NOT EXISTS gaps(start REAL PRIMARY KEY, end REAL);
CREATE TABLE IF NOT EXISTS web_identities(ts REAL PRIMARY KEY, id TEXT, kind TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS webhits(h TEXT PRIMARY KEY, ip TEXT, ts REAL, level TEXT, type TEXT, cve TEXT, sev INTEGER, rule TEXT, robots INTEGER, reply TEXT);
CREATE INDEX IF NOT EXISTS wh_ip ON webhits(ip);
CREATE INDEX IF NOT EXISTS wh_type ON webhits(type, ts);
CREATE TABLE IF NOT EXISTS mails(h TEXT PRIMARY KEY, mail_from TEXT, subject TEXT, rcpts TEXT, helo TEXT, size INTEGER, sample TEXT);
"""


# ---------------------------------------------------------------- database

def connect():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def tighten_data():
    # Password hash, feed token and everything collected: not for other users on the machine. Older installs were world-readable.
    for path, mode in [(DATA, 0o750), (TTY_DIR, 0o750)] + [(DB_PATH + x, 0o640) for x in ("", "-wal", "-shm")]:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def init_db():
    os.makedirs(DATA, exist_ok=True)
    tighten_data()
    con = connect()
    con.executescript(SCHEMA)
    tighten_data()
    if "rdns_ok" not in [r[1] for r in con.execute("PRAGMA table_info(enrich)")]:
        con.execute("ALTER TABLE enrich ADD COLUMN rdns_ok INTEGER")
        con.execute("UPDATE enrich SET fetched=0 WHERE research=1")       # look these up again soon, now with the forward check
    # Re-evaluate the research flag with the current rules (cheap, runs at start).
    for ip, rd, org, isp, hn, ok in con.execute("SELECT ip, rdns, org, isp, hostnames, rdns_ok FROM enrich").fetchall():
        con.execute("UPDATE enrich SET research=? WHERE ip=?", (research_flag(rd, org, isp, hn, ok), ip))
    cols = [r[1] for r in con.execute("PRAGMA table_info(sessions)")]
    if "tty" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN tty TEXT")
    if "termsize" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN termsize TEXT")
    fcols = [r[1] for r in con.execute("PRAGMA table_info(files)")]
    for col, typ in (("family", "TEXT"), ("mb", "TEXT"), ("mb_checked", "REAL")):
        if col not in fcols:
            con.execute("ALTER TABLE files ADD COLUMN %s %s" % (col, typ))
    con.commit()
    os.makedirs(TTY_DIR, exist_ok=True)
    if not get_meta(con, "feed_token"):
        set_meta(con, "feed_token", secrets.token_urlsafe(24))
    load_honeypot_meta(con)
    # One time only: attackers stored before this detection existed get their tag. Later rows are handled by store().
    if not get_meta(con, "sshole_backfilled"):
        with con:
            for (ip,) in con.execute("SELECT DISTINCT e.ip FROM events e WHERE %s" % SSHOLE_SQL).fetchall():
                recompute_ip(con, ip)
        set_meta(con, "sshole_backfilled", "1")
    if not get_meta(con, "vnc_logins"):
        vnc_logins_backfill(con)
    # One time only, all or nothing: script campaigns are grouped by the shape of their commands since 0.19.
    if DECOY_CAP > 0 and not get_meta(con, "decoy_cap_v1"):
        trim_decoys(con)
    if not get_meta(con, "cmdhash_shapes"):
        with con:
            for (sid,) in con.execute("SELECT session FROM sessions WHERE cmdhash IS NOT NULL").fetchall():
                con.execute("UPDATE sessions SET cmdhash=? WHERE session=?", (script_hash(session_commands(con, sid)), sid))
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('cmdhash_shapes','1')")
    con.close()


def get_meta(con, k, default=None):
    r = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def set_meta(con, k, v):
    with con:
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, str(v)))


_local = threading.local()


def db():
    c = getattr(_local, "con", None)
    if c is None:
        c = _local.con = connect()
    return c


# ---------------------------------------------------------------- parsing the export

def norm_ip(s):
    if not s:
        return None
    s = str(s).strip()
    if s.lower().startswith("::ffff:"):
        s = s[7:]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 6 and a.scope_id:   # "addr%anything" may hold line breaks, which would end up in firewall feeds
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if not is_public(a) and not (ALLOW_PRIVATE and a.is_private and not a.is_loopback):  # private addresses are dropped unless testing
        return None
    return str(a)


def trunc(s, n=4000):
    if s is None:
        return None
    s = str(s)
    for m in MASK:
        if m in s:
            s = s.replace(m, "[self]")
    return s if len(s) <= n else s[:n] + "…"


def iso_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


MAX_LINE = 65536                     # no real log line is this long, hp-export already drops most of them
MIN_TS = 946684800.0                 # 2000-01-01: anything older is not a real event
MAX_DURATION = 366 * 86400.0
SESSION_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def sane_duration(d):
    try:
        f = float(d)
    except (TypeError, ValueError, OverflowError):
        return None
    return str(d) if math.isfinite(f) and 0 <= f <= MAX_DURATION else None


def sane_row(r):
    # Last check before anything is stored, whatever the parser: a bad value must never reach the pages.
    ts, session = r[0], r[4]
    if not isinstance(ts, (int, float)) or not MIN_TS <= ts <= time.time() + 86400:
        return False
    return session is None or (isinstance(session, str) and SESSION_RE.fullmatch(session) is not None)


PROXY_REPLIES = {"http200": "answered 200", "hold": "held, no answer"}


def p_cowrie(line):
    if not line.startswith("{"):
        return None
    ev = json.loads(line)
    k = ev.get("eventid", "")
    ip = norm_ip(ev.get("src_ip"))
    if not ip or not ev.get("timestamp"):
        return None
    a = b = None
    if k == "cowrie.session.connect":
        kind, a, b = "connect", ev.get("protocol"), str(ev.get("dst_port", ""))
    elif k == "cowrie.login.success":
        kind, a, b = "login_ok", ev.get("username"), ev.get("password")
    elif k == "cowrie.login.failed":
        kind, a, b = "login_fail", ev.get("username"), ev.get("password")
    elif k == "cowrie.command.input":
        kind, a = "cmd", ev.get("input")
    elif k in ("cowrie.session.file_upload", "cowrie.session.file_download"):
        kind, a, b = "file", ev.get("url") or ev.get("filename") or ev.get("destfile"), ev.get("shasum")
    elif k == "cowrie.session.file_download.failed":
        kind, a = "file_fail", ev.get("url")
    elif k == "cowrie.direct-tcpip.request":
        kind, a = "tcpip", "%s:%s" % (ev.get("dst_ip"), ev.get("dst_port"))
    elif k == "cowrie.session.hp-exec":
        # Huginn's Cowrie patch: the attacker ran an uploaded program; it "ran" silently, nothing was executed (honeypot/patches.py).
        sha = str(ev.get("shasum") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            return None
        kind, a, b = "exec_sim", clean(("%s %s" % (ev.get("path") or "?", ev.get("args") or "")).strip(), 300), sha
    elif k == "cowrie.direct-tcpip.hp-reply":
        # Huginn's Cowrie patch answered a proxy check (http200) or held TLS (hold); see honeypot/patches.py.
        how, req = ev.get("hp_reply"), ev.get("hp_request")
        if how not in PROXY_REPLIES or not isinstance(req, str):
            return None
        kind, a, b = "proxy_reply", clean(req, 200), how
    elif k == "cowrie.telnet.exploit_attempt":
        kind, a, b = "exploit", ev.get("cve"), "%s=%s" % (ev.get("name"), ev.get("value"))
    elif k == "cowrie.client.version":
        kind, a = "version", ev.get("version")
    elif k == "cowrie.client.kex":
        kind, a = "hassh", ev.get("hassh")
    elif k == "cowrie.client.size":
        # The terminal size the client asked for (SSH pty request). Bots that ask often use one fixed size.
        w, h = ev.get("width"), ev.get("height")
        if not (type(w) is int and type(h) is int and 0 < w <= 2000 and 0 < h <= 2000):       # not bool, not float
            return None
        kind, a = "termsize", "%dx%d" % (w, h)
    elif k == "cowrie.log.closed":
        if not ev.get("shasum") or not ev.get("size"):
            return None
        kind, a, b = "tty", ev.get("shasum"), str(ev.get("size"))
    elif k == "cowrie.session.closed":
        d = ev.get("duration_ms")
        d = d / 1000.0 if isinstance(d, (int, float)) else ev.get("duration")
        kind, a = "closed", sane_duration(d)
    else:
        return None
    return (iso_ts(ev["timestamp"]), ip, "cowrie", kind, ev.get("session"), trunc(a), trunc(b))


# VNC never sends the password itself, only an answer to a challenge. OpenCanary tries a list of common passwords
# against it and logs the one that fits, or this placeholder. A known password is a login like any other; an unknown
# one stays a plain hit, so it cannot fill the password lists with the placeholder.
VNC_UNKNOWN = "<Password was not in the common list>"


def vnc_password(ld):
    if not isinstance(ld, dict):
        return None
    rest = [k for k in ld if "Challenge" not in k and "Response" not in k]
    pw = ld.get("VNC Password") if rest == ["VNC Password"] else None
    return pw if isinstance(pw, str) and pw and pw != VNC_UNKNOWN else None


def vnc_logins_backfill(con):
    # One time only (0.24.1): VNC lines stored before VNC passwords counted as logins get the login form " / password".
    with con:
        for h, b in con.execute("SELECT h, b FROM events WHERE kind='canary' AND b LIKE '{\"VNC Password\": %' "
                                "AND b NOT LIKE '%not in the common list%'").fetchall():
            try:
                pw = vnc_password(json.loads(b))
            except ValueError:
                continue
            if pw:
                con.execute("UPDATE events SET b=? WHERE h=?", (trunc(" / " + pw, 600), h))
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('vnc_logins','1')")


# ---------------------------------------------------------------- web attacks (rules from Krawl, MIT)
# static/web-rules.json.gz is made by tools/krawl-rules.py from Krawl's YARA rules (github.com/BlessedRebuS/Krawl).
# Each web request is matched once, when it is stored: its path, query, body and user agent, raw and URL-decoded.
# Rules are tried from the highest severity down, so the first match is the best one. A rule that only recognises a
# scanner by its user agent is a label, not an attack, and only counts when nothing else matched.
WEB_RULES_FILE = os.path.join(STATIC_DIR, "web-rules.json.gz")
WEB_SCANNER_TYPES = {"research_scanner_ua", "scanner_user_agent"}
WEB_EXPLOIT_SEV = 7
WEB_B = re.compile(r"^(\S{1,10}) (\S+?)(?: \((\d{1,3})\))?(?:  \[reply ([a-z_]{1,20})\])?(  \[robots\])?(?:  body: (.*?))?(?:  · (.*))?$", re.S)
WEB_BAIT_REPLIES = {"env", "aws", "phpinfo", "actuator", "robots_backup"}   # honeypot replies that hand out bait values (honeypot/webreply.py)
_web = {"rules": None, "sig": "", "error": ""}
_web_lock = threading.Lock()


def web_rules():
    with _web_lock:
        if _web["rules"] is None:
            rules, sig, err = [], "", ""
            try:
                with open(WEB_RULES_FILE, "rb") as fh:
                    raw = fh.read(16 << 20)
                sig = hashlib.sha1(raw).hexdigest()[:16]
                for r in json.loads(gzip.decompress(raw))["rules"]:
                    clauses = []
                    for targets, pats in r["clauses"]:
                        rx = []
                        for nocase in (False, True):
                            alt = [p for k, p, i in pats if k == "r" and bool(i) == nocase]
                            if alt:
                                rx.append(re.compile("|".join("(?:%s)" % p for p in alt), re.I if nocase else 0))
                        clauses.append((None if "*" in targets else tuple(targets),
                                        [p for k, p, i in pats if k == "l" and not i], [p.lower() for k, p, i in pats if k == "l" and i], rx))
                    rules.append((int(r["sev"]), bool(r.get("cve")), str(r["type"])[:60], str(r.get("cve") or "")[:80], str(r["rule"])[:80], clauses,
                                  str(r.get("desc") or "")[:200]))
            except (OSError, ValueError, KeyError, TypeError, IndexError, re.error, EOFError) as e:
                rules, err = [], repr(e)[:200]
            rules.sort(key=lambda x: (-x[0], not x[1]))
            _web.update(rules=rules, sig=sig, error=err)
        return _web["rules"], _web["sig"]


def web_fields(b):
    m = WEB_B.match(b or "")
    if not m:
        return None
    meth, url, status, reply, robots, body, ua = m.groups()
    path, _, query = url.partition("?")
    f = {"method": meth, "path": path, "query": query, "uri": url, "body": body or "", "user_agent": ua or ""}
    for k, v in f.items():
        d = urllib.parse.unquote_plus(v)
        if d != v:
            f[k] = v + "\n" + d
    return f, reply, bool(robots)


def web_rule_hits(rule, f, low):
    for targets, lits, ilits, rx in rule[5]:
        for t in targets or f:
            v = f.get(t, "")
            if not v:
                continue
            if any(x in v for x in lits) or any(x in low[t] for x in ilits) or any(r.search(v) for r in rx):
                return True
    return False


def web_classify(b):
    # (level, type, cve, sev, rule, robots, reply). level: exploit, probe, scanner, or "" when no rule matched.
    parsed = web_fields(b)
    if not parsed:
        return ("", None, None, 0, None, 0, None)
    f, reply, robots = parsed
    low = {k: v.lower() for k, v in f.items()}
    rules, _sig = web_rules()
    scanner = None
    for rule in rules:
        if rule[2] in WEB_SCANNER_TYPES:
            if scanner is None and web_rule_hits(rule, f, low):
                scanner = rule
            continue
        if web_rule_hits(rule, f, low):
            # A bare GET of a path only asks whether it exists: the attack itself needs input (query, body or "..").
            bare = f["method"] in ("GET", "HEAD") and not f["query"] and not f["body"] and ".." not in low["path"]
            level = "exploit" if rule[0] >= WEB_EXPLOIT_SEV and not bare else "probe"
            return (level, rule[2], rule[3], rule[0], rule[4], int(robots), reply)
    if scanner:
        return ("scanner", scanner[2], scanner[3], scanner[0], scanner[4], int(robots), reply)
    return ("", None, None, 0, None, int(robots), reply)


def web_rule_info(rtype):
    # Description and CVE of a rule type, for the pages.
    for r in web_rules()[0]:
        if r[2] == rtype:
            return r
    return None


# The worst level among a group of web hits.
WEB_LEVEL_SQL = ("CASE WHEN MAX(level='exploit') THEN 'exploit' WHEN MAX(level='probe') THEN 'probe' "
                 "WHEN MAX(level='scanner') THEN 'scanner' ELSE '' END")


def web_label(rtype, cve):
    # Short name for a rule type: the CVE when there is one, otherwise the type in words.
    if cve:
        return cve.split(",")[0].strip()
    return (rtype or "?").replace("_", " ")


def web_tag(level, rtype, cve):
    cls = {"exploit": "t-red", "probe": "t-yellow", "scanner": "t-grey"}.get(level)
    if not cls:
        return ""
    return '<a class="tag %s" href="/campaign/web/%s" title="%s">%s</a>' % (cls, esc(rtype), esc(level), esc(web_label(rtype, cve)))


def classify_web(con, budget=20.0, limit=5000):
    # Web requests not matched yet, newest first, until the time budget is used. New rules start again from the top.
    rules, sig = web_rules()
    if not rules:
        return 0
    if get_meta(con, "webrules") != sig:
        with con:
            con.execute("DELETE FROM webhits")
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('webrules',?)", (sig,))
    rows = con.execute("SELECT e.h, e.ip, e.ts, e.b FROM events e WHERE e.kind='canary' AND e.a IN ('http','https') "
                       "AND NOT EXISTS (SELECT 1 FROM webhits w WHERE w.h=e.h) ORDER BY e.ts DESC LIMIT ?", (limit,)).fetchall()
    end = time.time() + budget
    out, touched = [], set()
    for h, ip, ts, b in rows:
        r = web_classify(b)
        out.append((h, ip, ts) + r)
        if r[0] in ("exploit", "probe") or r[5] or r[6]:
            touched.add(ip)
        if time.time() > end:
            break
    if out:
        with con:
            con.executemany("INSERT OR IGNORE INTO webhits(h, ip, ts, level, type, cve, sev, rule, robots, reply) VALUES(?,?,?,?,?,?,?,?,?,?)", out)
            for ip in touched:
                recompute_ip(con, ip)
    return len(out)


def p_canary(line):
    if not line.startswith("{"):
        return None
    ev = json.loads(line)
    ip = norm_ip(ev.get("src_host"))
    if not ip or not ev.get("utc_time"):
        return None
    port = ev.get("dst_port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = None
    svc = PORTNAME.get(port, str(port))
    ld = ev.get("logdata") or {}
    if not isinstance(ld, dict):
        ld = {"data": ld}
    # The address the attacker connected to is our own public IP or hostname: never store it.
    for k in ("HOSTNAME", "SKIN"):
        ld.pop(k, None)
    user, pw = ld.get("USERNAME") or ld.get("USER"), ld.get("PASSWORD")
    if not user and not pw:
        pw = vnc_password(ld)
    if user or pw:
        return (datetime.fromisoformat(ev["utc_time"]).replace(tzinfo=timezone.utc).timestamp(), ip, "canary", "canary", None, svc, trunc("%s / %s" % (user or "", pw or ""), 600))
    if svc in ("http", "https") and ld.get("HP_DRIP") in ("done", "gone"):
        # The end of a slow export (honeypot/webreply.py): did the client wait for the last byte?
        try:
            secs = max(0.0, min(float(ld.get("HP_DRIP_SECS")), 3600.0))
        except (TypeError, ValueError):
            return None
        ts = datetime.fromisoformat(ev["utc_time"]).replace(tzinfo=timezone.utc).timestamp()
        return (ts, ip, "canary", "web_drip", None, clean(str(ld.get("PATH") or "?"), 200), "%s %.1f" % (ld["HP_DRIP"], secs))
    if svc in ("http", "https") and ld.get("PATH"):
        b = "%s %s%s" % (ld.get("METHOD") or "GET", ld.get("PATH"), " (%s)" % ld["STATUS"] if ld.get("STATUS") else "")
        # Set by the honeypot when it answered with fake content (which type) or the path is only listed in robots.txt.
        if isinstance(ld.get("HP_REPLY"), str) and re.fullmatch(r"[a-z_]{1,20}", ld["HP_REPLY"]):
            b += "  [reply %s]" % ld["HP_REPLY"]
        if ld.get("HP_ROBOTS") == "1":
            b += "  [robots]"
        if ld.get("HP_SLOW") == "1":
            b += "  [slow]"
        if ld.get("BODY"):
            b += "  body: " + str(ld["BODY"])[:300]
        if ld.get("USERAGENT"):
            b += "  · " + str(ld["USERAGENT"])[:120]
    else:
        ld2 = {k: v for k, v in ld.items() if "Challenge" not in k and "Response" not in k}
        b = json.dumps(ld2, ensure_ascii=False) if ld2 else ""
    ts = datetime.fromisoformat(ev["utc_time"]).replace(tzinfo=timezone.utc).timestamp()
    return (ts, ip, "canary", "canary", None, svc, trunc(not_a_login(b), 600))


RE_ENDLESSH = re.compile(r"^(\S+) CLOSE host=(\S+) port=(\d{1,5}) fd=\d+ time=(\d{1,8}(?:\.\d{1,6})?)(?:\s|$)")
RE_ENDLESSH_OPEN = re.compile(r"^(\S+) ACCEPT host=(\S+) port=(\d{1,5}) ")


def p_endlessh(line):
    # CLOSE = a finished catch (time in seconds), ACCEPT = someone got stuck (for "stuck right now").
    m = RE_ENDLESSH.match(line)
    if m:
        ip = norm_ip(m.group(2))
        return (iso_ts(m.group(1)), ip, "endlessh", "tarpit", None, m.group(4), m.group(3)) if ip else None
    m = RE_ENDLESSH_OPEN.match(line)
    if m:
        ip = norm_ip(m.group(2))
        return (iso_ts(m.group(1)), ip, "endlessh", "tarpit_open", None, m.group(3), None) if ip else None
    return None


def not_a_login(text):
    # " / " between user and password is what marks a stored login. Anything else an attacker wrote must not look like one.
    return re.sub(r"(?<= )/(?= )", "\u2044", text)       # lookarounds: " / / " shares its middle space


def mail_list(v, n=20):
    # Recipients as the honeypot sent them: a list of strings. Anything else (a broken or hostile honeypot) gives nothing.
    return [str(x)[:200] for x in v[:n]] if isinstance(v, list) else []


def mail_summary(ev):
    # One line for the event: who sent it, to whom, and the subject. A relay test usually goes to the sender's own mailbox.
    rcpts = mail_list(ev.get("rcpts"))
    try:
        count = max(int(ev.get("rcpt_count") or 0), len(rcpts))
    except (TypeError, ValueError):
        count = len(rcpts)
    to = ", ".join(rcpts[:5]) or ("%d recipient(s)" % count if count else "?")
    if rcpts and count > 5:
        to += " +%d more" % (count - 5)
    return not_a_login("relay: %s -> %s: %s" % (str(ev.get("mail_from") or "?")[:200], to, str(ev.get("subject") or "")[:200]))


def trap_mail(line):
    # The rest of a relay attempt, kept beside its event: every recipient, HELO name, size and the start of the message.
    ev = json.loads(line)
    if ev.get("event") != "mail":
        return None
    try:
        size = max(0, min(int(ev.get("size") or 0), 1 << 40))
    except (TypeError, ValueError):
        size = 0
    return (str(ev.get("mail_from") or "")[:200], str(ev.get("subject") or "")[:200], json.dumps(mail_list(ev.get("rcpts")), ensure_ascii=False),
            str(ev.get("helo") or "")[:200], size, str(ev.get("sample") or "")[:1500])


def p_traps(line):
    # hp-traps (our own service on the honeypot): stored as "canary" events, a = service, b = summary.
    if not line.startswith("{"):
        return None
    ev = json.loads(line)
    ip = norm_ip(ev.get("src_ip"))
    if not ip or not ev.get("ts"):
        return None
    e, svc = ev.get("event"), str(ev.get("service") or "?")[:20]
    if e == "login":
        b = "%s / %s" % (ev.get("username") or "", ev.get("password") or "")
        if ev.get("database"):
            b += "  (db %s)" % ev["database"]
    elif e == "mail":
        b = mail_summary(ev)
    elif e == "helo":
        name = str(ev.get("helo") or "").strip()[:200]
        if not name:
            return None
        b = not_a_login("HELO " + name)
    elif e == "proxy":
        b = not_a_login("proxy -> %s" % (ev.get("target") or "?"))
    elif e == "connect":
        b = ""
    elif e == "end" and svc in ("smtp", "submission"):
        # End of a mail session: how long the bot stayed, how many messages it sent, how long the fake queue made it wait.
        try:
            secs, mails, waited = (max(0.0, min(float(ev.get(k) or 0), 86400.0)) for k in ("secs", "mails", "waited"))
        except (TypeError, ValueError):
            return None
        return (iso_ts(ev["ts"]), ip, "traps", "trap_end", None, svc, "%.1f %d %.1f" % (secs, mails, waited))
    else:
        return None
    return (iso_ts(ev["ts"]), ip, "traps", "canary", None, svc, trunc(b, 600))


PARSERS = {"COWRIE": p_cowrie, "CANARY": p_canary, "ENDLESSH": p_endlessh, "TRAPS": p_traps}


def parse_export(text, skip):
    rows, hashes, section = [], set(), None
    files, personas, bait, identities, mails, status = [], [], {}, [], [], []
    seen = set()
    # Only "\n" ends a line. str.splitlines() also breaks on characters such as U+2028, which an attacker can send.
    for line in text.split("\n"):
        if line.startswith("##"):
            section = line[2:].strip()
            seen.add(section)
            continue
        if len(line) > MAX_LINE:
            continue
        if section == "FILES" and line.startswith("{"):
            try:
                files.append(json.loads(line))
            except ValueError:
                pass
            continue
        if section == "PERSONAS":
            personas.append(line)
            continue
        if section == "IDENTITY":
            identities.append(line)
            continue
        if section == "STATUS":
            status.append(line)
            continue
        if section == "BAIT" and line.startswith("{"):
            try:
                bait.update(json.loads(line))
            except (ValueError, TypeError):
                pass
            continue
        fn = PARSERS.get(section)
        if not fn or not line:
            continue
        h = hashlib.sha1(line.encode("utf-8", "replace")).hexdigest()
        hashes.add(h)
        if h in skip:
            continue
        try:
            r = fn(line)
        except Exception:
            r = None
        if r and sane_row(r):
            rows.append((h,) + r)
            if section == "TRAPS" and r[5] and r[6].startswith("relay: "):
                try:
                    m = trap_mail(line)
                except Exception:
                    m = None
                if m:
                    mails.append((h, r[6]) + m)
    parse_export.files = files
    parse_export.mails = mails
    parse_export.meta = {"personas": parse_personas(personas[:50]), "bait": bait_values(bait), "identities": parse_identities(identities[-500:]),
                         "has_personas": "PERSONAS" in seen, "has_bait": "BAIT" in seen,
                         "status": parse_status(status[:100]) if "STATUS" in seen else None,
                         "warnings": sorted(x[5:] for x in seen if x.startswith("WARN "))[:10]}
    return rows, hashes


STATUS_LINE = re.compile(r"^(sandbox|limits|running|patch):([a-z0-9-]{1,20}) (ok|missing)$")


def parse_status(lines):
    # The honeypot's own report of its protection (hp-export ##STATUS). Untrusted: only the exact expected words get through.
    return {m.group(1) + ":" + m.group(2): m.group(3) == "ok" for m in map(STATUS_LINE.match, lines) if m}


IDENTITY_LINE = re.compile(r"^([0-9]{9,11}) ([a-z0-9-]{1,32}) (nas|router) ([A-Za-z0-9 !+._-]{1,48})$")


def parse_identities(lines):
    # What the web trap pretended to be, and from when. From the honeypot, so only the exact expected shape gets through.
    return [(float(m.group(1)), m.group(2), m.group(3), m.group(4)) for m in map(IDENTITY_LINE.match, lines) if m]


def apply_honeypot_meta(con, meta):
    # Personas and bait announced by the honeypot. Stored so they survive a restart; a change of bait re-checks every attacker.
    if meta.get("identities"):
        # The honeypot's word only: nothing from the future, and a limit on how much it can ask us to keep.
        latest = time.time() + 86400
        with con:
            con.executemany("INSERT OR IGNORE INTO web_identities(ts,id,kind,label) VALUES(?,?,?,?)", [x for x in meta["identities"] if x[0] <= latest])
            con.execute("DELETE FROM web_identities WHERE ts NOT IN (SELECT ts FROM web_identities ORDER BY ts DESC LIMIT 2000)")
    if meta.get("status") is not None:
        set_meta(con, "hp_status", json.dumps({"at": time.time(), "items": meta["status"]}))
    if meta.get("has_personas"):
        set_meta(con, "hp_personas", json.dumps({str(k): v for k, v in meta["personas"].items()}))
    if meta.get("has_bait"):
        # Remember every value ever announced: after a new honeypot identity, old attackers keep their "took-bait".
        old = get_meta(con, "hp_bait", "[]")
        try:
            known = set(json.loads(old))
        except (ValueError, TypeError):
            known = set()
        new = json.dumps(sorted(known | set(meta["bait"]))[-2000:])
        if new != old:
            set_meta(con, "hp_bait", new)
            load_honeypot_meta(con)
            with con:
                for (ip,) in con.execute("SELECT ip FROM ips").fetchall():
                    recompute_ip(con, ip)
    load_honeypot_meta(con)


def load_honeypot_meta(con):
    try:
        announced = {int(k): str(v)[:20] for k, v in json.loads(get_meta(con, "hp_personas", "{}")).items()}
    except (ValueError, TypeError, AttributeError):
        announced = {}
    PERSONA.clear()
    PERSONA.update(PERSONA_ENV or announced)
    try:
        hp_bait = bait_values({str(i): v for i, v in enumerate(json.loads(get_meta(con, "hp_bait", "[]")))}, 2000)
    except (ValueError, TypeError):
        hp_bait = []
    BAIT[:] = sorted(set(BAIT_LOCAL) | set(hp_bait))


def store_mails(con, mails):
    # Kept beside the event (same key). The event line is rewritten too: relay lines stored before 0.24.1 had no recipients.
    with con:
        for h, b, frm, subj, rcpts, helo, size, sample in mails[:10000]:
            if con.execute("SELECT 1 FROM events WHERE h=?", (h,)).fetchone():
                con.execute("UPDATE events SET b=? WHERE h=?", (trunc(b, 600), h))
                con.execute("INSERT OR IGNORE INTO mails(h, mail_from, subject, rcpts, helo, size, sample) VALUES(?,?,?,?,?,?,?)",
                            (h, frm, subj, rcpts, helo, size, sample))


def store_files(con, files):
    now = time.time()
    with con:
        for f in files[:100000]:
            try:
                if not isinstance(f, dict):
                    continue
                sha = str(f.get("sha") or "")
                if not re.fullmatch(r"[0-9a-f]{64}", sha):
                    continue
                iocs = f.get("iocs") if isinstance(f.get("iocs"), list) else []
                iocs = [str(x)[:300] for x in iocs][:60]
                size, mtime = int(f.get("size") or 0), float(f.get("mtime") or 0)
                if not 0 <= size < 2 ** 53 or not math.isfinite(mtime) or not 0 <= mtime < 2 ** 40:
                    continue
            except (TypeError, ValueError, OverflowError):
                continue
            con.execute("INSERT INTO files(sha, src, size, type, arch, packed, iocs, mtime, updated, family) VALUES(?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(sha) DO UPDATE SET src=excluded.src, size=excluded.size, type=excluded.type, arch=excluded.arch, "
                        "packed=excluded.packed, iocs=excluded.iocs, mtime=excluded.mtime, updated=excluded.updated, family=excluded.family",
                        (sha, str(f.get("src") or "")[:20], size, str(f.get("type") or "")[:80],
                         str(f.get("arch") or "")[:20], 1 if f.get("packed") else 0, json.dumps(iocs), mtime, now,
                         str(f.get("family") or "")[:60]))


# File and URL names that give a family away, for files the honeypot could not fetch or analyse.
NAME_FAMILIES = [(re.compile(r"mozi\.[ma]\b|/mozi\b", re.I), "Mozi (P2P botnet)"),
                 (re.compile(r"xmrig|kdevtmpfsi|kinsing", re.I), "Crypto miner"),
                 (re.compile(r"redtail", re.I), "RedTail (miner)"),
                 (re.compile(r"mirai", re.I), "Mirai"),
                 (re.compile(r"gafgyt|bashlite", re.I), "Gafgyt / Bashlite"),
                 (re.compile(r"(^|/)(bins|wget|curl|t8UsA|ohshit|8UsA)\.sh\b", re.I), "Dropper script"),
                 (re.compile(r"authorized_keys", re.I), "SSH key backdoor")]


def name_family(names):
    for rx, fam in NAME_FAMILIES:
        if rx.search(names or ""):
            return fam
    return ""


def file_family(f, names=""):
    # Best guess, most reliable first: MalwareBazaar's signature, strings in the file, then its name or URL.
    if f is not None:
        try:
            mb = json.loads(f["mb"] or "{}")
        except (ValueError, TypeError, IndexError, KeyError):
            mb = {}
        if mb.get("signature"):
            return mb["signature"], "MalwareBazaar"
        if f["family"]:
            return f["family"], "strings in the file"
    fam = name_family(names)
    return (fam, "file name") if fam else ("", "")


def family_tag(fam, how=""):
    if not fam:
        return ""
    return '<span class="tag t-red" title="Looks like %s%s">%s</span>' % (esc(fam), (" (from %s)" % esc(how)) if how else "", esc(fam))


def mb_lookup(con, limit=4):
    # Ask MalwareBazaar about files we have not asked about yet (or not found a week ago). Only the hash leaves Huginn.
    if not MB_KEY:
        return 0
    rows = con.execute("SELECT sha FROM files WHERE mb_checked IS NULL OR (mb LIKE '%\"found\": false%' AND mb_checked < ?) "
                       "ORDER BY mtime DESC LIMIT ?", (time.time() - 7 * 86400, limit)).fetchall()
    done = 0
    for (sha,) in rows:
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode(),
                                     headers={"Auth-Key": MB_KEY, "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                d = json.loads(r.read(2 * 1024 * 1024))
        except Exception:
            break
        if d.get("query_status") == "ok" and d.get("data"):
            x = d["data"][0]
            mb = {"found": True, "signature": str(x.get("signature") or "")[:60],
                  "tags": [str(t)[:30] for t in (x.get("tags") or [])][:8], "first_seen": str(x.get("first_seen") or "")[:20]}
        elif d.get("query_status") in ("hash_not_found", "no_results"):
            mb = {"found": False}
        else:
            break                                    # bad key, rate limit, ...: try again later
        with con:
            con.execute("UPDATE files SET mb=?, mb_checked=? WHERE sha=?", (json.dumps(mb), time.time(), sha))
        done += 1
    return done


def tty_path(sha):
    return os.path.join(TTY_DIR, sha + ".gz")


def tty_cached(sha):
    for p, opener in ((tty_path(sha), gzip.open), (os.path.join(TTY_DIR, sha), open)):
        if os.path.exists(p):
            try:
                with opener(p, "rb") as fh:
                    return fh.read()
            except (OSError, EOFError, zlib.error):      # damaged copy: fetch it again
                return None
    return None


def tty_store(sha, data):
    # Recordings are kept here for good (gzip, they shrink a lot), so the honeypot may delete its old ones.
    tmp = "%s.%d.%d.tmp" % (tty_path(sha), os.getpid(), threading.get_ident())      # one per writer: two may store the same one
    try:
        with gzip.open(tmp, "wb", compresslevel=6) as fh:
            fh.write(data)
        os.replace(tmp, tty_path(sha))
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def hp_ssh(command):
    return ["ssh", "-T", "-i", HP_KEY, "-p", str(HP_PORT), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + HP_KNOWN,
            "root@" + HP_HOST, command]


def tty_decode(b64):
    try:
        data = base64.b64decode(b64.strip(), validate=True)
    except Exception:
        return None
    # Cowrie's "shasum" for tty logs is not the sha256 of the content (verified 2026-11-04), so only a sanity check.
    return data if data and len(data) <= 50 * 1024 * 1024 else None


def fetch_tty(sha):
    # One session recording: from the local cache, else through the same locked key ("tty <sha>").
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        return None
    data = tty_cached(sha)
    if data is not None:
        return data
    rc, out, _err = run_capped(hp_ssh("tty " + sha), 60, MAX_TTY * 4 // 3 + 16)
    if rc != 0:
        return None
    data = tty_decode(out)
    if data:
        tty_store(sha, data)
    return data


_tty_missing = {}


def prefetch_tty(con, batch=40, budget=40):
    # Copy new recordings to Huginn in the background (newest first), many per SSH call, so replays keep working
    # after the honeypot has cleaned up its own copies. Recordings the honeypot no longer has are retried once a day.
    t0, done = time.time(), 0
    rows = con.execute("SELECT DISTINCT tty FROM sessions WHERE tty IS NOT NULL ORDER BY start DESC").fetchall()
    recent_miss = {k for k, v in _tty_missing.items() if v > time.time() - 86400}
    todo = [r[0] for r in rows if re.fullmatch(r"[0-9a-f]{64}", r[0] or "") and r[0] not in recent_miss
            and not os.path.exists(tty_path(r[0])) and not os.path.exists(os.path.join(TTY_DIR, r[0]))]
    while todo and time.time() - t0 < budget:
        chunk, todo = todo[:batch], todo[batch:]
        rc, out, _err = run_capped(hp_ssh("tty " + " ".join(chunk)), 120, 64 * 1024 * 1024)
        if rc != 0:
            break
        if isinstance(out, bytes):
            out = out.decode("ascii", "replace")
        got = {}
        if len(chunk) == 1:
            got[chunk[0]] = out.strip()
        else:
            for line in out.splitlines():
                sha, _, b64 = line.partition(" ")
                if sha in chunk:
                    got[sha] = b64
        for sha in chunk:
            data = tty_decode(got.get(sha, "")) if got.get(sha, "-") != "-" else None
            if data:
                tty_store(sha, data)
                done += 1
            else:
                _tty_missing[sha] = time.time()
        if len(chunk) > 1 and not got:
            break                    # an older hp-export that only takes one recording per call: fetch on demand instead
    return done


def tty_frames(data):
    # Cowrie ttylog: records with header "<iLiiLL" (op, tty, length, direction, sec, usec) + data. Direction 2 = output, 3 = exec.
    import struct as _st
    hs = _st.calcsize("<iLiiLL")
    frames, i, t0 = [], 0, None
    while i + hs <= len(data):
        op, _tty, ln, d, sec, usec = _st.unpack("<iLiiLL", data[i:i + hs])
        i += hs
        if op == 3 and (ln < 0 or i + ln > len(data)):
            break                # a broken record: a negative length would loop for ever
        chunk = data[i:i + ln] if op == 3 else b""
        i += ln if op == 3 else 0
        t = sec + usec / 1e6
        if t0 is None:
            t0 = t
        if op == 3 and d in (2, 3) and chunk:
            frames.append([round(t - t0, 3), chunk.decode("utf-8", "replace")])
        if len(frames) > 20000:
            break
    return frames


def fetch_export():
    if not HP_HOST:
        raise RuntimeError("HUGINN_HP_HOST is not set")
    cmd = ["ssh", "-T", "-i", HP_KEY, "-p", str(HP_PORT),
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=15",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + HP_KNOWN,
           "-o", "ServerAliveInterval=15", "root@" + HP_HOST]
    rc, raw, err = run_capped(cmd, 240, MAX_EXPORT)
    out = raw.decode("utf-8", "replace")
    if rc != 0 or out.rstrip().rsplit("\n", 1)[-1] != "##END":   # the last line, so logged attacker text cannot pass for it
        raise RuntimeError("export failed (rc=%s): %s" % (rc, err.decode("utf-8", "replace")[-300:].strip()))
    return out


def run_capped(cmd, timeout, limit):
    # Like subprocess.run(capture_output=True) but stops reading (and kills ssh) after `limit` bytes.
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    errbuf = bytearray()

    def drain_stderr():
        # Read stderr all the time (keep the first 64 KB): a full pipe would block the child until the timeout.
        while True:
            b = p.stderr.read(1 << 16)
            if not b:
                return
            if len(errbuf) < 65536:
                errbuf.extend(b[:65536 - len(errbuf)])

    drainer = threading.Thread(target=drain_stderr, daemon=True)
    drainer.start()
    try:
        chunks, total = [], 0
        while True:
            b = p.stdout.read(1 << 20)
            if not b:
                break
            total += len(b)
            if total > limit:
                p.kill()
                p.wait()
                return 1, b"", b"output larger than %d MB, refused" % (limit // 1048576)
            chunks.append(b)
        rc = p.wait()
        drainer.join(5)
        return rc, b"".join(chunks), bytes(errbuf)
    finally:
        timer.cancel()
        p.stdout.close()


# ---------------------------------------------------------------- aggregation

def recompute_session(con, sid):
    rows = con.execute("SELECT ts,ip,kind,a,b FROM events WHERE session=? ORDER BY ts,rowid", (sid,)).fetchall()
    if not rows:
        con.execute("DELETE FROM sessions WHERE session=?", (sid,))
        return
    ip, start, end = rows[0]["ip"], rows[0]["ts"], rows[-1]["ts"]
    proto = port = version = hassh = dur = tty = termsize = None
    lo = lf = c = f = t = x = 0
    cmds = []
    for r in rows:
        k, a = r["kind"], r["a"]
        if k == "connect":
            proto = a
            b = r["b"] or ""
            port = int(b) if b.isascii() and b.isdigit() and len(b) <= 5 else None
        elif k == "login_ok":
            lo += 1
        elif k == "login_fail":
            lf += 1
        elif k == "cmd":
            c += 1
            cmds.append(a or "")
        elif k in ("file", "file_fail"):
            f += 1
        elif k == "tcpip":
            t += 1
        elif k == "exploit":
            x += 1
        elif k == "version":
            version = a
        elif k == "hassh":
            hassh = a
        elif k == "tty":
            tty = a
        elif k == "termsize":
            termsize = a
        elif k == "closed":
            dur = float(a) if sane_duration(a) is not None else dur
    if proto is None and port is None and version:
        proto = "ssh"
    cmdhash = script_hash(cmds)
    con.execute("INSERT OR REPLACE INTO sessions(session,ip,start,end,proto,port,version,hassh,duration,logins_ok,"
                "logins_fail,cmds,files,tcpip,exploits,cmdhash,tty,termsize) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, ip, start, end, proto, port, version, hassh, dur, lo, lf, c, f, t, x, cmdhash, tty, termsize))


def bait_flags(rows):
    took = read = False
    for kind, a, b in rows:
        txt = (a or "") + "\x00" + (b or "")
        if BAIT and any(x in txt for x in BAIT):
            took = True
        if kind == "cmd" and BAIT_FILES_RE.search(a or ""):
            read = True
        if took and read:
            break
    return took, read


# SSHole (CVE-2026-123158): musl's crypt() rejects passwords over 256 bytes, which sshd up to 10.6p1 could take for a match.
# Only SSH sessions count: telnet bots paste whole shell scripts into the login prompt, which would be false alarms.
SSHOLE_MIN, SSHOLE_MAX = 257, 1024
SSHOLE_SQL = ("e.kind IN ('login_ok','login_fail') AND length(CAST(e.b AS BLOB)) BETWEEN %d AND %d "
              "AND EXISTS(SELECT 1 FROM sessions s WHERE s.session=e.session AND s.proto='ssh')" % (SSHOLE_MIN, SSHOLE_MAX))


def sshole_password(proto, password):
    return proto == "ssh" and SSHOLE_MIN <= len((password or "").encode("utf-8", "surrogatepass")) <= SSHOLE_MAX


def score_parts(sess, lo, lf, cmds, files, tcpip, expl, csvcs, took=False, read=False, sshole=False, web=""):
    # The one place that defines the score: (label, points), zero points left out. web: "exploit", "probe" and/or "robots".
    parts = [("seen", 1), ("SSHole probe", 10 if sshole else 0), ("took bait", 20 if took else 0), ("read bait", 5 if read else 0),
             ("web exploit", 8 if "exploit" in web else 0), ("web probe", 3 if "probe" in web and "exploit" not in web else 0),
             ("robots.txt trap", 5 if "robots" in web else 0),
             ("login attempts", 2 if lo + lf else 0), ("brute force", 2 if lo + lf >= 10 else 0), ("commands", min(10, cmds // 2)),
             ("files", 15 if files else 0), ("proxy", 10 if tcpip else 0), ("exploit", 10 if expl else 0),
             ("decoy services", 3 * len(csvcs)), ("repeat visits", min(5, sess // 20))]
    return [(k, v) for k, v in parts if v]


# The same scoring in words, for the Blocklist page. tests/test_polish.py checks that every part of score_parts is named here.
SCORE_HELP = ("1 seen, +2 login attempts, +2 brute force (10 or more), +½ per command (max 10), +15 files, +10 proxy, +10 exploit, "
              "+10 SSHole probe, +20 took bait, +5 read bait, +8 web exploit, +3 web probe, +5 robots.txt trap, "
              "+3 per decoy service, +1 per 20 repeat visits (max 5).")


def score_and_tags(sess, lo, lf, cmds, files, tcpip, expl, csvcs, tarpit_s, protos, took=False, read=False, sshole=False, web=""):
    s = sum(v for _k, v in score_parts(sess, lo, lf, cmds, files, tcpip, expl, csvcs, took, read, sshole, web))
    tags = []
    if took:
        tags.append("took-bait")
    if read:
        tags.append("read-bait")
    if lo + lf >= 10:
        tags.append("bruteforce")
    if cmds:
        tags.append("shell")
    if files:
        tags.append("dropper")
    if tcpip:
        tags.append("proxy")
    if expl:
        tags.append("exploit")
    if sshole:
        tags.append("sshole-probe")
    if "exploit" in web:
        tags.append("web-exploit")
    elif "probe" in web:
        tags.append("web-probe")
    if "robots" in web:
        tags.append("robots-trap")
    if len(set(protos) | set(csvcs)) >= 2:
        tags.append("multi-service")
    if tarpit_s >= 60:
        tags.append("tarpitted")
    return s, ",".join(tags)


def recompute_ip(con, ip):
    s = con.execute("SELECT COUNT(*) n, MIN(start) f, MAX(end) l, COALESCE(SUM(logins_ok),0) lo, "
                    "COALESCE(SUM(logins_fail),0) lf, COALESCE(SUM(cmds),0) c, COALESCE(SUM(files),0) fi, "
                    "COALESCE(SUM(tcpip),0) t, COALESCE(SUM(exploits),0) x, GROUP_CONCAT(DISTINCT proto) p "
                    "FROM sessions WHERE ip=?", (ip,)).fetchone()
    c = con.execute("SELECT COUNT(*) n, MIN(ts) f, MAX(ts) l, GROUP_CONCAT(DISTINCT a) svcs "
                    "FROM events WHERE ip=? AND kind='canary'", (ip,)).fetchone()
    t = con.execute("SELECT COUNT(*) n, MIN(ts) f, MAX(ts) l, COALESCE(SUM(CAST(a AS REAL)),0) secs "
                    "FROM events WHERE ip=? AND kind='tarpit'", (ip,)).fetchone()
    cp = con.execute("SELECT COALESCE(SUM(dropped),0), MAX(CASE WHEN dropped>0 THEN upto END) FROM capped WHERE ip=?", (ip,)).fetchone()
    firsts = [v for v in (s["f"], c["f"], t["f"]) if v is not None]
    lasts = [v for v in (s["l"], c["l"], t["l"], cp[1]) if v is not None]
    if not firsts:
        con.execute("DELETE FROM ips WHERE ip=?", (ip,))
        return
    protos = [p for p in (s["p"] or "").split(",") if p]
    if t["n"]:
        protos.append("ssh-tarpit")
    csvcs = sorted({x for x in (c["svcs"] or "").split(",") if x})
    took, read = bait_flags(con.execute("SELECT kind,a,b FROM events WHERE ip=? AND kind IN ('cmd','login_ok','login_fail','canary')", (ip,)).fetchall())
    sshole = con.execute("SELECT 1 FROM events e WHERE e.ip=? AND %s LIMIT 1" % SSHOLE_SQL, (ip,)).fetchone() is not None
    w = con.execute("SELECT MAX(level='exploit'), MAX(level='probe'), MAX(robots), MAX(reply IN (%s)) FROM webhits WHERE ip=?"
                    % ",".join("'%s'" % x for x in sorted(WEB_BAIT_REPLIES)), (ip,)).fetchone()
    web = " ".join(k for k, v in zip(("exploit", "probe", "robots"), w[:3]) if v)
    read = read or bool(w[3])
    score, tags = score_and_tags(s["n"], s["lo"], s["lf"], s["c"], s["fi"], s["t"], s["x"], csvcs, t["secs"], protos, took, read, sshole, web)
    con.execute("INSERT OR REPLACE INTO ips VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ip, min(firsts), max(lasts), s["n"], s["lo"], s["lf"], s["c"], s["fi"], s["t"], s["x"],
                 c["n"] + cp[0], ",".join(csvcs), t["secs"], ",".join(sorted(set(protos))), score, tags))


def retry_seen(con):
    # Nothing new in this export. A failed update of New is finished here, or it would wait for the next new log line.
    done = get_meta(con, "seen_rowid")
    if not done or not done.isdigit() or int(done) >= con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0]:
        return
    try:
        note_seen(con, None)
    except Exception as e:
        if con.in_transaction:
            con.rollback()
        set_meta(con, "last_seen_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))


def store(con, rows):
    if not rows:
        retry_seen(con)
        return 0
    before = con.total_changes
    # New works from a saved position, so lines from a failed update are picked up by the next one. No position yet (first
    # run after an upgrade), or one above the highest rowid (rows deleted, rowids may be reused): start from here. Saved in
    # the same transaction as the events, so a crash in between cannot lose them, and decided under the write lock, so
    # another writer cannot have moved it in the meantime.
    sess = {r[5] for r in rows if r[5]}
    ips = {r[2] for r in rows}
    # One transaction: events and their totals are saved together. One bad session or IP must not stop the whole sync.
    with con:
        con.execute("BEGIN IMMEDIATE")
        top = con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0]
        done = get_meta(con, "seen_rowid")
        if not done or not done.isdigit() or int(done) > top:
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('seen_rowid',?)", (str(top),))
        rows = cap_rows(con, rows)
        before = con.total_changes
        con.executemany("INSERT OR IGNORE INTO events(h,ts,ip,src,kind,session,a,b) VALUES(?,?,?,?,?,?,?,?)", rows)
        inserted = con.total_changes - before
        for fn, keys in ((recompute_session, sess), (recompute_ip, ips)):
            for k in keys:
                try:
                    fn(con, k)
                except (ValueError, TypeError, OverflowError, sqlite3.Error) as e:
                    sys.stderr.write("recompute %s: %r\n" % (k, e))
    try:
        note_seen(con, None)
    except Exception as e:                 # never let the "New" page get in the way of collecting data
        if con.in_transaction:
            con.rollback()
        set_meta(con, "last_seen_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
    return inserted


def utc_day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def cap_rows(con, rows):
    # Decoy events beyond DECOY_CAP per IP, service and day are counted in `capped`, not stored. The export sends the newest
    # lines again on every sync, so each (IP, service, day) remembers the last time it handled (`upto`): older or equal rows
    # were stored then or counted then, and are skipped now. Inside store()'s transaction, so the count and the rows agree.
    if DECOY_CAP <= 0:
        return rows
    out, state, dirty = [], {}, set()
    for r in rows:
        if r[4] != "canary":
            out.append(r)
            continue
        key = (r[2], r[6] or "", utc_day(r[1]))
        st = state.get(key)
        if st is None:
            got = con.execute("SELECT kept, dropped, upto FROM capped WHERE ip=? AND svc=? AND day=?", key).fetchone()
            st = state[key] = [got[0], got[1], got[2]] if got else [0, 0, 0.0]
        if r[1] <= st[2]:
            continue
        st[2] = r[1]
        if st[0] < DECOY_CAP:
            st[0] += 1
            out.append(r)
        else:
            st[1] += 1
        dirty.add(key)
    con.executemany("INSERT OR REPLACE INTO capped(ip, svc, day, kept, dropped, upto) VALUES(?,?,?,?,?,?)",
                    [key + tuple(state[key]) for key in dirty])
    return out


def trim_decoys(con):
    # One time (0.28): bring the history under DECOY_CAP and set up `capped` for the days the export can still send again.
    now = time.time()
    touched = set()
    with con:
        con.execute("BEGIN IMMEDIATE")
        groups = con.execute("SELECT ip, COALESCE(a,'') svc, CAST(ts / 86400 AS INTEGER) d, COUNT(*) n, MAX(ts) u FROM events "
                             "WHERE kind='canary' GROUP BY ip, svc, d HAVING n > ? OR MAX(ts) >= ?", (DECOY_CAP, now - 14 * 86400)).fetchall()
        for ip, svc, d, n, u in groups:
            if n > DECOY_CAP:
                con.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE ip=? AND kind='canary' AND COALESCE(a,'')=? "
                            "AND ts>=? AND ts<? ORDER BY ts LIMIT -1 OFFSET ?)", (ip, svc, d * 86400, (d + 1) * 86400, DECOY_CAP))
                touched.add(ip)
            con.execute("INSERT OR REPLACE INTO capped(ip, svc, day, kept, dropped, upto) VALUES(?,?,?,?,?,?)",
                        (ip, svc, utc_day(d * 86400), min(n, DECOY_CAP), max(0, n - DECOY_CAP), u))
        if touched:
            con.execute("DELETE FROM webhits WHERE h NOT IN (SELECT h FROM events)")
            con.execute("DELETE FROM mails WHERE h NOT IN (SELECT h FROM events)")
        for ip in touched:
            recompute_ip(con, ip)
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('decoy_cap_v1','1')")
    return len(touched)


def note_size(con):
    # Once a day: how big the data folder is (database, WAL, backups, recordings), for the growth forecast on Account.
    day = utc_day(time.time())
    try:
        hist = json.loads(get_meta(con, "data_sizes", "[]"))
        hist = [h for h in hist if isinstance(h, list) and len(h) == 2 and isinstance(h[0], str) and isinstance(h[1], int)]
    except ValueError:
        hist = []
    if hist and hist[-1][0] == day:
        return
    total = 0
    for root, _dirs, files in os.walk(DATA):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    set_meta(con, "data_sizes", json.dumps((hist + [[day, total]])[-60:]))


def growth_note(con):
    # "X GB free · grows about Y MB a day · full in about Z days", from the daily sizes of the last two weeks.
    try:
        hist = json.loads(get_meta(con, "data_sizes", "[]"))[-15:]
    except ValueError:
        hist = []
    st = os.statvfs(DATA)
    free = st.f_bavail * st.f_frsize
    out = "%.1f GB free on the data disk" % (free / 1073741824)
    if len(hist) >= 3:
        days = (time.mktime(time.strptime(hist[-1][0], "%Y-%m-%d")) - time.mktime(time.strptime(hist[0][0], "%Y-%m-%d"))) / 86400
        per_day = (hist[-1][1] - hist[0][1]) / days if days > 0 else 0
        if per_day > 0:
            out += " · the data folder grows about %.1f MB a day · full in about %s days" % (per_day / 1048576, num(int(free / per_day)))
        else:
            out += " · the data folder has not grown in the last %d days" % int(days)
    else:
        out += " · growth is measured once a day; a forecast after three days"
    return out


def retention(con):
    with con:
        con.execute("DELETE FROM logins WHERE expires < ?", (time.time(),))
        # Cap state is only needed while the export can send a day again; the rows that dropped something stay as the count.
        con.execute("DELETE FROM capped WHERE dropped=0 AND day < ?", (utc_day(time.time() - 14 * 86400),))
    if RETENTION_DAYS == 0:          # keep the whole history
        con.execute("PRAGMA optimize")
        return
    cutoff = time.time() - RETENTION_DAYS * 86400
    with con:
        old_ips = [r[0] for r in con.execute("SELECT ip FROM ips WHERE first < ?", (cutoff,))]
        touched = [r[0] for r in con.execute("SELECT DISTINCT session FROM events WHERE ts < ? AND session IS NOT NULL", (cutoff,))]
        con.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        con.execute("DELETE FROM mails WHERE h NOT IN (SELECT h FROM events)")
        con.execute("DELETE FROM webhits WHERE h NOT IN (SELECT h FROM events)")
        con.execute("DELETE FROM sessions WHERE end < ?", (cutoff,))
        con.execute("DELETE FROM logins WHERE expires < ?", (time.time(),))
        for sid in touched:              # a session across the limit keeps only its newer events: count again
            recompute_session(con, sid)
        for ip in old_ips:
            recompute_ip(con, ip)
    con.execute("PRAGMA optimize")


# ---------------------------------------------------------------- first sightings ("New" page)

def _blob(m):
    s = m.group(0)
    return "<blob>" if re.search(r"[0-9]", s) and re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) else s


# An IPv6 candidate: a run of hex digits and colons with at least two colons. The lookahead cannot overlap the run it
# guards (no colon in its hex classes), so this stays linear. Three "*" over the same characters took minutes on one line.
V6_TOKEN = r"(?<![\w:.])(?=[0-9a-fA-F]*:[0-9a-fA-F]*:)[0-9a-fA-F:]+(?![\w:.])"


def _v6(m):
    try:
        ipaddress.IPv6Address(m.group(0))
    except ValueError:                  # a clock time, a MAC, an odd word
        return m.group(0)
    return "<ip>"


def cmd_shape(s):
    # Same command with other addresses, numbers or payloads = same shape. Order matters: numbers go last.
    s = re.sub(r"(\\x[0-9a-fA-F]{2})+", "<bytes>", (s or "").strip()[:2000])
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(V6_TOKEN, _v6, s)
    s = re.sub(r"(?<![0-9a-zA-Z])[0-9a-fA-F]{8,}(?![0-9a-zA-Z])", "<hex>", s.replace("_", "_ ")).replace("_ ", "_")    # also inside check_1f3a...
    s = re.sub(r"(?<![\w+/])[A-Za-z0-9+/]{24,}={0,2}(?![\w+/])", _blob, s)      # needs digits and both cases, so paths survive
    s = re.sub(r"\d+", "<n>", s)
    return re.sub(r"\s+", " ", s)[:300]


def pw_shape(p):
    # A = capitals, a = lower case, 0 = digits, # = anything else; runs collapsed. "Summer2026!" is Aa0#.
    out = []
    for c in (p or "")[:64]:
        k = "A" if "A" <= c <= "Z" else "a" if "a" <= c <= "z" else "0" if "0" <= c <= "9" else "#"
        if not out or out[-1] != k:
            out.append(k)
    return "".join(out)


def script_hash(cmds):
    # The same list of commands, in shapes: one script, one campaign. None when there is nothing to compare.
    if not any(cmds):
        return None
    return hashlib.sha1("\n".join(cmd_shape(c) for c in cmds).encode("utf-8", "replace")).hexdigest()[:16]


def session_commands(con, sid):
    return [x[0] or "" for x in con.execute("SELECT a FROM events WHERE session=? AND kind='cmd' ORDER BY ts,rowid", (sid,))]


def note_seen(con, after=None):
    # Remembers when Huginn first saw each thing. Time of arrival, not of the log line, so late or imported lines are
    # never missed, and the list survives retention. Position and results are read and written in one transaction, so two
    # writers (the sync and an import) cannot count the same lines. The very first run reads the whole history and dates it
    # by its log times.
    con.execute("BEGIN IMMEDIATE")
    try:
        _note_seen(con, after)
        con.commit()
    except Exception:
        con.rollback()
        raise


def _note_seen(con, after):
    first, now = get_meta(con, "seen_done") is None, time.time()
    if after is None:
        v = get_meta(con, "seen_rowid")
        after = int(v) if v and v.isdigit() else 0
    after = 0 if first else after
    upto = con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0]
    got = {}
    for rid, ts, ip, sess, kind, a, b in con.execute("SELECT rowid,ts,ip,session,kind,a,b FROM events WHERE rowid>? AND rowid<=? AND "
                                                     "kind IN ('cmd','file','login_ok','login_fail','closed') ORDER BY rowid", (after, upto)):
        if kind == "closed":                # a finished session: its whole command list, in shapes, is one script
            cmds = session_commands(con, sess)
            k, key, ex = "script", script_hash(cmds), next((c for c in cmds if c), "")
        else:
            k, key, ex = ("cmd", cmd_shape(a), a) if kind == "cmd" else ("file", b, a) if kind == "file" else ("pw", pw_shape(b), b)
        if not key:
            continue
        g = got.get((k, key))
        if g:
            g[4] += 1
            if first and ts < g[0]:         # imports are not in time order: keep the earliest sighting
                g[:4] = [ts, ip, sess, clean(ex or "", 300)]
        else:
            got[(k, key)] = [ts if first else now, ip, sess, clean(ex or "", 300), 1]
    con.executemany("INSERT INTO seen(kind,key,observed,ip,session,ex,n) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(kind,key) DO UPDATE SET n=n+excluded.n", [(k[0], k[1], *v) for k, v in got.items()])
    con.execute("INSERT OR IGNORE INTO seen(kind,key,observed,ip,session,ex,n) SELECT 'hassh',hassh,CASE WHEN ? THEN MIN(start) ELSE ? END,"
                "ip,session,version,1 FROM sessions WHERE hassh IS NOT NULL GROUP BY hassh", (first, now))
    con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('seen_done','1')")
    con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('seen_rowid',?)", (str(upto),))
    con.execute("DELETE FROM meta WHERE k='last_seen_error'")


def review_at(con):
    try:
        v = float(get_meta(con, "review_at") or 0)
    except ValueError:
        return 0
    return v if 0 < v < float("inf") else 0


def review_since(con):
    return review_at(con) or time.time() - 7 * 86400


def mark_reviewed(con, at):
    # Only ever forwards, and never past what was on the page: an old tab or a double click changes nothing.
    con.execute("BEGIN IMMEDIATE")
    try:
        cur = review_at(con)
        top = con.execute("SELECT MAX(observed) FROM seen").fetchone()[0]
        if top is not None and cur < at <= top:
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('review_prev',?)", (repr(cur) if cur else "",))
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('review_at',?)", (repr(at),))
        con.commit()
    except Exception:
        con.rollback()
        raise


def undo_review(con):
    con.execute("BEGIN IMMEDIATE")
    try:
        prev = get_meta(con, "review_prev")
        if prev is not None:
            if prev:
                con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('review_at',?)", (prev,))
            else:
                con.execute("DELETE FROM meta WHERE k='review_at'")
            con.execute("DELETE FROM meta WHERE k='review_prev'")
        con.commit()
    except Exception:
        con.rollback()
        raise


# ---------------------------------------------------------------- background threads

GAP_MIN = max(600, POLL * 5)


# Collection health (0.29): is data still coming in, per source? "Quiet" is measured against each source's own longest
# silence in the last week, so a tarpit that is often idle for hours does not raise an alarm that a busy SSH port would.
HEALTH_SYNC_LATE = max(1800, POLL * 6)


def health_sources(con, now=None):
    # {key: newest time}: OpenCanary, hp-traps and endlessh from events, Cowrie per listening port from sessions (last 2 days).
    now = now or time.time()
    out = {}
    for src, last in con.execute("SELECT src, MAX(ts) FROM events WHERE ts>=? AND src IN ('canary','traps','endlessh') GROUP BY src", (now - 2 * 86400,)):
        out[src] = last
    for port, last in con.execute("SELECT port, MAX(start) FROM sessions WHERE start>=? AND port IS NOT NULL GROUP BY port", (now - 2 * 86400,)):
        out["cowrie:%s" % port] = last
    return out


def health_label(key):
    if key == "sync":
        return "Honeypot sync"
    if key.startswith("prot:"):
        return protection_label(key[5:])
    if key.startswith("cowrie:"):
        port = key.split(":", 1)[1]
        name = PERSONA.get(int(port)) if port.isdigit() else None
        return "Cowrie port %s%s" % (port, " (%s)" % name if name else "")
    return {"canary": "OpenCanary", "traps": "hp-traps", "endlessh": "endlessh tarpit"}.get(key, key)


def health_limits(con):
    # Once a day: 2.5 x each source's longest silence in the last 7 days, at least 2 hours, at most 2 days.
    day = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        cached = json.loads(get_meta(con, "health_limits", "{}"))
        if cached.get("day") == day and isinstance(cached.get("lim"), dict):
            return cached["lim"]
    except ValueError:
        pass
    since = time.time() - 7 * 86400
    lim = {}
    q = ("SELECT COUNT(*), MAX(t - p) FROM (SELECT t, LAG(t) OVER (ORDER BY t) p FROM (%s))")
    for src in ("canary", "traps", "endlessh"):
        n, gap = con.execute(q % "SELECT ts t FROM events WHERE src=? AND ts>=?", (src, since)).fetchone()
        if n >= 20 and gap:
            lim[src] = min(2 * 86400, max(7200, 2.5 * gap))
    for (port,) in con.execute("SELECT DISTINCT port FROM sessions WHERE start>=? AND port IS NOT NULL", (since,)).fetchall():
        n, gap = con.execute(q % "SELECT start t FROM sessions WHERE port=? AND start>=?", (port, since)).fetchone()
        if n >= 20 and gap:
            lim["cowrie:%s" % port] = min(2 * 86400, max(7200, 2.5 * gap))
    set_meta(con, "health_limits", json.dumps({"day": day, "lim": lim}))
    return lim


def health_check(con, now=None):
    # Problems now, alerted once each by ntfy, and "back to normal" when they go away. Saved for Account and /healthz.
    now = now or time.time()
    issues = {}
    last = float(get_meta(con, "last_success", "0") or 0)
    if last and now - last > HEALTH_SYNC_LATE:
        err = (get_meta(con, "last_error", "") or "").strip()
        issues["sync"] = "No data from the honeypot for %s%s" % (dur(now - last), ("; last error: " + err[:120]) if err else "")
    else:
        lim = health_limits(con)
        for key, newest in health_sources(con, now).items():
            if key in lim and now - newest > lim[key]:
                issues[key] = "%s quiet for %s (longer than any time last week)" % (health_label(key), dur(now - newest))
    for k in protection_missing(con):                  # one key each: a second loss later alerts again
        issues["prot:" + k] = "Missing on the honeypot: " + protection_label(k)
    try:
        alerted = json.loads(get_meta(con, "health_alerted", "{}"))
        alerted = alerted if isinstance(alerted, dict) else {}
    except ValueError:
        alerted = {}
    new = sorted(k for k in issues if k not in alerted)
    back = sorted(k for k in alerted if k not in issues)
    if NTFY_URL and settings(con)["notify"]:
        if new:
            ntfy_post("\n".join(issues[k] for k in new), "Huginn: collection problem", 4)
        if back:
            ntfy_post("Back to normal: " + ", ".join(health_label(k) for k in back), "Huginn: collection is back", 2)
    set_meta(con, "health_alerted", json.dumps({k: alerted.get(k, now) for k in issues}))
    set_meta(con, "health_now", json.dumps(issues))
    return issues


def protection_status(con):
    # (items, time) from the last export that had a ##STATUS section, or (None, 0) from an older honeypot.
    try:
        st = json.loads(get_meta(con, "hp_status", "{}"))
        items = st.get("items")
        return (items if isinstance(items, dict) else None), float(st.get("at") or 0)
    except (ValueError, TypeError, AttributeError):
        return None, 0


def protection_missing(con):
    items, at = protection_status(con)
    if not items or time.time() - at > 3600:          # nothing reported recently: the sync check covers that
        return []
    return sorted(k for k, ok in items.items() if not ok)


def protection_label(key):
    what, _, name = key.partition(":")
    return {"sandbox": "%s sandbox", "limits": "%s memory/file limits", "running": "%s not running", "patch": "%s patch"}.get(what, "%s") % name


def protection_note(con):
    items, at = protection_status(con)
    if items is None:
        return "not reported (update the honeypot: update-honeypot.sh)"
    missing = protection_missing(con)
    kinds = lambda w: sum(1 for k in items if k.startswith(w + ":"))
    ok = "sandbox and limits on %d services, %d patches" % (kinds("sandbox"), kinds("patch"))
    if missing:
        return '<span class="err">missing: %s</span> · reported %s' % (esc(", ".join(protection_label(k) for k in missing)), esc(ago(at)))
    return "all in place: %s · reported %s" % (esc(ok), esc(ago(at)))


def health_note(con):
    # One line for Account: every source with its newest data, problems first.
    try:
        issues = json.loads(get_meta(con, "health_now", "{}"))
    except ValueError:
        issues = {}
    now = time.time()
    parts = ['<span class="err">%s</span>' % esc(v) for v in issues.values()]
    parts += ["%s %s" % (esc(health_label(k)), esc(ago(t))) for k, t in sorted(health_sources(con, now).items()) if k not in issues]
    return " · ".join(parts) or "no data in the last 2 days"


def note_sync(con, t0):
    # A long time since the last good sync is a gap, whatever the reason (honeypot away, Huginn stopped). Measured from
    # the end of the last good sync to the start of this one, so a slow export is no gap. No earlier sync known: no gap.
    prev = get_meta(con, "last_success")
    with con:
        if prev and t0 - float(prev) >= GAP_MIN:
            con.execute("INSERT OR IGNORE INTO gaps(start,end) VALUES(?,?)", (float(prev), t0))
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('last_success',?)", (repr(time.time()),))


def gap_spans(con, since):
    # One statement, one snapshot: a sync finishing in between must not make a gap vanish or count twice.
    rows = con.execute("SELECT start,end FROM gaps WHERE end>? UNION ALL SELECT CAST(v AS REAL),NULL FROM meta WHERE k='last_success' ORDER BY 1", (since,)).fetchall()
    spans, now = [(r[0], r[1]) for r in rows if r[1] is not None], time.time()
    last = next((r[0] for r in rows if r[1] is None), 0)
    if last and now - last >= GAP_MIN:             # still going on
        spans.append((last, now))
    return spans


def gap_days(con, labels):
    # Seconds without a sync on each local day. Days are cut at local midnight: not every day has 24 hours.
    if not labels:
        return {}
    start = lambda lab: datetime.strptime(lab, "%Y-%m-%d").replace(tzinfo=TZ)
    spans = gap_spans(con, start(labels[0]).timestamp())
    out = {}
    for lab in labels:
        a = start(lab).timestamp()
        b = (start(lab).replace(tzinfo=None) + timedelta(days=1)).replace(tzinfo=TZ).timestamp()
        secs = sum(max(0, min(e, b) - max(s, a)) for s, e in spans)
        if secs >= 60:
            out[lab] = secs
    return out


def gap_note(gaps):
    return '<div class="gap-note"><i></i>No sync for part of the day</div>' if gaps else ""


def collector_loop():
    con = connect()
    skip = set()
    last_ret = 0
    while True:
        t0 = time.time()
        try:
            text = fetch_export()
            rows, hashes = parse_export(text, skip)
            apply_honeypot_meta(con, parse_export.meta)
            n = store(con, rows)
            store_files(con, parse_export.files)
            store_mails(con, parse_export.mails)
            classify_web(con)
            note_sync(con, t0)
            skip = hashes  # only set once everything is stored
            set_meta(con, "last_ingest", t0)
            set_meta(con, "last_ingest_new", n)
            set_meta(con, "last_ingest_secs", round(time.time() - t0, 1))
            set_meta(con, "last_error", "")
            set_meta(con, "last_export_warn", ", ".join(parse_export.meta["warnings"])[:200])
        except Exception as e:
            set_meta(con, "last_error", "%s %s" % (fmt_ts(time.time()), str(e)[:300]))
        try:
            prefetch_tty(con)
            mb_lookup(con)
        except Exception as e:
            set_meta(con, "last_tty_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
        try:
            health_check(con)
        except Exception as e:
            set_meta(con, "last_health_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
        try:
            note_size(con)
            notify(con)
            weekly_digest(con)
            check_update(con)
        except Exception as e:
            set_meta(con, "last_notify_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
        if time.time() - last_ret > 86400:
            try:
                retention(con)
                last_ret = time.time()
            except Exception as e:
                set_meta(con, "last_error", "retention: %s" % e)
        time.sleep(max(10, POLL - (time.time() - t0)))


def vtuple(v):
    try:
        return tuple(int(x) for x in str(v).lstrip("v").split(".")[:3])
    except ValueError:
        return (0,)


def check_update(con):
    if not UPDATE_CHECK or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", REPO):
        return
    if time.time() - float(get_meta(con, "update_checked", "0") or 0) < 86400:
        return
    set_meta(con, "update_checked", time.time())
    try:
        req = urllib.request.Request("https://api.github.com/repos/%s/tags?per_page=50" % REPO,
                                     headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
        tags = json.loads(urllib.request.urlopen(req, timeout=15).read(500000))
        versions = [t.get("name", "") for t in tags if re.fullmatch(r"v?\d+\.\d+\.\d+", t.get("name", ""))]
        latest = max(versions, key=vtuple) if versions else ""
        set_meta(con, "update_latest", latest.lstrip("v"))
        set_meta(con, "update_error", "")
    except Exception as e:  # repo not public yet, offline, rate limited: never a problem, just no notice
        set_meta(con, "update_error", str(e)[:200])


def update_badge(con):
    latest = get_meta(con, "update_latest", "") or ""
    if latest and vtuple(latest) > vtuple(HUGINN_VERSION):
        return ("<a class='upd' href='https://github.com/%s/releases' target='_blank' rel='noopener noreferrer' "
                "title='Update with: git pull && ./update-huginn.sh'>update %s</a>" % (esc(REPO), esc(latest)))
    return ""


def human_gaps(ts):
    # At least three commands and a median pause over two seconds between them: typed, not pasted by a script.
    ts = sorted(ts)
    if len(ts) < 3:
        return False
    gaps = sorted(b - a for a, b in zip(ts, ts[1:]))
    return gaps[len(gaps) // 2] > 2.0


def human_like(con, sid):
    return human_gaps([r[0] for r in con.execute("SELECT ts FROM events WHERE session=? AND kind='cmd' ORDER BY ts", (sid,))])


def notify(con):
    # At most one ntfy summary per hour, only if something notable happened since the last one: bait, new files, human-like sessions, exploits (also web exploits).
    st = settings(con)
    if not NTFY_URL or not st["notify"]:
        return
    ev = set(st["notify_events"])
    now = time.time()
    last = float(get_meta(con, "ntfy_last", "0") or 0)
    if not last:
        set_meta(con, "ntfy_last", now)
        return
    if now - last < NOTIFY_EVERY:
        return
    lines, prio = [], 3
    rows = con.execute("SELECT ip,kind,a,b FROM events WHERE ts>? AND kind IN ('cmd','login_ok','login_fail','canary')", (last,)).fetchall()
    took, read = set(), set()
    for ip, kind, a, b in rows:
        t, r = bait_flags([(kind, a, b)])
        if t:
            took.add(ip)
        if r:
            read.add(ip)
    if "bait" not in ev:
        took, read = set(), set()
    if took:
        prio = 4
        lines.append("Took the bait: " + ", ".join(sorted(took)[:5]) + (" +%d" % (len(took) - 5) if len(took) > 5 else ""))
    if read - took:
        lines.append("Read bait files: %d IP(s)" % len(read - took))
    newf = con.execute("SELECT COUNT(*) FROM (SELECT b, MIN(ts) f FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b) WHERE f>?", (last,)).fetchone()[0]
    if newf and "files" in ev:
        lines.append("New files captured: %d" % newf)
    runs = con.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>? AND kind='exec_sim'", (last,)).fetchone()[0]
    if runs and "files" in ev:
        lines.append("Uploaded programs run (simulated) by %d IP(s)" % runs)
    hum = [r[0] for r in con.execute("SELECT session FROM sessions WHERE start>? AND cmds>=3", (last,)) if human_like(con, r[0])] if "human" in ev else []
    if hum:
        lines.append("Human-like sessions: %d" % len(hum))
    ex = con.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>? AND kind='exploit'", (last,)).fetchone()[0]
    if ex and "exploit" in ev:
        lines.append("Exploit attempts from %d IP(s)" % ex)
    # Web exploits recognised by the Krawl rules (webhits), not only Cowrie's own exploit events. Named by CVE when there is one.
    wx = con.execute("SELECT COUNT(DISTINCT ip) FROM webhits WHERE ts>? AND level='exploit'", (last,)).fetchone()[0]
    if wx and "exploit" in ev:
        cves = sorted({r[0] for r in con.execute("SELECT DISTINCT cve FROM webhits WHERE ts>? AND level='exploit' AND cve!=''", (last,))
                       if re.fullmatch(r"CVE-\d{4}-\d{3,7}", r[0] or "")})
        lines.append("Web exploits from %d IP(s)%s" % (wx, (": " + ", ".join(cves[:4]) + (" +%d" % (len(cves) - 4) if len(cves) > 4 else "")) if cves else ""))
    sshole = con.execute("SELECT COUNT(DISTINCT e.ip) FROM events e WHERE e.ts>? AND %s" % SSHOLE_SQL, (last,)).fetchone()[0]
    if sshole and "exploit" in ev:
        lines.append("SSHole probes from %d IP(s)" % sshole)
    set_meta(con, "ntfy_last", now)
    if not lines:
        return
    ntfy_post("\n".join(lines), "Huginn: honeypot activity", prio)
    set_meta(con, "last_notify", "%s: %s" % (fmt_ts(now), " | ".join(lines))[:500])


_rdns_pool = ThreadPoolExecutor(max_workers=2)


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read(200000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise


def ext_text(v, n=200):
    # Text from outside (ipwho.is, Shodan, the attacker's own reverse DNS): no control characters, bounded length.
    if v is None:
        return None
    v = "".join(c for c in str(v) if c.isprintable())[:n].strip()
    return v or None


def rdns_confirmed(name, ip):
    # Reverse DNS is whatever the owner of the address writes. Only its forward lookup can be trusted to belong to that domain.
    try:
        infos = _rdns_pool.submit(lambda: socket.getaddrinfo(name, None)).result(timeout=4)
    except socket.gaierror:
        return 0
    except Exception:                   # a timeout says nothing either way
        return None
    want = ipaddress.ip_address(ip)
    for info in infos:
        try:
            if ipaddress.ip_address(str(info[4][0]).split("%")[0]) == want:
                return 1
        except ValueError:
            pass
    return 0


def enrich_ip(ip):
    d = {"cc": None, "country": None, "city": None, "asn": None, "org": None, "isp": None, "rdns": None,
         "ports": None, "tags": None, "vulns": None, "hostnames": None, "rdns_ok": None}
    ok = 0
    try:
        j = http_json("https://ipwho.is/%s?fields=success,country,country_code,city,connection" % urllib.parse.quote(ip))
        if j.get("success"):
            conn = j.get("connection") or {}
            cc = str(j.get("country_code") or "").upper()
            asn = str(conn.get("asn") or "")
            d.update(cc=cc if re.fullmatch(r"[A-Z]{2}", cc) else None, country=ext_text(j.get("country"), 60), city=ext_text(j.get("city"), 60),
                     asn=asn if re.fullmatch(r"\d{1,10}", asn) else None, org=ext_text(conn.get("org")), isp=ext_text(conn.get("isp")))
            ok = 1
    except Exception:
        pass
    try:
        j = http_json("https://internetdb.shodan.io/" + urllib.parse.quote(ip))
        lst = lambda k, n, rx: [x for x in (str(v) for v in (j.get(k) or [])[:n]) if re.fullmatch(rx, x)]
        d.update(ports=",".join(lst("ports", 40, r"\d{1,5}")) or None,
                 tags=",".join(lst("tags", 20, r"[A-Za-z0-9_.-]{1,40}")) or None,
                 vulns=",".join(lst("vulns", 40, r"(CVE|cve)-\d{4}-\d{3,7}")) or None,
                 hostnames=",".join(lst("hostnames", 10, r"[A-Za-z0-9_.-]{1,253}")) or None)
        ok = 1
    except Exception:
        pass
    try:
        d["rdns"] = ext_text(_rdns_pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=4), 253)
    except Exception:
        pass
    # Only names count: Shodan's "scanner" tag just means "seen scanning", which every attacker is.
    d["rdns_ok"] = rdns_confirmed(d["rdns"], ip) if d["rdns"] else None
    research = research_flag(d["rdns"], d["org"], d["isp"], d["hostnames"], d["rdns_ok"])
    return d, ok, research


# ---------------------------------------------------------------- database backups
# A checked copy is made first. Old copies go only after that succeeded, so a damaged database never pushes out good ones.

class DatabaseDamaged(Exception):
    pass


def backup_files():
    # Newest first: (name, full path, size).
    try:
        names = sorted((n for n in os.listdir(BACKUP_DIR) if BACKUP_RE.fullmatch(n)), reverse=True)
    except OSError:
        return []
    out = []
    for n in names:
        p = os.path.join(BACKUP_DIR, n)
        try:
            out.append((n, p, os.path.getsize(p)))
        except OSError:
            pass
    return out


def check_copy(path):
    con = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(path), uri=True, timeout=30)
    try:
        return con.execute("PRAGMA quick_check").fetchone()[0]
    finally:
        con.close()


def check_is_huginn(path):
    # quick_check says the file is a sound SQLite database, not that it is ours: an empty one passes too.
    con = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(path), uri=True, timeout=30)
    try:
        # What every version has had. Newer columns are added at start, so an older backup is fine without them.
        need = {"events": {"h", "ts", "ip", "src", "kind", "session", "a", "b"}, "sessions": {"session", "ip", "start"},
                "ips": {"ip", "first", "last", "score", "tags"}, "meta": {"k", "v"}}
        for table, cols in sorted(need.items()):
            have = {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}
            if not have:
                return "not a Huginn database (no table %s)" % table
            if not cols <= have:
                return "not a Huginn database (table %s lacks %s)" % (table, ", ".join(sorted(cols - have)))
        return "ok"
    finally:
        con.close()


def remove_quietly(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def backup_db():
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    # One at a time: the scheduled one and "app.py backup" would otherwise delete each other's work files.
    with open(os.path.join(BACKUP_DIR, ".lock"), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("another backup is running")
        return _backup_db_locked()


def _backup_db_locked():
    size = os.path.getsize(DB_PATH)
    st = os.statvfs(BACKUP_DIR)
    if st.f_bavail * st.f_frsize < size * 2:
        raise RuntimeError("not enough free disk for a copy of the database (%.0f MB)" % (size / 1048576))
    for n in os.listdir(BACKUP_DIR):        # left behind by a crash
        if n.startswith(".tmp-"):
            remove_quietly(os.path.join(BACKUP_DIR, n))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tmp_db, tmp_gz = os.path.join(BACKUP_DIR, ".tmp-%s-%d.db" % (stamp, os.getpid())), os.path.join(BACKUP_DIR, ".tmp-%s-%d.gz" % (stamp, os.getpid()))
    final = os.path.join(BACKUP_DIR, "huginn-%s.db.gz" % stamp)
    try:
        src = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(DB_PATH), uri=True, timeout=30)
        dst = sqlite3.connect(tmp_db)
        try:
            os.chmod(tmp_db, 0o600)
            src.backup(dst, pages=2000, sleep=0.01)   # in small steps, so the sync and the web pages keep working
            dst.execute("PRAGMA journal_mode=DELETE")  # one self-contained file, no -wal or -shm next to it
        finally:
            dst.close()
            src.close()
        result = check_copy(tmp_db)
        if result != "ok":
            raise DatabaseDamaged("the database is damaged: %s" % str(result)[:150])
        fd = os.open(tmp_gz, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)    # holds the login hash and the feed token
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=raw) as gz, open(tmp_db, "rb") as fh:
            shutil.copyfileobj(fh, gz, 1 << 20)
        os.replace(tmp_gz, final)
    finally:
        remove_quietly(tmp_db, tmp_db + "-journal", tmp_db + "-wal", tmp_db + "-shm", tmp_gz)
    for _name, path, _size in backup_files()[max(1, BACKUP_KEEP):]:
        remove_quietly(path)
    return final


def backup_due(con, now):
    if not BACKUP_KEEP:
        return False
    last = float(get_meta(con, "backup_last", "0") or 0)
    tried = float(get_meta(con, "backup_tried", "0") or 0)
    return now - last >= BACKUP_HOURS * 3600 and now - tried >= BACKUP_RETRY


def backup_once(con):
    # One scheduled backup. Failures are kept for the Account page and sent once per try through ntfy.
    now = time.time()
    set_meta(con, "backup_tried", now)
    try:
        backup_db()
        set_meta(con, "backup_last", now)
        set_meta(con, "backup_error", "")
        return True
    except Exception as e:
        msg = "%s %s" % (fmt_ts(now), str(e)[:200])
        set_meta(con, "backup_error", msg)
        sys.stderr.write("database backup: %s\n" % msg)
        try:
            if NTFY_URL and settings(con)["notify"]:
                ntfy_post("Database backup failed: %s" % str(e)[:200], "Huginn: backup failed", 4)
        except Exception as e2:
            sys.stderr.write("ntfy: %r\n" % e2)
        return False


def backup_loop():
    time.sleep(300)
    con = connect()
    while True:
        try:
            if backup_due(con, time.time()):
                backup_once(con)
        except Exception as e:
            sys.stderr.write("backup loop: %r\n" % e)
        time.sleep(600)


def backup_note(con):
    if not BACKUP_KEEP:
        return "turned off (HUGINN_DB_BACKUPS=0)"
    files = backup_files()
    last = float(get_meta(con, "backup_last", "0") or 0)
    txt = "%s kept of %d" % (num(len(files)), BACKUP_KEEP)
    if files:
        txt += ", newest %s, %.1f MB" % (ago(last) if last else files[0][0][7:22], files[0][2] / 1048576)
    return txt


def enrich_loop():
    con = connect()
    time.sleep(20)
    while True:
        try:
            now = time.time()
            todo = [r[0] for r in con.execute(
                "SELECT i.ip FROM ips i LEFT JOIN enrich e USING(ip) WHERE e.ip IS NULL OR e.fetched < ? "
                "ORDER BY (e.ip IS NULL) DESC, i.last DESC LIMIT 25", (now - ENRICH_TTL,))]
            for ip in todo:
                if not ipaddress.ip_address(ip).is_global:  # test mode (HUGINN_ALLOW_PRIVATE): never send LAN addresses out
                    with con:
                        con.execute("INSERT OR REPLACE INTO enrich(ip,fetched,ok) VALUES(?,?,1)", (ip, time.time()))
                    continue
                d, ok, research = enrich_ip(ip)
                fetched = time.time() if ok else time.time() - ENRICH_TTL + 86400  # failed: retry in a day
                with con:
                    con.execute("INSERT OR REPLACE INTO enrich VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (ip, fetched, ok, d["cc"], d["country"], d["city"], d["asn"], d["org"], d["isp"],
                                 d["rdns"], d["ports"], d["tags"], d["vulns"], d["hostnames"], research, d.get("rdns_ok")))
                time.sleep(2)
        except Exception as e:
            set_meta(con, "last_enrich_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
        time.sleep(60)


# ---------------------------------------------------------------- login

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(h).decode())


_pw_slots = threading.BoundedSemaphore(2)      # scrypt takes 16 MB and real CPU: never many at once


def check_pw(pw, stored):
    try:
        _, s, h = stored.split("$")
        with _pw_slots:
            calc = hash_pw(pw, base64.b64decode(s)).split("$")[2]
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


_fails = {}
_fails_lock = threading.Lock()


def reserve_attempt(ip):
    # Counts the attempt BEFORE the password check, so parallel requests cannot get past the limit.
    with _fails_lock:
        now = time.time()
        if len(_fails) > 10000:
            for k in [k for k, v in _fails.items() if not v or now - v[-1] >= 900]:
                del _fails[k]
        lst = [t for t in _fails.get(ip, []) if now - t < 900]
        if len(lst) >= 5:
            _fails[ip] = lst
            return False
        lst.append(now)
        _fails[ip] = lst
        return True


def release_attempt(ip):
    # The password was right: this attempt does not count.
    with _fails_lock:
        lst = _fails.get(ip)
        if lst:
            lst.pop()


# ---------------------------------------------------------------- formatting

def esc(s):
    return html.escape("" if s is None else str(s), quote=True)


def clean(s, n=3000):
    s = "" if s is None else str(s)
    out = "".join(c if (c.isprintable() or c == "\t") else "\\x%02x" % ord(c) for c in s[:n])
    return out + ("…" if len(s) > n else "")


def fmt_time(ts, fmt):
    if not ts:
        return "–"
    try:
        return datetime.fromtimestamp(ts, TZ).strftime(fmt)
    except (OverflowError, OSError, ValueError):
        return "–"


def fmt_ts(ts):
    return fmt_time(ts, "%Y-%m-%d %I:%M %p" if getattr(_local, "h12", False) else "%Y-%m-%d %H:%M")


def fmt_tss(ts):
    return fmt_time(ts, "%Y-%m-%d %I:%M:%S %p" if getattr(_local, "h12", False) else "%Y-%m-%d %H:%M:%S")


def ago(ts):
    if not ts:
        return "never"
    d = time.time() - ts
    if d < 90:
        return "%ds ago" % max(0, d)
    if d < 5400:
        return "%dm ago" % (d // 60)
    if d < 172800:
        return "%dh ago" % (d // 3600)
    return "%dd ago" % (d // 86400)


def dur(secs):
    if secs is None:
        return "–"
    secs = float(secs)
    if not math.isfinite(secs):
        return "–"
    if secs < 60:
        return "%.1fs" % secs
    if secs < 3600:
        return "%dm %ds" % (secs // 60, secs % 60)
    return "%dh %dm" % (secs // 3600, (secs % 3600) // 60)


def num(n):
    return "{:,}".format(int(n or 0)).replace(",", " ")


TAG_CLASS = {"dropper": "t-red", "exploit": "t-red", "proxy": "t-orange", "shell": "t-yellow",
             "bruteforce": "t-blue", "multi-service": "t-purple", "tarpitted": "t-teal", "research": "t-grey",
             "block": "t-red", "allow": "t-green", "human-like": "t-orange", "took-bait": "t-red", "read-bait": "t-orange",
             "sshole-probe": "t-red", "web-exploit": "t-red", "web-probe": "t-yellow", "robots-trap": "t-orange", "server": "t-blue", "camera": "t-teal", "nas": "t-purple", "router": "t-teal"}


def tag_html(tags):
    out = []
    for t in [x for x in (tags or "").split(",") if x]:
        out.append('<span class="tag %s">%s</span>' % (TAG_CLASS.get(t, ""), esc(t)))
    return " ".join(out)


def ip_tags(row):
    tags = [t for t in (row["tags"] or "").split(",") if t]
    if "research" in row.keys() and row["research"]:
        tags.append("research")
    if "flag" in row.keys() and row["flag"]:
        tags.append(row["flag"])
    return ",".join(tags)


def cc_html(cc):
    return '<span class="cc">%s</span>' % esc(cc) if cc else '<span class="cc muted">··</span>'


HOT_TAGS = {"took-bait", "read-bait", "dropper", "exploit", "sshole-probe"}     # rare finds: these get the warm colour


def tags_row(tags, cols):
    # Phones only (CSS): the tags get a full-width line under their row instead of a narrow column.
    # Always one extra row, also when empty, so "the first five attackers" stays the first ten rows.
    return '<tr class="m-row"><td colspan=%d>%s</td></tr>' % (cols, tag_html(tags))


def score_html_cell(r):
    hot = HOT_TAGS & set((r["tags"] or "").split(","))
    return '<td class=num><b%s>%s</b></td>' % (' class="s-hot"' if hot else "", r["score"])


def none_yet(msg):
    # An empty section: one line, no table head with nothing under it.
    return '<p class="empty muted">%s</p>' % esc(msg)


def first_cmds(con, session, n=2):
    return [r[0] for r in con.execute("SELECT a FROM events WHERE session=? AND kind='cmd' AND TRIM(COALESCE(a,''))<>'' ORDER BY ts, rowid LIMIT ?", (session, n))]


def script_cell(key, cmds, link=True):
    # What a script does comes first. The hash is only its id, and two scripts can start with the same command.
    label = " ; ".join(clean(c, 90) for c in cmds) or key[:16]
    href = link and re.fullmatch(r"[0-9a-f]{8,64}", key or "")
    head = ('<a class="scr mono" href="/campaign/script/%s" title="%s">%s</a>' % (esc(key), esc(label), esc(label)) if href
            else '<span class="scr mono" title="%s">%s</span>' % (esc(label), esc(label)))
    return head + ('<div class="hash mono muted">%s</div>' % esc(key[:16]) if cmds else "")


def ip_link(ip, anchor=""):
    return '<a class="mono" href="/ip/%s%s">%s</a>' % (esc(urllib.parse.quote(ip)), esc(anchor), esc(ip))


def ext(url, label):
    return '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (esc(url), esc(label))


def short_num(v):
    # 1234 -> 1.2k, so the value fits above a narrow bar.
    if v >= 10000:
        return "%dk" % round(v / 1000)
    if v >= 1000:
        return ("%.1fk" % (v / 1000)).replace(".0k", "k")
    return str(v)


def bars(values, labels, h=90, cls="bar", partial_last=False, gaps=None):
    # Bars in plain HTML/CSS (not a stretched SVG), so the number above each bar stays sharp at any width.
    if not values:
        return ""
    mx = max(values) or 1
    # No style="" attributes: the Content-Security-Policy (style-src 'self') blocks them. Heights are CSS classes.
    # A short text for screen readers: the span and the highest bar (the numbers are only in tooltips otherwise).
    top = max(range(len(values)), key=lambda i: values[i])
    label = "Bar chart, %s to %s, highest %s on %s" % (labels[0], labels[-1], num(values[top]), labels[top]) if labels else "Bar chart"
    out = ['<div class="bars bars-%d" role="img" aria-label="%s">' % (90 if h >= 90 else 60, esc(label))]
    for i, (v, lab) in enumerate(zip(values, labels)):
        pct = (v / mx * 100) if v else 0
        step = max(2, round(pct / 2) * 2) if v else 0          # 2 % steps: 51 classes cover every bar
        part = partial_last and i == len(values) - 1
        gap = (gaps or {}).get(lab)
        out.append('<div class="bcol%s" title="%s: %s%s%s"><span class="bval">%s</span><i class="%s h%d%s"></i></div>'
                   % (" gapd" if gap else "", esc(lab), num(v), " so far" if part else "", " · no sync for %s" % dur(gap) if gap else "",
                      short_num(v) if v else "", cls, step, " partial" if part else ""))
    out.append("</div>")
    return "".join(out)


def kv(rows):
    return '<dl class="kv">' + "".join("<dt>%s</dt><dd>%s</dd>" % (esc(k), v) for k, v in rows) + "</dl>"


SETTINGS_DEFAULT = {"theme": "auto", "accent": "blue", "density": "comfortable", "title": "Huginn",
                    "cards": ["hero", "chart", "countries", "week", "heatmap", "top", "shells", "creds", "timewasted"], "ips_days": "30",
                    "bl_min": 3, "bl_days": 30, "notify": True, "notify_events": ["bait", "files", "human", "exploit", "weekly"], "v": 3,
                    "clock": "24", "ips_cols": ["cc", "network", "first", "last", "sessions", "logins", "cmds", "files", "tags", "score"],
                    "hide_cc": [], "hide_asn": [], "overview": "cards"}
# Optional columns of the Attackers list: key -> (header, sort key, css class)
IPS_COLS = [("cc", "CC", None, ""), ("network", "Network", None, ""), ("asn", "ASN", None, ""), ("rdns", "Reverse DNS", None, ""),
            ("first", "First seen", "first", ""), ("last", "Last seen", "last", ""), ("sessions", "Sess.", "sessions", "num"),
            ("logins", "Logins", "logins", "num"), ("cmds", "Cmds", "cmds", "num"), ("files", "Files", None, "num"),
            ("tarpit", "Tarpit", None, "num"), ("tags", "Tags", None, ""), ("score", "Score", "score", "num")]
CARDS = [("hero", "Banner (Huginn, what it has seen so far)"), ("chart", "Unique attackers per day"), ("countries", "Countries"), ("week", "New this week"), ("heatmap", "When they attack"), ("top", "Top attackers"),
         ("shells", "Latest shell sessions"), ("creds", "Top credentials (SSH/Telnet)"), ("timewasted", "Time wasted")]
# accent: (light accent, light tint, dark accent, dark tint)
ACCENTS = {"blue": ("#3b6fd8", "#e9effb", "#7aa2f7", "#1d2a44"), "purple": ("#7d4fc7", "#f1ebfb", "#b394f0", "#2a2140"),
           "green": ("#2e8b57", "#e6f4ec", "#5fc28a", "#17302a"), "orange": ("#c46a12", "#fbefe3", "#f0a050", "#352616"),
           "red": ("#c73a3a", "#fbe9e9", "#f07070", "#3a1d1f"), "teal": ("#178a8a", "#e3f4f4", "#4cc6c6", "#15302f")}
NOTIFY_EVENTS = [("bait", "Someone took or read the bait"), ("files", "New files captured"),
                 ("human", "Human-like sessions"), ("exploit", "Exploit attempts"), ("weekly", "Weekly summary (Sunday evening)")]
THEMES = ["auto", "light", "dark"]


def settings(con=None):
    con = con or db()
    try:
        saved = json.loads(get_meta(con, "settings", "{}") or "{}")
    except ValueError:
        saved = {}
    out = dict(SETTINGS_DEFAULT)
    out.update({k: v for k, v in saved.items() if k in SETTINGS_DEFAULT})
    if saved and saved.get("v", 1) < 2:
        # Settings saved before 0.14: show the new cards and the weekly summary once; the next save keeps the choice.
        out["cards"] = list(out["cards"]) + [c for c in ("week", "heatmap") if c not in out["cards"]]
        out["notify_events"] = list(out["notify_events"]) + (["weekly"] if "weekly" not in out["notify_events"] else [])
    if saved and saved.get("v", 1) < 3 and "hero" not in out["cards"]:
        out["cards"] = ["hero"] + list(out["cards"])                  # 0.15: the banner, once
    out["v"] = 3
    return out


def hidden_sql(st, alias="e"):
    # SQL that leaves out hidden countries/networks (views only — the blocklist never uses this).
    parts, args = [], []
    if st["hide_cc"]:
        parts.append("COALESCE(%s.cc,'') NOT IN (%s)" % (alias, ",".join("?" * len(st["hide_cc"]))))
        args += st["hide_cc"]
    if st["hide_asn"]:
        parts.append("COALESCE(%s.asn,'') NOT IN (%s)" % (alias, ",".join("?" * len(st["hide_asn"]))))
        args += st["hide_asn"]
    return (" AND " + " AND ".join(parts)) if parts else "", args


def footer():
    # AGPL section 5 and 13: show copyright, license, no warranty and where the source is.
    # Modified versions may add their own notice here, but must keep this one.
    return ("<footer class='site-foot'>Huginn %s · © 2026 Ancientswede · "
            "<a href='https://www.gnu.org/licenses/agpl-3.0.html' target='_blank' rel='noopener noreferrer'>AGPL-3.0</a>, no warranty · "
            "<a href='https://github.com/%s' target='_blank' rel='noopener noreferrer'>Source on GitHub</a></footer>" % (HUGINN_VERSION, esc(REPO)))


def html_attrs(st):
    a = ' data-accent="%s" data-density="%s"' % (esc(st["accent"]), esc(st["density"]))
    if st["theme"] in ("light", "dark"):
        a += ' data-theme="%s"' % st["theme"]
    return a


NAV = [("/", "Overview"), ("/new", "New"), ("/ips", "Attackers"), ("/campaigns", "Campaigns"), ("/personas", "Personas"), ("/engagement", "Engagement"), ("/search", "Search"), ("/files", "Files"),
       ("/creds", "Credentials"), ("/blocklist", "Blocklist")]


def page(title, body, active="/"):
    con = db()
    st = settings(con)
    nxt = THEMES[(THEMES.index(st["theme"]) + 1) % 3] if st["theme"] in THEMES else "auto"
    theme_btn = ("<form method=post action='/settings/theme'><button class='link theme-btn' title='Theme: %s (click for %s)'>"
                 "<span class='ti ti-%s'></span>%s</button></form>" % (st["theme"], nxt, st["theme"], st["theme"].capitalize()))
    li = float(get_meta(con, "last_ingest", "0") or 0)
    err = get_meta(con, "last_error", "")
    stale = (time.time() - li) > POLL * 3
    status = '<span class="sync %s" title="%s">synced %s</span>' % ("bad" if (err or stale) else "ok", esc(err or ""), esc(ago(li)))
    fresh = con.execute("SELECT COUNT(*) FROM seen WHERE observed>?", (review_since(con),)).fetchone()[0]
    badge = '<span class="nav-n">%s</span>' % ("99+" if fresh > 99 else fresh) if fresh else ""
    # The raven (app.js) compares these with what this browser saw last. Bait counts attackers, so it means "a new attacker
    # used the bait", and pruning old attackers in the same sync can hide one. It is a flourish: ntfy and New are the record.
    newest_file = con.execute("SELECT COALESCE(MAX(observed), 0) FROM seen WHERE kind='file'").fetchone()[0]
    took, read = con.execute("SELECT COALESCE(SUM(','||tags||',' LIKE '%,took-bait,%'), 0), COALESCE(SUM(','||tags||',' LIKE '%,read-bait,%'), 0) FROM ips").fetchone()
    nav = "".join('<a href="%s"%s>%s%s</a>' % (h, ' class="on"' if h == active else "", esc(t), badge if h == "/new" else "") for h, t in NAV)
    return ("<!doctype html><html lang=en%s><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s · %s</title><link rel=icon type=image/png sizes=32x32 href='/static/icon-32.png'><link rel=apple-touch-icon href='/static/icon-180.png'><link rel=stylesheet href='/static/app.css?v=%s'>"
            "<script src='/static/app.js?v=%s' defer></script></head><body>"
            "<header><div class=brand id=brand data-file='%s' data-took='%d' data-read='%d'><a href='/'><img class=brand-ic src='/static/icon-32.png' alt=''>%s</a></div><nav>%s</nav>"
            "<div class=hdr-right>%s<span class=muted>v%s</span>%s%s"
            "<button class='link kbd-btn' id='kbdHelp' title='Keyboard shortcuts (?)'>?</button>"
            "<a class='hdr-link%s' href='/settings'>Settings</a>"
            "<a class='hdr-link%s' href='/account'>Account</a><form method=post action='/logout'><button class=link>Log out</button></form></div></header>"
            "<main>%s</main>%s</body></html>") % (html_attrs(st), esc(title), esc(st["title"]), HUGINN_VERSION, HUGINN_VERSION,
                                                  esc(repr(newest_file)), took, read, esc(st["title"]), nav, status, HUGINN_VERSION, update_badge(con), theme_btn,
                                                  " on" if active == "/settings" else "", " on" if active == "/account" else "", body, footer())


# ---------------------------------------------------------------- pages

def overview_kpis(con, st):
    # The metric strip at the top of both Overview layouts. Returns the HTML and the week summary (the Cards view reuses it).
    now = time.time()
    d1, d7 = now - 86400, now - 7 * 86400
    k = con.execute("SELECT SUM(last>=?) a, SUM(last>=?) b, COUNT(*) c, SUM(first>=?) d FROM ips", (d1, d7, d1)).fetchone()
    s24 = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=?", (d1,)).fetchone()[0]
    sh24 = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND cmds>0", (d1,)).fetchone()[0]
    files = con.execute("SELECT COUNT(DISTINCT b) FROM events WHERE kind='file'").fetchone()[0]
    bl = len(blocklist_ips(con, int(st["bl_min"]), int(st["bl_days"]), False, True))
    tw = time_wasted(con, now - 7 * 86400)
    bait7 = con.execute("SELECT SUM(','||tags||',' LIKE '%,took-bait,%'), SUM(','||tags||',' LIKE '%,read-bait,%') FROM ips WHERE last>=?", (d7,)).fetchone()
    w = week_summary(con, d7, now)
    files_new = sum(w["families"].values())
    files_prior = con.execute("SELECT COUNT(*) FROM (SELECT b FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b "
                              "HAVING MIN(ts)>=? AND MIN(ts)<?)", (now - 14 * 86400, d7)).fetchone()[0]
    delta = "%+d%% vs prior 7d" % round((w["active"] - w["before"]) * 100.0 / w["before"]) if w["before"] else ""
    # The three without "kpi-x" are what a phone shows first. "hot": something rare happened, make it stand out.
    kpis = [("Attackers 24h", num(k["a"]), "%s new" % num(k["d"]), ""),
            ("Sessions 24h", num(s24), "%s with shell commands" % num(sh24), ""),
            ("Took the bait 7d", num(bait7[0] or 0), ("%s read bait files" % num(bait7[1] or 0)) if BAIT else "no bait values known yet", " hot" if bait7[0] else ""),
            ("Attackers 7d", num(w["active"]), " · ".join(x for x in ("%s total" % num(k["c"]), delta) if x), " kpi-x"),
            ("Files captured", num(files), "%s new 7d · %s prior" % (num(files_new), num(files_prior)), " kpi-x hot" if files_new else " kpi-x"),
            ("Time wasted 7d", esc(dur(tw["total"])) if tw["total"] else "0", "%s tarpit · %s fake shells%s" % (dur(tw["tarpit"]), dur(tw["shell"]), " · %d stuck now" % tw["stuck"] if tw["stuck"] else ""), " kpi-x"),
            ("On blocklist", num(bl), "score ≥%s, %s days" % (st["bl_min"], st["bl_days"]), " kpi-x")]
    kp = "".join('<div class="kpi%s"><div class="kpi-l">%s</div><div class="kpi-v">%s</div><div class="kpi-s">%s</div></div>' % (d, esc(a), b, esc(c)) for a, b, c, d in kpis)
    html_ = ('<input class="kpi-sw" type="checkbox" id="kpiMore" aria-label="More metrics"><div class="kpis">%s</div>'
             '<label class="kpi-more" for="kpiMore"><span class="a">More metrics</span><span class="b">Fewer metrics</span></label>' % kp)
    return html_, w, tw


def overview_switch(view, extra=""):
    # Cards or Board: saved in the settings, so the Overview opens the way it was left.
    return ('<div class="ov-bar"><form method=post action="/settings/overview" class="vtabs ov-tabs" aria-label="Overview layout">'
            '<button name=view value=cards%s>Cards</button><button name=view value=board%s>Board</button></form>%s</div>'
            % (" class=on" if view == "cards" else "", " class=on" if view == "board" else "", extra))


def v_overview(qs=None):
    con = db()
    if settings(con).get("overview") == "board":
        return v_board(con, qs or {})
    now = time.time()
    d7 = now - 7 * 86400
    st = settings(con)
    kp, w, tw = overview_kpis(con, st)

    days = []
    for i in range(13, -1, -1):
        days.append(datetime.fromtimestamp(now - i * 86400, TZ).strftime("%Y-%m-%d"))
    q = {r[0]: (r[1], r[2]) for r in con.execute(
        "SELECT date(start,'unixepoch','localtime') d, COUNT(*), COUNT(DISTINCT ip) FROM sessions WHERE start>=? GROUP BY d",
        (now - 15 * 86400,))}
    gaps = gap_days(con, days)
    chart = ('<div class="card chart-card"><h3>Unique attacker IPs per day</h3>%s<div class="axis"><span>%s</span><span>today</span></div>%s</div>'
             % (bars([q.get(d, (0, 0))[1] for d in days], days, partial_last=True, gaps=gaps), esc(days[0]), gap_note(gaps)))

    hs, ha = hidden_sql(st)
    top = con.execute("SELECT i.*, e.cc, e.org, e.research, f.flag FROM ips i LEFT JOIN enrich e USING(ip) "
                      "LEFT JOIN flags f USING(ip) WHERE i.last>=?" + hs + " ORDER BY i.score DESC, i.last DESC LIMIT 15", [d7] + ha).fetchall()
    trows = "".join("<tr><td>%s</td><td>%s</td><td data-h class=trunc>%s</td><td class=num>%s</td><td class=num>%s</td><td data-h>%s</td>%s</tr>%s"
                    % (ip_link(r["ip"]), cc_html(r["cc"]), esc(r["org"] or ""), num(r["sessions"]), num(r["cmds"]),
                       tag_html(ip_tags(r)), score_html_cell(r), tags_row(ip_tags(r), 7)) for r in top)
    top_html = ('<div class="card span2"><h3>Top attackers, 7 days <a class=more href="/ips?days=7">all →</a></h3>%s</div>'
                % (('<table class="top5"><thead><tr><th>IP</th><th>CC</th><th data-h>Network</th><th class=num>Sess.</th><th class=num>Cmds</th><th data-h>Tags</th><th class=num>Score</th></tr></thead><tbody>%s</tbody></table>' % trows)
                   if trows else none_yet("No attackers in the last 7 days")))

    shells = con.execute("SELECT s.*, e.cc FROM sessions s LEFT JOIN enrich e USING(ip) WHERE s.cmds>0" + hs + " ORDER BY s.start DESC LIMIT 10", ha).fetchall()
    srows = ""
    for s in shells:
        first = con.execute("SELECT a FROM events WHERE session=? AND kind='cmd' ORDER BY ts LIMIT 1", (s["session"],)).fetchone()
        srows += "<tr><td>%s</td><td>%s</td><td>%s</td><td class=num>%s</td><td class='mono trunc'>%s</td><td>%s</td></tr>" % (
            esc(ago(s["start"])), ip_link(s["ip"], "#s-" + s["session"]), cc_html(s["cc"]), s["cmds"], esc(clean(first[0] if first else "", 140)),
            ('<a class="replay-btn" href="/replay/%s?ip=%s">▶ Replay</a>' % (esc(s["tty"]), esc(urllib.parse.quote(s["ip"])))) if s["tty"] else "")
    shells_html = ('<div class="card span2"><h3>Latest shell sessions</h3>%s</div>'
                   % (('<table><thead><tr><th>When</th><th>IP</th><th>CC</th><th class=num>Cmds</th><th>First command</th><th></th></tr></thead><tbody>%s</tbody></table>' % srows)
                      if srows else none_yet("No shell sessions yet")))

    creds = con.execute("SELECT a,b,COUNT(*) n FROM events WHERE kind IN ('login_ok','login_fail') AND ts>=? GROUP BY a,b ORDER BY n DESC LIMIT 10", (d7,)).fetchall()
    crows = "".join("<tr><td class=mono>%s</td><td class=mono>%s</td><td class=num>%s</td></tr>" % (esc(clean(r["a"], 60)), esc(clean(r["b"], 60)), num(r["n"])) for r in creds)
    # SSH/Telnet only, like the "Pairs (SSH/Telnet)" card on Credentials; decoy-service logins are there too.
    creds_html = ('<div class="card"><h3>Top credentials, SSH/Telnet, 7 days <a class=more href="/creds">all →</a></h3>%s</div>'
                  % (('<table><thead><tr><th>User</th><th>Password</th><th class=num>Tries</th></tr></thead><tbody>%s</tbody></table>' % crows)
                     if crows else none_yet("No SSH/Telnet logins in the last 7 days")))

    ccs = con.execute("SELECT COALESCE(e.cc,'??') cc, MAX(e.country) country, COUNT(*) n FROM ips i LEFT JOIN enrich e USING(ip) WHERE i.last>=?" + hs + " GROUP BY cc ORDER BY n DESC LIMIT 10", [d7] + ha).fetchall()
    ccrows = "".join("<tr><td>%s</td><td>%s</td><td class=num>%s</td></tr>" % (cc_html(r["cc"]), esc(r["country"] or ""), num(r["n"])) for r in ccs)
    allcc = {r[0]: r[1] for r in con.execute("SELECT e.cc, COUNT(*) FROM ips i JOIN enrich e USING(ip) WHERE i.last>=? AND e.cc IS NOT NULL" + hs + " GROUP BY e.cc", [d7] + ha)
             if r[0] and re.fullmatch(r"[A-Z]{2}", r[0])}
    cc_html_ = ('<div class="card"><h3>Countries, 7 days <span class="vtabs"><button type=button data-cview="map">Map</button>'
                '<button type=button data-cview="list">List</button></span></h3>'
                '<div data-cpanel="map"><div class="wm" id="wmap" data-counts="%s"></div><div class="wm-legend"><span>fewer</span><i></i><span>more IPs</span></div></div>'
                '<div data-cpanel="list" hidden><table><thead><tr><th>CC</th><th>Country</th><th class=num>IPs</th></tr></thead><tbody>%s</tbody></table></div></div>'
                % (esc(json.dumps(allcc)), ccrows))

    twrows = "".join("<tr><td>%s</td><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num><b>%s</b></td><td class=num>%s</td></tr>"
                     % (ip_link(r["ip"]), cc_html(r["cc"]), esc(dur(r["tarpit"]) if r["tarpit"] else "–"), esc(dur(r["shell"]) if r["shell"] else "–"),
                        esc(dur(r["total"])), esc(dur(r["longest"]))) for r in tw["top"])
    tw_table = ('<table><thead><tr><th>IP</th><th>CC</th><th class=num>Tarpit</th><th class=num>Fake shell</th><th class=num>Total</th><th class=num>Longest</th></tr></thead><tbody>%s</tbody></table>' % twrows
                if twrows else none_yet("No time wasted yet"))
    tw_html = ('<div class="card"><h3>Time wasted, 7 days <span class=muted>%s total%s</span><a class=more href="/receipt?days=7">View receipt →</a></h3>%s</div>'
               % (esc(dur(tw["total"])), " · %d stuck in the tarpit right now" % tw["stuck"] if tw["stuck"] else "", tw_table))
    parts = {"chart": chart, "countries": cc_html_, "top": top_html, "shells": shells_html, "creds": creds_html, "timewasted": tw_html,
             "week": week_card(con, w) if "week" in st["cards"] else "",
             "heatmap": ('<div class="card"><h3>When they attack <span class=muted>30 days</span></h3>%s</div>'
                         % heat_html(heatmap(con))) if "heatmap" in st["cards"] else ""}
    body = ((hero_card(con, st) if "hero" in st["cards"] else "") + overview_switch("cards") + kp
            + '<div class="grid ov">%s</div>' % "".join(parts[k] for k, _ in CARDS if k in st["cards"] and k != "hero"))
    return page("Overview", body, "/")


# ---------------------------------------------------------------- Overview, Board layout
# Everything side by side on one screen, for one time range and optionally one service: what each service saw, two
# charts on the same time axis, and the latest raw data. Same data and definitions as the other pages (a login is what
# the Credentials page counts as one); only the layout is different.

BOARD_RANGES = {"24h": (86400, 3600, "per hour"), "7d": (7 * 86400, 4 * 3600, "per 4 hours")}
BOARD_SKIP = ("version", "hassh", "closed", "tty", "tarpit_open", "termsize")         # bookkeeping rows, not something an attacker did
BOARD_FEED = ("login_ok", "login_fail", "cmd", "file", "file_fail", "tcpip", "exploit", "canary", "tarpit")
BOARD_SVC = "CASE WHEN e.src='cowrie' THEN COALESCE(s.proto,'ssh') WHEN e.src='endlessh' THEN 'tarpit' ELSE COALESCE(e.a,'?') END"
BOARD_FROM = " FROM events e LEFT JOIN sessions s ON e.src='cowrie' AND s.session=e.session WHERE e.ts>=?"
ACCEPT_KNOWN = ("ssh", "telnet")      # only Cowrie says whether it let a login in; the other decoys do not record it
_board_cache = {}


def board_hidden(st):
    # "Hide from views" for queries on events: leave out IPs whose country/network is hidden.
    hs, ha = hidden_sql(st, "x")
    if not hs:
        return "", []
    return " AND e.ip NOT IN (SELECT x.ip FROM enrich x WHERE NOT (1" + hs + "))", ha


def board_cached(con, st, key, fn):
    full = (key, get_meta(con, "last_ingest", ""), tuple(st["hide_cc"]), tuple(st["hide_asn"]))
    if full not in _board_cache:
        if len(_board_cache) > 16:
            _board_cache.clear()
        _board_cache[full] = fn()
    return _board_cache[full]


def board_logins(con, since, hs, ha):
    # Decoy logins (not Cowrie): the same rule as the Credentials page (canary_is_login, and "(db x)" is not the password).
    out = []
    for ts, svc, src, b in con.execute("SELECT e.ts, COALESCE(e.a,'?'), e.src, e.b FROM events e WHERE e.ts>=? AND e.kind='canary' AND e.b LIKE '% / %'" + hs,
                                       [since] + ha):
        if canary_is_login(svc, b):
            user, _, pw = b.partition(" / ")
            if src == "traps":
                pw = re.sub(r"  \(db .*\)$", "", pw)
            out.append((ts, svc, user, pw))
    return out


def board_rows(con, st, rng):
    # One pass over the period, folded per service, IP, kind and time bucket (a few thousand rows for a week instead of
    # several hundred thousand events). The service table, both charts and the top list are counted from this in Python.
    # The alias is "bkt", not "b": in GROUP BY, SQLite would take events.b (the password column) before an alias.
    span, step, _ = BOARD_RANGES[rng]
    since = time.time() - span
    hs, ha = board_hidden(st)
    rows = con.execute("SELECT " + BOARD_SVC + " svc, e.ip, e.kind, CAST((e.ts-?)/? AS INTEGER) bkt, COUNT(*) n, MAX(e.ts) last" + BOARD_FROM
                       + " AND e.kind NOT IN (%s)" % ",".join("?" * len(BOARD_SKIP)) + hs + " GROUP BY svc, e.ip, e.kind, bkt",
                       [since, step, since] + list(BOARD_SKIP) + ha).fetchall()
    decoy = board_logins(con, since, hs, ha)
    creds = {}
    for svc, user, pw, n in con.execute("SELECT COALESCE(s.proto,'ssh'), COALESCE(e.a,''), COALESCE(e.b,''), COUNT(*)" + BOARD_FROM
                                        + " AND e.kind IN ('login_ok','login_fail')" + hs + " GROUP BY 1, 2, 3", [since] + ha):
        if user or pw:
            creds[(svc, user, pw)] = n
    for _ts, svc, user, pw in decoy:
        if user or pw:
            creds[(svc, user, pw)] = creds.get((svc, user, pw), 0) + 1
    return {"since": since, "rows": [tuple(r) for r in rows], "logins": [(svc, int((ts - since) // step)) for ts, svc, _u, _p in decoy],
            "creds": creds}


def board_services(con, st, rng):
    data = board_cached(con, st, ("rows", rng), lambda: board_rows(con, st, rng))
    out, ips = {}, {}
    for svc, ip, kind, _b, n, last in data["rows"]:
        v = out.setdefault(svc, {"ips": 0, "hits": 0, "logins": 0, "ok": 0 if svc in ACCEPT_KNOWN else None, "last": 0})
        ips.setdefault(svc, set()).add(ip)
        if kind in ("connect", "canary", "tarpit"):
            v["hits"] += n
        if kind in ("login_ok", "login_fail"):
            v["logins"] += n
        if kind == "login_ok" and v["ok"] is not None:
            v["ok"] += n
        v["last"] = max(v["last"], last)
    for svc, _b in data["logins"]:
        if svc in out:
            out[svc]["logins"] += 1
    for svc, s in ips.items():
        out[svc]["ips"] = len(s)
    return out


def board_detail(con, st, rng, svc):
    span, step, _ = BOARD_RANGES[rng]
    n = int(span // step)
    data = board_cached(con, st, ("rows", rng), lambda: board_rows(con, st, rng))
    since = data["since"]
    hs, ha = board_hidden(st)
    sf, sa = ((" AND " + BOARD_SVC + "=?"), [svc]) if svc else ("", [])
    per_bucket = [set() for _ in range(n)]
    logins = [0] * n
    per_ip = {}
    for s, ip, kind, b, cnt, _last in data["rows"]:
        if svc and s != svc:
            continue
        if 0 <= b < n:
            per_bucket[b].add(ip)
            if kind in ("login_ok", "login_fail"):
                logins[b] += cnt
        p = per_ip.setdefault(ip, [0, set()])
        p[0] += cnt
        p[1].add(s)
    for s, b in data["logins"]:
        if (not svc or s == svc) and 0 <= b < n:
            logins[b] += 1
    ips = [len(x) for x in per_bucket]
    labels = [fmt_time(since + i * step, "%a %H:%M") for i in range(n)]
    meta, cand = {}, list(per_ip)
    for i in range(0, len(cand), 500):
        part = cand[i:i + 500]
        for r in con.execute("SELECT i.ip, i.score, i.tags, en.cc, en.org, en.research, f.flag FROM ips i LEFT JOIN enrich en USING(ip) "
                             "LEFT JOIN flags f USING(ip) WHERE i.ip IN (%s)" % ",".join("?" * len(part)), part):
            meta[r["ip"]] = r
    top = sorted(((ip, p[0], len(p[1])) for ip, p in per_ip.items() if ip in meta), key=lambda x: (-meta[x[0]]["score"], -x[1]))[:10]
    # Latest raw data: identical rows from the same IP are folded into one line with a count (VNC alone sends thousands).
    feed = con.execute("SELECT " + BOARD_SVC + " svc, e.ip, e.kind, e.a, e.b, COUNT(*) n, MAX(e.ts) ts, MAX(e.h) h" + BOARD_FROM
                       + " AND e.kind IN (%s) AND NOT (e.kind='canary' AND COALESCE(e.b,'')='')" % ",".join("?" * len(BOARD_FEED))
                       + sf + hs + " GROUP BY svc, e.ip, e.kind, e.a, e.b ORDER BY ts DESC LIMIT 25", [since] + list(BOARD_FEED) + sa + ha).fetchall()
    ccs = {r[0]: r[1] for r in con.execute("SELECT ip, cc FROM enrich WHERE ip IN (%s)" % ",".join("?" * len(feed)), [r["ip"] for r in feed])} if feed else {}
    creds = {}
    for (s, user, pw), cnt in data["creds"].items():
        if not svc or s == svc:
            creds[(user, pw)] = creds.get((user, pw), 0) + cnt
    creds = sorted(creds.items(), key=lambda x: (-x[1], x[0]))[:12]
    return {"ips": ips, "logins": logins, "labels": labels, "since": since, "creds": creds, "top": [(ip, nn, ns, meta[ip]) for ip, nn, ns in top],
            "feed": [dict(r, web=web_of(con, r["h"]) if r["kind"] == "canary" and r["svc"] in ("http", "https") else None) for r in feed], "ccs": ccs}


def web_of(con, h):
    w = con.execute("SELECT level, type, cve FROM webhits WHERE h=?", (h,)).fetchone()
    return tuple(w) if w and w[0] else None


def board_text(kind, a, b):
    # One line for the raw data list. Attacker text: always escaped by the caller.
    if kind in ("login_ok", "login_fail"):
        return "%s / %s" % (a or "", b or "")
    if kind == "cmd":
        return a or ""
    if kind == "file":
        return "%s%s" % (a or "?", ("  sha256 " + b[:16]) if b else "")
    if kind == "exec_sim":
        return "ran an uploaded program (simulated): %s" % (a or "?")
    if kind == "file_fail":
        return "download failed: %s" % (a or "?")
    if kind == "tcpip":
        return "proxy -> %s" % (a or "?")
    if kind == "web_drip":
        how, _, secs = (b or "").partition(" ")
        return "slow export %s %s after %s s" % (a or "?", "sent in full" if how == "done" else "left early", secs or "?")
    if kind == "trap_end":
        f = (b or "").split()
        return "mail session ended after %s s, %s message(s)" % (f[0], f[1]) if len(f) == 3 else "mail session ended"
    if kind == "proxy_reply":
        return "proxy %s: %s" % (PROXY_REPLIES.get(b, "?"), a or "?")
    if kind == "exploit":
        return "exploit %s: %s" % (a or "?", b or "")
    if kind == "tarpit":
        try:
            return "held in the tarpit for %s" % dur(float(a))
        except (TypeError, ValueError):
            return "held in the tarpit"
    if b and b.startswith("{"):
        try:
            d = json.loads(b)
            if isinstance(d, dict):
                return ", ".join("%s: %s" % (k, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)) for k, v in d.items() if v not in ("", None))
        except ValueError:
            pass
    return b or ""


def board_link(rng, svc):
    q = {"range": rng}
    if svc:
        q["svc"] = svc
    return "/?" + urllib.parse.urlencode(q)


def v_board(con, qs):
    st = settings(con)
    rng = qs.get("range") if qs.get("range") in BOARD_RANGES else "24h"
    svcs = board_cached(con, st, ("svc", rng), lambda: board_services(con, st, rng))
    svc = qs.get("svc") if qs.get("svc") in svcs else None
    d = board_cached(con, st, ("detail", rng, svc), lambda: board_detail(con, st, rng, svc))
    kp, _w, _tw = overview_kpis(con, st)
    every = BOARD_RANGES[rng][2]
    what = esc(svc) if svc else "all services"

    chips = "".join('<a class="chip%s" href="%s">%s</a>' % (" on" if r == rng else "", esc(board_link(r, svc)), r) for r in BOARD_RANGES)
    opts = '<option value="">All services</option>' + "".join('<option value="%s"%s>%s</option>' % (esc(k), " selected" if k == svc else "", esc(k))
                                                               for k in sorted(svcs))
    li = float(get_meta(con, "last_ingest", "0") or 0)
    filt = ('<div class="ov-f"><div class="chips">%s</div><form method=get action="/" class="ov-svc"><input type=hidden name=range value="%s">'
            '<select name=svc data-autosubmit aria-label="Service">%s</select><button class="btn-s ov-go">Show</button></form>%s</div>'
            '<span class="ov-asof">%s · data until %s</span>'
            % (chips, esc(rng), opts, ('<a class="chip" href="%s">Clear</a>' % esc(board_link(rng, None))) if svc else "",
               "Last 24 hours" if rng == "24h" else "Last 7 days", esc(fmt_ts(li)) if li else "–"))

    rows = ""
    for name, v in sorted(svcs.items(), key=lambda x: (-x[1]["ips"], x[0])):
        acc = num(v["ok"]) if v["ok"] is not None else '<span class=muted title="Not recorded for this service">–</span>'
        rows += ('<tr%s><td><a class="svc-l" href="%s">%s</a></td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td>'
                 '<td class="num muted" data-h>%s</td></tr>' % (' class="sel"' if name == svc else "", esc(board_link(rng, None if name == svc else name)),
                                                               esc(name), num(v["ips"]), num(v["hits"]), num(v["logins"]) if v["logins"] else "–", acc, esc(ago(v["last"]))))
    services = ('<div class="card"><h3>Services</h3><table class="b-svc"><thead><tr><th>Service</th><th class=num>IPs</th>'
                '<th class=num title="Connections, requests and tarpit catches">Hits</th><th class=num>Logins</th>'
                '<th class=num title="Logins the honeypot let in. Only SSH and Telnet record this.">Accepted</th><th class=num data-h>Last</th></tr></thead>'
                '<tbody>%s</tbody></table><p class="muted small b-note">Click a service to filter the board. Accepted is only known for SSH and Telnet.</p></div>'
                % rows) if rows else '<div class="card"><h3>Services</h3>%s</div>' % none_yet("Nothing in this period")

    def chart(title, vals):
        peak = max(vals) if vals else 0
        return ('<div class="card b-chart"><h3>%s <span class=muted>%s, %s · peak %s</span></h3>%s<div class="axis"><span>%s</span><span>now</span></div></div>'
                % (title, what, every, num(peak), bars(vals, d["labels"], h=60, partial_last=True), esc(d["labels"][0])))
    charts = chart("Attacker IPs", d["ips"]) + chart("Login attempts", d["logins"])

    trows = ""
    for ip, nn, ns, m in d["top"]:
        trows += ('<tr><td>%s</td><td>%s</td><td class=trunc data-h>%s</td><td class=num>%s</td><td class=num data-h>%s</td>%s</tr>'
                  % (ip_link(ip), cc_html(m["cc"]), esc(m["org"] or ""), num(nn), ns, score_html_cell(m)))
    top = ('<div class="card"><h3>Top attackers <span class=muted>%s</span></h3><table><thead><tr><th>IP</th><th>CC</th><th data-h>Network</th>'
           '<th class=num>Events</th><th class=num data-h>Services</th><th class=num>Score</th></tr></thead><tbody>%s</tbody></table></div>'
           % (what, trows)) if trows else ""

    frows = ""
    for r in d["feed"]:
        txt = clean(board_text(r["kind"], r["a"], r["b"]), 600)
        cell = ('<details class="fd"><summary>%s</summary><div>%s</div></details>' % (esc(txt[:100]) + "…", esc(txt))) if len(txt) > 100 else esc(txt)
        mark = ' <span class="tag t-orange">accepted</span>' if r["kind"] == "login_ok" else ""
        if r.get("web"):
            mark += " " + web_tag(*r["web"])
        frows += ('<tr><td class="muted nowrap" title="%s">%s</td><td>%s</td><td class=nowrap>%s %s</td><td class="mono fd-d">%s%s%s</td></tr>'
                  % (esc(fmt_tss(r["ts"])), esc(ago(r["ts"])), esc(r["svc"]), ip_link(r["ip"]), cc_html(d["ccs"].get(r["ip"])), cell, mark,
                     (' <span class="fd-n">×%s</span>' % num(r["n"])) if r["n"] > 1 else ""))
    feed = ('<div class="card b-feed"><h3>Latest data <span class=muted>%s</span></h3>%s</div>'
            % (what, '<table><thead><tr><th>When</th><th>Service</th><th>IP</th><th>Data</th></tr></thead><tbody>%s</tbody></table>' % frows
               if frows else none_yet("Nothing in this period")))

    crows = "".join('<tr><td class="mono trunc">%s</td><td class="mono trunc">%s</td><td class=num>%s</td></tr>' % (esc(clean(u, 40)), esc(clean(p, 40)), num(c))
                    for (u, p), c in d["creds"])
    creds = ('<div class="card"><h3>Top credentials <span class=muted>%s</span><a class=more href="/creds">all →</a></h3><table class="b-creds"><thead><tr><th>User</th>'
             '<th>Password</th><th class=num>Tries</th></tr></thead><tbody>%s</tbody></table></div>' % (what, crows)) if crows else ""

    body = (overview_switch("board", filt) + '<div class="board-kpis">%s</div>' % kp
            + '<div class="board"><div class="board-col">%s%s</div><div class="board-col">%s%s</div>%s</div>' % (services, creds, charts, top, feed))
    return page("Overview", body, "/")



# ---------------------------------------------------------------- weekly view, digest and heat map

def week_summary(con, start, end):
    # What was new between start and end: the "New this week" card and the Sunday ntfy summary.
    q = lambda sql, *a: con.execute(sql, a).fetchone()[0] or 0
    span = end - start
    active = q("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>=? AND ts<?", start, end)
    before = q("SELECT COUNT(DISTINCT ip) FROM events WHERE ts>=? AND ts<?", start - span, start)
    new_ips = q("SELECT COUNT(*) FROM ips WHERE first>=? AND first<?", start, end)
    new_cc = [r[0] for r in con.execute("SELECT e.cc FROM ips i JOIN enrich e USING(ip) WHERE e.cc IS NOT NULL AND e.cc!='' "
                                        "GROUP BY e.cc HAVING MIN(i.first)>=? AND MIN(i.first)<? ORDER BY COUNT(*) DESC", (start, end))]
    camps = con.execute("SELECT cmdhash, COUNT(DISTINCT ip) n FROM sessions WHERE cmdhash IS NOT NULL GROUP BY cmdhash "
                        "HAVING MIN(start)>=? AND MIN(start)<? ORDER BY n DESC", (start, end)).fetchall()
    fams = {}
    for sha, names in con.execute("SELECT b, GROUP_CONCAT(DISTINCT a) FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b "
                                  "HAVING MIN(ts)>=? AND MIN(ts)<?", (start, end)):
        fam, _how = file_family(con.execute("SELECT * FROM files WHERE sha=?", (sha,)).fetchone(), names or "")
        fams[fam or "Unknown"] = fams.get(fam or "Unknown", 0) + 1
    took = q("SELECT COUNT(DISTINCT ip) FROM ips WHERE last>=? AND ','||tags||',' LIKE '%,took-bait,%'", start)
    top = con.execute("SELECT i.ip, i.score, e.cc FROM ips i LEFT JOIN enrich e USING(ip) WHERE i.last>=? ORDER BY i.score DESC LIMIT 3", (start,)).fetchall()
    pw = con.execute("SELECT b, COUNT(*) n FROM events WHERE kind IN ('login_ok','login_fail') AND ts>=? AND ts<? AND b IS NOT NULL "
                     "GROUP BY b ORDER BY n DESC LIMIT 1", (start, end)).fetchone()
    return {"active": active, "before": before, "new_ips": new_ips, "new_cc": new_cc, "campaigns": len(camps),
            "campaign_ips": sum(c["n"] for c in camps), "families": fams, "took": took, "top": top, "password": pw}


def trend(now_n, before_n):
    if not before_n:
        return ""
    pct = round((now_n - before_n) * 100.0 / before_n)
    return "%+d%% vs the week before" % pct


def weekly_digest(con):
    # One ntfy message on Sunday evening (Huginn's time zone) about the past seven days.
    st = settings(con)
    if not NTFY_URL or not st["notify"] or "weekly" not in st["notify_events"]:
        return
    now = datetime.now(TZ)
    if now.weekday() != 6 or now.hour < 18:
        return
    key = "%d-W%02d" % now.isocalendar()[:2]
    if get_meta(con, "weekly_sent") == key:
        return
    end = time.time()
    w = week_summary(con, end - 7 * 86400, end)
    lines = ["%s attackers (%s), %s of them new" % (num(w["active"]), trend(w["active"], w["before"]) or "first week", num(w["new_ips"]))]
    if w["new_cc"]:
        lines.append("New countries: " + ", ".join(w["new_cc"][:8]) + (" +%d" % (len(w["new_cc"]) - 8) if len(w["new_cc"]) > 8 else ""))
    if w["campaigns"]:
        lines.append("New campaigns: %d (%d IPs)" % (w["campaigns"], w["campaign_ips"]))
    if w["families"]:
        lines.append("New malware: " + ", ".join("%s ×%d" % (k, v) for k, v in sorted(w["families"].items(), key=lambda x: -x[1])[:5]))
    if w["took"]:
        lines.append("Took the bait: %d IP(s)" % w["took"])
    if w["top"]:
        lines.append("Top attacker: %s (%s, score %d)" % (w["top"][0]["ip"], w["top"][0]["cc"] or "?", w["top"][0]["score"]))
    if w["password"]:
        lines.append("Most tried password: %s (%s×)" % (clean(w["password"]["b"], 40), num(w["password"]["n"])))
    ntfy_post("\n".join(lines), "Huginn: week %d" % now.isocalendar()[1], 3)
    set_meta(con, "weekly_sent", key)
    set_meta(con, "last_notify", "%s: weekly summary %s" % (fmt_ts(end), key))


_heat_cache = {}


def heatmap(con, days=30):
    # Unique attacker IPs per hour of the week (Huginn's time zone), over the last `days` days. Cached until the next sync.
    key = (days, get_meta(con, "last_ingest", ""))
    if _heat_cache.get("key") == key:
        return _heat_cache["grid"]
    grid = [[0] * 24 for _ in range(7)]
    for ip, hour in con.execute("SELECT DISTINCT ip, CAST(ts/3600 AS INTEGER) FROM events WHERE ts>=?", (time.time() - days * 86400,)):
        t = datetime.fromtimestamp(hour * 3600, TZ)
        grid[t.weekday()][t.hour] += 1
    _heat_cache.update(key=key, grid=grid)
    return grid


DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def heat_html(grid):
    mx = max(max(r) for r in grid) or 1
    cells = ['<div class="hm-row hm-head"><span></span>%s</div>' % "".join('<span>%s</span>' % (("%02d" % h) if h % 3 == 0 else "") for h in range(24))]
    for d, row in enumerate(grid):
        cells.append('<div class="hm-row"><span class="hm-day">%s</span>%s</div>' % (DAYS[d], "".join(
            '<i class="hm%d" title="%s %02d:00–%02d:00: %s attacker IPs"></i>' % (0 if not v else max(1, -(-v * 8 // mx)), DAYS[d], h, (h + 1) % 24, num(v))
            for h, v in enumerate(row))))
    return ('<div class="heat">%s</div><div class="hm-legend"><span class="hm-what">attacker IPs per hour, %s</span><span>fewer</span>%s<span>more</span></div>'
            % ("".join(cells), esc(str(TZ)), "".join('<i class="hm%d"></i>' % n for n in range(1, 9))))


def hero_card(con, st):
    # The raven banner with what Huginn has seen so far. Two pictures of the same raven: CSS shows the one for the theme (and the text colour with it).
    n_ips, first = con.execute("SELECT COUNT(*), MIN(first) FROM ips").fetchone()
    n_cc = con.execute("SELECT COUNT(DISTINCT e.cc) FROM enrich e JOIN ips i USING(ip) WHERE e.cc IS NOT NULL AND e.cc!=''").fetchone()[0]
    n_logins = con.execute("SELECT COALESCE(SUM(logins_ok + logins_fail), 0) FROM ips").fetchone()[0]
    li = float(get_meta(con, "last_ingest", "0") or 0)
    facts = []
    if first:
        facts.append("watching since %s" % datetime.fromtimestamp(first, TZ).strftime("%Y-%m-%d"))
    facts += ["%s attackers" % num(n_ips), "%s countries" % num(n_cc), "%s login attempts" % num(n_logins)]
    return ('<div class="hero"><img class="hero-dark" src="/static/hero.jpg" alt="" width="2000" height="500">'
            '<img class="hero-light" src="/static/hero-light.jpg" alt="" width="2000" height="500">'
            '<div class="hero-txt"><div class="hero-name">%s</div><div class="hero-tag">Attacker intelligence for a homelab honeypot</div>'
            '<div class="hero-facts">%s%s</div></div></div>'
            % (esc(st["title"] or "Huginn"), esc(" · ".join(facts)), (" · last sync " + esc(ago(li))) if li else ""))


def week_card(con, w=None):
    if w is None:
        end = time.time()
        w = week_summary(con, end - 7 * 86400, end)
    rows = [("Attackers", "%s <span class=muted>%s</span>" % (num(w["active"]), esc(trend(w["active"], w["before"])))),
            ("New attackers", num(w["new_ips"])),
            ("New countries", " ".join(cc_html(c) for c in w["new_cc"][:12]) or "–"),
            ("New campaigns", ('<a href="/campaigns">%d</a> <span class=muted>(%d IPs)</span>' % (w["campaigns"], w["campaign_ips"])) if w["campaigns"] else "–"),
            ("New malware", " ".join("%s ×%d" % (family_tag(k) if k != "Unknown" else '<span class="tag">unknown</span>', v)
                                     for k, v in sorted(w["families"].items(), key=lambda x: -x[1])[:6]) or "–"),
            ("Took the bait", num(w["took"]) if w["took"] else "–")]
    return '<div class="card"><h3>New this week <span class=muted>last 7 days</span></h3>%s</div>' % kv(rows)


def time_wasted(con, since):
    # Time attackers spent in the tarpit (endlessh) and in the fake shells (Cowrie sessions with commands).
    tar = {r[0]: (r[1], r[2]) for r in con.execute(
        "SELECT ip, SUM(CAST(a AS REAL)), MAX(CAST(a AS REAL)) FROM events WHERE kind='tarpit' AND ts>=? GROUP BY ip", (since,))}
    sh = {r[0]: (r[1], r[2]) for r in con.execute(
        "SELECT ip, SUM(duration), MAX(duration) FROM sessions WHERE start>=? AND cmds>0 AND duration IS NOT NULL GROUP BY ip", (since,))}
    rows = []
    for ip in set(tar) | set(sh):
        t, tl = tar.get(ip, (0, 0)); s_, sl = sh.get(ip, (0, 0))
        rows.append({"ip": ip, "tarpit": t or 0, "shell": s_ or 0, "total": (t or 0) + (s_ or 0), "longest": max(tl or 0, sl or 0)})
    rows.sort(key=lambda r: -r["total"])
    st = settings(con)
    visible = rows
    if st["hide_cc"] or st["hide_asn"]:
        en = {r[0]: (r[1] or "", r[2] or "") for r in con.execute("SELECT ip, cc, asn FROM enrich")}
        hcc, has = set(st["hide_cc"]), set(st["hide_asn"])
        visible = [r for r in rows if en.get(r["ip"], ("", ""))[0] not in hcc and en.get(r["ip"], ("", ""))[1] not in has]
    top = visible[:10]
    if top:
        cc = {r[0]: r[1] for r in con.execute("SELECT ip, cc FROM enrich WHERE ip IN (%s)" % ",".join("?" * len(top)), [r["ip"] for r in top])}
        for r in top:
            r["cc"] = cc.get(r["ip"])
    # Stuck right now: ACCEPT without a matching CLOSE (same IP and source port) in the last 2 days.
    opens = con.execute("SELECT ip, a FROM events WHERE kind='tarpit_open' AND ts>=?", (time.time() - 2 * 86400,)).fetchall()
    closed = {(r[0], r[1]) for r in con.execute("SELECT ip, b FROM events WHERE kind='tarpit' AND b IS NOT NULL AND ts>=?", (time.time() - 2 * 86400,))}
    stuck = sum(1 for ip, port in opens if (ip, port) not in closed)
    longest = max(rows, key=lambda r: r["longest"], default=None)    # over all rows, like the totals; the address may be hidden
    return {"tarpit": sum(r["tarpit"] for r in rows), "shell": sum(r["shell"] for r in rows),
            "total": sum(r["total"] for r in rows), "top": top, "stuck": stuck,
            "longest": longest, "longest_shown": bool(longest) and any(r is longest for r in visible)}


IPS_SIZES = (25, 50, 100)
IPS_PHONE_HIDE = {"network", "asn", "rdns", "first", "sessions", "logins", "files", "tarpit", "tags"}     # what a phone leaves out
SORTS = {"score": "i.score DESC, i.last DESC", "last": "i.last DESC", "first": "i.first DESC",
         "sessions": "i.sessions DESC", "cmds": "i.cmds DESC", "logins": "(i.logins_ok+i.logins_fail) DESC"}


def v_ips(qs, mobile=False):
    con = db()
    q = (qs.get("q") or "").strip()[:100]
    days = qs.get("days") or str(settings()["ips_days"])
    tag = (qs.get("tag") or "").strip()[:30]
    ccf = (qs.get("cc") or "").strip().upper()
    ccf = ccf if re.fullmatch(r"[A-Z]{2}", ccf) else ""
    sort = qs.get("sort") if qs.get("sort") in SORTS else "last"
    try:
        pg = max(0, int(qs.get("p") or 0))
    except ValueError:
        pg = 0
    size_default = 25 if mobile else 100
    size = int(qs["n"]) if qs.get("n") in ("25", "50", "100") else size_default
    where, args = [], []
    if days != "all":
        try:
            d = max(1, min(3650, int(days)))
        except ValueError:
            d = 30
        days = str(d)
        where.append("i.last>=?")
        args.append(time.time() - d * 86400)
    if q:
        where.append("(i.ip LIKE ? OR e.org LIKE ? OR e.isp LIKE ? OR e.cc=? OR e.rdns LIKE ? OR e.asn=?)")
        like = "%" + q + "%"
        args += [like, like, like, q.upper(), like, q.lstrip("ASas")]
    if ccf:
        where.append("e.cc=?")
        args.append(ccf)
    if tag == "research":
        where.append("e.research=1")
    elif tag in ("block", "allow"):
        where.append("f.flag=?")
        args.append(tag)
    elif tag:
        where.append("(','||i.tags||',') LIKE ?")
        args.append("%," + tag + ",%")
    st = settings(con)
    show_hidden = qs.get("hidden") == "1"
    nhidden = 0
    hs, ha = hidden_sql(st)
    if hs:
        w0 = ("WHERE " + " AND ".join(where)) if where else ""
        allc = con.execute("SELECT COUNT(*) FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) " + w0, args).fetchone()[0]
        if not show_hidden:
            where.append(hs[5:])
            args += ha
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = con.execute("SELECT COUNT(*) FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) " + w, args).fetchone()[0]
    if hs:
        nhidden = allc - total if not show_hidden else 0
    pg = min(pg, max(0, (total - 1) // size))          # a page past the end (a stale link, or a number SQLite cannot take) shows the last one
    rows = con.execute("SELECT i.*, e.cc, e.org, e.rdns, e.asn, e.research, f.flag FROM ips i LEFT JOIN enrich e USING(ip) "
                       "LEFT JOIN flags f USING(ip) %s ORDER BY %s LIMIT ? OFFSET ?" % (w, SORTS[sort]), args + [size, pg * size]).fetchall()

    def link(**kw):
        p = {"q": q, "days": days, "tag": tag, "cc": ccf, "sort": sort, "hidden": "1" if show_hidden else "", "n": size if size != size_default else ""}
        p.update(kw)
        return "/ips?" + urllib.parse.urlencode({k: v for k, v in p.items() if v not in ("", None)})

    cols = [c for c in IPS_COLS if c[0] in st["ips_cols"]]
    dh = lambda k: " data-h" if k in IPS_PHONE_HIDE else ""
    # The active sort column says so (all sorts are descending): an arrow you can see and aria-sort for screen readers.
    act = lambda key: ' aria-sort="descending"' if key == sort else ""
    hdr = '<th>IP</th>' + "".join(('<th class="%s"%s%s><a href="%s">%s%s</a></th>' % (cls, dh(k), act(key), esc(link(sort=key, p=0)), esc(lab), " ↓" if key == sort else "")) if key
                                  else '<th class="%s"%s>%s</th>' % (cls, dh(k), esc(lab)) for k, lab, key, cls in cols)
    cell = {
        "cc": lambda r: "<td>%s</td>" % cc_html(r["cc"]),
        "network": lambda r: "<td class=trunc title='%s'>%s</td>" % (esc(r["rdns"] or ""), esc(r["org"] or "")),
        "asn": lambda r: "<td class=mono>%s</td>" % (esc("AS" + r["asn"]) if r["asn"] else "–"),
        "rdns": lambda r: "<td class='mono trunc'>%s</td>" % esc(r["rdns"] or "–"),
        "first": lambda r: "<td>%s</td>" % esc(fmt_ts(r["first"])),
        "last": lambda r: "<td>%s</td>" % esc(ago(r["last"])),
        "sessions": lambda r: "<td class=num>%s</td>" % num(r["sessions"]),
        "logins": lambda r: "<td class=num>%s</td>" % num(r["logins_ok"] + r["logins_fail"]),
        "cmds": lambda r: "<td class=num>%s</td>" % num(r["cmds"]),
        "files": lambda r: "<td class=num>%s</td>" % num(r["files"]),
        "tarpit": lambda r: "<td class=num>%s</td>" % (esc(dur(r["tarpit_s"])) if r["tarpit_s"] else "–"),
        "tags": lambda r: "<td>%s</td>" % tag_html(ip_tags(r)),
        "score": score_html_cell,
    }
    show_tags = "tags" in st["ips_cols"]
    trs = "".join("<tr><td>%s</td>%s</tr>%s" % (ip_link(r["ip"]), "".join(cell[c[0]](r).replace("<td", "<td" + dh(c[0]), 1) for c in cols),
                                                 tags_row(ip_tags(r), len(cols) + 1) if show_tags else "") for r in rows)
    opts = lambda cur, vals: "".join('<option value="%s"%s>%s</option>' % (esc(v), " selected" if v == cur else "", esc(l)) for v, l in vals)
    form = ('<form class="filters" method=get action="/ips"><input name=q value="%s" placeholder="IP, network, country code, ASN">'
            '<select name=days>%s</select><select name=tag>%s</select><input type=hidden name=sort value="%s">%s%s<button>Filter</button></form>'
            % (esc(q), opts(days, [("1", "Last 24h"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days"), ("all", "All time")]),
               opts(tag, [("", "Any tag")] + [(t, t) for t in ["took-bait", "read-bait", "shell", "dropper", "proxy", "exploit", "sshole-probe", "web-exploit", "web-probe", "robots-trap", "bruteforce", "multi-service", "tarpitted", "research", "block", "allow"]]), esc(sort),
               ('<input type=hidden name=cc value="%s"><span class="chip on">Country %s <a href="%s" title="Remove country filter">×</a></span>' % (esc(ccf), esc(ccf), esc(link(cc="", p=0)))) if ccf else "",
               '<input type=hidden name=n value="%d">' % size if size != size_default else ""))
    pager, pager_top = "", ""
    if total > IPS_SIZES[0]:
        # A size only makes sense where the server can answer it: the static demo has one fixed list.
        sizes = "" if DEMO else ' <span class="sizes">Show %s</span>' % " ".join(
            "<b>%d</b>" % v if v == size else '<a href="%s">%d</a>' % (esc(link(n=v if v != size_default else "", p=0)), v) for v in IPS_SIZES)
        pager = '<div class="pager">%s<span>%s–%s of %s%s</span>%s</div>' % (
            '<a href="%s">← Prev</a>' % esc(link(p=pg - 1)) if pg > 0 else "<span></span>",
            num(pg * size + 1), num(min(total, pg * size + size)), num(total), sizes,
            '<a href="%s">Next →</a>' % esc(link(p=pg + 1)) if (pg + 1) * size < total else "<span></span>")
        if total > size:
            pager_top = pager.replace('class="pager"', 'class="pager top"', 1)
    hidden_note = ""
    if nhidden:
        hidden_note = '<p class="muted small">%s hidden by your settings · <a href="%s">show them</a></p>' % (num(nhidden), esc(link(hidden="1", p=0)))
    elif show_hidden and hs:
        hidden_note = '<p class="muted small">Showing hidden networks too · <a href="%s">hide them again</a></p>' % esc(link(hidden="", p=0))
    body = ('<h1>Attackers <span class=muted>%s</span></h1>%s%s%s<div class="card"><table class="wide"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>%s'
            % (num(total), form, hidden_note, pager_top, hdr, trs or "<tr><td colspan=%d class=muted>No matches</td></tr>" % (len(cols) + 1), pager))
    return page("Attackers", body, "/ips")


CMD_TOKEN = (r"(?:https?|ftp|tftp)://[^\s'\"<>;|&)`]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|"
             + V6_TOKEN + r"|"
             r"\b(?:wget|curl|tftp|ftpget|chmod|nohup|crontab|base64)\b|authorized_keys")
CMD_RE = re.compile(CMD_TOKEN, re.I)


def session_files(events):
    # Name or URL -> hash for the files captured in one session. Very short names would match everywhere, and a name
    # that held different content during the session cannot be linked to either one.
    out, unclear = {}, set()
    for x in events:
        if x["kind"] == "file" and x["a"] and len(x["a"]) >= 3 and re.fullmatch(r"[0-9a-f]{64}", x["b"] or "") and len(out) < 20:
            name = clean(x["a"])
            if out.get(name, x["b"]) != x["b"]:
                unclear.add(name)
            out[name] = x["b"]
    return {k: v for k, v in out.items() if k not in unclear}


def cmd_html(text, files=None):
    # One log line with its interesting parts marked. Links stay inside Huginn: nothing here may lead to the attacker's server.
    s = clean(text)
    files = files or {}
    rx = CMD_RE
    if files:
        names = "|".join(re.escape(x) for x in sorted(files, key=len, reverse=True))
        rx = re.compile(r"(?<![\w./-])(?:%s)(?=$|[\s'\";|&)<>`])|%s" % (names, CMD_TOKEN), re.I)      # the whole word, not the start of a longer path

    def find(label, q):
        return '<a class="c-l" href="/search?q=%s" title="Search">%s</a>' % (esc(urllib.parse.quote(q, safe="")), esc(label))

    out, pos = [], 0
    for m in rx.finditer(s):
        out.append(esc(s[pos:m.start()]))
        pos, tok = m.end(), m.group(0)
        if tok in files:
            out.append('<a class="c-f" href="/campaign/file/%s" title="Captured file">%s</a>' % (esc(files[tok]), esc(tok)))
        elif "://" in tok:
            try:
                host = urllib.parse.urlsplit(tok).hostname
            except ValueError:
                host = None
            out.append(find(tok, host) if host and len(host) >= 3 else esc(tok))
        elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", tok):
            out.append(find(tok, tok.split(":")[0]))
        elif ":" in tok:
            try:
                ipaddress.IPv6Address(tok)
                out.append(find(tok, tok))
            except ValueError:                  # a clock time, a MAC
                out.append(esc(tok))
        else:
            out.append('<span class="c-k">%s</span>' % esc(tok))
    out.append(esc(s[pos:]))
    return "".join(out)


def score_html(r):
    # What the score is made of. The text below names the parts, in the same order. Rare finds are warm.
    have = set((r["tags"] or "").split(","))
    parts = sorted(score_parts(r["sessions"] or 0, r["logins_ok"] or 0, r["logins_fail"] or 0, r["cmds"] or 0, r["files"] or 0, r["tcpip"] or 0,
                               r["exploits"] or 0, [c for c in (r["canary_svcs"] or "").split(",") if c],
                               "took-bait" in have, "read-bait" in have, "sshole-probe" in have,
                               " ".join(k for k, t in (("exploit", "web-exploit"), ("probe", "web-probe"), ("robots", "robots-trap")) if t in have)), key=lambda p: -p[1])
    if sum(v for _k, v in parts) != r["score"]:         # scored by an older version: do not show numbers that do not add up
        return '<div class="sleg muted">Breakdown unavailable</div>'
    segs = "".join('<i class="g%d%s" title="%s: %d"></i>' % (min(v, 60), " hot" if k in ("took bait", "read bait", "SSHole probe", "files", "exploit") else "", esc(k), v) for k, v in parts)
    return '<div class="sbar" role="img" aria-label="Score breakdown">%s</div><div class="sleg muted">%s</div>' % (
        segs, esc(" · ".join("%s %d" % p for p in parts)))


def ip_story(con, r):
    # One line of plain facts, nothing guessed. "Accepted" is the honeypot's doing: it lets attackers in on purpose.
    plural = lambda n, word: "%s %s%s" % (num(n), word, "" if n == 1 else "s")
    tried, ok = (r["logins_ok"] or 0) + (r["logins_fail"] or 0), r["logins_ok"] or 0
    captured = con.execute("SELECT COUNT(DISTINCT b) FROM events WHERE ip=? AND kind='file' AND b IS NOT NULL", (r["ip"],)).fetchone()[0]
    failed = con.execute("SELECT COUNT(*) FROM events WHERE ip=? AND kind='file_fail'", (r["ip"],)).fetchone()[0]
    tags = set((r["tags"] or "").split(","))
    svcs = [c for c in (r["canary_svcs"] or "").split(",") if c]
    bits = []
    if tried:
        bits.append("tried %s%s" % (plural(tried, "login"), ", %s accepted" % num(ok) if ok else ""))
    if r["cmds"]:
        bits.append("ran %s" % plural(r["cmds"], "command"))
    if captured:
        bits.append("left %s" % plural(captured, "file"))
    elif failed:
        bits.append("failed to fetch %s" % plural(failed, "file"))
    if "took-bait" in tags:
        bits.append("used planted credentials")
    if "read-bait" in tags:
        bits.append("read planted files")
    if r["tcpip"]:
        bits.append("tried to use it as a proxy")
    if r["exploits"]:
        bits.append(plural(r["exploits"], "exploit attempt"))
    if svcs:
        bits.append("touched " + ", ".join(svcs[:5]))
    if r["tarpit_s"]:
        bits.append("spent %s in the tarpit" % dur(r["tarpit_s"]))
    text = ", ".join(bits) if bits else "connected, nothing more"
    return text[0].upper() + text[1:] + "."


# MITRE ATT&CK techniques recognised in commands (0.31). Simple patterns on one command line each, so no regex can
# backtrack badly on attacker text (tests/test_v031.py checks that). A match says what the command tried, not that it worked.
ATTACK = [
    ("T1082", "System Information Discovery", r"\b(?:uname|lscpu|nproc|lsb_release|hostnamectl)\b|/proc/(?:cpuinfo|meminfo|version)\b|/etc/(?:os-release|issue)\b"),
    ("T1033", "System Owner/User Discovery", r"(?:^|[;&|]\s*)(?:whoami|id|who|w)(?:\s|;|$)"),
    ("T1057", "Process Discovery", r"(?:^|[;&|]\s*)(?:ps|top|pgrep)(?:\s|;|$)"),
    ("T1016", "System Network Configuration Discovery", r"\b(?:ifconfig|netstat|arp -a)\b|\bip (?:a|addr|r|route)\b"),
    ("T1552.001", "Credentials In Files", r"\.my\.cnf\b|\.aws/credentials\b|\.git-credentials\b|wp-config\.php\b|/\.env\b"),
    ("T1105", "Ingress Tool Transfer", r"\b(?:wget|curl|tftp|ftpget)\b"),
    ("T1059.004", "Unix Shell", r"\|\s*(?:ba)?sh\b|\b(?:ba)?sh\s+-c\b"),
    ("T1222.002", "Linux File Permissions Modification", r"\bchmod\s+(?:[ugoa]*\+x|[0-7]*[1357][0-7]*)\b"),
    ("T1098.004", "SSH Authorized Keys", r"authorized_keys"),
    ("T1053.003", "Cron", r"\bcrontab\b|/etc/cron"),
    ("T1543.002", "Systemd Service", r"\bsystemctl\s+enable\b|/etc/systemd/system/"),
    ("T1136.001", "Create Local Account", r"\b(?:useradd|adduser)\b"),
    ("T1098", "Account Manipulation", r"\bchpasswd\b|(?:^|[;&|]\s*)passwd(?:\s|;|$)"),
    ("T1070.003", "Clear Command History", r"\bhistory\s+-c\b|unset\s+HISTFILE\b|HISTSIZE=0\b|rm\s[^;|&]{0,80}\.bash_history"),
    ("T1562.004", "Disable or Modify System Firewall", r"\biptables\s+-F\b|\bufw\s+disable\b|\bsetenforce\s+0\b"),
    ("T1496", "Resource Hijacking", r"xmrig|minerd|cpuminer|stratum\+tcp|--donate-level|nicehash"),
]
ATTACK_RE = [(t, n, re.compile(p, re.I)) for t, n, p in ATTACK]
ATTACK_NAME = dict((t, n) for t, n, _p in ATTACK)
ATTACK_NAME.update({"T1110": "Brute Force", "T1090": "Proxy"})


def attack_ids(cmds, logins_fail=0, proxy=0, files=0):
    # Techniques in ATTACK order, plus what a session shows without commands (brute force, proxy, transferred files).
    found = []
    for t, _n, rx in ATTACK_RE:
        if any(rx.search(c or "") for c in cmds):
            found.append(t)
    if files and "T1105" not in found:
        found.append("T1105")
    if logins_fail >= 3:
        found.append("T1110")
    if proxy:
        found.append("T1090")
    return found


def attack_chips(ids, limit=6):
    def chip(t):
        base, _, sub = t.partition(".")
        url = "https://attack.mitre.org/techniques/%s/%s" % (base, (sub + "/") if sub else "")
        return '<a class="tag t-att" href="%s" target="_blank" rel="noopener noreferrer" title="%s">%s</a>' % (esc(url), esc(ATTACK_NAME.get(t, t)), esc(t))
    out = "".join(chip(t) for t in ids[:limit])
    if len(ids) > limit:
        out += '<span class="tag" title="%s">+%d</span>' % (esc(", ".join(ids[limit:])), len(ids) - limit)
    return out


TL_PHASE = {"recon": ("Recon", "t-grey"), "access": ("Access", "t-yellow"), "exec": ("Commands", "t-orange"),
            "payload": ("Payload", "t-red"), "exploit": ("Exploit", "t-red")}


def ip_timeline(con, ip, days=30, steps_max=40):
    # One attacker's visits in order, across every service: the same kind of activity within 30 minutes is one step.
    since = time.time() - days * 86400
    items = []
    cmds_by, runs = {}, set()
    for sid, a, kind in con.execute("SELECT session, a, kind FROM events WHERE ip=? AND kind IN ('cmd','exec_sim') AND ts>=? LIMIT 20000", (ip, since)):
        if kind == "cmd":
            cmds_by.setdefault(sid, []).append(a)
        else:
            runs.add(sid)
    for s in con.execute("SELECT session, start, end, proto, logins_ok lo, logins_fail lf, cmds, files, tcpip FROM sessions "
                         "WHERE ip=? AND start>=? ORDER BY start LIMIT 5000", (ip, since)):
        k = "shell" if (s["cmds"] or s["files"]) else ("login" if s["lo"] + s["lf"] else "connect")
        items.append([s["start"], s["end"] or s["start"], (k, (s["proto"] or "?").upper()),
                      {"n": 1, "lo": s["lo"], "lf": s["lf"], "cmds": s["cmds"], "files": s["files"], "proxy": s["tcpip"],
                       "run": s["session"] in runs, "c": cmds_by.get(s["session"], [])}])
    for ts, svc in con.execute("SELECT ts, a FROM events WHERE ip=? AND kind='canary' AND ts>=? ORDER BY ts LIMIT 20000", (ip, since)):
        key = ("web", "Web") if svc in ("http", "https") else ("decoy", (svc or "?").upper())
        items.append([ts, ts, key, {"n": 1}])
    for ts, secs in con.execute("SELECT ts, a FROM events WHERE ip=? AND kind='tarpit' AND ts>=? LIMIT 5000", (ip, since)):
        try:
            secs = max(0.0, float(secs))
        except (TypeError, ValueError):
            secs = 0.0
        items.append([ts - secs, ts, ("tarpit", "Tarpit"), {"n": 1, "secs": secs}])
    hits = con.execute("SELECT ts, level, cve FROM webhits WHERE ip=? AND ts>=? AND level IN ('exploit','probe')", (ip, since)).fetchall()
    items.sort(key=lambda x: x[0])
    steps = []
    for it in items:
        last = steps[-1] if steps else None
        if last and last[2] == it[2] and it[0] - last[1] <= 1800:
            last[1] = max(last[1], it[1])
            for k, v in it[3].items():
                if k == "c":
                    last[3]["c"] = last[3].get("c", []) + v
                elif k == "run":
                    last[3]["run"] = last[3].get("run") or v
                else:
                    last[3][k] = last[3].get(k, 0) + v
        else:
            steps.append([it[0], it[1], it[2], dict(it[3])])
    if len(steps) < 2:
        return ""
    more = max(0, len(steps) - steps_max)
    lis = []
    for start, end, (kind, label), d in steps[-steps_max:]:
        chips, phase = "", "recon"
        n = d["n"]
        if kind == "connect":
            text = "%s: %s connection%s, nothing more" % (label, num(n), "" if n == 1 else "s")
        elif kind == "login":
            phase = "access"
            text = "%s: %s session%s, %s login attempt%s (%s accepted)" % (label, num(n), "" if n == 1 else "s", num(d["lo"] + d["lf"]),
                                                                       "" if d["lo"] + d["lf"] == 1 else "s", num(d["lo"]))
            chips = attack_chips(attack_ids([], d["lf"]))
        elif kind == "shell":
            phase = "payload" if d["files"] or d.get("run") else "exec"
            text = "%s: %s session%s with %s command%s" % (label, num(n), "" if n == 1 else "s", num(d["cmds"]), "" if d["cmds"] == 1 else "s")
            text += (", %s file%s" % (num(d["files"]), "" if d["files"] == 1 else "s")) if d["files"] else ""
            text += ", ran an uploaded program (simulated)" if d.get("run") else ""
            text += ", used it as a proxy" if d["proxy"] else ""
            chips = attack_chips(attack_ids(d.get("c", []), d["lf"], d["proxy"], d["files"]))
        elif kind == "web":
            mine = [h for h in hits if start - 1 <= h[0] <= end + 1]
            ex = [h for h in mine if h[1] == "exploit"]
            cves = sorted({h[2] for h in ex if h[2] and re.fullmatch(r"CVE-\d{4}-\d{3,7}", h[2])})
            phase = "exploit" if ex else "recon"
            text = "Web: %s request%s" % (num(n), "" if n == 1 else "s")
            if ex:
                text += ", %s exploit%s%s" % (num(len(ex)), "" if len(ex) == 1 else "s", (" (" + ", ".join(cves[:3]) + ")") if cves else "")
            probes = len(mine) - len(ex)
            if probes:
                text += ", %s probe%s" % (num(probes), "" if probes == 1 else "s")
        elif kind == "decoy":
            phase = "access"
            text = "%s: %s tr%s" % (label, num(n), "y" if n == 1 else "ies")
        else:
            text = "Tarpit: held for %s over %s connection%s" % (dur(d.get("secs", 0)), num(n), "" if n == 1 else "s")
        same_day = time.strftime("%Y%m%d", time.localtime(start)) == time.strftime("%Y%m%d", time.localtime(end))
        when = fmt_tss(start) + ((" – " + (datetime.fromtimestamp(end, TZ).strftime("%H:%M") if same_day else fmt_tss(end))) if end - start >= 60 else "")
        plabel, pcls = TL_PHASE[phase]
        lis.append('<li><span class="tl-t mono">%s</span><span class="tag %s">%s</span><span class="tl-x">%s</span>%s</li>'
                   % (esc(when), pcls, plabel, esc(text), (' <span class="tl-c">%s</span>' % chips) if chips else ""))
    return ('<div class="card span2"><h3>Timeline <span class=muted>last %d days%s</span></h3><ol class="tl">%s</ol></div>'
            % (days, (", latest %d steps (%s earlier)" % (steps_max, num(more))) if more else "", "".join(lis)))


def v_ip(ip, qs=None):
    con = db()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    r = con.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
    if not r:
        return None
    e = con.execute("SELECT * FROM enrich WHERE ip=?", (ip,)).fetchone()
    f = con.execute("SELECT * FROM flags WHERE ip=?", (ip,)).fetchone()
    now = time.time()
    tags = r["tags"] or ""
    if e and e["research"]:
        tags += ",research"
    if f:
        tags += "," + f["flag"]

    # Summary
    links = " · ".join(['<a href="/ip/%s/export.json">Export JSON</a>' % esc(urllib.parse.quote(ip)),
                        '<a href="/ip/%s/export.csv">Export CSV</a>' % esc(urllib.parse.quote(ip)),
                        ext("https://www.abuseipdb.com/check/" + ip, "AbuseIPDB"), ext("https://viz.greynoise.io/ip/" + ip, "GreyNoise"),
                        ext("https://www.shodan.io/host/" + ip, "Shodan"), ext("https://www.virustotal.com/gui/ip-address/" + ip, "VirusTotal"),
                        ext("https://ipinfo.io/" + ip, "ipinfo")])
    left = kv([("First seen", esc(fmt_tss(r["first"]))), ("Last seen", "%s <span class=muted>(%s)</span>" % (esc(fmt_tss(r["last"])), esc(ago(r["last"])))),
               ("Sessions", num(r["sessions"])), ("Logins", "%s ok · %s failed" % (num(r["logins_ok"]), num(r["logins_fail"]))),
               ("Commands", num(r["cmds"])), ("Files", num(r["files"])), ("Proxy attempts", num(r["tcpip"])), ("Exploits", num(r["exploits"])),
               ("Other services", esc(r["canary_svcs"] or "–") + (" (%s hits)" % num(r["canary"]) if r["canary"] else "")),
               ("Tarpit", esc(dur(r["tarpit_s"])) if r["tarpit_s"] else "–"), ("Protocols", esc(r["protos"] or "–"))])
    if e:
        right = kv([("Country", "%s %s" % (cc_html(e["cc"]), esc(", ".join(x for x in (e["city"], e["country"]) if x)))),
                    ("ASN", esc("AS" + e["asn"]) if e["asn"] else "–"), ("Org", esc(e["org"] or "–")), ("ISP", esc(e["isp"] or "–")),
                    ("Reverse DNS", '<span class=mono>%s</span>' % esc(e["rdns"] or "–")), ("Hostnames", esc(e["hostnames"] or "–")),
                    ("Open ports", esc(e["ports"] or "–")), ("Shodan tags", esc(e["tags"] or "–")),
                    ("Known CVEs", esc((e["vulns"] or "–")[:400])), ("Looked up", esc(ago(e["fetched"])))])
    else:
        right = '<p class=muted>Lookup pending (country, network, Shodan) — runs in the background.</p>'

    fl = f["flag"] if f else ""
    flag_form = ('<form class="flagform" method=post action="/ip/%s/flag"><label>Blocklist</label><select name=flag>'
                 '<option value=""%s>Automatic (by score)</option><option value=block%s>Always block</option><option value=allow%s>Never block</option></select>'
                 '<input name=note maxlength=200 placeholder="Note" value="%s"><button>Save</button></form>'
                 % (esc(urllib.parse.quote(ip)), " selected" if not fl else "", " selected" if fl == "block" else "", " selected" if fl == "allow" else "", esc(f["note"] if f else "")))

    # Activity, 30 days
    days = [datetime.fromtimestamp(now - i * 86400, TZ).strftime("%Y-%m-%d") for i in range(29, -1, -1)]
    q = {x[0]: x[1] for x in con.execute("SELECT date(ts,'unixepoch','localtime') d, COUNT(*) FROM events WHERE ip=? AND ts>=? AND kind IN ('connect','canary','tarpit') GROUP BY d", (ip, now - 31 * 86400))}
    gaps = gap_days(con, days)
    act = '<div class="card"><h3>Activity, 30 days</h3>%s<div class="axis"><span>%s</span><span>today</span></div>%s</div>' % (bars([q.get(d, 0) for d in days], days, 60, gaps=gaps), esc(days[0]), gap_note(gaps))

    # Credentials
    creds = con.execute("SELECT a,b,SUM(kind='login_ok') ok, COUNT(*) n, MAX(ts) l FROM events WHERE ip=? AND kind IN ('login_ok','login_fail') GROUP BY a,b ORDER BY n DESC, l DESC LIMIT 200", (ip,)).fetchall()
    ccount = con.execute("SELECT COUNT(DISTINCT a||char(0)||COALESCE(b,'')) FROM events WHERE ip=? AND kind IN ('login_ok','login_fail')", (ip,)).fetchone()[0]
    crows = "".join("<tr><td class=mono>%s</td><td class=mono>%s</td><td class=num>%s</td><td>%s</td></tr>" % (esc(clean(c["a"], 80)), esc(clean(c["b"], 80)), num(c["n"]), "accepted" if c["ok"] else "<span class=muted>rejected</span>") for c in creds)
    creds_html = ('<div class="card"><h3>Credentials tried <span class=muted>%s unique</span></h3><input class="qf" data-filter="t-creds" placeholder="Filter">'
                  '<div class="scroll"><table id="t-creds"><thead><tr><th>User</th><th>Password</th><th class=num>Tries</th><th>Result</th></tr></thead><tbody>%s</tbody></table></div></div>'
                  % (num(ccount), crows)) if crows else '<div class="card"><h3>Credentials tried</h3>%s</div>' % none_yet("No logins tried")

    # Files + URLs
    files = con.execute("SELECT a,b,MAX(ts) l,COUNT(*) n,kind FROM events WHERE ip=? AND kind IN ('file','file_fail') GROUP BY kind,a,b ORDER BY l DESC LIMIT 100", (ip,)).fetchall()
    frows = ""
    for x in files:
        sha = x["b"] or ""
        links_f = (ext("https://bazaar.abuse.ch/sample/" + sha + "/", "MalwareBazaar") + " · " + ext("https://www.virustotal.com/gui/file/" + sha, "VirusTotal")) if sha else (ext("https://urlhaus.abuse.ch/browse.php?search=" + urllib.parse.quote(x["a"] or ""), "URLhaus") if x["a"] else "")
        fam, how = file_family(con.execute("SELECT * FROM files WHERE sha=?", (sha,)).fetchone() if sha else None, x["a"] or "")
        frows += "<tr><td class='mono trunc'>%s %s</td><td class=mono>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            family_tag(fam, how), esc(clean(x["a"], 200)), esc(sha[:16] + "…" if sha else ("download failed" if x["kind"] == "file_fail" else "")), esc(ago(x["l"])), num(x["n"]), links_f)
    files_html = ('<div class="card span2"><h3>Files and URLs</h3><table><thead><tr><th>Name / URL</th><th>SHA-256</th><th>Last</th><th>Count</th><th>Lookup</th></tr></thead><tbody>%s</tbody></table></div>' % frows) if frows else ""

    # Related IPs
    same = "SELECT DISTINCT ip FROM sessions WHERE %s IN (SELECT DISTINCT %s FROM sessions WHERE ip=? AND %s IS NOT NULL) AND ip!=?"
    relations = [("Same SSH client (HASSH)", same % ("hassh", "hassh", "hassh"), (ip, ip)),
                 ("Same command script", same % ("cmdhash", "cmdhash", "cmdhash"), (ip, ip)),
                 ("Same file", "SELECT DISTINCT ip FROM events WHERE kind='file' AND b IN (SELECT DISTINCT b FROM events WHERE ip=? AND kind='file' AND b IS NOT NULL) AND ip!=?", (ip, ip))]
    if ":" not in ip:
        relations.append(("Same /24 network", "SELECT ip FROM ips WHERE ip LIKE ? AND ip!=?", (".".join(ip.split(".")[:3]) + ".%", ip)))
    rel = []
    for label, sql, a in relations:
        total = con.execute("SELECT COUNT(*) FROM (%s)" % sql, a).fetchone()[0]
        if total:
            rel.append((label, total, [x[0] for x in con.execute("SELECT r.ip FROM (%s) r JOIN ips i ON i.ip=r.ip ORDER BY i.last DESC, r.ip LIMIT 200" % sql, a)]))

    def rel_row(label, total, ips_):
        links_r = lambda xs: '<div class="rel-ips">%s</div>' % " ".join(ip_link(i) for i in xs)
        more = ""
        if len(ips_) > 5:
            note = '<div class="muted small">Latest 200 of %s</div>' % num(total) if total > len(ips_) else ""
            more = '<details class="rel-more"><summary>Show %s more</summary>%s%s</details>' % (num(len(ips_) - 5), links_r(ips_[5:]), note)
        return '<div class="rel"><div class="rel-l">%s <span class=muted>%s</span></div><div class="rel-r">%s%s</div></div>' % (esc(label), num(total), links_r(ips_[:5]), more)
    rel_html = '<div class="card"><h3>Related attackers</h3>%s</div>' % "".join(rel_row(*x) for x in rel) if rel else ""

    # Sessions
    # Session filter (?s=cmds|logins) and counts for its chips. Most IPs are bots with hundreds of identical sessions.
    sf = (qs or {}).get("s")
    sf = sf if sf in ("cmds", "logins") else "all"
    where = {"all": "", "cmds": " AND cmds>0", "logins": " AND (logins_ok+logins_fail)>0"}[sf]
    sc = con.execute("SELECT COUNT(*), COALESCE(SUM(cmds>0),0), COALESCE(SUM(logins_ok+logins_fail>0),0) FROM sessions WHERE ip=?", (ip,)).fetchone()
    sess = con.execute("SELECT * FROM sessions WHERE ip=?" + where + " ORDER BY start DESC LIMIT 150", (ip,)).fetchall()
    sids = [s["session"] for s in sess]
    evs = {}
    if sids:
        ph = ",".join("?" * len(sids))
        for x in con.execute("SELECT session,ts,kind,a,b FROM events WHERE session IN (%s) AND kind IN ('login_ok','login_fail','cmd','file','file_fail','exec_sim','tcpip','proxy_reply','exploit') ORDER BY ts" % ph, sids):
            evs.setdefault(x["session"], []).append(x)
    def sess_block(s, more=""):
        ev = evs.get(s["session"], [])
        cmd_ts = [x["ts"] for x in ev if x["kind"] == "cmd"]
        human = ""
        if len(cmd_ts) >= 3:
            gaps = sorted(b - a for a, b in zip(cmd_ts, cmd_ts[1:]))
            if gaps[len(gaps) // 2] > 2.0:
                human = '<span class="tag t-orange">human-like</span>'
        lines = []
        tech = attack_ids([x["a"] for x in ev if x["kind"] == "cmd"], s["logins_fail"], s["tcpip"], s["files"])
        fmap = session_files(ev)
        for x in ev:
            rel_t = "+%.1fs" % (x["ts"] - s["start"])
            k = x["kind"]
            if k == "cmd":
                lines.append('<div class="ln"><span class=t>%s</span><span class="pr">$</span><code>%s</code></div>' % (rel_t, cmd_html(x["a"], fmap)))
            elif k in ("login_ok", "login_fail") and sshole_password(s["proto"], x["b"]):
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">sshole</span><code>%s / %s (%d bytes, %s)</code></div>' % (rel_t, esc(clean(x["a"], 100)), esc(clean(x["b"], 100)), len(x["b"].encode("utf-8", "surrogatepass")), "accepted" if k == "login_ok" else "refused"))
            elif k in ("login_ok", "login_fail"):
                lines.append('<div class="ln %s"><span class=t>%s</span><span class="pr">login</span><code>%s / %s</code></div>' % ("ok" if k == "login_ok" else "fail", rel_t, esc(clean(x["a"], 100)), esc(clean(x["b"], 100))))
            elif k == "file":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">file</span><code>%s · %s</code></div>' % (rel_t, cmd_html(clean(x["a"], 300), fmap), ('<a class="c-f" href="/campaign/file/%s">%s</a>' % (esc(x["b"]), esc(x["b"]))) if re.fullmatch(r"[0-9a-f]{64}", x["b"] or "") else esc(x["b"] or "")))
            elif k == "exec_sim":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">run</span><code>%s · <a class="c-f" href="/campaign/file/%s">%s</a> (simulated, nothing ran)</code></div>'
                             % (rel_t, esc(clean(x["a"], 300)), esc(x["b"]), esc((x["b"] or "")[:16])))
            elif k == "file_fail":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">fetch</span><code>%s (failed)</code></div>' % (rel_t, cmd_html(clean(x["a"], 300))))
            elif k == "tcpip":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">proxy</span><code>→ %s</code></div>' % (rel_t, esc(x["a"])))
            elif k == "proxy_reply":
                lines.append('<div class="ln"><span class=t>%s</span><span class="pr">proxy</span><code>%s · %s</code></div>' % (rel_t, esc(clean(x["a"], 200)), esc(PROXY_REPLIES.get(x["b"], "?"))))
            elif k == "exploit":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">exploit</span><code>%s %s</code></div>' % (rel_t, esc(x["a"]), esc(clean(x["b"], 200))))
        persona = PERSONA.get(s["port"] or 0, "")
        summary = ('<span class=mono>%s</span><span>%s %s</span><span>%s</span><span class=muted>%s</span><span>%s</span>%s'
                   % (esc(fmt_tss(s["start"])), esc((s["proto"] or "?").upper()), tag_html(persona), esc(dur(s["duration"])),
                      esc(" · ".join(x for x in ["%d logins" % (s["logins_ok"] + s["logins_fail"]) if (s["logins_ok"] + s["logins_fail"]) else "",
                                                  "%d cmds" % s["cmds"] if s["cmds"] else "", "%d files" % s["files"] if s["files"] else "",
                                                  "%d proxy" % s["tcpip"] if s["tcpip"] else ""] if x) or "connect only"),
                      esc(clean(s["version"] or "", 60)), human + (attack_chips(tech, 4) if tech else ""))
                   + ((' <a class="replay-btn" href="/replay/%s?ip=%s">▶ Replay</a>' % (esc(s["tty"]), esc(urllib.parse.quote(ip)))) if s["tty"] and s["cmds"] else ""))
        meta_ = '<div class="smeta">Session <span class=mono>%s</span>%s%s' % (
            esc(s["session"]), (' · HASSH <a class=mono href="/campaign/hassh/%s">%s</a>' % (esc(s["hassh"]), esc(s["hassh"]))) if s["hassh"] else "",
            (' · script <a class=mono href="/campaign/script/%s">%s</a>' % (esc(s["cmdhash"]), esc(s["cmdhash"]))) if s["cmdhash"] else "") \
            + ((' · terminal <span class=mono>%s</span>' % esc(s["termsize"].replace("x", "×"))) if s["termsize"] else "") \
            + ((' · <a class="replay" href="/replay/%s?ip=%s">▶ Replay</a>' % (esc(s["tty"]), esc(urllib.parse.quote(ip)))) if s["tty"] else "")
        meta_ += "</div>"
        return ('<details class="sess" id="s-%s"><summary>%s%s</summary>%s<div class="term">%s</div></details>'
                % (esc(s["session"]), summary, more, meta_, "".join(lines) or '<div class="ln muted">No interaction recorded.</div>'))

    # Sessions that did something come first, newest first; the same command script is shown once with its repeats folded
    # under it. Sessions that only connected or only tried to log in are folded into two groups at the end.
    busy = lambda s: s["cmds"] or s["files"] or s["tcpip"] or s["exploits"]
    by_script = {}
    for s in sess:
        if busy(s) and s["cmdhash"]:
            by_script.setdefault(s["cmdhash"], []).append(s)
    sblocks, done = [], set()
    for s in sess:
        if not busy(s) or s["session"] in done:
            continue
        same = by_script.get(s["cmdhash"], [s]) if s["cmdhash"] else [s]
        done.update(x["session"] for x in same)
        rest = same[1:]
        sblocks.append(sess_block(s, (' <span class="tag">×%s like this</span>' % num(len(same))) if rest else ""))
        if rest:
            sblocks.append('<details class="sess-more"><summary>Show %s more like this</summary>%s</details>' % (num(len(rest)), "".join(sess_block(x) for x in rest)))
    for label, pick in (("tried to log in, nothing more", lambda s: not busy(s) and (s["logins_ok"] + s["logins_fail"])),
                        ("only connected", lambda s: not busy(s) and not (s["logins_ok"] + s["logins_fail"]))):
        grp = [s for s in sess if pick(s)]
        if grp:
            vers = sorted({clean(s["version"] or "", 40) for s in grp if s["version"]})
            sblocks.append('<details class="sess-more"><summary>%s sessions %s <span class=muted>%s – %s%s</span></summary>%s</details>'
                           % (num(len(grp)), label, esc(fmt_ts(grp[-1]["start"])), esc(fmt_ts(grp[0]["start"])),
                              esc(" · " + ", ".join(vers[:3]) + (" +%d" % (len(vers) - 3) if len(vers) > 3 else "")) if vers else "",
                              "".join(sess_block(x) for x in grp)))
    chip = lambda key, label, n: '<a class="chip%s" href="/ip/%s%s#sessions">%s <span class=muted>%s</span></a>' % (
        " on" if key == sf else "", esc(urllib.parse.quote(ip)), "" if key == "all" else "?s=" + key, esc(label), num(n))
    chips = ('<div class="chips">%s%s%s</div>' % (chip("all", "All", sc[0]), chip("cmds", "With commands", sc[1]), chip("logins", "With logins", sc[2]))
             if sc[0] > 1 else "")
    shown = len(sess)
    sess_html = ('<div class="card span2" id="sessions"><h3>Sessions <span class=muted>%s total%s</span></h3>%s<div class="scroll tall">%s</div></div>'
                 % (num(r["sessions"]), (", latest %s shown" % num(shown)) if shown >= 150 else "", chips,
                    "".join(sblocks) or ("<p class=muted>No SSH/Telnet sessions.</p>" if sf == "all" else none_yet("No sessions like that"))))

    # Other services (OpenCanary, hp-traps) + tarpit
    can = con.execute("SELECT ts,a,b FROM events WHERE ip=? AND kind='canary' ORDER BY ts DESC LIMIT 200", (ip,)).fetchall()
    can_html = ""
    if can:
        dropped = con.execute("SELECT COALESCE(SUM(dropped),0) FROM capped WHERE ip=?", (ip,)).fetchone()[0]
        can_html = ('<div class="card span2"><h3>Other services (decoys)%s</h3><div class="scroll"><table><thead><tr><th>Time</th><th>Service</th><th>Data</th></tr></thead><tbody>%s</tbody></table></div></div>'
                    % ((' <span class=muted>+%s repeated tries counted, not stored</span>' % num(dropped)) if dropped else "",
                       "".join("<tr><td>%s</td><td>%s</td><td class='mono trunc'>%s</td></tr>" % (esc(fmt_tss(x["ts"])), esc(x["a"]), esc(clean(x["b"], 300))) for x in can)))

    # Web attacks: what the rules recognised in this IP's web requests, worst first.
    wh = con.execute("SELECT " + WEB_LEVEL_SQL + " level, type, MAX(cve) cve, MAX(sev) sev, COUNT(*) n, MAX(ts) l, MAX(robots) rb, GROUP_CONCAT(DISTINCT reply) rp "
                     "FROM webhits WHERE ip=? AND (level!='' OR robots OR reply IS NOT NULL) GROUP BY type ORDER BY sev DESC, n DESC LIMIT 40", (ip,)).fetchall()
    if wh:
        wrows = "".join("<tr><td>%s</td><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>"
                        % (web_tag(w["level"], w["type"], w["cve"]) or '<span class=muted>–</span>',
                           esc(", ".join(x for x in (("robots.txt trap" if w["rb"] else ""), ("fake reply: " + w["rp"] if w["rp"] else "")) if x) or (web_rule_info(w["type"]) or [""] * 7)[6]),
                           esc(w["sev"] or "–"), num(w["n"]), esc(ago(w["l"]))) for w in wh)
        can_html += ('<div class="card span2"><h3>Web attacks <span class=muted>rules from Krawl</span></h3><div class="scroll"><table class=wide><thead><tr>'
                     '<th>Attack</th><th>What it is</th><th class=num>Severity</th><th class=num>Requests</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div></div>' % wrows)

    # Mail sent to the relay trap: every recipient and the start of the message (attacker text, escaped, never a link).
    mails = con.execute("SELECT e.ts, e.a, m.mail_from, m.subject, m.rcpts, m.helo, m.size, m.sample FROM mails m JOIN events e ON e.h = m.h "
                        "WHERE e.ip=? ORDER BY e.ts DESC LIMIT 50", (ip,)).fetchall()
    if mails:
        can_html += ('<div class="card span2"><h3>Mail to the relay trap <span class=muted>%s</span></h3><div class="scroll">%s</div></div>'
                     % (num(len(mails)), "".join(mail_block(m) for m in mails)))

    # Sessions come first in the page itself, so reading and keyboard order match what a phone shows.
    body = ('<div class="iphead ip-h"><h1 class="ip-title mono">%s</h1><div class="ip-tags">%s</div><div class="score">Score <b>%s</b></div></div>%s<p class="story">%s</p>'
            '<div class="links">%s</div>'
            '<div class="ip-w"><div class="ip-main">%s%s%s%s%s</div><div class="ip-side"><div class="card"><h3>Activity</h3>%s</div>'
            '<div class="card"><h3>Network</h3>%s</div><div class="card flagcard">%s</div>%s%s</div></div>'
            % (esc(ip), tag_html(tags.strip(",")), r["score"], score_html(r), esc(ip_story(con, r)), links,
               ip_timeline(con, ip), sess_html, files_html, can_html, rel_html, left, right, flag_form, act, creds_html))
    return page(ip, body, "/ips")


def export_ip(ip):
    # Everything Huginn knows about one IP, for JSON/CSV download.
    con = db()
    r = con.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
    if not r:
        return None
    e = con.execute("SELECT * FROM enrich WHERE ip=?", (ip,)).fetchone()
    f = con.execute("SELECT * FROM flags WHERE ip=?", (ip,)).fetchone()
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if t else None
    evs = con.execute("SELECT ts, src, kind, session, a, b FROM events WHERE ip=? ORDER BY ts", (ip,)).fetchall()
    sess = con.execute("SELECT * FROM sessions WHERE ip=? ORDER BY start", (ip,)).fetchall()
    return {
        "ip": ip, "exported": iso(time.time()), "huginn_version": HUGINN_VERSION,
        "summary": {k: r[k] for k in r.keys() if k not in ("first", "last")} | {"first_seen": iso(r["first"]), "last_seen": iso(r["last"])},
        "network": ({k: e[k] for k in e.keys() if k not in ("ip", "fetched", "ok")} | {"looked_up": iso(e["fetched"])}) if e else None,
        "manual_rule": {"rule": f["flag"], "note": f["note"]} if f else None,
        "sessions": [{k: s[k] for k in s.keys() if k not in ("start", "end")} | {"start": iso(s["start"]), "end": iso(s["end"]),
                      "persona": PERSONA.get(s["port"] or 0)} for s in sess],
        "events": [{"time": iso(x["ts"]), "source": x["src"], "kind": x["kind"], "session": x["session"], "a": x["a"], "b": x["b"]} for x in evs],
    }


def csv_safe(v):
    # Attacker text must not become a spreadsheet formula (CSV injection).
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def export_csv(data):
    import csv, io
    safe = csv_safe
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "ip", "source", "kind", "session", "value", "detail"])
    for x in data["events"]:
        w.writerow([x["time"], data["ip"], x["source"], x["kind"], safe(x["session"]), safe(x["a"]), safe(x["b"])])
    return out.getvalue()


def ioc_cell(iocs):
    line = lambda xs: "<br>".join(esc(clean(x, 120)) for x in xs)
    rest = iocs[2:]
    return line(iocs[:2]) + ('<details class="ioc-more"><summary>Show %d more</summary>%s</details>' % (len(rest), line(rest)) if rest else "")


NEW_ROWS = 20


def new_card(con, kind, title, since, limit, head, row, order="observed DESC", cls="card"):
    total = con.execute("SELECT COUNT(*) FROM seen WHERE kind=? AND observed>?", (kind, since)).fetchone()[0]
    if not total:
        return ""
    rows = con.execute("SELECT * FROM seen WHERE kind=? AND observed>? ORDER BY %s LIMIT ?" % order, (kind, since, limit)).fetchall()
    more = '<a class=more href="/new?all=1">Show all %s</a>' % num(total) if total > len(rows) else ""      # never hide what Mark all covers
    return ('<div class="%s"><h3>%s <span class=muted>%s</span>%s</h3><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>'
            % (cls, esc(title), num(total), more, head, "".join("<tr>%s</tr>" % row(r) for r in rows)))


def v_new(qs):
    con = db()
    saved = review_at(con)
    since = saved or time.time() - 7 * 86400
    limit = -1 if qs.get("all") == "1" else NEW_ROWS          # -1: no limit in SQLite
    top, total = con.execute("SELECT MAX(observed), COUNT(*) FROM seen WHERE observed>?", (since,)).fetchone()
    # A link only where the target page can exist: the values come from log data.
    camp = lambda kind, key: ('<a class=mono href="/campaign/%s/%s">%s</a>' % (kind, esc(key), esc(key[:16]))
                              if re.fullmatch(r"[0-9a-f]{8,64}", key) else '<span class=mono>%s</span>' % esc(key[:16]))
    who = lambda r: ip_link(r["ip"], "#s-" + r["session"] if r["session"] else "") if r["ip"] else "–"
    when = lambda r: "<td class=nw>%s</td>" % esc(ago(r["observed"]))

    def r_file(r):
        f = con.execute("SELECT * FROM files WHERE sha=?", (r["key"],)).fetchone()
        fam, how = file_family(f, r["ex"] or "")
        return "<td>%s</td><td>%s</td><td class='mono trunc'>%s</td>%s<td>%s</td>" % (
            camp("file", r["key"]), family_tag(fam, how) if fam else (esc(f["type"]) if f else "–"), esc(r["ex"] or ""), when(r), who(r))

    live = lambda key: con.execute("SELECT 1 FROM sessions WHERE cmdhash=? LIMIT 1", (key,)).fetchone()     # gone after retention: no dead link
    r_cmds = lambda r: (first_cmds(con, r["session"]) if r["session"] else []) or ([r["ex"]] if r["ex"] else [])
    r_script = lambda r: "<td>%s</td><td class='num nw'>%s</td>%s<td>%s</td>" % (script_cell(r["key"], r_cmds(r), bool(live(r["key"]))), num(r["n"]), when(r), who(r))

    r_cmd = lambda r: "<td class='mono wrap'>%s</td><td class='num nw'>%s</td>%s<td>%s</td>" % (esc(r["ex"] or ""), num(r["n"]), when(r), who(r))
    r_pw = lambda r: "<td class=mono>%s</td><td class='mono trunc'>%s</td><td class='num nw'>%s</td>%s<td>%s</td>" % (esc(r["key"]), esc(r["ex"] or ""), num(r["n"]), when(r), who(r))
    r_hassh = lambda r: "<td>%s</td><td class='mono trunc'>%s</td>%s<td>%s</td>" % (camp("hassh", r["key"]), esc(r["ex"] or ""), when(r), who(r))
    cards = (new_card(con, "file", "Files", since, limit, "<th>SHA-256</th><th>Type</th><th>Name</th><th>First</th><th>IP</th>", r_file)
             + new_card(con, "script", "Scripts", since, limit, "<th>Script</th><th class=num>Runs</th><th>First</th><th>IP</th>", r_script)
             + new_card(con, "cmd", "Commands", since, limit, "<th>Example</th><th class=num>Runs</th><th>First</th><th>IP</th>", r_cmd, "n DESC, observed DESC", "card span2")
             + new_card(con, "pw", "Password patterns", since, limit, "<th>Pattern</th><th>Example</th><th class=num>Tries</th><th>First</th><th>IP</th>", r_pw)
             + new_card(con, "hassh", "SSH clients", since, limit, "<th>HASSH</th><th>Client</th><th>First</th><th>IP</th>", r_hassh))
    what = "since %s" % fmt_tss(saved) if saved else "last 7 days, not reviewed yet"
    acts = ""
    if not DEMO:
        if top is not None:
            acts += ('<form method=post action="/new/reviewed"><input type=hidden name=at value="%s"><button>Mark all %s reviewed</button></form>'
                     % (esc(repr(top)), num(total)))
        if get_meta(con, "review_prev") is not None:
            acts += '<form method=post action="/new/undo"><button class="btn-s">Undo</button></form>'
    body = ('<div class="newhead"><div><h1>New</h1><p class=muted>Never seen before, %s</p></div><div class="newact">%s</div></div>%s'
            % (esc(what), acts, '<div class="grid">%s</div>' % cards if total else '<div class="card muted">Nothing new.</div>'))
    return page("New", body, "/new")


# A guess at "going for a payload": a download tool with a target in the same command, or a step that only makes sense
# after one. "which wget", "curl --version" or reading authorized_keys are still looking around.
PAYLOAD_RE = re.compile(r"\b(?:wget|curl|tftp|ftpget)\b[^;|&\n]{0,400}\s(?!-)[^\s;|&]{0,400}\.[^\s;|&]|/dev/tcp/|>>?\s{0,20}\S{0,400}authorized_keys|chmod\s+(?:[ugoa]*\+x|7[0-7]{2})\s|base64\s+-d", re.I)
_persona_cache = {}
_identity_cache = {}
WEB_REQUEST_RE = re.compile(r"[A-Z]{3,12} \S+(?: \(\d+\))?(?:  body: |  · |$)")


def persona_stats(con):
    # Finished sessions the honeypot let in, sorted by how far they got. Cached until the data changes (sync, import, retention).
    key = (get_meta(con, "last_ingest", ""), con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0],
           con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
    if _persona_cache.get("key") == key:
        return _persona_cache["data"]
    ev = {}
    for sid, kind, a in con.execute("SELECT session,kind,a FROM events WHERE kind IN ('cmd','file','file_fail') AND session IS NOT NULL ORDER BY ts,rowid"):
        x = ev.setdefault(sid, [[], False])
        if kind == "cmd":
            if (a or "").strip():
                x[0].append(a)
        else:
            x[1] = True
    rows, stop, ran, probe = {}, {}, {}, {}
    for s in con.execute("SELECT session,port,proto,logins_ok FROM sessions WHERE duration IS NOT NULL"):
        name = PERSONA.get(s["port"] or 0) or "%s:%s" % ((s["proto"] or "?").lower(), s["port"] or "?")
        r = rows.setdefault(name, {"persona": name, "sessions": 0, "in": 0, "none": 0, "one": 0, "short": 0, "payload": 0})
        r["sessions"] += 1
        if not s["logins_ok"]:
            continue
        r["in"] += 1
        cmds, got_file = ev.get(s["session"], ([], False))
        if got_file or any(PAYLOAD_RE.search(c) for c in cmds):
            r["payload"] += 1
            many = True
        elif not cmds:
            r["none"] += 1
            continue
        elif len(cmds) == 1:
            r["one"] += 1
            g = probe.setdefault(cmd_shape(cmds[0]), [0, cmds[0]])
            g[0] += 1
            continue
        else:
            r["short"] += 1
            g = stop.setdefault(cmd_shape(cmds[-1]), {"n": 0, "ex": cmds[-1], "by": {}})
            g["n"] += 1
            g["by"][name] = g["by"].get(name, 0) + 1
            many = True
        if many:
            for shape in {cmd_shape(c) for c in cmds}:      # the denominator: only sessions that did more than one thing
                ran[shape] = ran.get(shape, 0) + 1
    stops = [dict(v, shape=k, ran=ran.get(k, v["n"])) for k, v in stop.items() if v["n"] >= 2]
    data = {"rows": sorted(rows.values(), key=lambda r: -r["sessions"]),
            "stops": sorted(stops, key=lambda v: (-v["n"], v["shape"]))[:30],
            "probes": sorted(probe.items(), key=lambda kv: (-kv[1][0], kv[0]))[:10]}
    _persona_cache.update(key=key, data=data)
    return data


def identity_stats(con):
    # Web traffic per device the trap pretended to be. An identity can come back, so its periods are added up.
    # Cached until the data changes: this walks every web event.
    key = (get_meta(con, "last_ingest", ""), con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0],
           con.execute("SELECT COUNT(*) FROM web_identities").fetchone()[0])
    if _identity_cache.get("key") == key:
        return _identity_cache["data"]
    hist = con.execute("SELECT ts,id,kind,label FROM (SELECT * FROM web_identities ORDER BY ts DESC LIMIT 1000) ORDER BY ts").fetchall()
    now, out = time.time(), {}
    # Time only counts where Huginn was collecting and still keeps the data. Pruned periods are unknown, not quiet, but a
    # quiet day while collecting is a real zero: so this is when anything at all was first kept, not the first web hit.
    kept = max(con.execute("SELECT COALESCE(MIN(ts), ?) FROM events", (now,)).fetchone()[0], now - RETENTION_DAYS * 86400 if RETENTION_DAYS else 0)
    for i, h in enumerate(hist):
        end = hist[i + 1]["ts"] if i + 1 < len(hist) else now
        current = i + 1 == len(hist)
        if end <= kept and not current:
            continue
        r = out.setdefault(h["id"], {"id": h["id"], "kind": h["kind"], "label": h["label"], "secs": 0.0, "hits": 0, "logins": 0, "ips": set(), "last": 0, "now": False})
        r.update(label=h["label"], secs=r["secs"] + max(0.0, end - max(h["ts"], kept)), last=end, now=current)
        for ip, b in con.execute("SELECT ip,b FROM events WHERE kind='canary' AND a IN ('http','https') AND ts>=? AND ts<?", (h["ts"], end)):
            r["hits"] += 1
            r["ips"].add(ip)
            if canary_is_login("http", b):
                r["logins"] += 1
    rows = [dict(r, ips=len(r["ips"]), per_day=r["hits"] * 86400.0 / max(r["secs"], 3600.0)) for r in out.values()]
    rows.sort(key=lambda r: (-r["now"], -r["per_day"]))
    _identity_cache.update(key=key, data=rows)
    return rows


def identity_section(con):
    rows = identity_stats(con)
    if not rows:
        return "<h2>Web trap</h2><div class=\"card\">%s</div>" % none_yet("The honeypot has not announced a web identity yet")
    days = lambda s: ("%.1f" % (s / 86400.0)).replace(".0", "")
    trs = "".join("<tr><td>%s%s</td><td>%s</td><td class='num nw'>%s</td><td class='num nw'><b>%s</b></td><td class='num nw'>%s</td><td class='num nw'>%s</td></tr>"
                  % (esc(r["label"]), ' <span class="now-tag">now</span>' if r["now"] else "", tag_html(r["kind"]), days(r["secs"]), ("%.1f" % r["per_day"]).replace(".0", ""), num(r["ips"]), num(r["logins"])) for r in rows)
    # NAS against router, once both have run. Per day, so a device that ran longer does not win by default.
    kinds = {}
    for r in rows:
        k = kinds.setdefault(r["kind"], [0.0, 0])
        k[0] += r["secs"]
        k[1] += r["hits"]
    compare = ""
    if len(kinds) > 1:
        compare = '<p class="muted small note">%s</p>' % esc(" · ".join("%s %.1f hits a day" % (k.upper() if k == "nas" else k.capitalize(), v[1] * 86400.0 / max(v[0], 3600.0)) for k, v in sorted(kinds.items())))
    return ('<h2>Web trap</h2><p class=muted>What ports 80 and 443 have pretended to be. Compare hits per day: each one runs for a different time.</p>'
            '<div class="card"><table class="wide"><thead><tr><th>Device</th><th>Type</th><th class=num>Days</th><th class=num>Hits a day</th><th class=num>Attackers</th><th class=num>Login tries</th></tr></thead><tbody>%s</tbody></table>%s</div>' % (trs, compare))


def v_personas():
    d = persona_stats(db())
    n = lambda v: "<td class='num nw'>%s</td>" % num(v)
    pct = lambda a, b: "<td class='num nw'>%d%%</td>" % round(a * 100.0 / b) if b else "<td class='num nw muted'>–</td>"
    outcomes = (("none", "No command", "o-none"), ("one", "One line", "o-one"), ("short", "Stopped short", "o-short"), ("payload", "Went for payload", "o-pay"))

    def journey(r):
        # What happened after the login, as shares of those who got in. The exact numbers stay right below the bar.
        if not r["in"]:
            return "<span class=muted>Nobody got in</span>"
        parts = [(k, lab, c, r[k]) for k, lab, c in outcomes if r[k]]
        bar = "".join('<i class="%s p%d" title="%s: %s"></i>' % (c, max(1, round(v * 100.0 / r["in"])), esc(lab), num(v)) for _k, lab, c, v in parts)
        leg = "".join('<span><i class="%s"></i>%s <b>%s</b></span>' % (c, esc(lab), num(r[k])) for k, lab, c in outcomes)
        return '<div class="dist" role="img" aria-label="Outcome after login">%s</div><div class="dleg">%s</div>' % (bar, leg)

    lab_n = lambda label, v: "<td class='num nw' data-l='%s'>%s</td>" % (esc(label), num(v))
    share = lambda r: ("<td class='num nw' data-l='Payload share'>%d%%</td>" % round(r["payload"] * 100.0 / (r["short"] + r["payload"]))) if r["short"] + r["payload"] else "<td class='num nw muted' data-l='Payload share'>–</td>"
    rows = "".join("<tr><td>%s</td>%s%s<td class=pb>%s</td>%s</tr>" % (tag_html(r["persona"]), lab_n("Sessions", r["sessions"]), lab_n("Got in", r["in"]), journey(r), share(r))
                   for r in d["rows"])
    stops = "".join("<tr><td class='mono wrap'>%s</td>%s%s%s<td>%s</td></tr>" % (esc(clean(s["ex"], 300)), n(s["n"]), n(s["ran"]), pct(s["n"], s["ran"]),
                    " ".join("%s <span class=muted>%s</span>" % (tag_html(k), num(v)) for k, v in sorted(s["by"].items(), key=lambda x: -x[1]))) for s in d["stops"])
    probes = "".join("<tr><td class='mono wrap'>%s</td>%s</tr>" % (esc(clean(v[1], 300)), n(v[0])) for _k, v in d["probes"])
    body = ('<h1>Personas</h1><p class=muted>How far attackers get on each fake machine. Finished sessions, by port, under the current persona names.</p>'
            '<div class="card">%s<p class="muted small note">One line: a single input line, then gone. Stopped short: several lines, no download seen. Went for payload is a best guess from files and commands. Payload share is of those two.</p></div>'
            '%s<h2>Where they stopped</h2><p class=muted>The last line before a session with several lines ended with no download seen. A hint, not proof: they may have spotted the fake or simply been done.</p>'
            '<div class="card">%s</div>'
            '<h2>One-line sessions</h2><div class="card">%s</div>'
            % ('<table class="wide ptab"><thead><tr><th>Persona</th><th class=num>Sessions</th><th class=num>Got in</th><th>After the login</th><th class=num>Payload share</th></tr></thead><tbody>%s</tbody></table>' % rows if rows else none_yet("No finished sessions yet"),
               identity_section(db()),
               '<table class="wide"><thead><tr><th>Last command, example</th><th class=num>Stopped here</th><th class=num>Ran it</th><th class=num>Stop rate</th><th>Persona</th></tr></thead><tbody>%s</tbody></table>' % stops if stops else none_yet("No repeated stopping points yet"),
               '<table class="wide"><thead><tr><th>Command, example</th><th class=num>Sessions</th></tr></thead><tbody>%s</tbody></table>' % probes if probes else none_yet("No one-line sessions yet")))
    return page("Personas", body, "/personas")


# ---------------------------------------------------------------- engagement over time (0.32)
# Do changes to the honeypot keep attackers busier? Sessions that got in, by local day: what they did after the login,
# how long they stayed, how many were typed by hand, and whether the attackers were new. A release can be picked to
# compare the days before it with the days after it.
ENG_RANGES = (7, 14, 30)
ENG_OUTCOMES = (("left", "Left at once", "o-none"), ("proxy", "Proxy only", "o-one"), ("cmds", "Ran commands", "o-short"), ("payload", "Went for payload", "o-pay"))
_eng_cache = {}


def day_start(d):
    return datetime(d.year, d.month, d.day, tzinfo=TZ).timestamp()


def eng_sessions(con, since, until):
    # Finished shell sessions that got in, started in [since, until). One dict per session, oldest first.
    rows = con.execute("SELECT s.session, s.ip, s.start, s.duration, s.tcpip, s.files, s.termsize, i.first FROM sessions s "
                       "LEFT JOIN ips i ON i.ip=s.ip WHERE s.start>=? AND s.start<? AND s.logins_ok>0 AND s.duration IS NOT NULL "
                       "ORDER BY s.start LIMIT 200000", (since, until)).fetchall()
    cmds = {}
    for sid, ts, a in con.execute("SELECT session, ts, a FROM events WHERE kind='cmd' AND ts>=? AND ts<? AND session IS NOT NULL",
                                  (since, until + 86400)):
        cmds.setdefault(sid, []).append((ts, a or ""))
    out = []
    for r in rows:
        c = [x for x in cmds.get(r["session"], []) if x[1].strip()]
        text = [x[1] for x in c]
        if r["files"] or any(PAYLOAD_RE.search(x) for x in text):
            kind = "payload"
        elif text:
            kind = "cmds"
        elif r["tcpip"]:
            kind = "proxy"
        else:
            kind = "left"
        day = datetime.fromtimestamp(r["start"], TZ).strftime("%Y-%m-%d")
        first = datetime.fromtimestamp(r["first"], TZ).strftime("%Y-%m-%d") if r["first"] else day
        out.append({"day": day, "ip": r["ip"], "kind": kind, "dur": r["duration"] or 0.0, "cmds": len(text),
                    "human": human_gaps([x[0] for x in c]), "new": first >= day, "size": r["termsize"]})
    return out


def eng_summary(rows):
    n = len(rows)
    d = {"n": n, "ips": len({r["ip"] for r in rows}), "new_ips": len({r["ip"] for r in rows if r["new"]}),
         "human": sum(r["human"] for r in rows)}
    for k, _l, _c in ENG_OUTCOMES:
        d[k] = sum(r["kind"] == k for r in rows)
    durs = sorted(r["dur"] for r in rows)
    d["median"] = durs[n // 2] if n else None
    busy = [r["cmds"] for r in rows if r["cmds"]]
    d["cmds_avg"] = sum(busy) / len(busy) if busy else None
    return d


def engagement_data(con, days, version=None):
    key = (days, version, get_meta(con, "last_ingest", ""), con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
    if _eng_cache.get("key") == key:
        return _eng_cache["data"]
    today = datetime.now(TZ).date()
    start = day_start(today - timedelta(days=days - 1))
    rows = eng_sessions(con, start, time.time() + 1)
    labels = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
    per = {lab: [] for lab in labels}
    for r in rows:
        if r["day"] in per:
            per[r["day"]].append(r)
    data = {"labels": labels, "days": [(lab, eng_summary(per[lab])) for lab in labels], "total": eng_summary(rows)}
    # Terminal sizes in the same window: every SSH session that asked for one, not only those that got in.
    sizes = {}
    asked = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND termsize IS NOT NULL", (start,)).fetchone()[0]
    shells = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND cmds>0 AND proto='ssh'", (start,)).fetchone()[0]
    sized = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND cmds>0 AND proto='ssh' AND termsize IS NOT NULL", (start,)).fetchone()[0]
    hum = {r["ip"] for r in rows if r["human"]}
    for size, sid, ip, c in con.execute("SELECT termsize, session, ip, cmds FROM sessions WHERE start>=? AND termsize IS NOT NULL LIMIT 50000", (start,)):
        x = sizes.setdefault(size, {"size": size, "n": 0, "ips": set(), "cmds": 0, "human_ips": set()})
        x["n"] += 1
        x["ips"].add(ip)
        x["cmds"] += 1 if c else 0
        if ip in hum:
            x["human_ips"].add(ip)
    data["sizes"] = sorted(({"size": v["size"], "n": v["n"], "ips": len(v["ips"]), "cmds": v["cmds"], "human_ips": len(v["human_ips"])}
                            for v in sizes.values()), key=lambda v: (-v["n"], v["size"]))[:30]
    data["asked"], data["shells"], data["sized"] = asked, shells, sized
    # Before and after a release: up to 7 whole days on each side, the release day itself left out.
    data["cmp"] = None
    rel = {v: dt for v, dt, _t in CHANGELOG}
    if version in rel:
        vday = datetime.strptime(rel[version], "%Y-%m-%d").date()
        after_days = max(0, min(7, (today - vday).days - 1))
        span = max(after_days, 1)
        before = eng_sessions(con, day_start(vday - timedelta(days=span)), day_start(vday))
        after = eng_sessions(con, day_start(vday + timedelta(days=1)), day_start(vday + timedelta(days=1 + after_days))) if after_days else []
        data["cmp"] = {"version": version, "date": rel[version], "days": after_days, "before": eng_summary(before), "after": eng_summary(after)}
    _eng_cache.update(key=key, data=data)
    return data


def eng_pct(a, b):
    return "%d%%" % round(a * 100.0 / b) if b else "–"


def v_engagement(qs=None):
    qs = qs or {}
    try:
        days = int(qs.get("days", 14))
    except (TypeError, ValueError):
        days = 14
    days = days if days in ENG_RANGES else 14
    version = qs.get("v") or None
    versions = [v for v, _d, _t in CHANGELOG][:20]
    version = version if version in versions else None
    d = engagement_data(db(), days, version)
    t = d["total"]
    link = lambda n: "/engagement?" + urllib.parse.urlencode(dict({"days": n}, **({"v": version} if version else {})))
    chips = '<div class="chips">%s</div>' % "".join('<a class="chip%s" href="%s">%d days</a>' % (" on" if n == days else "", esc(link(n)), n) for n in ENG_RANGES)

    def dist(r):
        if not r["n"]:
            return "<span class=muted>Nobody got in</span>"
        bar = "".join('<i class="%s p%d" title="%s: %s"></i>' % (c, max(1, round(r[k] * 100.0 / r["n"])), esc(lab), num(r[k])) for k, lab, c in ENG_OUTCOMES if r[k])
        return '<div class="dist" role="img" aria-label="What they did after the login">%s</div>' % bar

    leg = '<div class="dleg">%s</div>' % "".join('<span><i class="%s"></i>%s <b>%s</b></span>' % (c, esc(lab), num(t[k])) for k, lab, c in ENG_OUTCOMES)
    kpis = [("Got in", num(t["n"]), "%s attackers" % num(t["ips"])),
            ("Left at once", eng_pct(t["left"], t["n"]), "logged in, then nothing"),
            ("Ran commands", eng_pct(t["cmds"] + t["payload"], t["n"]), "%s went for a payload" % num(t["payload"])),
            ("Typed by hand", num(t["human"]), "human-like sessions"),
            ("Median stay", esc(dur(t["median"])) if t["median"] is not None else "–", "per session that got in"),
            ("New attackers", eng_pct(t["new_ips"], t["ips"]), "first seen that day")]
    kp = '<div class="kpis">%s</div>' % "".join('<div class="kpi"><div class="kpi-l">%s</div><div class="kpi-v">%s</div><div class="kpi-s">%s</div></div>'
                                                 % (esc(a), b, esc(c)) for a, b, c in kpis)
    chart = ('<div class="card"><h3>Sessions that got in, per day</h3>%s<div class="axis"><span>%s</span><span>today</span></div></div>'
             % (bars([x[1]["n"] for x in d["days"]], d["labels"], 60, partial_last=True), esc(d["labels"][0])))
    cell = lambda v, label: "<td class='num nw' data-l='%s'>%s</td>" % (esc(label), v)
    rows = "".join("<tr><td class=nw>%s</td>%s<td class=pb>%s</td>%s%s%s%s%s</tr>"
                   % (esc(lab), cell(num(r["n"]), "Got in"), dist(r), cell(eng_pct(r["left"], r["n"]), "Left at once"),
                      cell(num(r["human"]) if r["n"] else "–", "Typed by hand"), cell(esc(dur(r["median"])) if r["median"] is not None else "–", "Median stay"),
                      cell(("%.1f" % r["cmds_avg"]) if r["cmds_avg"] else "–", "Commands"),
                      cell(("%s / %s" % (num(r["new_ips"]), num(r["ips"] - r["new_ips"]))) if r["ips"] else "–", "New / returning"))
                   for lab, r in reversed(d["days"]))
    table = ('<div class="card">%s<table class="wide etab"><thead><tr><th>Day</th><th class=num>Got in</th><th>After the login</th><th class=num>Left at once</th>'
             '<th class=num>Typed by hand</th><th class=num>Median stay</th><th class=num>Commands</th><th class=num>New / returning</th></tr></thead><tbody>%s</tbody></table>'
             '<p class="muted small note">Finished SSH and Telnet sessions that logged in. Left at once: no command, no file, no proxy use. Commands: average per session that ran any. '
             'New / returning: attackers first seen that day, and those seen before.</p></div>' % (leg, rows)) if t["n"] else '<div class="card">%s</div>' % none_yet("No sessions got in during these days")

    # Before / after a release
    opts = "".join('<option value="%s"%s>%s · %s</option>' % (esc(v), " selected" if v == version else "", esc(v), esc(dt)) for v, dt, _t in CHANGELOG[:20])
    form = ('<form class="filters" method=get action="/engagement"><input type=hidden name=days value="%d"><select name=v aria-label="Release">'
            '<option value="">Pick a release</option>%s</select><button>Compare</button></form>' % (days, opts))
    cmp_html = ""
    c = d["cmp"]
    if c and not c["days"]:
        cmp_html = '<p class=muted>%s is from %s: there is no whole day after it yet.</p>' % (esc(c["version"]), esc(c["date"]))
    elif c:
        b, a = c["before"], c["after"]
        def line(label, fb, fa, better_up=True, kind="pct"):
            if fb is None or fa is None:
                return "<tr><td>%s</td><td class=num>–</td><td class=num>–</td><td class=num>–</td></tr>" % esc(label)
            if kind == "pct":
                vb, va, show = fb, fa, lambda v: "%d%%" % round(v)
                diff = "%+d points" % round(va - vb)
            elif kind == "dur":
                vb, va, show = fb, fa, lambda v: dur(v)
                diff = ("%+d%%" % round((va - vb) * 100.0 / vb)) if vb else "–"
            else:
                vb, va, show = fb, fa, lambda v: ("%.1f" % v) if isinstance(v, float) else num(v)
                diff = ("%+d%%" % round((va - vb) * 100.0 / vb)) if vb else ("%+d" % round(va) if va else "–")
            good = (va > vb) == better_up if va != vb and better_up is not None else None
            cls = "" if good is None else (" t-green" if good else " t-red")
            return "<tr><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class='num%s'>%s</td></tr>" % (esc(label), esc(show(vb)), esc(show(va)), cls, esc(diff))
        per_day = lambda x: x["n"] / float(c["days"])
        sh = lambda x, k: (x[k] * 100.0 / x["n"]) if x["n"] else None
        ran = lambda x: ((x["cmds"] + x["payload"]) * 100.0 / x["n"]) if x["n"] else None
        new_share = lambda x: (x["new_ips"] * 100.0 / x["ips"]) if x["ips"] else None
        body_rows = "".join([
            line("Got in, per day", per_day(b), per_day(a), None, "n"),
            line("Left at once", sh(b, "left"), sh(a, "left"), False),
            line("Proxy only", sh(b, "proxy"), sh(a, "proxy"), False),
            line("Ran commands", ran(b), ran(a), True),
            line("Went for payload", sh(b, "payload"), sh(a, "payload"), True),
            line("Typed by hand", b["human"], a["human"], True, "n"),
            line("Median stay", b["median"], a["median"], True, "dur"),
            line("Commands per busy session", b["cmds_avg"], a["cmds_avg"], True, "n"),
            line("New attackers", new_share(b), new_share(a), None)])
        few = '<p class="muted small note">Few sessions on one side (under 30): read the change with care.</p>' if min(b["n"], a["n"]) < 30 else ""
        cmp_html = ('<p class=muted>%d whole days before %s (%s) against %d whole days after it. The release day itself is left out. '
                    'Other things change too (new botnets, quiet weekends), so this is a hint, not proof.</p>'
                    '<table class="wide"><thead><tr><th>Measure</th><th class=num>Before (%s)</th><th class=num>After (%s)</th><th class=num>Change</th></tr></thead><tbody>%s</tbody></table>%s'
                    % (c["days"], esc(c["version"]), esc(c["date"]), c["days"], num(b["n"]), num(a["n"]), body_rows, few))

    # Terminal sizes
    if d["sizes"]:
        srows = "".join("<tr><td class=mono>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td></tr>"
                        % (esc(x["size"].replace("x", "×")), num(x["n"]), num(x["ips"]), num(x["cmds"]), num(x["human_ips"]) if x["human_ips"] else "<span class=muted>–</span>")
                        for x in d["sizes"])
        sizes = ('<p class=muted>%s of %s SSH sessions with commands asked for a terminal (%s sessions asked in all). Scripts usually run commands without one, '
                 'and a bot that asks tends to use the same size every time; a person\'s window size varies.</p>'
                 '<table class="wide"><thead><tr><th>Size</th><th class=num>Sessions</th><th class=num>Attackers</th><th class=num>With cmds</th>'
                 '<th class=num title="Attackers with a session that looks typed by hand">By hand</th></tr></thead><tbody>%s</tbody></table>'
                 % (num(d["sized"]), num(d["shells"]), num(d["asked"]), srows))
    else:
        sizes = none_yet("No session asked for a terminal size in these days")

    body = ('<h1>Engagement</h1><p class=muted>How far attackers get once they are in, day by day, and how that changes after a release. Times are %s.</p>%s%s%s%s'
            '<h2>Before and after a release</h2><div class="card">%s%s</div>'
            '<h2>Terminal sizes</h2><div class="card">%s</div>'
            % (esc(str(TZ)), chips, kp, chart, table, form, cmp_html, sizes))
    return page("Engagement", body, "/engagement")


SEARCH_ROWS = 50


def snippet(text, q, width=260):
    # Log text around the match, with the match marked. Every piece is escaped on its own.
    s = clean(text or "", 4000)
    at = s.lower().find(q.lower())
    if at > 80:
        s = "…" + s[at - 60:]
    width = max(width, len(q) + 120)         # the whole match always fits
    if len(s) > width:
        s = s[:width] + "…"
    return "".join("<mark>%s</mark>" % esc(p) if i % 2 else esc(p) for i, p in enumerate(re.split("(%s)" % re.escape(q), s, flags=re.I)))


def v_search(qs):
    con = db()
    q = (qs.get("q") or "").strip()[:200]
    days = qs.get("days") if qs.get("days") in ("7", "30") else "all"
    since = time.time() - int(days) * 86400 if days != "all" else 0
    tabs = " ".join('<a class="chip%s" href="/search?q=%s&days=%s">%s</a>' % (" on" if d == days else "", esc(urllib.parse.quote(q)), d, l)
                    for d, l in (("all", "All"), ("30", "30 days"), ("7", "7 days")))
    form = ('<h1>Search</h1><form class="filters" method=get action="/search"><input name=q value="%s" maxlength=200 placeholder="Command, URL, hash, IP or session" autofocus>'
            '<input type=hidden name=days value="%s"><button>Search</button></form><div class="chips">%s</div>' % (esc(q), esc(days), tabs))
    if len(q) < 3:
        return page("Search", form + '<p class=muted>Type at least 3 characters.</p>', "/search")
    pat = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like, pre = "%" + pat + "%", pat + "%"
    n = lambda v: "<td class='num nw'>%s</td>" % num(v)
    when = lambda ts: "<td class=nw>%s</td>" % esc(ago(ts))
    who = lambda ip, sid: "<td>%s</td>" % ip_link(ip, "#s-" + sid if sid else "")

    def section(title, total, head, rows):
        if not total:
            return ""
        more = ' <span class=muted>latest %d shown</span>' % SEARCH_ROWS if total > SEARCH_ROWS else ""
        return '<div class="card"><h3>%s <span class=muted>%s</span>%s</h3><table class="wide"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
            esc(title), num(total), more, head, "".join("<tr>%s</tr>" % r for r in rows))

    # Commands: the same shape once, with every attacker who ran a variant of it.
    groups = {}
    for r in con.execute("SELECT a,ip,session,MAX(ts) l,COUNT(*) c FROM events WHERE kind='cmd' AND ts>=? AND a LIKE ? ESCAPE '\\' GROUP BY a,ip ORDER BY l DESC", (since, like)):
        g = groups.setdefault(cmd_shape(r["a"]), {"ex": r["a"], "n": 0, "ips": set(), "l": r["l"], "ip": r["ip"], "s": r["session"]})
        g["n"] += r["c"]
        g["ips"].add(r["ip"])
    cmds = section("Commands", len(groups), "<th>Example</th><th class=num>Runs</th><th class=num>IPs</th><th>Last</th><th>IP</th>",
                   ["<td class='mono wrap'>%s</td>%s%s%s%s" % (snippet(g["ex"], q), n(g["n"]), n(len(g["ips"])), when(g["l"]), who(g["ip"], g["s"])) for g in list(groups.values())[:SEARCH_ROWS]])

    # Files: by hash, name or an address found inside the file. Few enough to compare in Python, on the real values
    # (the stored addresses are JSON text and several names can belong to one hash). A file known only from its metadata counts too.
    needle, seen_f = q.lower(), {}
    for b, a, ip, ts in con.execute("SELECT b,a,ip,ts FROM events WHERE kind='file' AND b IS NOT NULL AND ts>=?", (since,)):
        g = seen_f.setdefault(b, {"names": set(), "ips": set(), "l": 0})
        if a:
            g["names"].add(a)
        g["ips"].add(ip)
        g["l"] = max(g["l"], ts)
    meta = {r["sha"]: r for r in con.execute("SELECT * FROM files")}
    for sha, f in meta.items():
        if sha not in seen_f and (f["mtime"] or 0) >= since and not con.execute("SELECT 1 FROM events WHERE kind='file' AND b=? LIMIT 1", (sha,)).fetchone():
            seen_f[sha] = {"names": set(), "ips": set(), "l": f["mtime"] or 0, "only_meta": True}
    found = []
    for sha, g in seen_f.items():
        f = meta.get(sha)
        try:
            iocs = [str(x) for x in json.loads(f["iocs"])] if f and f["iocs"] else []
        except ValueError:
            iocs = []
        hit = next((x for x in sorted(g["names"]) + iocs if needle in x.lower()), None)
        if hit is not None or sha.startswith(needle):
            found.append((g["l"], sha, g, f, hit))
    found.sort(key=lambda x: (-x[0], x[1]))
    frows = []
    for last, sha, g, f, hit in found[:SEARCH_ROWS]:
        fam, how = file_family(f, ",".join(sorted(g["names"])))
        link = "<a class=mono href=\"/campaign/file/%s\">%s…</a>" % (esc(sha), esc(sha[:16])) if not g.get("only_meta") else "<span class=mono>%s…</span>" % esc(sha[:16])
        frows.append("<td>%s</td><td>%s</td><td class='mono wrap'>%s</td>%s%s" % (
            link, family_tag(fam, how) if fam else (esc(f["type"]) if f else "–"), snippet(hit if hit is not None else sha, q), n(len(g["ips"])), when(last)))
    files_ = section("Files", len(found), "<th>SHA-256</th><th>Type</th><th>Match</th><th class=num>IPs</th><th>Last</th>", frows)

    urls = con.execute("SELECT a,ip,session,MAX(ts) l,COUNT(*) c,COUNT(DISTINCT ip) nip FROM events WHERE kind='file_fail' AND ts>=? AND a LIKE ? ESCAPE '\\' GROUP BY a ORDER BY l DESC", (since, like)).fetchall()
    fails = section("Failed downloads", len(urls), "<th>URL</th><th class=num>Tries</th><th class=num>IPs</th><th>Last</th><th>IP</th>",
                    ["<td class='mono wrap'>%s</td>%s%s%s%s" % (snippet(r["a"], q), n(r["c"]), n(r["nip"]), when(r["l"]), who(r["ip"], r["session"])) for r in urls[:SEARCH_ROWS]])

    where = "kind='canary' AND ts>=? AND (b LIKE ? ESCAPE '\\' OR a LIKE ? ESCAPE '\\')"
    can_n = con.execute("SELECT COUNT(*) FROM events WHERE " + where, (since, like, like)).fetchone()[0]
    can = con.execute("SELECT ts,ip,a,b FROM events WHERE " + where + " ORDER BY ts DESC LIMIT ?", (since, like, like, SEARCH_ROWS)).fetchall()
    decoys = section("Decoy services", can_n, "<th>Service</th><th>Data</th><th>Last</th><th>IP</th>",
                     ["<td>%s</td><td class='mono wrap'>%s</td>%s%s" % (esc(r["a"]), snippet(r["b"], q), when(r["ts"]), who(r["ip"], None)) for r in can])

    ses_n = con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND session LIKE ? ESCAPE '\\'", (since, pre)).fetchone()[0]
    ses = con.execute("SELECT session,ip,start,cmds FROM sessions WHERE start>=? AND session LIKE ? ESCAPE '\\' ORDER BY start DESC LIMIT ?", (since, pre, SEARCH_ROWS)).fetchall()
    sessions_ = section("Sessions", ses_n, "<th>Session</th><th class=num>Commands</th><th>Started</th><th>IP</th>",
                        ["<td class=mono>%s</td>%s%s%s" % (snippet(r["session"], q), n(r["cmds"]), when(r["start"]), who(r["ip"], r["session"])) for r in ses])

    ip_n = con.execute("SELECT COUNT(*) FROM ips WHERE last>=? AND ip LIKE ? ESCAPE '\\'", (since, pre)).fetchone()[0]
    ips_ = con.execute("SELECT i.ip,i.last,i.score,e.cc,e.org FROM ips i LEFT JOIN enrich e USING(ip) WHERE i.last>=? AND i.ip LIKE ? ESCAPE '\\' ORDER BY i.last DESC LIMIT ?", (since, pre, SEARCH_ROWS)).fetchall()
    attackers = section("Attackers", ip_n, "<th>IP</th><th>CC</th><th>Network</th><th>Last</th><th class=num>Score</th>",
                        ["<td>%s</td><td>%s</td><td class=trunc>%s</td>%s%s" % (ip_link(r["ip"]), cc_html(r["cc"]), esc(r["org"] or ""), when(r["last"]), n(r["score"])) for r in ips_])

    wa = con.execute("SELECT type, MAX(cve) cve, MAX(level='exploit') x, COUNT(DISTINCT ip) nip, MAX(ts) l FROM webhits WHERE ts>=? AND level IN ('exploit','probe') "
                     "AND (cve LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\') GROUP BY type ORDER BY l DESC LIMIT ?", (since, like, like, SEARCH_ROWS)).fetchall()
    webs = section("Web attacks", len(wa), "<th>Attack</th><th>Type</th><th class=num>IPs</th><th>Last</th>",
                   ["<td>%s</td><td class=mono>%s</td>%s%s" % (web_tag("exploit" if r["x"] else "probe", r["type"], r["cve"]), snippet(r["type"], q), n(r["nip"]), when(r["l"])) for r in wa])

    quoted = esc(urllib.parse.quote(q))
    also = '<p class="muted small">Also look in <a href="/ips?q=%s">attacker networks</a> or <a href="/creds?q=%s">credentials</a>.</p>' % (quoted, quoted)
    found_any = cmds + files_ + fails + webs + decoys + sessions_ + attackers
    return page("Search", form + '<div class="stack-w">%s</div>%s' % (found_any or '<div class="card muted">Nothing found.</div>', also), "/search")


def v_files(qs=None):
    con = db()
    want = ((qs or {}).get("fam") or "")[:80]
    ev = {r["sha"]: r for r in con.execute("SELECT b sha, MIN(ts) f, MAX(ts) l, COUNT(*) n, COUNT(DISTINCT ip) nip, GROUP_CONCAT(DISTINCT a) names "
                                            "FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b")}
    fi = {r["sha"]: r for r in con.execute("SELECT * FROM files")}
    shas = sorted(set(ev) | set(fi), key=lambda x: -((ev[x]["l"] if x in ev else 0) or (fi[x]["mtime"] if x in fi else 0)))
    fams = {sha: file_family(fi.get(sha), ev[sha]["names"] if sha in ev else "") for sha in shas}
    # Chips per family (with counts) filter the list; "Unknown" are files no rule recognised yet.
    counts = {}
    for fam, _how in fams.values():
        counts[fam or ""] = counts.get(fam or "", 0) + 1
    if want and want != "unknown" and want not in counts:
        want = ""
    chip = lambda key, label, n: '<a class="chip%s" href="/files%s">%s <span class=muted>%s</span></a>' % (
        " on" if key == want else "", ("?fam=" + esc(urllib.parse.quote(key))) if key else "", esc(label), num(n))
    chips = ('<div class="chips">' + chip("", "All", len(shas))
             + "".join(chip(k, k, n) for k, n in sorted(counts.items(), key=lambda x: (-x[1], x[0])) if k)
             + (chip("unknown", "Unknown", counts[""]) if counts.get("") else "") + "</div>") if len(counts) > 1 or counts.get("") else ""
    if want:
        shas = [x for x in shas if (fams[x][0] or "unknown") == want or (want == "unknown" and not fams[x][0])]
    shas = shas[:300]
    trs = ""
    for sha in shas:
        e, f = ev.get(sha), fi.get(sha)
        iocs = json.loads(f["iocs"]) if f and f["iocs"] else []
        fam, how = fams[sha]
        kind = (family_tag(fam, how) if fam else "") + ('<div class="ft">%s</div>' % (esc(f["type"]) + (" · " + esc(f["arch"]) if f["arch"] else "") + (' <span class="tag t-orange">UPX</span>' if f["packed"] else "")
                + ('' if f["src"] != "redir" else ' <span class="tag">echo-built</span>')) if f else '<span class=muted>–</span>')
        trs += ("<tr><td class=mono>%s</td><td>%s</td><td class='num nw'>%s</td><td class='mono trunc'>%s</td><td class='mono small iocs'>%s</td><td class=nw>%s</td><td class=num>%s</td><td class=nw>%s · %s</td></tr>"
                % (("<a href='/campaign/file/%s'>%s…</a>" % (esc(sha), esc(sha[:16]))) if e else esc(sha[:16]) + "…", kind,
                   esc("%.1f KB" % (f["size"] / 1024.0)) if f else "", esc(clean(e["names"], 200)) if e else "",
                   ioc_cell(iocs),
                   esc(ago(e["l"] if e else f["mtime"])), num(e["nip"]) if e else "",
                   ext("https://bazaar.abuse.ch/sample/%s/" % sha, "MalwareBazaar"), ext("https://www.virustotal.com/gui/file/" + sha, "VirusTotal")))
    urls = con.execute("SELECT a, MAX(ts) l, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind='file_fail' AND a IS NOT NULL GROUP BY a ORDER BY l DESC LIMIT 200").fetchall()
    urs = "".join("<tr><td class='mono trunc'>%s</td><td>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                  % (esc(clean(u["a"], 200)), esc(ago(u["l"])), num(u["n"]), num(u["nip"]), ext("https://urlhaus.abuse.ch/browse.php?search=" + urllib.parse.quote(u["a"]), "URLhaus")) for u in urls)
    body = ('<h1>Files</h1><p class=muted>Captured by the honeypot (uploads and downloads). Never executed here — look them up by hash only.</p>'
            '<div class="card">%s%s</div><h2>Malware URLs (fetch blocked)</h2><div class="card">%s</div>'
            % (chips, '<input class="qf" data-filter="t-files" placeholder="Filter"><table id="t-files" class="wide"><thead><tr><th>SHA-256</th><th>Type</th><th class=num>Size</th><th>Names / URLs</th>'
               '<th>Embedded IPs / URLs</th><th>Last</th><th class=num>IPs</th><th>Lookup</th></tr></thead><tbody>%s</tbody></table>' % trs if trs else none_yet("No files captured yet"),
               '<table class="wide"><thead><tr><th>URL</th><th>Last</th><th class=num>Tries</th><th class=num>IPs</th><th>Lookup</th></tr></thead><tbody>%s</tbody></table>' % urs if urs else none_yet("No blocked downloads recorded")))
    return page("Files", body, "/files")


def v_creds(qs):
    con = db()
    days = qs.get("days") or "7"
    if days not in ("1", "7", "30", "all"):
        days = "7"
    since = 0 if days == "all" else time.time() - int(days) * 86400
    users = con.execute("SELECT a, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind IN ('login_ok','login_fail') AND ts>=? GROUP BY a ORDER BY n DESC LIMIT 300", (since,)).fetchall()
    pws = con.execute("SELECT b, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind IN ('login_ok','login_fail') AND ts>=? GROUP BY b ORDER BY n DESC LIMIT 300", (since,)).fetchall()
    pairs = con.execute("SELECT a,b, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind IN ('login_ok','login_fail') AND ts>=? GROUP BY a,b ORDER BY n DESC LIMIT 500", (since,)).fetchall()
    canary = con.execute("SELECT a svc, b, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind='canary' AND b LIKE '% / %' AND ts>=? GROUP BY a,b ORDER BY n DESC", (since,)).fetchall()
    canary = [r for r in canary if canary_is_login(r["svc"], r["b"])][:300]
    t = lambda rows, cols: "".join("<tr>%s</tr>" % "".join(c(r) for c in cols) for r in rows)
    td = lambda k, n=80: (lambda r: "<td class=mono>%s</td>" % esc(clean(r[k], n)))
    tn = lambda k: (lambda r: "<td class=num>%s</td>" % num(r[k]))
    tabs = " ".join('<a class="chip%s" href="/creds?days=%s">%s</a>' % (" on" if d == days else "", d, l) for d, l in [("1", "24h"), ("7", "7 days"), ("30", "30 days"), ("all", "All")])
    q = (qs.get("q") or "").strip()[:100]
    search = ""
    if q:
        found, total = cred_search(con, q)
        rows = "".join("<tr><td>%s</td><td class=mono>%s</td><td class=mono>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                       % (esc(svc), esc(clean(u, 60)), esc(clean(pw, 60)), num(d["n"]), num(len(d["ips"])), esc(ago(d["last"])))
                       for (svc, u, pw), d in found)
        search = ('<div class="card"><h3>Search: %s <span class=muted>%s matches%s</span></h3><table><thead><tr><th>Service</th><th>User</th><th>Password</th>'
                  '<th class=num>Tries</th><th class=num>IPs</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div>'
                  % (esc(q), num(total), ", first 200" if total > 200 else "", rows or '<tr><td colspan=6 class=muted>Nothing found.</td></tr>'))
    exp = " · ".join('<a href="/creds/export.%s?days=%s%s">%s</a>' % (ext, days, ("&what=" + w) if w else "", lab)
                     for ext, w, lab in [("txt", "passwords", "Passwords (word list)"), ("txt", "usernames", "Usernames (word list)"), ("csv", "", "Every attempt (CSV)")])
    check = ('<div class="grid2"><div class="card"><h3>Is my password in here?</h3>'
             '<form class="pwcheck" id="pwcheck" data-src="/api/creds-check/" data-prefix="%d"><input type="password" id="pwc-in" autocomplete="off" '
             'placeholder="Type a password to check" aria-label="Password to check"> <button type=submit>Check</button></form>'
             '<div id="pwc-out" class="pwc-out" aria-live="polite"></div>'
             '<p class="muted small">Checked in your browser. Only the first %d characters of its SHA-256 hash are sent to Huginn, '
             'never the password itself. Exact match, case-sensitive.</p></div>'
             '<div class="card"><h3>Search and export</h3><form method=get action="/creds" class="pwcheck"><input name=q value="%s" '
             'placeholder="Search usernames and passwords" aria-label="Search"><input type=hidden name=days value="%s"> <button type=submit>Search</button></form>'
             '<p class="muted small">For words like your name, domain or company. Do not type real passwords here: the search is sent to Huginn. '
             'Use the check on the left instead.</p><p class=small>Export (%s): %s</p></div></div>'
             % (CRED_PREFIX, CRED_PREFIX, esc(q), esc(days), {"1": "24h", "7": "7 days", "30": "30 days", "all": "all"}[days], exp))
    def card(title, tid, heads, rows):
        # Fixed height, scrolls inside, header row stays visible, own filter box.
        if not rows:
            return '<div class="card"><h3>%s</h3>%s</div>' % (title, none_yet("Nothing in this period"))
        return ('<div class="card"><h3>%s <span class=muted>top %s</span></h3><input class="qf" data-filter="%s" placeholder="Filter">'
                '<div class="scroll tall"><table id="%s"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div></div>'
                % (title, num(rows.count("<tr>")), tid, tid, heads, rows))
    nums = '<th class=num>Tries</th><th class=num>IPs</th>'
    body = (('<h1>Credentials</h1><div class="chips">%s</div>' % tabs) + check + search + '<div class="grid3">'
            + card("Usernames", "t-cu", "<th>User</th>" + nums, t(users, [td("a"), tn("n"), tn("nip")]))
            + card("Passwords", "t-cp", "<th>Password</th>" + nums, t(pws, [td("b"), tn("n"), tn("nip")]))
            + card("Pairs (SSH/Telnet)", "t-cpair", "<th>User</th><th>Password</th>" + nums, t(pairs, [td("a", 40), td("b", 40), tn("n"), tn("nip")]))
            + card("Other services", "t-cother", "<th>Service</th><th>User / password</th>" + nums, t(canary, [td("svc", 10), td("b", 80), tn("n"), tn("nip")]))
            + '</div>')
    return page("Credentials", body, "/creds")


# ---------------------------------------------------------------- every password attackers tried
# "Is my password in here?": the browser hashes the password (SHA-256) and sends only the first CRED_PREFIX hex
# characters. Huginn answers with every tried password whose hash starts the same way, and the browser compares the
# rest itself. Your password never leaves the browser, so it cannot end up in a log, a proxy or Huginn's database.
CRED_PREFIX = 4
_cred_lock = threading.Lock()
_cred_cache = {"key": None}


def canary_is_login(svc, b):
    # A decoy line holds a login as "user / password". Since 0.23.1 the parsers keep " / " out of everything else (see
    # not_a_login), so this only has to recognise lines stored before that: requests, service data as JSON, mail and proxy
    # summaries. Those guesses can be wrong for an odd old line. A login whose user name looks like one is not counted.
    if not b or " / " not in b:
        return False
    if svc in ("http", "https") and WEB_REQUEST_RE.match(b):
        return False
    return not b.startswith(("{", "relay: ", "proxy -> "))


def cred_rows(con, since=0):
    # Every login attempt on every service: (ts, ip, service, user, password, accepted).
    out = []
    q = ("SELECT e.ts, e.ip, e.src, e.kind, e.a, e.b, s.proto FROM events e LEFT JOIN sessions s ON s.session = e.session "
         "WHERE e.ts >= ? AND (e.kind IN ('login_ok','login_fail') OR (e.kind = 'canary' AND e.b LIKE '% / %')) ORDER BY e.ts")
    for ts, ip, src, kind, a, b, proto in con.execute(q, (since,)):
        if kind == "canary":
            if not canary_is_login(a, b):
                continue
            user, _, pw = (b or "").partition(" / ")
            if src == "traps":
                pw = re.sub(r"  \(db .*\)$", "", pw)
            svc = a or "?"
        else:
            user, pw, svc = a or "", b or "", proto or "ssh"
        if user or pw:
            out.append((ts, ip, svc, user, pw, kind == "login_ok"))
    return out


def pw_hash(pw):
    return hashlib.sha256(pw.encode("utf-8", "replace")).hexdigest()


def cred_index(con):
    global _cred_cache
    key = "%s|%s" % (get_meta(con, "last_ingest", ""), con.execute("SELECT COUNT(*) FROM events WHERE kind IN ('login_ok','login_fail','canary')").fetchone()[0])
    with _cred_lock:
        if _cred_cache.get("key") == key:
            return _cred_cache
        agg, oldest = {}, None
        for ts, ip, svc, user, pw, ok in cred_rows(con):
            if not pw:
                continue
            oldest = ts if oldest is None else min(oldest, ts)
            d = agg.get(pw)
            if d is None:
                d = agg[pw] = {"tries": 0, "ok": 0, "ips": set(), "first": ts, "last": ts, "svcs": {}, "users": {}}
            d["tries"] += 1
            d["ok"] += 1 if ok else 0
            d["ips"].add(ip)
            d["last"] = max(d["last"], ts)
            d["svcs"][svc] = d["svcs"].get(svc, 0) + 1
            d["users"][user] = d["users"].get(user, 0) + 1
        buckets = {}
        for pw, d in agg.items():
            h = pw_hash(pw)
            buckets.setdefault(h[:CRED_PREFIX], []).append((h[CRED_PREFIX:], d))
        # A new object each time: a page still reading the old one must not see it emptied.
        _cred_cache = {"key": key, "buckets": buckets, "distinct": len(agg), "oldest": oldest}
        return _cred_cache


def cred_check(con, prefix):
    idx = cred_index(con)
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    matches = [{"s": suf, "tries": d["tries"], "accepted": d["ok"], "ips": len(d["ips"]), "first": iso(d["first"]), "last": iso(d["last"]),
                "services": sorted(d["svcs"], key=lambda k: -d["svcs"][k])[:8],
                "users": [[u, n] for u, n in sorted(d["users"].items(), key=lambda x: -x[1])[:10]]}
               for suf, d in idx["buckets"].get(prefix, [])]
    return {"distinct": idx["distinct"], "since": iso(idx["oldest"]) if idx["oldest"] else None, "matches": matches}


def cred_export(con, what, days):
    since = 0 if days == "all" else time.time() - int(days) * 86400
    rows = cred_rows(con, since)
    if what in ("passwords", "usernames"):
        # A word list, most tried first: one entry per line, so entries with line breaks are left out.
        count = {}
        for r in rows:
            v = r[4] if what == "passwords" else r[3]
            if v and "\n" not in v and "\r" not in v:
                count[v] = count.get(v, 0) + 1
        return "".join(v + "\n" for v, _ in sorted(count.items(), key=lambda x: (-x[1], x[0]))), "text/plain"
    import csv, io
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "ip", "service", "username", "password", "accepted"])
    for ts, ip, svc, user, pw, ok in rows:
        w.writerow([datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), ip, csv_safe(svc), csv_safe(user), csv_safe(pw), "yes" if ok else "no"])
    return out.getvalue(), "text/csv"


def cred_search(con, q, limit=200):
    # Plain text search in usernames and passwords (for words like your domain or company name, not real passwords).
    ql = q.lower()
    agg = {}
    for ts, ip, svc, user, pw, ok in cred_rows(con):
        if ql in user.lower() or ql in pw.lower():
            d = agg.setdefault((svc, user, pw), {"n": 0, "ips": set(), "last": 0})
            d["n"] += 1
            d["ips"].add(ip)
            d["last"] = max(d["last"], ts)
    return sorted(agg.items(), key=lambda x: (-x[1]["n"], -x[1]["last"]))[:limit], len(agg)


def mail_block(m):
    try:
        rcpts = [str(x) for x in json.loads(m["rcpts"] or "[]")]
    except ValueError:
        rcpts = []
    head = ("<div class=mail-h><b>%s</b> <span class=muted>%s · %s · %s</span></div>"
            "<div class=mono>From %s</div><div class='mono fd-d'>To %s</div><div>Subject: %s</div>"
            % (esc(fmt_tss(m["ts"])), esc(m["a"]), esc("HELO " + clean(m["helo"], 120) if m["helo"] else "no HELO"), esc(size_fmt(m["size"])),
               esc(clean(m["mail_from"], 200) or "?"), esc(", ".join(clean(r, 200) for r in rcpts) or "?"), esc(clean(m["subject"], 200))))
    body = ('<details><summary>Message (first %s characters)</summary><pre class="mono mail-body">%s</pre></details>'
            % (num(len(m["sample"])), esc(m["sample"]))) if m["sample"] else ""
    return '<div class=mail>%s%s</div>' % (head, body)


def size_fmt(n):
    n = n or 0
    return "%d bytes" % n if n < 1024 else "%.1f KB" % (n / 1024.0) if n < 1048576 else "%.1f MB" % (n / 1048576.0)


def v_campaigns(qs=None):
    con = db()
    # "Active" = scripts run in the last 7 days, busiest first; otherwise all time, as before. IPs 7d shows which are still going.
    active = (qs or {}).get("active") == "1"
    d7 = time.time() - 7 * 86400
    scripts = con.execute("SELECT cmdhash, COUNT(*) n, COUNT(DISTINCT ip) nip, COUNT(DISTINCT CASE WHEN start>=? THEN ip END) nip7, "
                          "MIN(start) f, MAX(start) l, MAX(cmds) c, MIN(session) sid FROM sessions WHERE cmdhash IS NOT NULL GROUP BY cmdhash "
                          + ("HAVING MAX(start)>=? ORDER BY nip7 DESC, nip DESC LIMIT 60" if active else "ORDER BY nip DESC, n DESC LIMIT 60"),
                          (d7, d7) if active else (d7,)).fetchall()
    srows = ""
    for s in scripts:
        srows += "<tr><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td><td>%s</td></tr>" % (
            script_cell(s["cmdhash"], first_cmds(con, s["sid"])), num(s["c"]), num(s["nip"]), (num(s["nip7"]) if s["nip7"] else '<span class=muted>–</span>'),
            num(s["n"]), esc(fmt_ts(s["f"])), esc(ago(s["l"])))
    stabs = ('<div class="chips"><a class="chip%s" href="/campaigns">All time</a><a class="chip%s" href="/campaigns?active=1">Active, 7 days</a></div>'
             % ("" if active else " on", " on" if active else ""))
    hs = con.execute("SELECT hassh, COUNT(*) n, COUNT(DISTINCT ip) nip, MAX(version) v, MAX(start) l FROM sessions WHERE hassh IS NOT NULL "
                     "GROUP BY hassh ORDER BY nip DESC LIMIT 40").fetchall()
    hrows = "".join("<tr><td class=mono><a href='/campaign/hassh/%s'>%s</a></td><td class='mono trunc'>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                    % (esc(h["hassh"]), esc(h["hassh"]), esc(clean(h["v"] or "", 60)), num(h["nip"]), num(h["n"]), esc(ago(h["l"]))) for h in hs)
    # Web attacks by rule: how many addresses tried the same thing.
    wa = con.execute("SELECT type, MAX(cve) cve, MAX(sev) sev, MAX(level='exploit') x, COUNT(DISTINCT ip) nip, COUNT(*) n, MAX(ts) l FROM webhits "
                     "WHERE level IN ('exploit','probe') GROUP BY type ORDER BY x DESC, nip DESC, n DESC LIMIT 60").fetchall()
    warows = "".join("<tr><td class=nowrap>%s</td><td class=trunc>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>"
                     % (web_tag("exploit" if w["x"] else "probe", w["type"], w["cve"]), esc((web_rule_info(w["type"]) or [""] * 7)[6]),
                        num(w["sev"]), num(w["nip"]), num(w["n"]), esc(ago(w["l"]))) for w in wa)

    # Mail clients: the name a bot gives in HELO/EHLO is often its own and stays the same across many addresses.
    hl = con.execute("SELECT LOWER(SUBSTR(b, 6)) name, COUNT(DISTINCT ip) nip, COUNT(*) n, MAX(ts) l FROM events "
                     "WHERE kind='canary' AND src='traps' AND b LIKE 'HELO %' GROUP BY name ORDER BY nip DESC, n DESC LIMIT 40").fetchall()
    hlrows = "".join("<tr><td class='mono fd-d'><a href='/search?q=%s&days=all'>%s</a></td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                     % (esc(urllib.parse.quote("HELO " + h["name"], safe="")), esc(clean(h["name"], 120)), num(h["nip"]), num(h["n"]), esc(ago(h["l"]))) for h in hl)
    # Proxy use: what bots fetch through the fake SSH proxy, and whether the honeypot answered (Cowrie patch).
    since = time.time() - 7 * 86400
    ps = con.execute("SELECT COUNT(*) n, SUM(tcpip) t, COUNT(DISTINCT ip) nip FROM sessions WHERE tcpip > 0 AND start >= ?", (since,)).fetchone()
    pa = con.execute("SELECT COUNT(*) FROM events WHERE kind='proxy_reply' AND ts >= ?", (since,)).fetchone()[0]
    pr = con.execute("SELECT a, b, COUNT(DISTINCT ip) nip, COUNT(*) n, MAX(ts) l FROM events WHERE kind='proxy_reply' AND ts >= ? "
                     "GROUP BY a, b ORDER BY nip DESC, n DESC LIMIT 40", (since,)).fetchall()
    prows = "".join("<tr><td class='mono trunc'>%s</td><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>"
                    % (esc(clean(r["a"], 120)), esc(PROXY_REPLIES.get(r["b"], "?")), num(r["nip"]), num(r["n"]), esc(ago(r["l"]))) for r in pr)
    psum = ("<p class=muted>Last 7 days: %s proxy sessions from %s IPs, %s proxy requests (%.1f per session), %s answered by the honeypot. "
            "Nothing is ever forwarded: plain HTTP checks get an empty 200 page, TLS is held silently for up to 30 s.</p>"
            % (num(ps["n"] or 0), num(ps["nip"] or 0), num(ps["t"] or 0), (ps["t"] or 0) / float(ps["n"] or 1), num(pa)))
    # Slow replies (0.27): the slow robots export and the mail queue wait. Did bots stay, and did they still go on?
    dr = con.execute("SELECT COUNT(*) n, SUM(b LIKE 'done %') d, AVG(CAST(substr(b, 6) AS REAL)) s FROM events WHERE kind='web_drip' AND ts >= ?", (since,)).fetchone()
    mt, mip = [], set()
    for r in con.execute("SELECT ip, b FROM events WHERE kind='trap_end' AND ts >= ?", (since,)):
        try:
            secs, mails, waited = (float(x) for x in (r["b"] or "").split())
        except ValueError:
            continue
        if mails > 0:
            mt.append((secs, mails, waited)); mip.add(r["ip"])
    slow = ("<p class=muted>Last 7 days. Web: %s slow exports (robots paths, about 4.5 s), %s sent in full, %s left early, %.1f s on average. "
            "Mail: %s sessions that sent mail, from %s IPs, %.1f messages and %.0f s per session, %.0f s of it waiting for the fake queue (1 to 2.5 s per message, after the message is logged).</p>"
            % (num(dr["n"] or 0), num(dr["d"] or 0), num((dr["n"] or 0) - (dr["d"] or 0)), dr["s"] or 0.0,
               num(len(mt)), num(len(mip)), sum(x[1] for x in mt) / float(len(mt) or 1),
               sum(x[0] for x in mt) / float(len(mt) or 1), sum(x[2] for x in mt) / float(len(mt) or 1)))
    body = ('<h1>Campaigns</h1><p class=muted>Attackers grouped by command script (addresses, numbers and random markers ignored), SSH client fingerprint (HASSH), web attack (rules from Krawl), mail client name (HELO) and what they fetch through the fake SSH proxy.</p>'
            '<div class="cgrid"><section class="cs-wide"><h2>Command scripts</h2><div class="card">%s</div></section><section><h2>SSH clients (HASSH)</h2><div class="card">%s</div></section>'
            '<section class="cs-wide"><h2>Web attacks</h2><div class="card">%s</div></section><section><h2>Mail clients (HELO)</h2><div class="card">%s</div></section>'
            '<section><h2>Proxy use</h2><div class="card">%s%s</div></section><section><h2>Slow replies</h2><div class="card">%s</div></section></div>'
            % (stabs + ('<table class="wide"><thead><tr><th>Script</th><th class=num>Cmds</th><th class=num>IPs</th><th class=num>IPs 7d</th><th class=num>Sessions</th><th>First</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % srows
                        if srows else none_yet("No command scripts in the last 7 days" if active else "No command scripts yet")),
               '<table class="wide"><thead><tr><th>HASSH</th><th>Client version</th><th class=num>IPs</th><th class=num>Sessions</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % hrows if hrows else none_yet("No SSH clients yet"),
               '<table class="wide"><thead><tr><th>Attack</th><th>What it is</th><th class=num>Severity</th><th class=num>IPs</th><th class=num>Requests</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % warows if warows else none_yet("No web attacks recognised yet"),
               '<table class="wide"><thead><tr><th>HELO name</th><th class=num>IPs</th><th class=num>Times</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % hlrows if hlrows else none_yet("No mail clients yet"),
               psum, '<table class="wide"><thead><tr><th>Request</th><th>Honeypot</th><th class=num>IPs</th><th class=num>Times</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % prows if prows else none_yet("No proxy checks answered yet"), slow))
    return page("Campaigns", body, "/campaigns")


def v_campaign(kind, val):
    con = db()
    if kind == "web":
        return v_campaign_web(con, val)
    if not re.fullmatch(r"[0-9a-f]{8,64}", val or ""):
        return None
    if kind == "script":
        ips = con.execute("SELECT ip, COUNT(*) n, MAX(start) l FROM sessions WHERE cmdhash=? GROUP BY ip ORDER BY l DESC", (val,)).fetchall()
        sid = con.execute("SELECT session FROM sessions WHERE cmdhash=? LIMIT 1", (val,)).fetchone()
        cmds = con.execute("SELECT a FROM events WHERE session=? AND kind='cmd' ORDER BY ts", (sid[0],)).fetchall() if sid else []
        detail = '<div class="card"><h3>Script <span class=muted>one example</span></h3><div class="term">%s</div></div>' % "".join('<div class="ln"><span class="pr">$</span><code>%s</code></div>' % cmd_html(c[0]) for c in cmds)
        title = "Script " + val
    elif kind == "hassh":
        ips = con.execute("SELECT ip, COUNT(*) n, MAX(start) l FROM sessions WHERE hassh=? GROUP BY ip ORDER BY l DESC", (val,)).fetchall()
        vers = con.execute("SELECT version, COUNT(*) n FROM sessions WHERE hassh=? GROUP BY version ORDER BY n DESC LIMIT 10", (val,)).fetchall()
        detail = '<div class="card"><h3>Client versions</h3>%s</div>' % "".join("<div class=mono>%s <span class=muted>%s</span></div>" % (esc(clean(v[0] or "?", 80)), num(v[1])) for v in vers)
        title = "HASSH " + val
    elif kind == "file":
        ips = con.execute("SELECT ip, COUNT(*) n, MAX(ts) l FROM events WHERE kind='file' AND b=? GROUP BY ip ORDER BY l DESC", (val,)).fetchall()
        names = con.execute("SELECT DISTINCT a FROM events WHERE kind='file' AND b=? LIMIT 30", (val,)).fetchall()
        detail = ('<div class="card"><h3>File</h3><div class=mono>%s</div><p>%s · %s</p>%s</div>'
                  % (esc(val), ext("https://bazaar.abuse.ch/sample/%s/" % val, "MalwareBazaar"), ext("https://www.virustotal.com/gui/file/" + val, "VirusTotal"),
                     "".join("<div class=mono>%s</div>" % esc(clean(n[0], 200)) for n in names)))
        title = "File " + val[:16]
    else:
        return None
    if not ips:
        return None
    en = {x["ip"]: x for x in con.execute("SELECT ip, cc, org FROM enrich WHERE ip IN (%s)" % ",".join("?" * len(ips)), [i["ip"] for i in ips])} if len(ips) < 900 else {}
    rows = "".join("<tr><td>%s</td><td>%s</td><td class=trunc>%s</td><td class=num>%s</td><td>%s</td></tr>"
                   % (ip_link(i["ip"]), cc_html(en.get(i["ip"], {"cc": None})["cc"] if i["ip"] in en else None), esc(en[i["ip"]]["org"] if i["ip"] in en else ""),
                      num(i["n"]), esc(ago(i["l"]))) for i in ips)
    body = ('<h1 class=mono>%s</h1><div class="grid"><div class="span2">%s</div><div class="card span2"><h3>IPs <span class=muted>%s</span></h3>'
            '<table class="wide"><thead><tr><th>IP</th><th>CC</th><th>Network</th><th class=num>Count</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div></div>'
            % (esc(title), detail, num(len(ips)), rows))
    return page(title, body, "/campaigns")


def v_campaign_web(con, rtype):
    info = web_rule_info(rtype)
    ips = con.execute("SELECT ip, COUNT(*) n, MAX(ts) l FROM webhits WHERE type=? GROUP BY ip ORDER BY l DESC LIMIT 500", (rtype,)).fetchall()
    if not ips:
        return None
    ex = con.execute("SELECT e.b, w.level, COUNT(*) n, MAX(e.ts) l FROM webhits w JOIN events e ON e.h=w.h WHERE w.type=? "
                     "GROUP BY e.b ORDER BY l DESC LIMIT 30", (rtype,)).fetchall()
    cves = [c.strip() for c in (info[3] if info else "").split(",") if re.fullmatch(r"CVE-\d{4}-\d{3,7}", c.strip())]
    detail = ('<div class="card"><h3>%s <span class=muted>severity %s</span></h3><p>%s</p>%s<p class="muted small">Rule %s from Krawl (MIT).</p></div>'
              % (esc(web_label(rtype, info[3] if info else "")), esc(info[0] if info else "?"), esc(info[6] if info else "This rule is no longer in the rule set."),
                 ("<p>%s</p>" % " · ".join(ext("https://nvd.nist.gov/vuln/detail/" + c, c) for c in cves)) if cves else "", esc(info[4] if info else rtype)))
    detail += ('<div class="card"><h3>Requests <span class=muted>latest %s, attacker text</span></h3><table class=wide><thead><tr><th>Request</th><th class=num>Count</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div>'
               % (num(len(ex)), "".join("<tr><td class='mono fd-d'>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>" % (esc(clean(x["b"], 400)), num(x["n"]), esc(ago(x["l"]))) for x in ex)))
    en = {x["ip"]: x for x in con.execute("SELECT ip, cc, org FROM enrich WHERE ip IN (%s)" % ",".join("?" * len(ips)), [i["ip"] for i in ips])}
    rows = "".join("<tr><td>%s</td><td>%s</td><td class=trunc>%s</td><td class=num>%s</td><td>%s</td></tr>"
                   % (ip_link(i["ip"]), cc_html(en[i["ip"]]["cc"] if i["ip"] in en else None), esc(en[i["ip"]]["org"] or "" if i["ip"] in en else ""),
                      num(i["n"]), esc(ago(i["l"]))) for i in ips)
    title = "Web attack " + web_label(rtype, info[3] if info else "")
    body = ('<h1>%s</h1><div class="grid"><div class="span2">%s</div><div class="card span2"><h3>IPs <span class=muted>%s</span></h3>'
            '<table class="wide"><thead><tr><th>IP</th><th>CC</th><th>Network</th><th class=num>Requests</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div></div>'
            % (esc(title), detail, num(len(ips)), rows))
    return page(title, body, "/campaigns")


def blocklist_ips(con, min_score, days, research, v6):
    since = time.time() - days * 86400
    rows = con.execute(
        "SELECT i.ip, COALESCE(e.research,0) AND COALESCE(f.flag,'')!='block' AND (i.logins_ok + i.logins_fail + i.cmds + i.files + i.exploits + i.tcpip) = 0 maybe "
        "FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) "
        "WHERE COALESCE(f.flag,'')!='allow' AND (f.flag='block' OR (i.last>=? AND i.score>=?))",
        (since, min_score)).fetchall()
    out = []
    for ip, maybe in rows:
        # A scanner by name, and nothing but looking around: left out, unless it tried to log in to a decoy service.
        if maybe and not research and not any(canary_is_login(s, b) for s, b in con.execute("SELECT a,b FROM events WHERE ip=? AND kind='canary' AND b LIKE '% / %'", (ip,))):
            continue
        a = ipaddress.ip_address(ip)
        if not is_public(a) or getattr(a, "scope_id", None) or (a.version == 6 and not v6):
            continue
        out.append(a)
    out.sort(key=lambda a: (a.version, int(a)))
    return [str(a) for a in out]


def c2_list(con):
    # IP addresses of the attackers' servers: embedded in captured files + hosts in download URLs. Harmless ones removed.
    # Attackers choose both, so an address needs at least C2_MIN_SOURCES different attackers, and a failed download never counts.
    out, sources = {}, {}

    def host_of(x):
        try:
            return urllib.parse.urlsplit(x).hostname if "://" in x else x.rsplit(":", 1)[0] if x.count(":") == 1 else x
        except ValueError:
            return None

    def add(host, why, ips):
        host = (host or "").strip().strip("[]")
        try:
            a = ipaddress.ip_address(host)
        except ValueError:
            return
        if not is_public(a) or getattr(a, "scope_id", None) or str(a) in BENIGN_IOC or str(a) in C2_EXCLUDE:
            return
        out.setdefault(str(a), set()).add(why)
        sources.setdefault(str(a), set()).update(ips)

    dropped = {}
    for sha, ip in con.execute("SELECT DISTINCT b, ip FROM events WHERE kind='file' AND b IS NOT NULL"):
        dropped.setdefault(sha, set()).add(ip)
    for r in con.execute("SELECT sha, iocs FROM files WHERE iocs IS NOT NULL AND iocs!='[]'"):
        for x in json.loads(r["iocs"]):
            add(host_of(x), "embedded in " + r["sha"][:12], dropped.get(r["sha"], ()))
    for url, ip in con.execute("SELECT DISTINCT a, ip FROM events WHERE kind='file' AND a LIKE '%://%'"):
        add(host_of(url), "malware download host", (ip,))
    return {k: v for k, v in out.items() if len(sources[k]) >= C2_MIN_SOURCES}


def bl_params(qs):
    st = settings()
    def gi(k, d, lo, hi):
        try:
            return max(lo, min(hi, int(qs.get(k) or d)))
        except ValueError:
            return d
    return gi("min", int(st["bl_min"]), 1, 1000), gi("days", int(st["bl_days"]), 1, 3650), qs.get("research") == "1", qs.get("v6", "1") != "0"


def render_feed(fmt, ips, with_v6=True):
    # with_v6: this feed manages IPv6 too, so an empty list must still clear what an earlier one added.
    now = datetime.now(TZ).strftime("%Y-%m-%d %H:%M")
    v4 = [i for i in ips if ":" not in i]
    v6 = [i for i in ips if ":" in i]
    if fmt == "txt":
        return "# Huginn honeypot blocklist, %s, %d entries\n" % (now, len(ips)) + "".join(i + "\n" for i in ips), "text/plain"
    if fmt == "nft":
        s = ["# Huginn honeypot blocklist, %s — load with: nft -f huginn.nft" % now,
             "table inet huginn", "delete table inet huginn", "table inet huginn {",
             "  set bl4 { type ipv4_addr; flags interval; auto-merge;%s }" % (" elements = { %s };" % ", ".join(v4) if v4 else ""),
             "  set bl6 { type ipv6_addr; flags interval; auto-merge;%s }" % (" elements = { %s };" % ", ".join(v6) if v6 else ""),
             "  chain input { type filter hook input priority -10; policy accept; ip saddr @bl4 drop; ip6 saddr @bl6 drop; }",
             "  chain forward { type filter hook forward priority -10; policy accept; ip saddr @bl4 drop; ip6 saddr @bl6 drop; }",
             "}"]
        return "\n".join(s) + "\n", "text/plain"
    if fmt == "ipset":
        s = ["# Huginn honeypot blocklist, %s — load with: ipset restore -exist < huginn.ipset" % now,
             "create huginn4 hash:ip family inet maxelem 262144 -exist", "flush huginn4"]
        s += ["add huginn4 %s -exist" % i for i in v4]
        if v6 or with_v6:
            s += ["create huginn6 hash:ip family inet6 maxelem 262144 -exist", "flush huginn6"] + ["add huginn6 %s -exist" % i for i in v6]
        return "\n".join(s) + "\n", "text/plain"
    if fmt == "mikrotik":
        s = ["# Huginn honeypot blocklist, %s" % now, "/ip firewall address-list remove [find list=huginn]"]
        s += ["/ip firewall address-list add list=huginn address=%s" % i for i in v4]
        if v6 or with_v6:
            s += ["/ipv6 firewall address-list remove [find list=huginn]" if v6 else ":do { /ipv6 firewall address-list remove [find list=huginn] } on-error={}"] + ["/ipv6 firewall address-list add list=huginn address=%s" % i for i in v6]
        return "\n".join(s) + "\n", "text/plain"
    if fmt == "c2":
        c2 = c2_list(db())
        return ("# Huginn C2 / malware hosts, %s, %d entries\n" % (now, len(c2))) + "".join("%s\n" % i for i in sorted(c2)), "text/plain"
    if fmt == "csv":
        # Real CSV quoting: no value (country, tags) can ever start a new row in a firewall's import.
        import csv as _csv, io as _io
        con = db()
        meta = {}
        if ips:
            for r in con.execute("SELECT i.ip, i.score, i.last, i.tags, e.cc FROM ips i LEFT JOIN enrich e USING(ip)"):
                meta[r["ip"]] = r
        out = _io.StringIO()
        w = _csv.writer(out, lineterminator="\n")
        w.writerow(["value", "score", "last_seen", "country", "reason"])
        for i in ips:
            r = meta.get(i)
            cc = (r["cc"] or "") if r else ""
            w.writerow([i, r["score"] if r else "", datetime.fromtimestamp(r["last"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if r else "",
                        cc if re.fullmatch(r"[A-Z]{2}", cc) else "", "huginn " + re.sub(r"[^a-z0-9 -]", "", ((r["tags"] or "").replace(",", " ")) if r else "")])
        return out.getvalue(), "text/csv"
    return None, None


FEEDS = [("txt", "Plain list", "One IP per line. OPNsense/pfSense URL Table alias, pfBlockerNG, CrowdSec (cscli decisions import --format values), Pi-hole-style tools."),
         ("nft", "nftables", "Complete table with sets and drop rules. Cron: curl -fsS URL -o /etc/huginn.nft && nft -f /etc/huginn.nft"),
         ("ipset", "ipset", "Sets huginn4/huginn6. Cron: curl -fsS URL | ipset restore -exist — then iptables -I INPUT -m set --match-set huginn4 src -j DROP"),
         ("mikrotik", "MikroTik", "RouterOS script for address-list 'huginn': /tool fetch url=URL dst-path=huginn.rsc; /import huginn.rsc"),
         ("csv", "CSV", "IP with score, last seen, country and tags. CrowdSec: cscli decisions import -i huginn.csv")]


def base_url(h):
    host = h.headers.get("Host") or ("%s:%d" % (BIND, PORT))
    proto = "http"
    if h.client_address[0] in TRUSTED_PROXIES and h.headers.get("X-Forwarded-Proto") == "https":
        proto = "https"
    return "%s://%s" % (proto, host)


def v_blocklist(h, qs):
    con = db()
    mn, days, research, v6 = bl_params(qs)
    ips = blocklist_ips(con, mn, days, research, v6)
    c2 = c2_list(con)
    token = get_meta(con, "feed_token")
    params = urllib.parse.urlencode({"min": mn, "days": days, "research": "1" if research else "0", "v6": "1" if v6 else "0"})
    feeds = "".join('<div class="feed"><div class="feed-h"><b>%s</b><button class="btn-s" data-copy="%s">Copy URL</button></div><div class="mono url">%s</div><div class="muted small">%s</div></div>'
                    % (esc(lab), esc("%s/feed/%s/%s?%s" % (base_url(h), token, fmt, params)), esc("%s/feed/••••/%s?%s" % (base_url(h), fmt, params)), esc(desc))
                    for fmt, lab, desc in FEEDS)
    flags = con.execute("SELECT f.*, e.cc FROM flags f LEFT JOIN enrich e USING(ip) ORDER BY f.updated DESC").fetchall()
    frows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (ip_link(f["ip"]), cc_html(f["cc"]), tag_html(f["flag"]), esc(f["note"] or ""), esc(fmt_ts(f["updated"]))) for f in flags)
    sel = lambda name, cur, vals: '<select name=%s>%s</select>' % (name, "".join('<option value="%s"%s>%s</option>' % (v, " selected" if str(v) == str(cur) else "", esc(l)) for v, l in vals))
    form = ('<form class="filters" method=get action="/blocklist"><label>Min score %s</label><label>Seen within %s</label>'
            '<label>Research scanners %s</label><label>IPv6 %s</label><button>Update</button></form>'
            % (sel("min", mn, [(1, "1 (everything)"), (3, "3 (tried to log in)"), (5, "5"), (10, "10 (ran commands)"), (15, "15 (dropped files)"), (25, "25")]),
               sel("days", days, [(1, "24 hours"), (7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year")]),
               sel("research", "1" if research else "0", [("0", "Exclude"), ("1", "Include")]), sel("v6", "1" if v6 else "0", [("1", "Include"), ("0", "Exclude")])))
    preview = " ".join('<span class=mono>%s</span>' % esc(i) for i in ips[:300])
    body = ('<h1>Blocklist <span class=muted>%s IPs</span></h1>%s'
            '<div class="grid"><div class="card span2"><h3>Feeds</h3><p class="muted small">Feed URLs contain a secret token and need no login — keep them on the LAN. '
            'Score: %s</p>%s'
            '<form method=post action="/blocklist/rotate" class="inline"><button class="btn-s danger">Rotate token</button> <span class="muted small">Old feed URLs stop working.</span></form></div>'
            '<div class="card span2"><h3>C2 and malware hosts <span class=muted>%s IPs</span></h3><p class="muted small">Addresses found inside captured malware and in its download URLs, seen from at least %d attackers. Attackers can choose these addresses, so treat this as advice and do not block from it automatically.</p>'
            '<div class="feed"><div class="feed-h"><b>Plain list</b><button class="btn-s" data-copy="%s">Copy URL</button></div><div class="mono url">%s</div></div>'
            '<div class="preview">%s</div></div>'
            '<div class="card span2"><h3>Manual overrides</h3>%s</div>'
            '<div class="card span2"><h3>Preview%s</h3><div class="preview">%s</div></div></div>'
            % (num(len(ips)), form, esc(SCORE_HELP), feeds, num(len(c2)), C2_MIN_SOURCES, esc("%s/feed/%s/c2" % (base_url(h), token)), esc("%s/feed/••••/c2" % base_url(h)),
               " ".join('<span class=mono title="%s">%s</span>' % (esc("; ".join(sorted(w))), esc(i)) for i, w in sorted(c2.items())) or "<span class=muted>None yet</span>",
               '<table><thead><tr><th>IP</th><th>CC</th><th>Rule</th><th>Note</th><th>Updated</th></tr></thead><tbody>%s</tbody></table>' % frows if frows else none_yet("None. Set them on an attacker page."),
               " (first 300)" if len(ips) > 300 else "", preview or "<span class=muted>Empty</span>"))
    return page("Blocklist", body, "/blocklist")


def capped_note(con):
    n, ips = con.execute("SELECT COALESCE(SUM(dropped),0), COUNT(DISTINCT CASE WHEN dropped>0 THEN ip END) FROM capped").fetchone()
    if DECOY_CAP <= 0:
        return "all are stored (HUGINN_DECOY_CAP=0)"
    return ("%s counted but not stored, from %s IPs (the first %s per IP, service and day are stored)" % (num(n), num(ips), num(DECOY_CAP))
            if n else "none so far (the first %s per IP, service and day are stored)" % num(DECOY_CAP))


def disk_note():
    # Cached session recordings and the free space left for the database.
    n = b = 0
    try:
        for e in os.scandir(TTY_DIR):
            n += 1
            b += e.stat().st_size
    except OSError:
        pass
    st = os.statvfs(DATA)
    free = st.f_bavail * st.f_frsize
    return "%s kept here, %.1f MB · %.1f GB free on the data disk" % (num(n), b / 1048576, free / 1073741824)


def gap_summary(con):
    spans = gap_spans(con, time.time() - 30 * 86400)
    if not spans:
        return "none in 30 days"
    start, end = spans[-1]
    return "%d in 30 days, latest %s for %s" % (len(spans), esc(fmt_ts(start)), esc(dur(end - start)))


def v_account(cur, ok="", err=""):
    con = db()
    now = time.time()
    others = con.execute("SELECT COUNT(*) FROM logins WHERE expires>? AND token_hash!=?", (now, cur or "")).fetchone()[0]
    mine = con.execute("SELECT expires FROM logins WHERE token_hash=?", (cur or "",)).fetchone()
    msg = {"pw": "Password changed. Other sessions were logged out.", "others": "Other sessions logged out."}.get(ok, "")
    note = ('<p class="okmsg">%s</p>' % esc(msg)) if msg else ""
    note += ('<p class="err">%s</p>' % esc(err)) if err else ""
    li = float(get_meta(con, "last_ingest", "0") or 0)
    try:
        size = os.path.getsize(DB_PATH) + (os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0)
    except OSError:
        size = 0
    counts = con.execute("SELECT (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM sessions), (SELECT COUNT(*) FROM ips), "
                         "(SELECT COUNT(*) FROM enrich WHERE ok=1), (SELECT MIN(ts) FROM events)").fetchone()
    status = kv([("Version", esc(HUGINN_VERSION)), ("Last sync", "%s <span class=muted>(%s new rows, %ss)</span>" % (esc(ago(li)), esc(get_meta(con, "last_ingest_new", "0")), esc(get_meta(con, "last_ingest_secs", "–")))),
                 ("Sync error", esc(get_meta(con, "last_error", "") or "none")), ("Export warning", esc(get_meta(con, "last_export_warn", "") or "none")), ("Lookup error", esc(get_meta(con, "last_enrich_error", "") or "none")),
                 ("New page error", esc(get_meta(con, "last_seen_error", "") or "none")),
                 ("History since", esc(fmt_ts(counts[4]))), ("Retention", "everything is kept" if RETENTION_DAYS == 0 else "%d days" % RETENTION_DAYS),
                 ("Database", "%.1f MB · %s events · %s sessions · %s IPs (%s looked up)" % (size / 1048576, num(counts[0]), num(counts[1]), num(counts[2]), num(counts[3]))),
                 ("Session recordings", disk_note()),
                 ("Collection", health_note(con)),
                 ("Honeypot protection", protection_note(con)),
                 ("Disk", esc(growth_note(con))),
                 ("Repeated decoy tries", esc(capped_note(con))),
                 ("Sync gaps", gap_summary(con)),
                 ("Database backups", esc(backup_note(con))),
                 ("Backup error", '<span class="err">%s</span>' % esc(get_meta(con, "backup_error", "")) if get_meta(con, "backup_error", "") else "none"),
                 ("Honeypot", '<span class=mono>%s:%s</span> every %ss' % (esc(HP_HOST), esc(HP_PORT), POLL)),
                 ("Updates", esc(("newest release %s" % get_meta(con, "update_latest")) if get_meta(con, "update_latest") else
                                 ("not checked yet" if UPDATE_CHECK else "check turned off (HUGINN_UPDATE_CHECK=0)"))
                  + (' <span class=muted>(%s)</span>' % esc(ago(float(get_meta(con, "update_checked", "0") or 0))) if get_meta(con, "update_checked") else ""))])
    log = "".join('<div class="cl"><span class="mono">%s</span><span class="muted">%s</span><span>%s</span></div>' % (esc(v), esc(d), esc(t)) for v, d, t in CHANGELOG)
    body = ('<h1>Account</h1>%s<div class="grid">'
            '<div class="card"><h3>Change password</h3><form method=post action="/account/password" class="stack">'
            '<label>Current password<input type=password name=current autocomplete=current-password required></label>'
            '<label>New password <span class=muted>(min 10 characters)</span><input type=password name=new minlength=10 autocomplete=new-password required></label>'
            '<label>Repeat new password<input type=password name=repeat minlength=10 autocomplete=new-password required></label>'
            '<button>Change password</button></form><p class="muted small">Changing it logs out every other browser.</p></div>'
            '<div class="card"><h3>Sessions</h3>%s<p>%s other active %s.</p>'
            '<form method=post action="/account/logout-others"><button class="btn-s"%s>Log out other sessions</button></form></div>'
            '<div class="card"><h3>System</h3>%s</div><div class="card"><h3>Changelog</h3>%s</div></div>'
            % (note, kv([("This browser", "logged in until %s" % esc(fmt_ts(mine[0])) if mine else "–")]), num(others),
               "session" if others == 1 else "sessions", "" if others else " disabled", status, log))
    return page("Account", body, "/account")


RECEIPT_DAYS = {"1": "Last 24 hours", "7": "Last 7 days", "30": "Last 30 days", "all": "All time"}


def receipt_worth(secs):
    # A dry comparison, not a claim about anyone's evening: recorded connection time only.
    if secs >= 558 * 60:
        return "Lord of the Rings trilogies", secs / (558 * 60.0)     # theatrical cuts: 178 + 179 + 201 minutes
    if secs >= 2 * 3600:
        return "Feature films", secs / 7200.0
    if secs >= 15 * 60:
        return "Coffee breaks", secs / 900.0
    return None


def v_receipt(qs):
    con = db()
    days = qs.get("days") if qs.get("days") in RECEIPT_DAYS else "7"
    now = time.time()
    since = 0 if days == "all" else now - int(days) * 86400
    tw = time_wasted(con, since)
    visits = (con.execute("SELECT COUNT(*) FROM events WHERE kind='tarpit' AND ts>=?", (since,)).fetchone()[0]
              + con.execute("SELECT COUNT(*) FROM sessions WHERE start>=? AND cmds>0 AND duration IS NOT NULL", (since,)).fetchone()[0])
    row = lambda k, v: '<div class="rc-r"><span>%s</span><span>%s</span></div>' % (esc(k), v)
    period = RECEIPT_DAYS[days] if days == "all" else "%s to %s" % (datetime.fromtimestamp(since, TZ).strftime("%Y-%m-%d"), datetime.fromtimestamp(now, TZ).strftime("%Y-%m-%d"))
    chips = "" if DEMO else '<div class="chips">%s</div>' % "".join(
        '<a class="chip%s" href="/receipt?days=%s">%s</a>' % (" on" if k == days else "", k, esc(v)) for k, v in RECEIPT_DAYS.items())
    if not tw["total"]:
        lines = '<div class="rc-c">Nothing to bill yet.</div>'
    else:
        worth = receipt_worth(tw["total"])
        lines = (row("Tarpit", esc(dur(tw["tarpit"]))) + row("Fake shells", esc(dur(tw["shell"]))) + row("Visits", num(visits)) + "<hr>"
                 + '<div class="rc-r rc-total"><span>TOTAL</span><span>%s</span></div><hr>' % esc(dur(tw["total"]))
                 + (row("Longest visit", esc(dur(tw["longest"]["longest"]))) + (row("Guest", ip_link(tw["longest"]["ip"])) if tw["longest_shown"] else "") if tw["longest"] else "")
                 + (row(worth[0], "× %.1f" % worth[1]) if worth else "") + "<hr>")
    body = ('<h1>Receipt</h1>%s<div class="rcpt mono"><div class="rc-c rc-title">%s</div><div class="rc-c">Honeypot services rendered</div><div class="rc-c rc-dim">%s</div><hr>%s'
            '<div class="rc-c">Thank you for your time.</div><div class="rc-c rc-dim">No refunds.</div><div class="rc-bar" aria-hidden="true"></div></div>'
            '<p class="muted small rc-note">Recorded connection and session time. Parallel connections can overlap, and a bot waiting is not a person waiting.</p>'
            % (chips, esc(settings(con)["title"].upper()), esc(period), lines))
    return page("Receipt", body, "/")


def v_replay(sha, ip):
    con = db()
    s = con.execute("SELECT * FROM sessions WHERE tty=? ORDER BY start DESC LIMIT 1", (sha,)).fetchone()
    if not s:
        return None
    ip = s["ip"]
    head = ('<div class="iphead"><h1>Replay</h1><div>%s %s</div></div><p class="links">%s · %s · %s · session <span class=mono>%s</span></p>'
            % (ip_link(ip, "#s-" + s["session"]), tag_html(PERSONA.get(s["port"] or 0, "")), esc(fmt_tss(s["start"])),
               esc((s["proto"] or "").upper()), esc(dur(s["duration"])), esc(s["session"])))
    title = " · ".join(x for x in ((s["proto"] or "").upper(), PERSONA.get(s["port"] or 0, "")) if x) or "session"
    body = (head + '<div class="card replay-card"><div class="pctl"><button id="pPlay">Play</button><button class="btn-s" id="pRestart">Restart</button>'
            '<label>Speed <select id="pSpeed"><option value=1>1×</option><option value=4 selected>4×</option><option value=16>16×</option></select></label>'
            '<label><input type=checkbox id="pIdle" checked> Skip pauses</label><span class="muted" id="pTime"></span></div>'
            '<div class="twin"><div class="twin-bar"><i></i><i></i><i></i><span>%s</span></div><pre class="term player" id="player" data-src="/api/tty/%s">Loading…</pre></div>'
            '<input type=range id="pSeek" class="pseek" min=0 max=0 value=0 aria-label="Position in the recording"></div>' % (esc(title), esc(sha)))
    return page("Replay", body, "/ips")


def v_settings(ok="", err=""):
    st = settings()
    def radio(name, val, label):
        return '<label class="opt"><input type=radio name=%s value="%s"%s> %s</label>' % (name, val, " checked" if str(st[name]) == str(val) else "", esc(label))
    def check(name, val, label, on):
        return '<label class="opt"><input type=checkbox name=%s value="%s"%s> %s</label>' % (name, val, " checked" if on else "", esc(label))
    def sel(name, vals):
        return '<select name=%s>%s</select>' % (name, "".join('<option value="%s"%s>%s</option>' % (v, " selected" if str(st[name]) == str(v) else "", esc(l)) for v, l in vals))
    msg = {"1": "Saved.", "test": "Test notification sent."}.get(ok, "")
    note = ('<p class="okmsg">%s</p>' % esc(msg)) if msg else ""
    note += ('<p class="err">%s</p>' % esc(err)) if err else ""
    accents = "".join('<label class="opt sw"><input type=radio name=accent value="%s"%s><span class="dot dot-%s"></span> %s</label>'
                      % (a, " checked" if st["accent"] == a else "", a, a.capitalize()) for a in ACCENTS)
    ntfy_host = urllib.parse.urlsplit(NTFY_URL).netloc if NTFY_URL else ""
    ntfy_line = ("Sends to <span class=mono>%s</span> (HUGINN_NTFY_URL%s)." % (esc(ntfy_host), ", with access token" if NTFY_TOKEN else "")) if NTFY_URL else "HUGINN_NTFY_URL is not set in .env, so nothing is sent."
    body = ('<h1>Settings</h1>%s<form method=post action="/settings" class="settings"><div class="grid">'
            '<div class="card"><h3>Appearance</h3>'
            '<div class="row"><div class="rl">Theme</div><div>%s%s%s</div></div>'
            '<div class="row"><div class="rl">Accent</div><div class="sws">%s</div></div>'
            '<div class="row"><div class="rl">Layout</div><div>%s%s</div></div>'
            '<div class="row"><div class="rl">Page title</div><div><input name=title maxlength=40 value="%s"></div></div>'
            '<div class="row"><div class="rl">Clock</div><div>%s%s</div></div></div>'
            '<div class="card"><h3>Overview cards</h3><div class="col">%s</div></div>'
            '<div class="card"><h3>Defaults</h3>'
            '<div class="row"><div class="rl">Attackers list</div><div>%s</div></div>'
            '<div class="row"><div class="rl">Blocklist min score</div><div>%s</div></div>'
            '<div class="row"><div class="rl">Blocklist window</div><div>%s</div></div>'
            '<p class="muted small">Used by the Overview count, the Blocklist page and feed URLs without parameters.</p></div>'
            '<div class="card"><h3>Attackers list columns</h3><div class="cols2">%s</div></div>'
            '<div class="card"><h3>Hide from views</h3><p class="muted small">Countries (two letters) and networks (AS numbers) to leave out of the '
            'Overview and the Attackers list, for example your own VPS provider. They are still recorded and still blocklisted.</p>'
            '<input name=hidden_nets class="wide-input" maxlength=500 placeholder="e.g. CN, RU, AS14061" value="%s"></div>'
            '<div class="card"><h3>Notifications</h3><p class="muted small">%s At most one summary per hour.</p>'
            '<div class="col">%s<div class="sub">%s</div></div></div>'
            '</div><div class="actions"><button>Save</button></div></form>'
            '<form method=post action="/settings/test-ntfy" class="actions"><button class="btn-s"%s>Send a test notification</button></form>'
            % (note, radio("theme", "auto", "Auto (follow the system)"), radio("theme", "light", "Light"), radio("theme", "dark", "Dark"),
               accents, radio("density", "comfortable", "Comfortable"), radio("density", "compact", "Compact"), esc(st["title"]),
               radio("clock", "24", "24-hour"), radio("clock", "12", "12-hour (AM/PM)"),
               "".join(check("cards", k, l, k in st["cards"]) for k, l in CARDS),
               sel("ips_days", [("1", "Last 24h"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days"), ("all", "All time")]),
               sel("bl_min", [(1, "1 (everything)"), (3, "3 (tried to log in)"), (5, "5"), (10, "10 (ran commands)"), (15, "15 (dropped files)"), (25, "25")]),
               sel("bl_days", [(1, "24 hours"), (7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year")]),
               "".join(check("ips_cols", k, lab, k in st["ips_cols"]) for k, lab, _s, _c in IPS_COLS),
               esc(", ".join(st["hide_cc"] + ["AS" + a for a in st["hide_asn"]])),
               ntfy_line, check("notify", "1", "Send ntfy notifications", st["notify"]),
               "".join(check("notify_events", k, l, k in st["notify_events"]) for k, l in NOTIFY_EVENTS),
               "" if NTFY_URL else " disabled"))
    return page("Settings", body, "/settings")


def save_settings(f, lists):
    st = settings()
    if f.get("theme") in THEMES:
        st["theme"] = f["theme"]
    if f.get("accent") in ACCENTS:
        st["accent"] = f["accent"]
    if f.get("density") in ("comfortable", "compact"):
        st["density"] = f["density"]
    title = re.sub(r"[\x00-\x1f]", "", (f.get("title") or "").strip())[:40]
    st["title"] = title or "Huginn"
    st["cards"] = [k for k, _ in CARDS if k in lists.get("cards", [])]
    if f.get("ips_days") in ("1", "7", "30", "90", "all"):
        st["ips_days"] = f["ips_days"]
    if f.get("bl_min") in ("1", "3", "5", "10", "15", "25"):
        st["bl_min"] = int(f["bl_min"])
    if f.get("bl_days") in ("1", "7", "30", "90", "365"):
        st["bl_days"] = int(f["bl_days"])
    if f.get("clock") in ("24", "12"):
        st["clock"] = f["clock"]
    st["ips_cols"] = [k for k, *_ in IPS_COLS if k in lists.get("ips_cols", [])]
    cc, asn = [], []
    for tok in re.split(r"[\s,;]+", (f.get("hidden_nets") or "").upper())[:100]:
        if re.fullmatch(r"[A-Z]{2}", tok):
            cc.append(tok)
        elif re.fullmatch(r"(AS)?\d{1,10}", tok):
            asn.append(tok.lstrip("AS"))
    st["hide_cc"], st["hide_asn"] = sorted(set(cc)), sorted(set(asn))
    st["notify"] = f.get("notify") == "1"
    st["notify_events"] = [k for k, _ in NOTIFY_EVENTS if k in lists.get("notify_events", [])]
    set_meta(db(), "settings", json.dumps(st))


def v_login(err=""):
    st = settings()
    return ("<!doctype html><html lang=en%s><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s</title><link rel=icon type=image/png sizes=32x32 href='/static/icon-32.png'><link rel=apple-touch-icon href='/static/icon-180.png'><link rel=stylesheet href='/static/app.css?v=%s'></head><body class=login>"
            "<form method=post action='/login' class='card loginbox'><img class=login-ic src='/static/icon-192.png' alt=''><h1>%s</h1>%s"
            "<input type=password name=password placeholder=Password autofocus autocomplete=current-password required>"
            "<button>Log in</button></form>%s</body></html>") % (html_attrs(st), esc(st["title"]), HUGINN_VERSION, esc(st["title"]),
                                                              '<p class=err>%s</p>' % esc(err) if err else "", footer())


# ---------------------------------------------------------------- static files

CSS = r"""
.hero{position:relative;border-radius:12px;overflow:hidden;margin-bottom:14px;background:var(--hero-bg);border:1px solid var(--line)}
.hero-dark{display:none!important}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .hero-dark{display:block!important}:root:not([data-theme=light]) .hero-light{display:none!important}}
:root[data-theme=dark] .hero-dark{display:block!important}:root[data-theme=dark] .hero-light{display:none!important}
.hero img{display:block;width:100%;height:190px;object-fit:cover;object-position:0 5%}
@media (min-width:1600px){.hero img{height:230px}.hero-name{font-size:48px}}
.hero-txt{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;padding:0 32px 0 46%;color:var(--hero-text)}
.hero-name{font-size:42px;font-weight:800;letter-spacing:.5px;line-height:1.05}
.hero-tag{font-size:17px;color:var(--hero-tag);margin-top:6px}.hero-facts{font-size:13px;color:var(--hero-facts);margin-top:12px}
@media (max-width:800px){.hero img{height:64px;object-position:0 8%}.hero-txt{flex-direction:row;align-items:center;justify-content:flex-start;padding:0 14px 0 34%}.hero-name{font-size:22px}.hero-tag,.hero-facts{display:none}}
.heat{display:flex;flex-direction:column;gap:3px;font-size:11px;color:var(--muted)}
.hm-row{display:grid;grid-template-columns:34px repeat(24,minmax(0,1fr));gap:3px;align-items:center}
.hm-row i{display:block;aspect-ratio:1;border-radius:3px;background:var(--panel2);min-height:10px}.hm-head span{text-align:left}
@media (min-width:1001px){.hm-row i{aspect-ratio:auto;height:16px}}
.hm1{background:color-mix(in srgb,var(--accent) 14%,var(--panel2))!important}.hm2{background:color-mix(in srgb,var(--accent) 26%,var(--panel2))!important}
.hm3{background:color-mix(in srgb,var(--accent) 38%,var(--panel2))!important}.hm4{background:color-mix(in srgb,var(--accent) 50%,var(--panel2))!important}
.hm5{background:color-mix(in srgb,var(--accent) 62%,var(--panel2))!important}.hm6{background:color-mix(in srgb,var(--accent) 74%,var(--panel2))!important}
.hm7{background:color-mix(in srgb,var(--accent) 87%,var(--panel2))!important}.hm8{background:var(--accent)!important}
.hm-legend{display:flex;align-items:center;gap:3px;justify-content:flex-end;margin-top:8px;font-size:11px;color:var(--muted)}
.hm-legend i{width:12px;height:12px;border-radius:3px;display:block}.hm-legend span{margin:0 4px}.hm-legend .hm-what{margin-right:auto;margin-left:0}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-bottom:14px}@media(max-width:800px){.grid2{grid-template-columns:1fr}}
.pwcheck{display:flex;gap:8px;flex-wrap:wrap}.pwcheck input{flex:1;min-width:180px}.pwc-out{margin-top:10px}.pwc-out table{margin-top:6px}
.pwc-out th{text-align:left;font-weight:500;color:var(--muted);padding-right:14px}.pwc-ok{color:#2f9e5b;font-weight:600}.pwc-bad{color:#d1453b;font-weight:600}
:root{--bg:#f4f5f7;--panel:#fff;--panel2:#f8f9fb;--line:#e3e6ea;--text:#1b1f24;--muted:#6b7480;--accent:#3b6fd8;--accent2:#e9effb;
--red:#c73a3a;--orange:#c46a12;--yellow:#9a7b00;--green:#2e8b57;--blue:#3b6fd8;--purple:#7d4fc7;--teal:#178a8a;--grey:#6b7480;
--term:#11151a;--termtext:#d6dde6;--shadow:0 1px 2px rgba(0,0,0,.05),0 4px 14px rgba(0,0,0,.04);
--hero-bg:#eef1f5;--hero-text:#1b1f24;--hero-tag:#4a5361;--hero-facts:#3b6fd8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--panel:#161b22;--panel2:#1b212a;--line:#262d37;--text:#e4e8ee;--muted:#8b95a3;
--accent:#7aa2f7;--accent2:#1d2a44;--red:#f07070;--orange:#f0a050;--yellow:#e0c050;--green:#5fc28a;--blue:#7aa2f7;--purple:#b394f0;--teal:#4cc6c6;--grey:#8b95a3;
--term:#0a0d11;--termtext:#cdd6e0;--shadow:none;color-scheme:dark;--hero-bg:#06080d;--hero-text:#e8ecf2;--hero-tag:#c8cfd9;--hero-facts:#7aa2f7}}
:root[data-theme=dark]{--bg:#0e1116;--panel:#161b22;--panel2:#1b212a;--line:#262d37;--text:#e4e8ee;--muted:#8b95a3;
--accent:#7aa2f7;--accent2:#1d2a44;--red:#f07070;--orange:#f0a050;--yellow:#e0c050;--green:#5fc28a;--blue:#7aa2f7;--purple:#b394f0;--teal:#4cc6c6;--grey:#8b95a3;
--term:#0a0d11;--termtext:#cdd6e0;--shadow:none;color-scheme:dark;--hero-bg:#06080d;--hero-text:#e8ecf2;--hero-tag:#c8cfd9;--hero-facts:#7aa2f7}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mono,code{font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;font-size:12.5px}
.brand a{display:flex;align-items:center;gap:9px}.brand-ic{width:24px;height:24px;border-radius:6px;display:block}.login-ic{width:72px;height:72px;border-radius:16px;align-self:center;margin-bottom:4px}
.muted{color:var(--muted)}.small{font-size:12px}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:24px;padding:0 24px;height:52px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand a{font-weight:650;letter-spacing:.3px;color:var(--text);font-size:16px}
nav{display:flex;gap:4px;overflow-x:auto}nav a{padding:6px 10px;border-radius:6px;color:var(--muted);white-space:nowrap}
nav a:hover{background:var(--panel2);text-decoration:none;color:var(--text)}nav a.on{background:var(--accent2);color:var(--accent)}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:14px;white-space:nowrap}.hdr-right form{margin:0}
.sync{font-size:12px}.sync::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:1px;background:var(--green)}
.sync.bad::before{background:var(--red)}
button{font:inherit;cursor:pointer;border:1px solid var(--line);background:var(--accent);color:#fff;border-radius:6px;padding:6px 14px}
button.link{background:none;border:0;color:var(--muted);padding:0}button.link:hover{color:var(--text)}
.btn-s{padding:3px 10px;font-size:12px;background:var(--panel2);color:var(--text)}.btn-s.danger{color:var(--red)}
input,select{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 9px}
main{max-width:2200px;margin:0 auto;padding:22px 24px 60px}
h1{font-size:22px;font-weight:620;margin:4px 0 16px}h2{font-size:16px;font-weight:600;margin:26px 0 10px}
h3{font-size:13px;font-weight:600;margin:0 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;display:flex;align-items:baseline;gap:8px}
h3 .muted{text-transform:none;letter-spacing:0;font-weight:400}h3 .more{margin-left:auto;text-transform:none;letter-spacing:0;font-weight:500}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;box-shadow:var(--shadow);min-width:0}
.kpis{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:14px;margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;box-shadow:var(--shadow)}
.kpi-l{font-size:12px;color:var(--muted)}.kpi-v{font-size:26px;font-weight:620;margin:2px 0}.kpi-s{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.span2{grid-column:span 2}
.grid3{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
@media (min-width:1500px){.grid3{grid-template-columns:repeat(4,minmax(0,1fr))}}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;font-weight:600;color:var(--muted);position:sticky;top:0;background:var(--panel)}th a{color:var(--muted)}
tbody tr:hover{background:var(--panel2)}tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums}.trunc{max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scroll{max-height:420px;overflow:auto;overscroll-behavior:contain}.scroll.tall{max-height:560px}
.rel-ips{max-height:120px;overflow:auto}
.cc{display:inline-block;min-width:24px;padding:0 4px;border-radius:4px;background:var(--panel2);border:1px solid var(--line);font-size:11px;font-weight:600;text-align:center}
.tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:500;border:1px solid currentColor;margin:1px 2px 1px 0;color:var(--muted)}
.t-red{color:var(--red)}.t-orange{color:var(--orange)}.t-yellow{color:var(--yellow)}.t-blue{color:var(--blue)}.t-purple{color:var(--purple)}
.t-teal{color:var(--teal)}.t-grey{color:var(--grey)}.t-green{color:var(--green)}
.bars{display:flex;align-items:flex-end;gap:4px;width:100%;height:108px}.bars-60{height:78px}
.bcol{flex:1;min-width:0;height:100%;display:flex;flex-direction:column;justify-content:flex-end;align-items:center}
.bval{font-size:11px;line-height:1;color:var(--muted);margin-bottom:4px;font-variant-numeric:tabular-nums;white-space:nowrap}
.bcol i{display:block;width:100%;max-width:44px;border-radius:3px 3px 0 0;background:var(--accent);opacity:.85;flex:none}
.bcol:hover i{opacity:1}.bcol:hover .bval{color:var(--text)}
@media (max-width:700px){.bars .bval{font-size:9px}}
.axis{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-top:4px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px}.filters input[name=q]{min-width:280px}
.filters label{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px}
.pager{display:flex;justify-content:space-between;align-items:center;margin-top:12px;color:var(--muted)}
.qf{width:100%;margin-bottom:8px}
.iphead{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.iphead h1{margin:0}.score{margin-left:auto;color:var(--muted)}.score b{font-size:22px;color:var(--text);margin-left:6px}
.links{margin:6px 0 16px;color:var(--muted)}
.kv{display:grid;grid-template-columns:140px 1fr;gap:5px 12px;margin:0}.kv dt{color:var(--muted)}.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}
.flagform{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0}.flagform label{color:var(--muted);font-weight:600;font-size:13px}.flagform input{flex:1;min-width:180px}
.rel{display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--line)}.rel:last-child{border:0}.rel-l{width:200px;flex:none;color:var(--muted)}
.rel-ips{display:flex;flex-wrap:wrap;gap:4px 12px}
details.sess{border:1px solid var(--line);border-radius:8px;margin-bottom:6px;background:var(--panel2)}
details.sess summary{cursor:pointer;padding:8px 12px;display:flex;gap:16px;align-items:center;flex-wrap:wrap;list-style:none}
details.sess summary::-webkit-details-marker{display:none}details.sess summary::before{content:"▸";color:var(--muted)}details.sess[open] summary::before{content:"▾"}
details.sess:target,details.sess.hl{border-color:var(--accent)}
.smeta{padding:0 12px 8px;font-size:12px;color:var(--muted)}
.term{background:var(--term);color:var(--termtext);border-radius:0 0 8px 8px;padding:10px 12px;overflow-x:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.ln{display:flex;gap:10px;white-space:pre-wrap;word-break:break-all;padding:1px 0}.ln .t{color:#6d7886;flex:none;width:62px;text-align:right}
.ln .pr{color:#7aa2f7;flex:none;min-width:42px}.ln code{color:inherit;font-size:inherit}.ln.ok .pr{color:#5fc28a}.ln.fail .pr{color:#8b95a3}.ln.warn .pr{color:#f0a050}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}.chip{padding:4px 12px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--muted)}
.chip.on{background:var(--accent2);color:var(--accent);border-color:transparent}
.feed{padding:10px 0;border-bottom:1px solid var(--line)}.feed-h{display:flex;justify-content:space-between;align-items:center;gap:10px}
.url{margin:4px 0;color:var(--muted);overflow-wrap:anywhere}.inline{margin-top:12px}
.preview{display:flex;flex-wrap:wrap;gap:4px 14px;max-height:300px;overflow:auto}
body.login{display:grid;place-items:center;min-height:100vh}.loginbox{width:320px;display:flex;flex-direction:column;gap:12px}.loginbox h1{margin:0 0 4px;text-align:center}
.err{color:var(--red);margin:0}
@media (max-width:1000px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.grid,.grid3{grid-template-columns:minmax(0,1fr)}.span2{grid-column:auto}
header{padding:0 16px;gap:12px}main{padding:16px}.card{overflow-x:auto}.hdr-right .muted{display:none}.rel{flex-direction:column;gap:4px}.kv{grid-template-columns:110px 1fr}}
"""

JS = r"""
(function(){var f=document.getElementById('pwcheck');if(!f)return;var inp=document.getElementById('pwc-in'),out=document.getElementById('pwc-out');
// SHA-256 in plain JavaScript: crypto.subtle only exists on HTTPS pages, and Huginn often runs on plain http on the LAN.
function sha256(str){var b=new TextEncoder().encode(str),K=[],H=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],
n=2,c=0;while(c<64){var p=true;for(var i=2;i*i<=n;i++)if(n%i===0){p=false;break}if(p){K[c++]=(Math.pow(n,1/3)%1)*4294967296|0}n++}
var l=b.length,m=new Uint8Array(((l+9+63)>>6)<<6);m.set(b);m[l]=128;var bits=l*8,dv=new DataView(m.buffer);dv.setUint32(m.length-4,bits>>>0);dv.setUint32(m.length-8,Math.floor(bits/4294967296));
var w=new Array(64);for(var o=0;o<m.length;o+=64){for(var t=0;t<16;t++)w[t]=dv.getUint32(o+t*4);
for(t=16;t<64;t++){var x=w[t-15],y=w[t-2];w[t]=(w[t-16]+((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+w[t-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10)))|0}
var a=H[0],bb=H[1],cc=H[2],d=H[3],e=H[4],ff=H[5],g=H[6],h=H[7];
for(t=0;t<64;t++){var t1=(h+((e>>>6|e<<26)^(e>>>11|e<<21)^(e>>>25|e<<7))+((e&ff)^(~e&g))+K[t]+w[t])|0,t2=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&bb)^(a&cc)^(bb&cc)))|0;
h=g;g=ff;ff=e;e=(d+t1)|0;d=cc;cc=bb;bb=a;a=(t1+t2)|0}
H[0]=(H[0]+a)|0;H[1]=(H[1]+bb)|0;H[2]=(H[2]+cc)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+ff)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0}
return H.map(function(v){return('00000000'+(v>>>0).toString(16)).slice(-8)}).join('')}
window.huginnSha256=sha256;
function el(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}
var P=+f.dataset.prefix||4;
f.addEventListener('submit',function(ev){ev.preventDefault();var pw=inp.value;out.textContent='';if(!pw)return;
var h=sha256(pw),pre=h.slice(0,P),suf=h.slice(P);out.textContent='Checking…';
fetch(f.dataset.src+pre+'.json',{credentials:'same-origin'}).then(function(r){return r.ok?r.json():{matches:[],distinct:null}}).then(function(d){
out.textContent='';var hit=(d.matches||[]).filter(function(x){return x.s===suf})[0];
if(!hit){out.appendChild(el('div','pwc-ok','Not found'));out.appendChild(el('div','muted small','Not among the '+(d.distinct!=null?d.distinct.toLocaleString()+' different ':'')+'passwords attackers tried'+(d.since?' since '+d.since.slice(0,10):'')+'.'));return}
out.appendChild(el('div','pwc-bad','Found: attackers tried this password'));
var t=el('table','');[['Tries',hit.tries+(hit.accepted?' ('+hit.accepted+' accepted by the honeypot)':'')],['From',hit.ips+' IP address'+(hit.ips===1?'':'es')],
['First / last',hit.first.slice(0,10)+' / '+hit.last.slice(0,10)],['Services',hit.services.join(', ')],
['With usernames',hit.users.map(function(u){return u[0]+(u[1]>1?' ('+u[1]+')':'')}).join(', ')]].forEach(function(r){var tr=el('tr');tr.appendChild(el('th','',r[0]));tr.appendChild(el('td','',r[1]));t.appendChild(tr)});
out.appendChild(t);out.appendChild(el('div','muted small','It is on attackers’ lists: do not use it anywhere that can be reached from the internet.'))
}).catch(function(){out.textContent='Could not check right now.'})});
inp.addEventListener('input',function(){out.textContent=''})})();
function copyText(t){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(t);
var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.className='offscreen';document.body.appendChild(a);a.select();
try{document.execCommand('copy')}finally{a.remove()}return Promise.resolve()}
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b)return;e.preventDefault();
copyText(b.dataset.copy).then(function(){var t=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=t},1200)})});
document.querySelectorAll('input[data-filter]').forEach(function(inp){var t=document.getElementById(inp.dataset.filter);if(!t)return;
inp.addEventListener('input',function(){var q=inp.value.toLowerCase();t.querySelectorAll('tbody tr').forEach(function(r){r.hidden=!!q&&r.textContent.toLowerCase().indexOf(q)<0})})});
(function(){
var keys=[['g o','Overview'],['g n','New'],['g a','Attackers'],['g c','Campaigns'],['g p','Personas'],['g e','Engagement'],['g f','Files'],['g r','Credentials'],['g b','Blocklist'],['g s','Settings'],
['/','Search / filter'],['t','Switch theme'],['Space','Play / pause a replay'],['?','This help'],['Esc','Close']];
var box=null;function hide(){if(box){box.remove();box=null}}
function show(){if(box){hide();return}box=document.createElement('div');box.className='kbd-help';var c=document.createElement('div');c.className='card';
var h=document.createElement('h3');h.textContent='Keyboard shortcuts';c.appendChild(h);keys.forEach(function(k){var r=document.createElement('div');r.className='kr';
var a=document.createElement('kbd');a.textContent=k[0];var b=document.createElement('span');b.textContent=k[1];r.appendChild(a);r.appendChild(b);c.appendChild(r)});
box.appendChild(c);box.addEventListener('click',function(e){if(e.target===box)hide()});document.body.appendChild(box)}
var hb=document.getElementById('kbdHelp');if(hb)hb.addEventListener('click',function(e){e.preventDefault();show()});
var g=false,gt=null,map={o:'/',n:'/new',a:'/ips',c:'/campaigns',p:'/personas',e:'/engagement',f:'/files',r:'/creds',b:'/blocklist',s:'/settings'};
document.addEventListener('keydown',function(e){var t=e.target;if(e.ctrlKey||e.metaKey||e.altKey)return;
if(t&&(t.tagName==='INPUT'||t.tagName==='TEXTAREA'||t.tagName==='SELECT'||t.isContentEditable)){if(e.key==='Escape')t.blur();return}
var k=e.key;if(g){g=false;clearTimeout(gt);if(map[k]){location.href=map[k];e.preventDefault()}return}
if(k==='g'){g=true;gt=setTimeout(function(){g=false},1500);return}
if(k==='/'){var i=document.querySelector('input[name=q],input.qf');if(i){i.focus();e.preventDefault()}else if(document.querySelector('nav a[href="/search"]')){location.href='/search';e.preventDefault()}return}
if(k==='t'){var f=document.querySelector('form[action="/settings/theme"]');if(f)f.submit();return}
if(k===' '){var p=document.getElementById('pPlay');if(p){p.click();e.preventDefault()}return}
if(k==='?'){show();e.preventDefault();return}
if(k==='Escape')hide()})})();
(function(){var pl=document.getElementById('player');if(!pl)return;var fr=[],i=0,t=0,timer=null,buf='',playing=false;
var bt=document.getElementById('pPlay'),sp=document.getElementById('pSpeed'),idle=document.getElementById('pIdle'),tm=document.getElementById('pTime');
function feed(s){s=s.replace(/\x1b\][^\x07\x1b]{0,4096}\x07/g,'').replace(/\x1b\[[0-9;?]*[A-Za-z]/g,'').replace(/\x1b[()][A-Z0-9]/g,'').replace(/\r\n/g,'\n');
for(var k=0;k<s.length;k++){var c=s[k];if(c==='\b'){buf=buf.slice(0,-1)}else if(c==='\r'){var p=buf.lastIndexOf('\n');buf=buf.slice(0,p+1)}else if(c==='\x07'){}else{buf+=c}}if(buf.length>2000000)buf=buf.slice(-1000000)}
var PR=/^((?:[^\s@]{1,64}@[\w.-]+:[^#$]{0,200}|[\w.\/~-]{0,200} ?)[#$](?: |$))(.*)$/,sk=document.getElementById('pSeek');
function span(c,x){var e=document.createElement('span');e.className=c;e.textContent=x;return e}
// Attacker text: built with textContent only, never as HTML. Very long recordings show their tail.
function show(){var ls=buf.split('\n'),f=document.createDocumentFragment();if(ls.length>3000)ls=ls.slice(-3000);
ls.forEach(function(l,n){var m=l.length<2000?PR.exec(l):null;if(m){f.appendChild(span('tp',m[1]));f.appendChild(span('tc',m[2]))}else f.appendChild(document.createTextNode(l));if(n<ls.length-1)f.appendChild(document.createTextNode('\n'))});
pl.textContent='';pl.appendChild(f);pl.scrollTop=pl.scrollHeight;tm.textContent=(fr.length?Math.round(t)+'s / '+Math.round(fr[fr.length-1][0])+'s':'');if(sk){sk.max=fr.length;sk.value=i}}
function seek(n){clearTimeout(timer);playing=false;bt.textContent='Play';buf='';for(var k=0;k<n;k++)feed(fr[k][1]);i=n;t=n?fr[n-1][0]:0;show()}
var sq=null,want=0;if(sk)sk.addEventListener('input',function(){want=+sk.value||0;clearTimeout(timer);playing=false;bt.textContent='Play';if(sq!==null)return;sq=requestAnimationFrame(function(){sq=null;seek(Math.max(0,Math.min(fr.length,want)))})});
function step(){if(!playing)return;if(i>=fr.length){playing=false;bt.textContent='Play';return}
feed(fr[i][1]);t=fr[i][0];i++;show();if(i>=fr.length){playing=false;bt.textContent='Play';return}
var d=(fr[i][0]-t);if(idle.checked)d=Math.min(d,1);timer=setTimeout(step,Math.max(0,d*1000/(+sp.value||1)))}
function restart(){clearTimeout(timer);i=0;t=0;buf='';show()}
bt.addEventListener('click',function(){if(playing){playing=false;clearTimeout(timer);bt.textContent='Play'}else{if(i>=fr.length)restart();playing=true;bt.textContent='Pause';step()}});
document.getElementById('pRestart').addEventListener('click',function(){restart();if(playing){clearTimeout(timer);step()}});
fetch(pl.dataset.src,{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){if(d.error){pl.textContent=d.error;return}
fr=d.frames||[];pl.textContent=fr.length?'':'Empty recording.';if(fr.length){playing=true;bt.textContent='Pause';step()}}).catch(function(){pl.textContent='Could not load the recording.'})})();
(function(){var box=document.getElementById('wmap');if(!box)return;var card=box.closest('.card');var drawn=false;
function view(v){card.querySelectorAll('[data-cview]').forEach(function(b){b.classList.toggle('on',b.dataset.cview===v)});
card.querySelectorAll('[data-cpanel]').forEach(function(p){p.hidden=p.dataset.cpanel!==v});try{localStorage.setItem('hgCview',v)}catch(e){}if(v==='map')draw()}
function draw(){if(drawn)return;drawn=true;fetch('/static/world-map.json').then(function(r){return r.json()}).then(function(w){
var counts={};try{counts=JSON.parse(box.dataset.counts||'{}')}catch(e){}var max=1;for(var k in counts)max=Math.max(max,counts[k]);
var NS='http://www.w3.org/2000/svg',svg=document.createElementNS(NS,'svg');svg.setAttribute('viewBox','0 0 '+w.w+' '+w.h);svg.setAttribute('class','wm-svg');
svg.setAttribute('role','img');svg.setAttribute('aria-label','World map of attacker countries');
Object.keys(w.c).forEach(function(id){var cc=id.toUpperCase(),n=counts[cc],p=document.createElementNS(NS,'path');p.setAttribute('d',w.c[id][1]);
p.setAttribute('class','wm-land'+(n?' wm-hit':''));var t=document.createElementNS(NS,'title');t.textContent=w.c[id][0]+(n?': '+n+' IP'+(n===1?'':'s'):'');p.appendChild(t);
if(n){p.setAttribute('fill-opacity',(0.28+0.72*Math.log(1+n)/Math.log(1+max)).toFixed(2));p.addEventListener('click',function(){location.href='/ips?days=7&cc='+cc})}
svg.appendChild(p)});box.textContent='';box.appendChild(svg);
svg.querySelectorAll('path.wm-hit').forEach(function(p){var bb=p.getBBox();if(Math.max(bb.width,bb.height)>=14)return;
var d=document.createElementNS(NS,'circle');d.setAttribute('cx',bb.x+bb.width/2);d.setAttribute('cy',bb.y+bb.height/2);d.setAttribute('r',5);
d.setAttribute('class','wm-dot');d.setAttribute('fill-opacity',p.getAttribute('fill-opacity'));var t=p.querySelector('title');if(t)d.appendChild(t.cloneNode(true));
d.addEventListener('click',function(){p.dispatchEvent(new Event('click'))});svg.appendChild(d)})}).catch(function(){box.textContent='Map not available.'})}
card.querySelectorAll('[data-cview]').forEach(function(b){b.addEventListener('click',function(){view(b.dataset.cview)})});
var v='map';try{v=localStorage.getItem('hgCview')||'map'}catch(e){}view(v==='list'?'list':'map')})();
(function(){var b=document.getElementById('brand');if(!b)return;var now={f:+b.dataset.file||0,t:+b.dataset.took||0,r:+b.dataset.read||0},old=null;
// Reacts once, to a real find since this browser last looked. The first visit only remembers.
try{old=JSON.parse(localStorage.getItem('hgFinds')||'null');localStorage.setItem('hgFinds',JSON.stringify(now))}catch(e){return}
if(!old||typeof old!=='object')return;
var hit=now.t>old.t?['Bait used','/ips?tag=took-bait&days=7&sort=last']:now.r>old.r?['Bait read','/ips?tag=read-bait&days=7&sort=last']:now.f>old.f?['New file','/new']:null;
if(!hit)return;var a=document.createElement('a');a.className='raven-note';a.href=hit[1];a.textContent=hit[0];b.appendChild(a);b.classList.add('raven-on')})();
document.documentElement.classList.add('js');document.querySelectorAll('select[data-autosubmit]').forEach(function(s){s.addEventListener('change',function(){s.form.submit()})});
if(location.hash){var d=document.getElementById(location.hash.slice(1));if(d&&d.tagName==='DETAILS'){d.open=true;d.classList.add('hl');d.scrollIntoView({block:'center'})}}
"""
CSS += (".ov-bar{display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin-bottom:12px}.ov-bar form{margin:0}.ov-bar .vtabs{margin-left:0}"
        ".ov-tabs button{padding:5px 14px;font-size:13px}.ov-f{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.ov-f .chips{margin:0}.ov-f .chip{padding:4px 12px}"
        ".ov-svc{display:flex;gap:6px;align-items:center}.ov-svc select{padding:4px 8px}.js .ov-go{display:none}"
        ".ov-asof{margin-left:auto;font-size:12px;color:var(--muted)}"
        ".board-kpis .kpis{gap:10px;margin-bottom:10px}.board-kpis .kpi{padding:9px 12px;border-radius:6px}.board-kpis .kpi-v{font-size:21px}"
        ".board{display:grid;grid-template-columns:minmax(0,1fr);gap:10px;align-items:start}.board-col{display:flex;flex-direction:column;gap:10px;min-width:0}"
        "@media (min-width:1001px){.board{grid-template-columns:repeat(2,minmax(0,1fr))}.board .b-feed{grid-column:span 2}}"
        "@media (min-width:1500px){.board{grid-template-columns:minmax(0,25fr) minmax(0,45fr) minmax(0,30fr)}.board .b-feed{grid-column:auto}}"
        ".board .card{padding:12px 14px;border-radius:6px}.board h3{font-size:12px;margin-bottom:8px}.board table{font-size:13px}.board th,.board td{padding:4px 6px}"
        ".board .bval{display:none}.board .bars{height:92px;gap:2px}.board .bcol i{max-width:none;border-radius:2px 2px 0 0}"
        ".board tr.sel td{background:var(--accent2)}.board tr.sel .svc-l{color:var(--accent);font-weight:600}.svc-l{color:var(--text)}.b-note{margin:8px 0 0}"
        ".mail{padding:8px 0;border-top:1px solid var(--line)}.mail:first-child{border-top:0}.mail-h{margin-bottom:2px}"
        ".mail-body{white-space:pre-wrap;overflow-wrap:anywhere;max-height:22em;overflow:auto;margin:6px 0 0}"
        ".nowrap{white-space:nowrap}.fd-d{overflow-wrap:anywhere;word-break:break-word}.fd-n{color:var(--muted);font-family:system-ui,sans-serif;font-size:12px;margin-left:4px;white-space:nowrap}"
        "details.fd summary{cursor:pointer;list-style:none}details.fd summary::-webkit-details-marker{display:none}details.fd[open] summary{display:none}"
        ".b-creds .trunc{max-width:150px}"
        "@media (max-width:800px){.b-feed thead{display:none}.b-feed tr{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 10px;padding:7px 0;border-bottom:1px solid var(--line)}"
        ".b-feed td{border:0;padding:0}.b-feed td.fd-d{flex-basis:100%}.b-feed tbody tr:hover{background:none}}"
        "@media (max-width:1000px){.ov-asof{margin-left:0;width:100%}.ov-svc select{min-height:40px}.ov-f .chip{padding:9px 14px}}")
CSS += ".offscreen{position:fixed;left:-9999px;top:0}"
# Accent colours: light first, then dark (higher specificity wins in dark mode), then compact layout and settings page.
CSS += "".join(".bcol i.h%d{height:calc((100%% - 16px) * %.2f)}" % (n, n / 100) for n in range(0, 101, 2))
CSS += ":root{color-scheme:light}" + "".join(":root[data-accent=%s]{--accent:%s;--accent2:%s}" % (k, v[0], v[1]) for k, v in ACCENTS.items())
CSS += "@media (prefers-color-scheme:dark){" + "".join(":root:not([data-theme=light])[data-accent=%s]{--accent:%s;--accent2:%s}" % (k, v[2], v[3]) for k, v in ACCENTS.items()) + "}"
CSS += "".join(":root[data-theme=dark][data-accent=%s]{--accent:%s;--accent2:%s}" % (k, v[2], v[3]) for k, v in ACCENTS.items())
CSS += "".join(".dot-%s{background:%s}" % (k, v[0]) for k, v in ACCENTS.items())
CSS += ("[data-density=compact] th,[data-density=compact] td{padding:3px 6px}[data-density=compact] .card{padding:11px}"
        "[data-density=compact] .kpi{padding:9px 12px}[data-density=compact] .kpi-v{font-size:21px}[data-density=compact] .grid,"
        "[data-density=compact] .kpis,[data-density=compact] .grid3{gap:9px}[data-density=compact] main{padding-top:14px}"
        "[data-density=compact] body{font-size:13px}")
CSS += (".site-foot{max-width:2200px;margin:0 auto;padding:18px 24px 28px;color:var(--muted);font-size:12px;text-align:center}"
        ".site-foot a{color:var(--muted);text-decoration:underline}.site-foot a:hover{color:var(--text)}"
        "body.login{grid-template-rows:1fr auto}body.login .site-foot{padding-bottom:16px}")
CSS += (".upd{font-size:12px;font-weight:600;color:var(--accent);border:1px solid var(--accent);border-radius:999px;padding:1px 9px}")
CSS += (".vtabs{margin-left:auto;display:inline-flex;border:1px solid var(--line);border-radius:6px;overflow:hidden;text-transform:none;letter-spacing:0}"
        ".vtabs button{background:none;color:var(--muted);border:0;border-radius:0;padding:3px 12px;font-size:12px}.vtabs button.on{background:var(--accent2);color:var(--accent)}"
        ".wm-svg{width:100%;height:auto;max-height:300px;display:block;margin:0 auto}.chart-card{display:flex;flex-direction:column}.chart-card .bars{flex:1;height:auto;min-height:108px}.wm-land{fill:var(--panel2);stroke:var(--line);stroke-width:.6}"
        ".wm-hit{fill:var(--accent);cursor:pointer}.wm-hit:hover,.wm-dot:hover{fill-opacity:1}.wm-dot{fill:var(--accent);stroke:var(--panel);stroke-width:1.5;cursor:pointer}"
        ".wm-legend{display:flex;align-items:center;gap:8px;justify-content:flex-end;font-size:11px;color:var(--muted);margin-top:6px}"
        ".wm-legend i{display:inline-block;width:90px;height:8px;border-radius:4px;background:linear-gradient(90deg,var(--accent2),var(--accent))}")
CSS += (".kbd-btn{font-weight:600;width:22px;height:22px;border:1px solid var(--line)!important;border-radius:50%;display:inline-grid;place-items:center;padding:0!important}"
        ".kbd-help{position:fixed;inset:0;background:rgba(0,0,0,.45);display:grid;place-items:center;z-index:50}.kbd-help .card{width:340px}"
        ".kr{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--line)}.kr:last-child{border:0}"
        "kbd{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:var(--panel2);border:1px solid var(--line);border-radius:4px;padding:1px 6px}"
        ".cols2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:2px 12px}.cols2 .opt{display:flex}.wide-input{width:100%}")
CSS += (".theme-btn{display:flex;align-items:center;gap:6px}.ti{display:inline-block;width:12px;height:12px;border-radius:50%;border:1.5px solid currentColor}"
        ".ti-light{background:transparent}.ti-dark{background:currentColor}.ti-auto{background:linear-gradient(90deg,currentColor 50%,transparent 50%)}"
        ".settings .row{display:grid;grid-template-columns:170px 1fr;gap:10px;align-items:start;padding:8px 0;border-bottom:1px solid var(--line)}"
        ".settings .row:last-of-type{border:0}.settings .rl{color:var(--muted);padding-top:2px}.opt{display:inline-flex;align-items:center;gap:6px;margin:0 16px 6px 0;cursor:pointer}"
        ".col .opt{display:flex}.sub{margin:6px 0 0 24px}.sws{display:flex;flex-wrap:wrap}.dot{width:14px;height:14px;border-radius:50%;display:inline-block}"
        ".actions{margin-top:14px;display:flex;gap:10px}@media (max-width:1000px){.settings .row{grid-template-columns:1fr}}"
        "@media (max-width:1000px){header{position:static;flex-wrap:wrap;height:auto;padding:4px 16px;gap:2px 10px}header nav{order:3;width:100%}"
        ".hdr-right{display:contents}.brand{margin-right:auto}.theme-btn{font-size:0}.theme-btn .ti{font-size:14px}.sync{order:2;width:100%;text-align:right}}")
CSS += (".pctl{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.pctl label{display:flex;gap:6px;align-items:center;color:var(--muted)}"
        ".player{min-height:min(220px,70vh);max-height:70vh;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0;border-radius:8px}"
        ".iocs{line-height:1.5;max-width:420px;overflow-wrap:anywhere}.replay{font-weight:600}"
        ".replay-btn{display:inline-block;padding:2px 10px;border:1px solid var(--accent);border-radius:999px;color:var(--accent);font-size:12px;"
        "font-weight:600;white-space:nowrap;text-decoration:none}.replay-btn:hover{background:var(--accent);color:var(--bg)}"
        "details.sess summary .replay-btn{margin-left:auto}")
CSS += (".hdr-link{color:var(--muted)}.hdr-link:hover,.hdr-link.on{color:var(--text)}"
        ".stack{display:flex;flex-direction:column;gap:12px;max-width:420px}.stack label{display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:13px}"
        ".stack button{align-self:flex-start}.okmsg{color:var(--green);margin:0 0 14px}.err{margin:0 0 14px}"
        ".cl{display:grid;grid-template-columns:60px 90px 1fr;gap:10px;padding:5px 0;border-bottom:1px solid var(--line)}.cl:last-child{border:0}"
        "button[disabled]{opacity:.5;cursor:default}")
CSS += "".join(".sbar .g%d{flex-grow:%d}" % (n, n) for n in range(1, 61))
CSS += (".sbar{display:flex;gap:2px;height:8px;margin:12px 0 4px}.sbar i{display:block;flex-basis:0;min-width:3px;background:var(--accent)}"
        ".sbar i:nth-child(even){opacity:.55}.sbar i:first-child{border-radius:4px 0 0 4px}.sbar i:last-child{border-radius:0 4px 4px 0}.sleg{font-size:12px;margin-bottom:8px}"
        ".bcol i.partial{background:repeating-linear-gradient(135deg,var(--accent) 0 3px,transparent 3px 6px);box-shadow:inset 0 0 0 1px var(--accent)}"
        ".kpi.hot{border-color:var(--hot)}.kpi.hot .kpi-v{color:var(--hot)}.kpi-sw{position:absolute;opacity:0;pointer-events:none}.kpi-more{display:none}"
        ".nw{white-space:nowrap}.ft{margin-top:3px}.ioc-more summary{cursor:pointer;color:var(--accent);font-family:system-ui,sans-serif}"
        ".nav-n{margin-left:6px;padding:0 6px;border-radius:9px;font-size:11px;background:var(--accent2);color:var(--accent);font-variant-numeric:tabular-nums}"
        "nav a.on .nav-n{background:var(--panel)}.wrap{overflow-wrap:anywhere}"
        ".newhead{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}.newhead h1{margin-bottom:2px}.newhead p{margin:0 0 14px}"
        ".newact{display:flex;gap:8px;align-items:center}.newact form{margin:0}"
        "@media (max-width:1000px){.kpis{grid-template-columns:repeat(6,minmax(0,1fr));gap:8px}.kpi{grid-column:span 2;padding:10px;min-width:0}"
        ".kpi.kpi-x{display:none;grid-column:span 3}.kpi-sw:checked~.kpis .kpi-x{display:block}.kpi-v{font-size:22px}.kpi:not(.kpi-x) .kpi-s{display:none}"
        ".kpi-more{display:flex;align-items:center;justify-content:center;min-height:44px;margin:-6px 0 8px;color:var(--accent);cursor:pointer}"
        ".kpi-sw:checked~.kpi-more .a,.kpi-sw:not(:checked)~.kpi-more .b{display:none}.kpi-sw:focus-visible~.kpi-more{outline:2px solid var(--accent);border-radius:6px}"
        "nav a,button.link,.hdr-link,.vtabs button{min-height:44px;display:inline-flex;align-items:center}.btn-s{min-height:44px;padding:8px 12px}"
        "button.kbd-btn{position:relative;min-height:22px}.kbd-btn::after{content:'';position:absolute;inset:-11px}.replay-btn{padding:10px 14px}}")
CSS += (".story{font-size:15px;margin:8px 0}.ip-w{display:grid;grid-template-columns:minmax(0,1fr);gap:14px}"
        ".ip-main{display:flex;flex-direction:column;gap:14px;min-width:0}.ip-main>*{min-width:0}"
        ".ip-side{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;align-content:start;min-width:0}.ip-side>*{min-width:0}.ip-side .flagcard{grid-column:1/-1}"
        "@media (min-width:1500px){.ip-w{grid-template-columns:minmax(0,1fr) 400px}.ip-side{grid-template-columns:minmax(0,1fr)}.ip-main .scroll.tall{max-height:72vh}}"
        "@media (max-width:1000px){.ip-side{grid-template-columns:minmax(0,1fr)}}"
        ".rel-r{flex:1;min-width:0}.rel-more summary{cursor:pointer;color:var(--accent);font-size:13px;margin-top:4px}.rel-more .rel-ips{margin-top:4px;max-height:none}"
        ".bcol{position:relative}.bcol.gapd::after{content:'';position:absolute;bottom:-6px;left:50%;transform:translateX(-50%);width:100%;max-width:44px;height:3px;background:var(--orange)}"
        ".gap-note{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);margin-top:6px}.gap-note i{display:block;width:14px;height:3px;background:var(--orange)}")
CSS += ".c-k{color:#f0a050}.c-l{color:#7aa2f7;text-decoration:underline}.c-f{color:#5fc28a;text-decoration:underline}"
CSS += (".note{margin:10px 0 0}mark{background:var(--accent2);color:var(--accent);border-radius:2px;padding:0 1px}"
        ".stack-w{display:flex;flex-direction:column;gap:14px;margin-bottom:10px}.stack-w>*{min-width:0}")
CSS += (":root{--hot:#b4540a}@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--hot:#f0a050}}:root[data-theme=dark]{--hot:#f0a050}:root[data-accent=orange]{--hot:var(--red)}"
        ".s-hot{color:var(--hot)}.sbar i.hot{background:var(--hot)}.empty{margin:2px 0}.m-row{display:none}"
        ".ip-h{align-items:baseline}h1.ip-title{font-size:26px;font-weight:600;letter-spacing:.2px;overflow-wrap:anywhere}.ip-tags{order:3;flex-basis:100%}"
        ".scr{display:block;max-width:640px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hash.mono{font-size:11px;margin-top:1px}"
        ".pager.top{margin:0 0 10px}.sizes{margin-left:14px}.sizes a,.sizes b{margin-left:6px;font-weight:500}.sizes b{color:var(--text)}"
        ".replay-card{max-width:1240px}.twin{border:1px solid var(--line);border-radius:8px;overflow:hidden}"
        ".twin-bar{display:flex;align-items:center;gap:6px;padding:7px 12px;background:var(--panel2);border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}"
        ".twin-bar i{display:block;width:10px;height:10px;border-radius:50%;background:var(--line)}.twin-bar span{margin-left:8px}"
        ".twin .player{border-radius:0;min-height:min(340px,60vh)}.tp{color:#5fc28a}.tc{color:#fff;font-weight:500}"
        ".pseek{width:100%;margin-top:10px;padding:0;border:0;background:none;accent-color:var(--accent)}"
        ".pb{min-width:340px;width:55%}.dist{display:flex;gap:2px;height:10px}.dist i{display:block;flex-basis:0;min-width:3px;border-radius:2px}"
        ".o-none{background:var(--line)}.o-one{background:color-mix(in srgb,var(--muted) 60%,var(--panel))}.o-short{background:var(--accent)}.o-pay{background:var(--hot)}"
        ".dleg{display:flex;flex-wrap:wrap;gap:2px 16px;margin-top:6px;font-size:12px;color:var(--muted)}.dleg span{display:inline-flex;align-items:center;gap:5px}"
        ".dleg i{display:block;width:8px;height:8px;border-radius:2px}.dleg b{font-weight:500;color:var(--text)}"
        ".now-tag{margin-left:6px;font-size:11px;color:var(--hot)}.brand{display:flex;align-items:center;gap:10px}.raven-note{font-size:12px;color:var(--hot);white-space:nowrap}"
        ".raven-on .brand-ic{animation:raven 1.1s ease-in-out 1;box-shadow:0 0 0 2px var(--hot),0 0 14px var(--hot)}"
        "@keyframes raven{0%,100%{transform:rotate(0)}25%{transform:rotate(-16deg)}55%{transform:rotate(12deg)}80%{transform:rotate(-4deg)}}"
        "@media (prefers-reduced-motion:reduce){.raven-on .brand-ic{animation:none}}"
        ".rcpt{position:relative;max-width:400px;margin:4px 0 26px;padding:24px 26px 20px;background:#f4f1e8;color:#23211c;line-height:1.7}.rcpt.mono{font-size:14px}"
        ".rcpt::after{content:'';position:absolute;left:0;right:0;bottom:-8px;height:8px;background:linear-gradient(135deg,#f4f1e8 50%,transparent 50%) 0 0/12px 8px,linear-gradient(225deg,#f4f1e8 50%,transparent 50%) 0 0/12px 8px}"
        ".rcpt a{color:inherit;text-decoration:underline}.rcpt hr{border:0;border-top:1px dashed #8d887b;margin:10px 0}.rc-c{text-align:center}.rc-title{font-size:20px;font-weight:600;letter-spacing:3px}.rc-dim{color:#6a665b}"
        ".rc-r{display:flex;justify-content:space-between;gap:16px}.rc-total{font-size:17px;font-weight:600}"
        ".rc-bar{height:34px;margin-top:14px;background:repeating-linear-gradient(90deg,#23211c 0 2px,transparent 2px 5px,#23211c 5px 6px,transparent 6px 11px,#23211c 11px 14px,transparent 14px 17px)}.rc-note{max-width:400px}"
        "@media (max-width:800px){[data-h]{display:none}.m-row{display:table-row}.m-row td{padding:0 8px 7px}.m-row td:empty{display:none}tr:has(+.m-row) td{border-bottom:0}.top5 tbody tr:nth-child(n+11){display:none}h1.ip-title{font-size:22px}"
        ".ptab thead{display:none}.ptab tr{display:grid;grid-template-columns:1fr auto auto;gap:6px 14px;padding:10px 0;border-bottom:1px solid var(--line)}.ptab tr:last-child{border:0}.ptab td{border:0;padding:0}"
        ".ptab td.pb{grid-column:1/-1;grid-row:2;min-width:0;width:auto}.ptab td[data-l]::before{content:attr(data-l) ' ';color:var(--muted);font-size:11px}.ptab td[data-l='Payload share']{grid-column:1/-1;grid-row:3;text-align:left}"
        ".etab thead{display:none}.etab tr{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 14px;padding:10px 0;border-bottom:1px solid var(--line)}.etab tr:last-child{border:0}"
        ".etab td{border:0;padding:0}.etab td.num{text-align:left}.etab td:first-child{flex:1 0 auto;font-weight:600}.etab td.pb{flex:1 0 100%;min-width:0;width:auto;order:1}.etab td.pb~td{order:2}"
        ".etab td[data-l]::before{content:attr(data-l) ' ';color:var(--muted);font-size:11px}"
        ".pager{flex-wrap:wrap;gap:6px}.sizes{margin-left:8px}.top5 th,.top5 td{padding-left:5px;padding-right:5px}}")
CSS += "".join(".dist .p%d{flex-grow:%d}" % (n, n) for n in range(1, 101))
# 0.28: wide screens (2K) get three columns on the Overview (dense, so a wide card never leaves a hole) and two on Campaigns.
CSS += (".cgrid{display:grid;grid-template-columns:minmax(0,1fr);gap:0 14px}.cgrid h2{margin-top:18px}"
        "@media (min-width:1800px){.grid.ov{grid-template-columns:repeat(3,minmax(0,1fr));grid-auto-flow:dense}"
        ".cgrid{grid-template-columns:repeat(2,minmax(0,1fr));grid-auto-flow:dense}.cgrid .cs-wide{grid-column:span 2}}")
# 0.30: folded sessions on the attacker page.
CSS += (".sess-more{margin:2px 0 6px;border:1px dashed var(--line);border-radius:8px;padding:2px 8px}"
        ".sess-more>summary{cursor:pointer;color:var(--muted);font-size:13px;padding:6px 2px}.sess-more .sess{margin-left:6px}")
# 0.31: the attacker timeline and ATT&CK chips.
CSS += (".tl{list-style:none;margin:0;padding:0;border-left:2px solid var(--line);margin-left:6px}"
        ".tl li{position:relative;padding:5px 0 5px 14px;display:flex;flex-wrap:wrap;gap:4px 8px;align-items:baseline}"
        ".tl li::before{content:'';position:absolute;left:-5px;top:11px;width:8px;height:8px;border-radius:50%;background:var(--accent)}"
        ".tl-t{color:var(--muted);font-size:12px;min-width:150px}.tl-x{flex:1 1 300px}.tl-c{display:inline-flex;gap:4px;flex-wrap:wrap}"
        ".tag.t-att{font-family:var(--mono,monospace);font-size:11px}")
# 0.28: a visible keyboard focus everywhere (the mouse never shows it).
CSS += ("a:focus-visible,button:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible"
        "{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}")
ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1b212a"/>'
        '<path d="M6 21c4-1 6-4 8-8 2-3 5-5 9-5l3 2-3 1c-1 4-3 8-7 10-3 2-7 2-10 0z" fill="#7aa2f7"/></svg>')


# ---------------------------------------------------------------- HTTP

SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Huginn"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30                 # seconds per socket operation: a stalled client cannot hold a thread for ever

    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        ip = self.client_address[0]
        xff = self.headers.get("X-Forwarded-For")
        if ip in TRUSTED_PROXIES and xff:
            return xff.split(",")[-1].strip()
        return ip

    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None, cache=False):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400" if cache else "no-store")
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, to, headers=None):
        h = {"Location": to}
        h.update(headers or {})
        self.send(303, "", headers=h)

    def cookie_secure(self):
        return self.client_address[0] in TRUSTED_PROXIES and self.headers.get("X-Forwarded-Proto") == "https"

    def authed(self):
        c = cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie") or "")
        except cookies.CookieError:
            return False
        m = c.get("huginn_s")
        if not m or not m.value:
            return False
        th = hashlib.sha256(m.value.encode()).hexdigest()
        r = db().execute("SELECT expires FROM logins WHERE token_hash=?", (th,)).fetchone()
        return th if (r and r[0] > time.time()) else None

    def same_origin(self):
        o = self.headers.get("Origin")
        if not o:
            ref = self.headers.get("Referer")
            if not ref:
                return False
            o = ref
        return urllib.parse.urlsplit(o).netloc == (self.headers.get("Host") or "")

    def form(self, lists=None):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > 20000:
            # Never read an unknown or huge body (a negative length would wait forever); drop the connection instead.
            self.close_connection = True
            return {}
        raw = self.rfile.read(n).decode("utf-8", "replace")
        self._body_read = True
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        if lists is not None:
            lists.update(parsed)
        return {k: v[0] for k, v in parsed.items()}

    def back(self):
        # Redirect to the page the form was posted from (same origin was already checked).
        ref = urllib.parse.urlsplit(self.headers.get("Referer") or "/")
        target = ref.path + ("?" + ref.query if ref.query else "")
        # Only a path on this site: "//host" and "/\host" would send the browser elsewhere.
        if not target.startswith("/") or target[1:2] in ("/", "\\") or any(c in target for c in "\\\r\n\t"):
            return "/"
        return target

    def host_ok(self):
        return not ALLOWED_HOSTS or (self.headers.get("Host") or "").lower() in ALLOWED_HOSTS

    def do_HEAD(self):
        self.do_GET()

    def finish_body(self):
        # A body nobody read must not be parsed as the next request on this connection, so hang up instead.
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1 or (not self._body_read and lengths and lengths[0].strip() != "0"):
            self.close_connection = True

    def do_GET(self):
        self._body_read = False
        try:
            self.route_get()
        except Exception as e:
            sys.stderr.write("GET %s: %r\n" % (self.path, e))
            self.close_connection = True
            self.send(500, "Internal error", "text/plain")
        finally:
            self.finish_body()

    def do_POST(self):
        self._body_read = False
        try:
            self.route_post()
        except Exception as e:
            sys.stderr.write("POST %s: %r\n" % (self.path, e))
            self.close_connection = True
            self.send(500, "Internal error", "text/plain")
        finally:
            self.finish_body()

    def route_get(self):
        _local.h12 = settings().get("clock") == "12"
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if path == "/healthz":
            con = db()
            li = float(get_meta(con, "last_ingest", "0") or 0)
            ok = (time.time() - li) < POLL * 3
            try:
                problems = sorted(json.loads(get_meta(con, "health_now", "{}")))
            except ValueError:
                problems = []
            return self.send(200 if ok else 503, json.dumps({"ok": ok, "version": HUGINN_VERSION, "last_ingest_age_s": int(time.time() - li) if li else None,
                                                             "collection_problems": problems}), "application/json")
        if not self.host_ok():
            return self.send(421, "Unknown host", "text/plain")
        if path == "/static/app.css":
            return self.send(200, CSS, "text/css; charset=utf-8", cache=True)
        if path == "/static/world-map.json":
            try:
                with open(os.path.join(STATIC_DIR, "world-map.json"), "rb") as fh:
                    return self.send(200, fh.read(), "application/json", cache=True)
            except OSError:
                return self.send(404, "{}", "application/json")
        m = re.fullmatch(r"/static/icon-(32|180|192)\.png|/favicon\.ico", path)
        if m:
            try:
                with open(os.path.join(STATIC_DIR, "icon-%s.png" % (m.group(1) or "32")), "rb") as fh:
                    return self.send(200, fh.read(), "image/png", cache=True)
            except OSError:
                return self.send(200, ICON, "image/svg+xml", cache=True)
        if path in ("/static/hero.jpg", "/static/hero-light.jpg"):
            try:
                with open(os.path.join(STATIC_DIR, path.rsplit("/", 1)[1]), "rb") as fh:
                    return self.send(200, fh.read(), "image/jpeg", cache=True)
            except OSError:
                return self.send(404, "", "text/plain")
        if path == "/static/icon.svg":
            return self.send(200, ICON, "image/svg+xml", cache=True)
        if path == "/static/app.js":
            return self.send(200, JS, "application/javascript; charset=utf-8", cache=True)
        m = re.fullmatch(r"/feed/([A-Za-z0-9_-]{16,64})/(txt|nft|ipset|mikrotik|csv|c2)", path)
        if m:
            tok = get_meta(db(), "feed_token") or ""
            if not hmac.compare_digest(m.group(1), tok):
                return self.send(404, "Not found", "text/plain")
            mn, days, research, v6 = bl_params(qs)
            body, ctype = render_feed(m.group(2), blocklist_ips(db(), mn, days, research, v6), v6)
            return self.send(200, body, ctype + "; charset=utf-8")
        if path == "/login":
            if not get_meta(db(), "pw"):
                return self.send(503, v_login("No password set. On huginn run: runuser -u huginn -- python3 /opt/huginn/app.py set-password"))
            return self.send(200, v_login())
        if not self.authed():
            return self.redirect("/login")
        if path == "/":
            return self.send(200, v_overview(qs))
        if path == "/ips":
            return self.send(200, v_ips(qs, mobile="Mobi" in self.headers.get("User-Agent", "")))
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.]{3,45})/export\.(json|csv)", path)
        if m:
            try:
                xip = str(ipaddress.ip_address(urllib.parse.unquote(m.group(1))))
            except ValueError:
                return self.send(400, "Bad IP", "text/plain")
            data = export_ip(xip)
            if not data:
                return self.send(404, "Not found", "text/plain")
            fn = "huginn-%s.%s" % (xip.replace(":", "_"), m.group(2))
            if m.group(2) == "json":
                return self.send(200, json.dumps(data, indent=1, ensure_ascii=False), "application/json; charset=utf-8",
                                 headers={"Content-Disposition": 'attachment; filename="%s"' % fn})
            return self.send(200, export_csv(data), "text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="%s"' % fn})
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.]{3,45})", path)
        if m:
            out = v_ip(urllib.parse.unquote(m.group(1)), qs)
            return self.send(200, out) if out else self.send(404, page("Not found", "<h1>Not found</h1><p class=muted>No data for that IP.</p>"))
        if path == "/files":
            return self.send(200, v_files(qs))
        if path == "/new":
            return self.send(200, v_new(qs))
        if path == "/personas":
            return self.send(200, v_personas())
        if path == "/engagement":
            return self.send(200, v_engagement(qs))
        if path == "/receipt":
            return self.send(200, v_receipt(qs))
        if path == "/search":
            return self.send(200, v_search(qs))
        if path == "/creds":
            return self.send(200, v_creds(qs))
        m = re.fullmatch(r"/creds/export\.(txt|csv)", path)
        if m:
            days = qs.get("days") if qs.get("days") in ("1", "7", "30", "all") else "all"
            what = "csv" if m.group(1) == "csv" else ("usernames" if qs.get("what") == "usernames" else "passwords")
            body, ctype = cred_export(db(), what, days)
            fn = "huginn-%s-%s.%s" % ("attempts" if what == "csv" else what, days, m.group(1))
            return self.send(200, body, ctype + "; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="%s"' % fn})
        m = re.fullmatch(r"/api/creds-check/([0-9a-f]{%d})\.json" % CRED_PREFIX, path)
        if m:
            return self.send(200, json.dumps(cred_check(db(), m.group(1))), "application/json")
        if path == "/campaigns":
            return self.send(200, v_campaigns(qs))
        m = re.fullmatch(r"/campaign/(script|hassh|file)/([0-9a-f]{8,64})", path) or re.fullmatch(r"/campaign/(web)/([a-z0-9_]{1,60})", path)
        if m:
            out = v_campaign(m.group(1), m.group(2))
            return self.send(200, out) if out else self.send(404, page("Not found", "<h1>Not found</h1>"))
        if path == "/blocklist":
            return self.send(200, v_blocklist(self, qs))
        m = re.fullmatch(r"/replay/([0-9a-f]{64})", path)
        if m:
            out = v_replay(m.group(1), qs.get("ip", ""))
            return self.send(200, out) if out else self.send(404, page("Not found", "<h1>Not found</h1>"))
        m = re.fullmatch(r"/api/tty/([0-9a-f]{64})", path)
        if m:
            if not db().execute("SELECT 1 FROM sessions WHERE tty=? LIMIT 1", (m.group(1),)).fetchone():
                return self.send(404, "{}", "application/json")
            data = fetch_tty(m.group(1))
            if data is None:
                return self.send(502, json.dumps({"error": "Could not fetch the recording from the honeypot."}), "application/json")
            return self.send(200, json.dumps({"frames": tty_frames(data)}), "application/json")
        if path == "/account":
            return self.send(200, v_account(self.authed(), qs.get("ok", "")))
        if path == "/settings":
            return self.send(200, v_settings(qs.get("ok", "")))
        return self.send(404, page("Not found", "<h1>Not found</h1>"))

    def route_post(self):
        _local.h12 = settings().get("clock") == "12"
        path = urllib.parse.urlsplit(self.path).path
        if not self.host_ok():
            return self.send(421, "Unknown host", "text/plain")
        if not self.same_origin():
            return self.send(403, "Forbidden", "text/plain")
        con = db()
        if path == "/login":
            ip = self.client_ip()
            f = self.form()
            if not reserve_attempt(ip):
                return self.send(429, v_login("Too many attempts. Wait 15 minutes."))
            stored = get_meta(con, "pw")
            if not stored or not check_pw(f.get("password", ""), stored):
                time.sleep(1)
                return self.send(401, v_login("Wrong password."))
            release_attempt(ip)
            tok = secrets.token_urlsafe(32)
            with con:
                con.execute("INSERT INTO logins VALUES(?,?)", (hashlib.sha256(tok.encode()).hexdigest(), time.time() + SESSION_DAYS * 86400))
            ck = "huginn_s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (tok, SESSION_DAYS * 86400, "; Secure" if self.cookie_secure() else "")
            return self.redirect("/", {"Set-Cookie": ck})
        cur = self.authed()
        if not cur:
            return self.send(401, "Unauthorized", "text/plain")
        if path == "/settings":
            lists = {}
            f = self.form(lists)
            save_settings(f, lists)
            return self.redirect("/settings?ok=1")
        if path == "/settings/theme":
            st = settings(con)
            st["theme"] = THEMES[(THEMES.index(st["theme"]) + 1) % 3] if st["theme"] in THEMES else "auto"
            set_meta(con, "settings", json.dumps(st))
            return self.redirect(self.back())
        if path == "/settings/overview":
            view = self.form().get("view")
            if view in ("cards", "board"):
                st = settings(con)
                st["overview"] = view
                set_meta(con, "settings", json.dumps(st))
            return self.redirect("/")
        if path == "/settings/test-ntfy":
            if not NTFY_URL:
                return self.send(400, v_settings(err="HUGINN_NTFY_URL is not set."))
            try:
                ntfy_post("Test from Huginn. Notifications work.", "Huginn: test")
            except Exception as e:
                return self.send(502, v_settings(err="Sending failed: %s" % str(e)[:150]))
            return self.redirect("/settings?ok=test")
        if path == "/account/password":
            ip = self.client_ip()
            f = self.form()
            if not reserve_attempt(ip):
                return self.send(429, v_account(cur, err="Too many attempts. Wait 15 minutes."))
            if not check_pw(f.get("current", ""), get_meta(con, "pw") or ""):
                time.sleep(1)
                return self.send(400, v_account(cur, err="Current password is wrong."))
            release_attempt(ip)
            new = f.get("new", "")
            if len(new) < 10:
                return self.send(400, v_account(cur, err="New password must be at least 10 characters."))
            if new != f.get("repeat", ""):
                return self.send(400, v_account(cur, err="New passwords do not match."))
            set_meta(con, "pw", hash_pw(new))
            with con:
                con.execute("DELETE FROM logins WHERE token_hash!=?", (cur,))
            return self.redirect("/account?ok=pw")
        if path == "/account/logout-others":
            with con:
                con.execute("DELETE FROM logins WHERE token_hash!=?", (cur,))
            return self.redirect("/account?ok=others")
        if path == "/logout":
            c = cookies.SimpleCookie()
            try:
                c.load(self.headers.get("Cookie") or "")
                m = c.get("huginn_s")
                if m:
                    with con:
                        con.execute("DELETE FROM logins WHERE token_hash=?", (hashlib.sha256(m.value.encode()).hexdigest(),))
            except cookies.CookieError:
                pass
            return self.redirect("/login", {"Set-Cookie": "huginn_s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if path == "/new/reviewed":
            try:
                mark_reviewed(con, float(self.form().get("at", "")))
            except ValueError:
                return self.send(400, "Bad value", "text/plain")
            return self.redirect("/new")
        if path == "/new/undo":
            undo_review(con)
            return self.redirect("/new")
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.]{3,45})/flag", path)
        if m:
            try:
                ip = str(ipaddress.ip_address(urllib.parse.unquote(m.group(1))))
            except ValueError:
                return self.send(400, "Bad IP", "text/plain")
            f = self.form()
            flag = f.get("flag", "")
            note = (f.get("note") or "")[:200]
            with con:
                if flag in ("block", "allow"):
                    con.execute("INSERT OR REPLACE INTO flags VALUES(?,?,?,?)", (ip, flag, note, time.time()))
                else:
                    con.execute("DELETE FROM flags WHERE ip=?", (ip,))
            return self.redirect("/ip/" + urllib.parse.quote(ip))
        if path == "/blocklist/rotate":
            set_meta(con, "feed_token", secrets.token_urlsafe(24))
            return self.redirect("/blocklist")
        return self.send(404, "Not found", "text/plain")


class HuginnServer(ThreadingHTTPServer):
    # One thread per connection, with limits: extra connections are closed at once, and one address cannot take every slot.
    daemon_threads = True
    request_queue_size = 64
    max_clients = 64
    max_per_ip = 24

    def __init__(self, *a, **kw):
        self._lock = threading.Lock()
        self._per_ip = {}
        self._total = 0
        super().__init__(*a, **kw)

    def _release(self, ip):
        with self._lock:
            self._total -= 1
            left = self._per_ip.get(ip, 1) - 1
            if left > 0:
                self._per_ip[ip] = left
            else:
                self._per_ip.pop(ip, None)

    def process_request(self, request, client_address):
        ip = client_address[0]
        with self._lock:
            n = self._per_ip.get(ip, 0)
            refused = self._total >= self.max_clients or (n >= self.max_per_ip and ip not in TRUSTED_PROXIES)
            if not refused:
                self._total += 1
                self._per_ip[ip] = n + 1
        if refused:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(client_address[0])


_db_lock = None


def hold_db_lock():
    # Everything that uses the database holds this, shared. restore-db takes it alone, for as long as it works.
    global _db_lock
    os.makedirs(DATA, exist_ok=True)
    _db_lock = open(os.path.join(DATA, ".running"), "a")
    try:
        fcntl.flock(_db_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:
        sys.exit("A database restore is running. Try again when it is done.")


def need_service_user():
    # A file made by root would be unreadable for the service.
    if os.getuid() == 0:
        sys.exit("Run this as Huginn's own user: runuser -u huginn -- python3 %s ..." % os.path.abspath(__file__))


def list_backups():
    files = backup_files()
    if not files:
        print("No backups in %s" % BACKUP_DIR)
    for name, _path, size in files:
        print("%s  %.1f MB" % (name, size / 1048576))


def settle_wal():
    # "ok": the log is folded in. "busy": someone is reading, leave everything alone. "damaged": it cannot be opened properly.
    if not os.path.exists(DB_PATH):
        return "damaged"
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            return "busy" if con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] else "ok"
        finally:
            con.close()
    except sqlite3.OperationalError as e:
        return "busy" if "locked" in str(e) or "busy" in str(e) else "damaged"
    except sqlite3.Error:
        return "damaged"


def restore_db(name):
    need_service_user()
    os.makedirs(DATA, exist_ok=True)
    lock = open(os.path.join(DATA, ".running"), "a")           # stays locked until this function returns
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("Huginn is running. Stop it first: systemctl stop huginn")
    path = name if os.sep in name else os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(path):
        sys.exit("No such backup: %s (see: app.py backups)" % name)
    os.makedirs(DATA, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    for n in os.listdir(DATA):          # left by an interrupted restore; nothing else can be running now
        if n.startswith(".restore-"):
            remove_quietly(os.path.join(DATA, n))
    tmp = os.path.join(DATA, ".restore-%s.db" % stamp)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "wb") as out, gzip.open(path, "rb") as gz:
            shutil.copyfileobj(gz, out, 1 << 20)
        result = check_copy(tmp)
        if result == "ok":
            result = check_is_huginn(tmp)
    except (OSError, EOFError, zlib.error, sqlite3.Error) as e:
        remove_quietly(tmp, tmp + "-wal", tmp + "-shm")
        sys.exit("That backup cannot be read, nothing was changed: %s" % e)
    remove_quietly(tmp + "-wal", tmp + "-shm")
    if result != "ok":
        remove_quietly(tmp)
        sys.exit("That backup is damaged or not Huginn's, nothing was changed: %s" % str(result)[:200])
    kept = DB_PATH + ".before-restore-" + stamp
    # Fold the write-ahead log into the old database first: then there is nothing left to lose when the files change. A real
    # copy goes aside (a hard link would let a later start change it). Only after that is the database swapped, in one step.
    settled = settle_wal()
    if settled == "busy":
        remove_quietly(tmp)
        sys.exit("Something else is reading the database. Close it and try again, nothing was changed.")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(DB_PATH + suffix):
            shutil.copy2(DB_PATH + suffix, kept + suffix)
    if settled != "ok":                 # a damaged database: its log must never be applied to the restored file
        remove_quietly(DB_PATH + "-wal", DB_PATH + "-shm")
    os.replace(tmp, DB_PATH)
    remove_quietly(DB_PATH + "-wal", DB_PATH + "-shm")
    print("Restored %s." % os.path.basename(path))
    print("The database you had is kept as %s. Delete it when you are happy." % kept)
    print("Start Huginn again. Newer events still in the honeypot's export come back at the next sync.")


def serve():
    hold_db_lock()
    init_db()
    threading.Thread(target=collector_loop, daemon=True, name="collector").start()
    if ENRICH:
        threading.Thread(target=enrich_loop, daemon=True, name="enrich").start()
    threading.Thread(target=backup_loop, daemon=True, name="backup").start()
    srv = HuginnServer((BIND, PORT), Handler)
    print("Huginn %s listening on %s:%d" % (HUGINN_VERSION, BIND, PORT), flush=True)
    srv.serve_forever()


def set_password():
    hold_db_lock()
    init_db()
    p1 = getpass.getpass("New Huginn password: ")
    if len(p1) < 10:
        sys.exit("Too short (min 10 characters).")
    if getpass.getpass("Repeat: ") != p1:
        sys.exit("Passwords do not match.")
    con = connect()
    set_meta(con, "pw", hash_pw(p1))
    with con:
        con.execute("DELETE FROM logins")
    print("Password set. All existing sessions logged out.")


def ingest_once():
    hold_db_lock()
    init_db()
    con = connect()
    t0 = time.time()
    text = fetch_export()
    rows, _ = parse_export(text, set())
    apply_honeypot_meta(con, parse_export.meta)
    n = store(con, rows)
    store_files(con, parse_export.files)
    store_mails(con, parse_export.mails)
    while classify_web(con, budget=60.0):
        pass
    note_sync(con, t0)
    set_meta(con, "last_ingest", t0)
    print("parsed %d rows, %d new, %.1fs" % (len(rows), n, time.time() - t0))


def import_files(paths):
    # One-off import of whole log files (cowrie.json*, opencanary.log*). Same parsing and dedupe as the sync,
    # so overlap with stored data is skipped. Reads in blocks to keep memory low.
    hold_db_lock()
    init_db()
    con = connect()
    total_rows = total_new = 0
    for path in paths:
        name = os.path.basename(path)
        section = "COWRIE" if name.startswith("cowrie.json") else "CANARY" if name.startswith("opencanary.log") else None
        if not section:
            print("skip (unknown file type): %s" % path)
            continue
        t0 = time.time()
        n_rows = n_new = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            buf = []
            for line in fh:
                buf.append(line.rstrip("\n"))
                if len(buf) >= 20000:
                    rows, _ = parse_export("##%s\n" % section + "\n".join(buf), set())
                    n_rows += len(rows); n_new += store(con, rows); buf = []
            if buf:
                rows, _ = parse_export("##%s\n" % section + "\n".join(buf), set())
                n_rows += len(rows); n_new += store(con, rows)
        print("%s: %d rows, %d new, %.1fs" % (name, n_rows, n_new, time.time() - t0), flush=True)
        total_rows += n_rows; total_new += n_new
    print("total: %d rows, %d new" % (total_rows, total_new))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        serve()
    elif cmd == "set-password":
        set_password()
    elif cmd == "ingest-once":
        ingest_once()
    elif cmd == "import" and len(sys.argv) > 2:
        import_files(sys.argv[2:])
    elif cmd == "backups":
        list_backups()
    elif cmd == "backup":
        need_service_user()
        hold_db_lock()
        init_db()
        try:
            print("Saved %s" % backup_db())
        except (RuntimeError, DatabaseDamaged) as e:
            sys.exit("No backup made: %s" % e)
    elif cmd == "restore-db" and len(sys.argv) == 3:
        restore_db(sys.argv[2])
    else:
        sys.exit("usage: app.py [serve|set-password|ingest-once|import FILE...|backup|backups|restore-db FILE]")
