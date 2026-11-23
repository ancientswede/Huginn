#!/usr/bin/env python3
# Huginn — attacker intelligence for a homelab honeypot.
# Pulls logs (Cowrie, OpenCanary, endlessh, hp-traps) over SSH with a key that is locked to
# hp-export on the honeypot (read-only, pull-only: the honeypot never connects to Huginn),
# keeps history in SQLite, shows a page per attacker IP and serves firewall blocklists.
# Python standard library only. Copyright (C) 2026 Ancientswede. License: AGPL-3.0-or-later (see LICENSE).

HUGINN_VERSION = "1.0.0-rc4"
CHANGELOG = [
    ('1.0.0-rc4', '2026-11-23',
     'Fixes found by fuzzing the honeypot data path, and three small ones left from the rc3 review.\n'
     '- Only real hashes are read from Cowrie: a HASSH must be 32 hex characters, a file or session recording hash 64; '
     'other text no longer turns into file, HASSH or replay links\n'
     '- Every link built from honeypot data is URL-encoded\n'
     '- Honeypot protection is no longer "all in place" when the report holds no sandbox or limits checks; it alerts instead\n'
     '- /healthz on an unknown host name only says up or down, without version or problems\n'
     '- Forms work when the browser writes the host name in other letter case'),
    ('1.0.0-rc3', '2026-11-22',
     'Fixes from a security review of rc2.\n'
     '- Blocklist feeds never hold the big public DNS resolvers or the addresses in the new HUGINN_NEVER_BLOCK; '
     'a fully compromised honeypot could otherwise put any address on them with fake log lines\n'
     '- Blocklist feeds hold at most HUGINN_BL_MAX addresses (50000), highest score first\n'
     '- A deeply nested line in the Suricata alerts no longer stops every sync\n'
     '- install-huginn.sh fills in HUGINN_ALLOWED_HOSTS with this machine\'s names and addresses (stops DNS rebinding); '
     'the "Unknown host" page says what to add\n'
     '- The C2 list follows the same never-block list and cap\n'
     '- A service log can no longer fake the honeypot\'s protection report: hp-export drops lines that look like section markers, '
     'and Huginn uses the last copy of each section\n'
     '- IDS counters with non-ASCII digits no longer stop the sync\n'
     '- A Cowrie or OpenCanary service that will not start with its sandbox or limits is left stopped, never run without them\n'
     '- check-isolation.sh fails when a LAN machine answers ping or refuses a connection (it is reachable)\n'
     '- HUGINN_NEVER_BLOCK understands IPv4-mapped networks; HUGINN_BL_MAX accepts values under 100'),
    ('1.0.0-rc2', '2026-11-21',
     'DNS list lookups stay on recent attackers, and fixes from a full review before 1.0.\n'
     '- DroneBL, Spamhaus and Abusix only look up attackers seen in the last 30 days, like GreyNoise and http:BL\n'
     '- Before, the weekly recheck of every address ever seen grew with the database until it used up the daily allowance\n'
     '- ntfy: a redirect from the server is no longer followed, so the access token cannot end up at another host\n'
     '- Retention also removes a gone attacker\'s lookups and session recordings; first sightings stay without the address\n'
     '- The command to connect Huginn to the honeypot is built only from a checked key\n'
     '- The honeypot installer checks that the real sshd has left port 22 (IPv6 too); check-isolation.sh tests IPv6 and reports untested targets\n'
     '- Debian package: a failed upgrade is reported to dpkg instead of being marked as done\n'
     '- update-honeypot.sh --suricata-on on an old honeypot installs hp-readlogs first; the export warns if it is missing\n'
     '- uninstall-huginn.sh only removes a folder that holds Huginn; the demo builder never wipes a folder that is not a demo\n'
     '- Countries: an attacker whose location lookup failed (ipwho.is over its free allowance) is asked again after a day, '
     'Huginn pauses an hour when ipwho.is says too many, and the card says "Not known yet" instead of an empty row\n'
     '- IPv6 attacker pages and their exports open from Huginn\'s own links; the C2 feed follows v6=0\n'
     '- Every spelling of an IPv4-mapped address is read as the IPv4 address, and multicast is never an attacker\n'
     '- A login that races a password change cannot outlive it; a form that is too large changes nothing (413)\n'
     '- DNS lists also look up known addresses with a fresh IDS alert, and private addresses in test mode no longer hold up public ones\n'
     '- import reads the honeypot\'s gzipped logs, and says so when a file cannot be read or holds no events\n'
     '- import and ingest-once refuse to run without the settings in .env; the docs give a systemd-run command that loads them\n'
     '- The manual install copies static/ (web attack rules, map); the Account page shows how many web rules are loaded\n'
     '- HUGINN_C2_EXCLUDE matches an IPv6 address however it is written; an AS name is only stored for the AS number that was asked\n'
     '- Behind a trusted proxy that reports https, a form from the http address is refused; the retention limits are documented\n'
     '- /healthz answers 503 while a collection problem is open, and an alert that could not be sent is tried again\n'
     '- A DroneBL or Spamhaus answer and the tag it gives are saved together; VirusTotal\'s daily allowance is booked atomically\n'
     '- An Abusix allowance of 1 a day is one lookup, not zero; broken file hashes no longer hold up the VirusTotal queue\n'
     '- Search checks loose file records in one query instead of one per file\n'
     '- hp-traps: POP3, IMAP, PostgreSQL and SOCKS5 sessions have a total time limit and a share of the places each, like SMTP\n'
     '- update-honeypot.sh also updates hp-add-huginn-key; the uninstaller shows the ports sshd really listens on\n'
     '- The installer only adds a link to Huginn in ntfy messages when the ntfy server is on your own network\n'
     '- The abuse report gives its times in UTC; the demo build ignores the machine\'s own HUGINN_ settings\n'
     '- The Docker files of a release candidate run that candidate\'s image instead of latest; the docs say what the export key can do'),
    ('1.0.0-rc1', '2026-11-21',
     'First release candidate for 1.0.\n'
     '- Feeds, exports, /healthz, /metrics and env names are now a promise: see Stability promise in the README\n'
     '- Tested upgrades from old releases (0.9 and later) and a restore from a real backup\n'
     '- Release files and the Docker image are signed (gh attestation verify)\n'
     '- Version numbers with -rc are understood, and a release candidate never shows as an update for 0.x'),
    ('0.52.2', '2026-11-19',
     'DNS lookups recover by themselves.\n'
     '- DroneBL and Spamhaus try their test question once more before pausing\n'
     '- A resolver that did not answer in time pauses them for 15 minutes, not an hour'),
    ('0.52.1', '2026-11-19',
     'Help and filters know the new tags.\n'
     '- Help explains dronebl and spamhaus\n'
     '- Attackers can be filtered on dronebl, spamhaus and ids-alert'),
    ('0.52.0', '2026-11-19',
     'Spamhaus, abuse contacts and your own DNS resolver.\n'
     '- Spamhaus ZEN on the attacker page: spam source, exploited or infected machine, hijacked network or home range (tag spamhaus, no score change)\n'
     '- Abuse contact per attacker (Abusix Abuse Contact DB), with a Report link that opens a ready e-mail\n'
     '- Every DNS lookup can use any resolver: a new choice for 127.0.0.1 and a field for another address\n'
     '- Spamhaus needs your own resolver (it refuses public ones): README explains Unbound in a few lines\n'
     '- Campaigns: the DroneBL tab also counts Spamhaus lists\n'
     '- From LinkedIn comments'),
    ('0.51.0', '2026-11-19',
     'DroneBL lookups.\n'
     '- Is the attacker a known drone, botnet member, open proxy, brute forcer or compromised router? (dronebl.org, free, no key)\n'
     '- Shown on the attacker page and in the JSON export, with the tag dronebl (no change to the score)\n'
     '- Campaigns has a DroneBL tab with attackers per class\n'
     '- On by default; turn off or pick a DNS server on Settings, Lookups\n'
     '- The DNS server is tested first, since Pi-hole and many routers drop the answers\n'
     '- From a LinkedIn comment'),
    ('0.50.3', '2026-11-19',
     'Uninstall fix.\n'
     '- uninstall-honeypot.sh --purge now also deletes the hp-traps logs (they sit under /var/log/private)'),
    ('0.50.2', '2026-11-18',
     'Ready for the newest Cowrie.\n'
     '- Cowrie now reads the persona\'s memory figures itself, so Huginn\'s free patch is no longer needed there\n'
     '- The honeypot status shows it as in place instead of missing after a Cowrie upgrade'),
    ('0.50.1', '2026-11-18',
     'Faster Search.\n'
     '- About twice as fast on common words (0.43 s to 0.22 s on 650,000 events)'),
    ('0.50.0', '2026-11-18',
     'Second part of the full code review.\n'
     '- The honeypot reads logs, patch checks and captured files as the user who owns them, never as root\n'
     '- Logs are read from the end, so a long history is not read on every sync\n'
     '- IDS switch: same lock as rule updates, and only on when engine and rule timer both run\n'
     '- A new Suricata config is tested first; the old one comes back if the engine will not start\n'
     '- Failed Cowrie or OpenCanary upgrades go back to the version that ran before\n'
     '- One broken field in the export no longer stops the whole sync\n'
     '- Board and Overview numbers are kept for up to 5 minutes\n'
     '- hp-add-huginn-key refuses a key that is already there with other options'),
    ('0.49.1', '2026-11-18',
     'Fixes from a full code review of everything since 0.25.\n'
     '- Sharing: hp-sample-zip prints the hashes that went into the zip; paste them to mark them as shared\n'
     '- Files deleted from the honeypot leave the share list, and large files get the right hash\n'
     '- New web rules remove tags the old rules gave\n'
     '- Decoy cap: a line sent twice counts once, and old events are not stored again after a restart\n'
     '- returned/stepped-up: tarpit time counts as being there, a failed download is not a payload\n'
     '- Tor is judged per listing period\n'
     '- Odd VirusTotal answers count as errors, not as known files\n'
     '- GreyNoise and http:BL are no longer held back by LAN addresses\n'
     '- Settings forms saved at the same time keep both changes\n'
     '- A failed ntfy alert is sent again\n'
     '- Feed tokens stay out of the error log'),
    ('0.49.0', '2026-11-18',
     'Share captured malware with Sanesecurity.\n'
     '- Files lists what VirusTotal has never seen and gives a command for the honeypot\n'
     '- hp-sample-zip packs those files into a zip with the password "infected", ready to send\n'
     '- Nothing is run, and nothing leaves the honeypot unless you send the zip\n'
     '- Mark as shared keeps the list to what is left\n'
     '- The attacker page links to Cisco Talos\n'
     '- From a LinkedIn comment'),
    ('0.48.0', '2026-11-18',
     'Tor exit nodes.\n'
     "- The Tor Project's exit list is fetched once a day; nothing is sent\n"
     '- Attackers that came through Tor are tagged tor\n'
     '- They never count as returned and stay off the blocklist unless you choose otherwise (Settings, Lookups)\n'
     '- On by default. From a LinkedIn comment'),
    ("0.47.1", "2026-11-17", "Campaigns has a tab per grouping (command scripts, SSH clients, netblocks, web attacks, IDS alerts, mail clients, "
               "proxy use, slow replies) with how many rows each holds, instead of one long page to scroll. The tab you chose is "
               "remembered and can be linked to (#c-netblocks). Without JavaScript the tabs jump to their section as before."),
    ('0.47.0', '2026-11-17',
     'Netblocks from Team Cymru (over DNS, no key).\n'
     '- The attacker page shows the network block, its owner and how many attackers came from it\n'
     '- Filter attackers by block, and an optional Netblock column\n'
     '- Campaigns lists blocks with more than one attacker\n'
     '- On by default; turn off or pick a DNS server under Settings, Lookups\n'
     '- From a LinkedIn comment'),
    ('0.46.2', '2026-11-17',
     'Fixes from a code review.\n'
     '- returned counts every day with activity, so an attacker who never left is not "back"\n'
     '- New return alerts can no longer be crowded out\n'
     '- The http:BL DNS client only accepts answers to its own question\n'
     '- Settings never sends a form twice'),
    ('0.46.1', '2026-11-17',
     'Choose the DNS server for Project Honey Pot.\n'
     '- System resolver, Cloudflare, Quad9 or Google (Settings, Lookups)\n'
     "- Pi-hole and many routers block http:BL's answers; the key test now says so\n"
     '- Settings saves without reloading the page'),
    ('0.46.0', '2026-11-17',
     'Project Honey Pot (http:BL).\n'
     '- With a free key: is the attacker a known spammer, harvester or suspicious visitor, and how bad\n'
     '- Shown on the attacker page and in its JSON export\n'
     '- IPv4 only, top attackers first, at most 300 a day\n'
     '- From a LinkedIn comment'),
    ('0.45.0', '2026-11-16',
     'Attackers that come back.\n'
     '- returned: seen again after 7 or more quiet days (Settings, Views & defaults)\n'
     '- stepped-up (+5): it then got further than ever before\n'
     '- The attacker page says what it did before and since\n'
     '- An ntfy alert once per return\n'
     '- From a LinkedIn comment'),
    ("0.44.0", "2026-11-15", "Suricata can be turned on and off under Settings, Honeypot, once it is set up on the honeypot (update-honeypot.sh --suricata-on, which installs the package and the rules). The locked export key accepts exactly \"ids on\" or \"ids off\", which only start or stop a Suricata that is already set up, and checks that it really started or stopped. Update the honeypot side once for the switch to show."),
    ('0.43.0', '2026-11-15',
     'Optional Suricata IDS on the honeypot.\n'
     '- One command: update-honeypot.sh --suricata-on\n'
     '- Listens only, never blocks, sandboxed and capped at 900 MB\n'
     '- Attacker pages get IDS alerts, Campaigns a page per rule\n'
     '- Rules update daily, or from a file on a honeypot without internet\n'
     '- An attack rule adds 3 to the score and tags ids-alert'),
    ("0.42.0", "2026-11-14", "Every number at the top of the Overview is a link to the list behind it: Took the bait opens the attackers who took the bait in the last 7 days, Sessions the attackers with the most sessions, Files captured the Files page, Time wasted the receipt, On blocklist the Blocklist. New this week links its attackers, new attackers, each new country, each malware family and the bait count too."),
    ("0.41.1", "2026-11-14", "Account: the changelog is as tall as the System card next to it and scrolls, instead of making the page very long. Settings, Logout message shows how often the note was shown, to how many addresses, in the last 7 days and when last (also in /metrics as events of kind goodbye)."),
    ('0.41.0', '2026-11-14',
     'Settings rebuilt, and the logout note from Huginn.\n'
     '- Turn the goodbye note on or off in Settings (update the honeypot once)\n'
     '- A menu of sections, one Save per part, status badges\n'
     '- Buy me a coffee link in the footer'),
    ('0.40.0', '2026-11-14',
     'An optional goodbye on logout.\n'
     '- People who really logged in see how long they stayed and that everything was logged\n'
     '- Off by default: update-honeypot.sh --goodbye-on\n'
     '- Never shown to scripts or bots that just disconnect\n'
     '- Campaigns compares long scripts quickly'),
    ('0.39.0', '2026-11-14',
     'Campaigns tells similar scripts apart.\n'
     '- Each row shows where a script differs from the others\n'
     '- Preview lists all commands, with the differing one marked'),
    ('0.38.0', '2026-11-14',
     'Metrics and JSON logs.\n'
     '- Prometheus metrics with a token (Settings): counts only, never addresses\n'
     '- A ready Grafana dashboard in examples/grafana\n'
     '- JSON logs for Loki and similar (HUGINN_LOG_FORMAT=json)'),
    ("0.37.0", "2026-11-14", "A GreyNoise key can be saved on the Settings page, like the VirusTotal and MalwareBazaar keys. It is tested without using a lookup and never shown again. Without a key Huginn now asks at most 20 addresses a day, under the free allowance; with one, 40."),
    ('0.36.0', '2026-11-14',
     'Fixes from a deep security and bug review.\n'
     '- The decoy cap never drops web attacks, bait hits or new kinds of passwords\n'
     '- Lookups never follow redirects, so a key only goes to its own service\n'
     '- Web exploits and bait use always keep an attacker on the blocklist\n'
     '- A stopped source stays alerted for 30 days\n'
     '- Engagement and Files are more accurate and faster'),
    ("0.35.0", "2026-11-14", "New Help page (link in the header, or g h): what every attacker tag, session badge, file badge, lookup result and blocklist rule means. Every tag also explains itself when you hover it."),
    ("0.34.0", "2026-11-14", "The MalwareBazaar key can be pasted on the Settings page too (Lookups), like the VirusTotal key: it is tested before it is saved and never shown again. The page shows how many files were checked and how many abuse.ch knows, and the last error if a lookup failed."),
    ('0.33.0', '2026-11-14',
     'VirusTotal and GreyNoise.\n'
     '- VirusTotal verdicts for captured files, by hash only\n'
     '- novel when VirusTotal has never seen a file\n'
     '- GreyNoise marks known mass scanners as research\n'
     '- Both stay within a daily allowance'),
    ('0.32.0', '2026-11-14',
     'New Engagement page.\n'
     '- What sessions that got in did, day by day\n'
     '- Hand-typed sessions, median stay, new against returning attackers\n'
     '- Compare the days before and after a release'),
    ('0.31.0', '2026-11-13',
     'A timeline on the attacker page.\n'
     '- 30 days across every service, grouped into phases (Recon, Access, Commands, Payload, Exploit)\n'
     '- Commands labelled with MITRE ATT&CK techniques'),
    ('0.30.0', '2026-11-13',
     'Folded sessions and honeypot protection status.\n'
     '- The same script shows once with ×N like this\n'
     '- Filter sessions with commands or logins\n'
     '- The honeypot reports its sandbox, limits and patches; Huginn alerts when something is missing\n'
     '- Update the honeypot too'),
    ('0.29.0', '2026-11-13',
     'Alerts when collection stops.\n'
     '- No sync for 30 minutes, or a source quiet for longer than usual\n'
     '- One alert per problem and one when it is back\n'
     '- More realistic wget, and uploaded programs "run" silently (nothing is ever executed)\n'
     '- Update the honeypot too'),
    ('0.28.0', '2026-11-13',
     'A cap on repeated decoy tries.\n'
     '- The first 2,000 per IP, service and day are stored, the rest counted\n'
     '- Account shows how fast the data grows\n'
     '- Web exploits with a CVE trigger the phone alert\n'
     '- Wider layouts, family chips on Files, better accessibility'),
    ("0.27.3", "2026-11-12", "The Overview banner is a new raven with a soft beam of light from its eye, in a dark and a light version that follow the theme."),
    ("0.27.2", "2026-11-12", "A new raven banner on the Overview, in a dark and a light version that follow the theme (Auto, Light or Dark), with the text colour to match."),
    ('0.27.1', '2026-11-12',
     'Two Cowrie bugs that ended attacks early are fixed.\n'
     '- ping -c N works\n'
     '- Uploaded files stay for the whole connection\n'
     '- Upload size and memory limits on the honeypot\n'
     '- Update the honeypot'),
    ('0.27.0', '2026-11-12',
     'Slow replies.\n'
     '- The fake mail server waits before it says queued\n'
     "- The web trap's bait file is sent slowly\n"
     '- Campaigns has a Slow replies summary\n'
     '- Update the honeypot too'),
    ('0.26.0', '2026-11-11',
     'A proxy that seems to work.\n'
     '- Bots testing the SSH honeypot as a proxy get an empty page instead of a refusal; nothing is forwarded\n'
     '- Campaigns has a Proxy use table'),
    ('0.25.0', '2026-11-11',
     'Web attacks named.\n'
     '- Every web trap request is matched against about 3,100 Krawl rules\n'
     '- Tags web-exploit (+8) and web-probe (+3)\n'
     '- A page per attack, with the CVE\n'
     '- Fake .env, .git and similar files with bait values, and a robots.txt trap'),
    ('0.24.1', '2026-11-11',
     'VNC passwords and mail details.\n'
     '- VNC passwords count as logins\n'
     '- The mail relay trap keeps recipients, HELO name and the start of each message\n'
     '- Campaigns groups mail clients'),
    ("0.24.0", "2026-11-11", "Overview has a second layout, Board: every service side by side with IPs, hits, logins and accepted logins, attacker IPs and login attempts on the same time axis, top attackers and the latest raw data, for the last 24 hours or 7 days and one service or all. Switch between Cards and Board at the top of the Overview; the choice is remembered."),
    ('0.23.1', '2026-11-09',
     'Security and bug hunt.\n'
     '- A crafted command could freeze Huginn\n'
     '- Web requests were counted as logins\n'
     '- Backup and restore are safer\n'
     '- One huge file could stop file analysis\n'
     '- The database file was readable by other users'),
    ("0.23.0", "2026-11-09", "The web trap can pretend to be many NAS and router brands and changes by itself every few weeks (hp-identity on the honeypot, ROTATE_DAYS sets how often, 0 turns it off). Personas shows which device drew the most attention, per day, because each one runs for a different time."),
    ('0.22.0', '2026-11-09',
     'A visual pass.\n'
     '- The attacker page is headed by its address\n'
     '- Better phone layouts\n'
     '- Replay looks like a terminal\n'
     '- Personas shows how far attackers got\n'
     '- A receipt for Time wasted'),
    ("0.21.2", "2026-11-08", "Releases now include a Debian package, plus Docker files that work without cloning the repository."),
    ("0.21.1", "2026-11-08", "Session logs are easier to read: download and permission commands stand out, addresses link to Search (never to the attacker's server) and captured files link to their file page."),
    ("0.21.0", "2026-11-08", "New page, Search: commands, file hashes and names, addresses inside malware, failed downloads, decoy service data, sessions and attacker IPs across the whole history. Press / on any page without a filter to get there."),
    ("0.20.0", "2026-11-08", "New page, Personas: how far attackers get on each fake machine, where sessions with several lines stop with no download seen, and which single lines hit it. A hint about what may give the honeypot away, not proof."),
    ("0.19.1", "2026-11-08", "Overview: the banner is back to its full size on computers. It stays low on phones."),
    ("0.19.0", "2026-11-08", "Campaigns: scripts that differ only in addresses, numbers or random markers are now one campaign (old links to a script campaign stop working). Attacker page: a one-line summary, sessions first with the facts in a side column on wide screens, related attackers as a count and the five latest. Sync gaps: the day charts and the Account page show when Huginn did not collect."),
    ('0.18.0', '2026-11-08',
     'New page: New.\n'
     '- Everything Huginn has not seen before since you last looked, with Mark all reviewed and Undo\n'
     '- A lower Overview banner, rare events stand out\n'
     '- What makes up a score, on the attacker page'),
    ("0.17.0", "2026-11-07", "Automatic database backups: once a day Huginn saves a checked, compressed copy of its database in data/backups and keeps the last 3 (HUGINN_DB_BACKUPS, HUGINN_DB_BACKUP_HOURS). A damaged database never pushes out the good copies, you get a warning on the Account page and through ntfy. Bring one back with: app.py restore-db."),
    ('0.16.2', '2026-11-06',
     'More security fixes from a deep review.\n'
     '- Root no longer writes files the honeypot users control (update the honeypot)\n'
     '- Cowrie and OpenCanary run in a sandbox\n'
     '- The C2 list needs at least 2 attackers\n'
     '- update-huginn.sh rolls back a failed restart'),
    ('0.16.1', '2026-11-06',
     'Security fixes.\n'
     '- Text sent to a decoy could add fake lines to the export\n'
     '- Time limits and connection caps on the web server\n'
     '- Update the honeypot too'),
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
import functools
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
import select
import shutil
import socket
import statistics
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
# Repeated decoy tries from one address can otherwise fill much of the database. 0 = keep everything.
try:
    DECOY_CAP = max(0, int(os.environ.get("HUGINN_DECOY_CAP", "2000")))
except ValueError:
    DECOY_CAP = 2000
# An attacker seen again after this many quiet UTC days (nothing at all from it) gets "returned"; one that then gets further
# than it ever did before (say only knocked, then ran commands) also gets "stepped-up". 0.45, from a LinkedIn comment:
# a home connection is worth most as a proxy, and the checks are often followed later by "specific tasks".
# Set under Settings, Views & defaults; this is only the starting value before anything is saved there.
RETURN_CHOICES = (3, 5, 7, 14, 30)
try:
    RETURN_DAYS = max(1, int(os.environ.get("HUGINN_RETURN_DAYS", "7")))
except ValueError:
    RETURN_DAYS = 7
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
def _canon_ip(x):
    # "2001:0db8:0000::0001" and "2001:db8::1" are the same address; compare the short form the feeds use.
    try:
        return str(ipaddress.ip_address(x))
    except ValueError:
        return x
C2_EXCLUDE = {_canon_ip(x.strip()) for x in os.environ.get("HUGINN_C2_EXCLUDE", "").split(",") if x.strip()}
def _nets(v):
    out = []
    for x in v.split(","):
        try:
            n = ipaddress.ip_network(x.strip(), strict=False)
        except ValueError:
            continue
        # ::ffff:a.b.c.d/120 is the IPv4 network a.b.c.d/24: stored addresses are already IPv4 (norm_ip), so compare as IPv4.
        if n.version == 6 and n.prefixlen >= 96 and n.network_address.ipv4_mapped:
            n = ipaddress.ip_network("%s/%d" % (n.network_address.ipv4_mapped, n.prefixlen - 96), strict=False)
        out.append(n)
    return out
# Never on the blocklist, whatever the score: a compromised honeypot can write fake log lines with any source address,
# and a firewall that loads the feed would then cut off DNS or your own servers (appsec review 2026-11-22).
# Big public resolvers by default; add your WAN address, VPS and other must-reach addresses with HUGINN_NEVER_BLOCK (CIDRs).
NEVER_BLOCK = _nets("1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,208.67.220.220,4.2.2.2,"
                    "2606:4700:4700::1111,2606:4700:4700::1001,2001:4860:4860::8888,2001:4860:4860::8844,2620:fe::fe,2620:fe::9") \
    + _nets(os.environ.get("HUGINN_NEVER_BLOCK", ""))
# At most this many addresses in the blocklist feeds (highest score kept), so fake log lines cannot grow the list without end.
BL_MAX = max(1, int(os.environ.get("HUGINN_BL_MAX", "50000") or 50000))


def never_block(a):
    return any(a.version == n.version and a in n for n in NEVER_BLOCK)
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
# Optional: VirusTotal verdicts for captured files by SHA-256. Only the hash leaves Huginn, never a file. The free key allows
# 4 lookups a minute and 500 a day; Huginn stays under HUGINN_VIRUSTOTAL_DAILY (default 400). Key: virustotal.com, API key.
VT_KEY = os.environ.get("HUGINN_VIRUSTOTAL_KEY", "")
VT_DAILY = max(0, min(500, int(os.environ.get("HUGINN_VIRUSTOTAL_DAILY", "400") or 0)))
# GreyNoise community API: is an address a known mass scanner, and is it a benign one (Censys, Shodan, a university)?
# Works without a key, with a small daily allowance (about 25); a free key raises it. Only the attacker's address is sent.
# HUGINN_GREYNOISE_DAILY unset: 20 a day without a key, 40 with one (a key can also be saved on the Settings page).
GN_KEY = os.environ.get("HUGINN_GREYNOISE_KEY", "")
GN_DAILY = max(0, min(5000, int(os.environ["HUGINN_GREYNOISE_DAILY"] or 0))) if os.environ.get("HUGINN_GREYNOISE_DAILY", "").strip() else -1
# Optional: Project Honey Pot http:BL. One DNS question per attacker address: is it a known web spammer, e-mail harvester or
# suspicious visitor, how bad and how recently? Needs a free access key (12 letters) from projecthoneypot.org, which can also
# be pasted on the Settings page. The question goes through the normal DNS resolver, so key and address travel unencrypted.
HB_KEY = os.environ.get("HUGINN_HTTPBL_KEY", "").strip()
HB_DAILY = max(0, min(5000, int(os.environ.get("HUGINN_HTTPBL_DAILY", "300") or 0)))
DBL_DAILY = max(0, min(20000, int(os.environ.get("HUGINN_DRONEBL_DAILY", "2000") or 0)))
SH_DAILY = max(0, min(5000, int(os.environ.get("HUGINN_SPAMHAUS_DAILY", "500") or 0)))      # free mirrors: low volume only
AB_DAILY = max(0, min(20000, int(os.environ.get("HUGINN_ABUSIX_DAILY", "2000") or 0)))
# Which DNS server to ask: "system" (the normal resolver) or an IPv4 address. Pi-hole and many routers drop answers in
# 127.0.0.0/8, which is all http:BL ever answers, so a public server is often needed. Changeable on the Settings page.
HB_DNS = os.environ.get("HUGINN_HTTPBL_DNS", "").strip()
# Netblocks (0.47): Team Cymru's free IP-to-ASN service over DNS, no key. One TXT question per attacker address gives the
# announced block (prefix), its origin AS, country, registry and allocation date; one more per AS gives the owner's name.
# On by default, through the system resolver; both can be changed on the Settings page.
NB_DAILY = max(0, min(50000, int(os.environ.get("HUGINN_NETBLOCK_DAILY", "5000") or 0)))

# Logging to stderr (journald): "text" (default) or "json", one object per line, for log tools such as Grafana Loki, Graylog or Elasticsearch.
LOG_FORMAT = "json" if os.environ.get("HUGINN_LOG_FORMAT", "").strip().lower() == "json" else "text"
LOG_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
LOG_LEVEL = LOG_LEVELS.get(os.environ.get("HUGINN_LOG_LEVEL", "").strip().lower(), 20 if LOG_FORMAT == "json" else 30)
# Prometheus metrics on /metrics: off unless turned on in Settings, or a token is given here (16+ characters).
METRICS_TOKEN = os.environ.get("HUGINN_METRICS_TOKEN", "").strip()
METRICS_TOKEN = METRICS_TOKEN if re.fullmatch(r"[A-Za-z0-9_.~+/=-]{16,128}", METRICS_TOKEN) else ""
_log_lock = threading.Lock()


def _log_text(v):
    # Attacker text can end up in a log line: no control characters, so it can never start a line of its own.
    return re.sub(r"[\x00-\x1f\x7f\u2028\u2029]", lambda m: "\\x%02x" % ord(m.group(0)) if ord(m.group(0)) < 256 else "\\u%04x" % ord(m.group(0)), str(v))[:2000]


def log(level, event, msg="", **fields):
    # One line per event. JSON: {"ts", "level", "app", "event", "msg", ...fields}. Never pass secrets in here.
    if LOG_LEVELS.get(level, 20) < LOG_LEVEL:
        return
    if LOG_FORMAT == "json":
        d = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"), "level": level,
             "app": "huginn", "event": event}
        if msg:
            d["msg"] = str(msg)[:2000]
        for k, v in fields.items():
            d[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:2000]
        line = json.dumps(d, ensure_ascii=True)
    else:
        line = "%s %s%s%s" % (level.upper(), event, (": " + _log_text(msg)) if msg else "",
                              "".join(" %s=%s" % (k, _log_text(v)) for k, v in fields.items()))
    with _log_lock:
        try:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass


class BadBody(Exception):
    """A POST body Huginn will not read: no valid Content-Length, or over the limit."""


def ntfy_post(body, title, prio=3):
    # One place that talks to ntfy (alerts and the test button). Never logs the token.
    h = {"Title": title, "Priority": str(prio), "Tags": "honey_pot", "User-Agent": UA}
    if PUBLIC_URL:
        h["Click"] = PUBLIC_URL.rstrip("/") + "/"
    if NTFY_TOKEN:
        h["Authorization"] = "Bearer " + NTFY_TOKEN
    req = urllib.request.Request(NTFY_URL, data=body.encode("utf-8"), method="POST", headers=h)
    # No redirects: a redirect would hand the token to whatever host it points at. The reply body is not used.
    with _api_opener.open(req, timeout=10) as r:
        r.read(64 * 1024)
PUBLIC_URL = os.environ.get("HUGINN_PUBLIC_URL", "")      # link in the notifications
NOTIFY_EVERY = 3600
# Automatic copies of the database: how many to keep (0 = off) and how often. See "Database backups" in docs/operations.md.
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
CREATE TABLE IF NOT EXISTS vt(sha TEXT PRIMARY KEY, checked REAL, data TEXT);
CREATE TABLE IF NOT EXISTS capped_seen(h TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS greynoise(ip TEXT PRIMARY KEY, checked REAL, data TEXT);
CREATE TABLE IF NOT EXISTS httpbl(ip TEXT PRIMARY KEY, checked REAL, data TEXT);
CREATE TABLE IF NOT EXISTS netblock(ip TEXT PRIMARY KEY, checked REAL, prefix TEXT, asn TEXT, cc TEXT, registry TEXT, allocated TEXT);
CREATE TABLE IF NOT EXISTS dronebl(ip TEXT PRIMARY KEY, checked REAL, codes TEXT);
CREATE TABLE IF NOT EXISTS spamhaus(ip TEXT PRIMARY KEY, checked REAL, codes TEXT);
CREATE TABLE IF NOT EXISTS abusecontact(ip TEXT PRIMARY KEY, checked REAL, email TEXT);
CREATE INDEX IF NOT EXISTS nb_prefix ON netblock(prefix);
CREATE TABLE IF NOT EXISTS asname(asn TEXT PRIMARY KEY, checked REAL, name TEXT);
CREATE TABLE IF NOT EXISTS tor(ip TEXT PRIMARY KEY, first REAL, last REAL);
CREATE TABLE IF NOT EXISTS torp(ip TEXT, first REAL, last REAL, PRIMARY KEY(ip, first));
CREATE TABLE IF NOT EXISTS shared(sha TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS mails(h TEXT PRIMARY KEY, mail_from TEXT, subject TEXT, rcpts TEXT, helo TEXT, size INTEGER, sample TEXT);
CREATE TABLE IF NOT EXISTS ids(ip TEXT, sid INTEGER, day TEXT, proto TEXT, port INTEGER, n INTEGER, first REAL, last REAL, sev INTEGER,
  sig TEXT, cat TEXT, PRIMARY KEY(ip, sid, day, proto, port));
CREATE INDEX IF NOT EXISTS ids_sid ON ids(sid, last);
CREATE INDEX IF NOT EXISTS ids_last ON ids(last);
CREATE TABLE IF NOT EXISTS ids_seen(h TEXT PRIMARY KEY, ts REAL);
CREATE INDEX IF NOT EXISTS ids_seen_ts ON ids_seen(ts);
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
    benign = {ip for ip, d in con.execute("SELECT ip, data FROM greynoise") if gn_benign(d)}
    for ip, rd, org, isp, hn, ok in con.execute("SELECT ip, rdns, org, isp, hostnames, rdns_ok FROM enrich").fetchall():
        con.execute("UPDATE enrich SET research=? WHERE ip=?", (1 if ip in benign else research_flag(rd, org, isp, hn, ok), ip))
    cols = [r[1] for r in con.execute("PRAGMA table_info(sessions)")]
    if "tty" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN tty TEXT")
    if "termsize" not in cols:
        con.execute("ALTER TABLE sessions ADD COLUMN termsize TEXT")
    if "src" not in [r[1] for r in con.execute("PRAGMA table_info(capped)")]:
        con.execute("ALTER TABLE capped ADD COLUMN src TEXT")
    if not get_meta(con, "capped_seen_since"):     # 0.36: rows the old cap handled (ts <= upto) before this are not counted again
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('capped_seen_since',?)", (str(time.time()),))
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
    # 0.45: "returned" and "stepped-up" for attackers already stored (Settings also runs this when the quiet days change).
    if get_meta(con, "returned_days") != str(return_days(con)):
        recheck_returned(con)
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
    if k.endswith("_error") and v and LOG_LEVEL <= 30:
        # Every "last error" Huginn keeps for its pages is logged once when it changes.
        try:
            if get_meta(con, k) != str(v):
                log("warning", k, str(v))
        except sqlite3.Error:
            pass
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
    try:
        a = ipaddress.ip_address(s)     # "::ffff:1.2.3.4" and "::ffff:102:304" both become 1.2.3.4 below
    except ValueError:
        return None
    if a.version == 6 and a.scope_id:   # "addr%anything" may hold line breaks, which would end up in firewall feeds
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_multicast:                  # never a source: Python counts some IPv6 multicast as global
        return None
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


HEX64 = re.compile(r"[0-9a-f]{64}")


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
        sha = ev.get("shasum")
        kind, a, b = "file", ev.get("url") or ev.get("filename") or ev.get("destfile"), sha if isinstance(sha, str) and HEX64.fullmatch(sha) else None
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
    elif k == "cowrie.session.hp-goodbye":
        # Huginn's optional Cowrie patch (0.40): the login typed exit/logout and got the goodbye note. Numbers only.
        try:
            secs, n = int(ev.get("secs") or 0), int(ev.get("commands") or 0)
        except (TypeError, ValueError):
            return None
        kind, a = "goodbye", "%d s, %d line%s typed" % (max(0, min(secs, 10 ** 7)), max(0, min(n, 10 ** 6)), "" if n == 1 else "s")
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
        h = ev.get("hassh")
        if not (isinstance(h, str) and re.fullmatch(r"[0-9a-f]{32}", h)):        # HASSH is an MD5: 32 hex characters
            return None
        kind, a = "hassh", h
    elif k == "cowrie.client.size":
        # The terminal size the client asked for (SSH pty request). Bots that ask often use one fixed size.
        w, h = ev.get("width"), ev.get("height")
        if not (type(w) is int and type(h) is int and 0 < w <= 2000 and 0 < h <= 2000):       # not bool, not float
            return None
        kind, a = "termsize", "%dx%d" % (w, h)
    elif k == "cowrie.log.closed":
        if not (isinstance(ev.get("shasum"), str) and HEX64.fullmatch(ev["shasum"])) or not ev.get("size"):
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


def web_rules_note():
    rules, _sig = web_rules()
    if rules:
        return "%s rules" % num(len(rules))
    return '<span class=err>none loaded, web requests are not classified: %s is missing or broken (%s)</span>' % (
        esc(WEB_RULES_FILE), esc(_web["error"] or "no rules"))


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
        # Attackers whose tags or score came from the old rules are remembered (in meta, so a restart does not lose
        # them) and recomputed once every request has been matched again: a rule that disappeared takes its tag along.
        old = {r[0] for r in con.execute("SELECT DISTINCT ip FROM webhits WHERE level IN ('exploit','probe') OR robots=1 OR reply<>''")}
        try:
            old |= set(json.loads(get_meta(con, "webrules_redo", "[]") or "[]"))
        except ValueError:
            pass
        with con:
            con.execute("DELETE FROM webhits")
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('webrules',?)", (sig,))
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('webrules_redo',?)", (json.dumps(sorted(old)),))
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
    done = len(out) == len(rows) and len(rows) < limit
    redo = []
    if done:
        try:
            redo = json.loads(get_meta(con, "webrules_redo", "[]") or "[]")
        except ValueError:
            redo = []
    if out or redo:
        with con:
            con.executemany("INSERT OR IGNORE INTO webhits(h, ip, ts, level, type, cve, sev, rule, robots, reply) VALUES(?,?,?,?,?,?,?,?,?,?)", out)
            for ip in touched | set(redo):
                if con.execute("SELECT 1 FROM ips WHERE ip=?", (ip,)).fetchone():
                    recompute_ip(con, ip)
            if done:
                con.execute("DELETE FROM meta WHERE k='webrules_redo'")
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


def u8(x):
    # Text SQLite can store: JSON may hold lone surrogates (\ud800) that UTF-8 cannot encode, and one such field would
    # roll back the whole batch (Codex 049 M19). Other types pass through.
    if isinstance(x, str):
        try:
            x.encode("utf-8")
        except UnicodeEncodeError:
            return x.encode("utf-8", "replace").decode("utf-8")
    return x


def parse_export(text, skip):
    rows, hashes, section = [], set(), None
    files, personas, bait, identities, mails, status, ids_lines = [], [], {}, [], [], [], []
    ids_meta_lines = []
    seen = set()
    # Only "\n" ends a line. str.splitlines() also breaks on characters such as U+2028, which an attacker can send.
    for line in text.split("\n"):
        if line.startswith("##"):
            section = line[2:].strip()
            seen.add(section)
            # A service user can write "##STATUS" (or another marker) into its own log. hp-export drops such lines, and
            # here the last copy of a section wins: the real ones come after the logs (appsec/Codex review 2026-11-22).
            if section in ("FILES", "PERSONAS", "IDENTITY", "STATUS", "IDS"):
                {"FILES": files, "PERSONAS": personas, "IDENTITY": identities, "STATUS": status, "IDS": ids_lines}[section].clear()
                if section == "IDS":
                    ids_meta_lines.clear()
            elif section == "BAIT":
                bait.clear()
            continue
        if len(line) > MAX_LINE:
            continue
        if section == "FILES" and line.startswith("{"):
            try:
                files.append(json.loads(line))
            except (ValueError, RecursionError):        # deeply nested JSON must not stop the whole sync (Codex 049 M19)
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
        if section == "IDS":
            if line.startswith("rules ") or line.startswith("dropped "):
                ids_meta_lines.append(line)    # metadata: never takes a place in the 20000-alert window
            else:
                ids_lines.append(line)
            continue
        if section == "BAIT" and line.startswith("{"):
            try:
                bait.update(json.loads(line))
            except (ValueError, TypeError, RecursionError):
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
            r = tuple(u8(x) for x in r)
            rows.append((h,) + r)
            if section == "TRAPS" and r[5] and r[6].startswith("relay: "):
                try:
                    m = trap_mail(line)
                except Exception:
                    m = None
                if m:
                    mails.append(tuple(u8(x) for x in (h, r[6]) + m))
    parse_export.files = files
    parse_export.mails = mails
    parse_export.ids, ids_rules = parse_ids(ids_lines[-20000:] + ids_meta_lines[-2:], skip, hashes)
    parse_export.ids = [tuple(u8(x) for x in r) for r in parse_export.ids]
    ids_dropped = max([int(x[8:]) for x in ids_meta_lines if x.startswith("dropped ") and x[8:].isascii() and x[8:].isdigit() and len(x) < 20] or [0])
    parse_export.meta = {"personas": parse_personas(personas[:50]), "bait": bait_values(bait), "identities": parse_identities(identities[-500:]),
                         "has_personas": "PERSONAS" in seen, "has_bait": "BAIT" in seen,
                         "has_ids": "IDS" in seen, "ids_rules": ids_rules, "ids_dropped": ids_dropped,
                         "status": parse_status(status[:100]) if "STATUS" in seen else None,
                         "warnings": sorted(x[5:] for x in seen if x.startswith("WARN "))[:10]}
    return rows, hashes


STATUS_LINE = re.compile(r"^(sandbox|limits|running|patch|option):([a-z0-9-]{1,20}) (ok|missing)$")   # option: a choice, never alerted on


def parse_status(lines):
    # The honeypot's own report of its protection (hp-export ##STATUS). Untrusted: only the exact expected words get through.
    return {m.group(1) + ":" + m.group(2): m.group(3) == "ok" for m in map(STATUS_LINE.match, lines) if m}


IDS_TEXT = re.compile(r"[\x20-\x7e]{1,240}")
IDS_PROTO = re.compile(r"[A-Za-z0-9-]{1,12}")
IDS_MAX_AGE = 9 * 86400          # older alerts are ignored: ids_seen remembers 10 days, and eve.json holds about a week


def parse_ids(lines, skip, hashes):
    # Suricata alerts from hp-export ##IDS (optional). The honeypot already cut them down to a few fields; here every one
    # is checked again, because they hold attacker-chosen traffic matched by rules. Returns (alerts, rules file time).
    out, rules, oldest = [], None, time.time() - IDS_MAX_AGE
    for line in lines:
        if line.startswith("rules "):
            v = line[6:]
            rules = int(v) if v.isascii() and v.isdigit() and len(v) <= 11 else rules
            continue
        if not line.startswith("{"):
            continue
        h = "ids:" + hashlib.sha1(line.encode("utf-8", "replace")).hexdigest()
        hashes.add(h)
        if h in skip:
            continue
        try:
            e = json.loads(line)
            t = str(e["t"])
            if re.search(r"[+-]\d{4}$", t):                    # Suricata writes +0000; older Pythons want +00:00
                t = t[:-2] + ":" + t[-2:]
            ts = iso_ts(t)
            ip = norm_ip(e.get("ip"))
            sid, sev = int(e["sid"]), int(e.get("sev") or 3)
            sig, cat, proto, port = e.get("sig"), e.get("cat") or "", e.get("proto") or "", e.get("port")
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError):   # [[[[... from a compromised honeypot
            continue
        if not ip or not oldest <= ts <= time.time() + 86400 or not 0 < sid < 2 ** 31 or not isinstance(sig, str) or not IDS_TEXT.fullmatch(sig):
            continue
        cat = cat if isinstance(cat, str) and IDS_TEXT.fullmatch(cat) else ""
        proto = proto.upper() if isinstance(proto, str) and IDS_PROTO.fullmatch(proto) else ""
        port = port if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535 else 0     # 0: none (ICMP)
        out.append((h, ts, ip, sid, sev if 1 <= sev <= 4 else 3, sig, cat[:100], proto, port))
    return out, rules


def store_ids(con, alerts):
    # One row per IP, rule, UTC day, protocol and port with a count: a scanner can trip the same rule thousands of times. ids_seen knows
    # which alert lines were counted, because the export sends the newest ones again on every sync.
    if not alerts:
        return 0
    new, touched = 0, set()
    with con:
        con.execute("BEGIN IMMEDIATE")
        for h, ts, ip, sid, sev, sig, cat, proto, port in alerts:
            if con.execute("SELECT 1 FROM ids_seen WHERE h=?", (h,)).fetchone():
                continue
            con.execute("INSERT INTO ids_seen(h, ts) VALUES(?,?)", (h, ts))
            # The worst severity stays (a rule update must not take back an attack already seen); the text is the newest.
            con.execute("INSERT INTO ids(ip, sid, day, proto, port, n, first, last, sev, sig, cat) VALUES(?,?,?,?,?,1,?,?,?,?,?) "
                        "ON CONFLICT(ip, sid, day, proto, port) DO UPDATE SET n=n+1, first=MIN(first, excluded.first), "
                        "sev=MIN(sev, excluded.sev), sig=CASE WHEN excluded.last>=last THEN excluded.sig ELSE sig END, "
                        "cat=CASE WHEN excluded.last>=last THEN excluded.cat ELSE cat END, last=MAX(last, excluded.last)",
                        (ip, sid, utc_day(ts), proto, port, ts, ts, sev, sig, cat))
            new += 1
            touched.add(ip)
        # Only addresses Huginn already knows get a new score; one that only tripped a rule is listed under Campaigns.
        for ip in touched:
            if con.execute("SELECT 1 FROM ips WHERE ip=?", (ip,)).fetchone():
                try:
                    recompute_ip(con, ip)
                except (ValueError, TypeError, OverflowError, sqlite3.Error) as e:
                    log("error", "recompute", repr(e), key=ip)
    return new


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
    # Suricata on the honeypot: on (the section is there) or not, and when its rules were last updated.
    if "has_ids" in meta:
        set_meta(con, "hp_ids", json.dumps({"on": bool(meta["has_ids"]), "rules": meta.get("ids_rules"), "at": time.time(),
                                            "dropped": meta.get("ids_dropped") or 0}))
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
            row = tuple(u8(x) for x in (sha, str(f.get("src") or "")[:20], size, str(f.get("type") or "")[:80],
                                        str(f.get("arch") or "")[:20], 1 if f.get("packed") else 0, json.dumps(iocs), mtime, now,
                                        str(f.get("family") or "")[:60]))
            try:
                con.execute("INSERT INTO files(sha, src, size, type, arch, packed, iocs, mtime, updated, family) VALUES(?,?,?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(sha) DO UPDATE SET src=excluded.src, size=excluded.size, type=excluded.type, arch=excluded.arch, "
                            "packed=excluded.packed, iocs=excluded.iocs, mtime=excluded.mtime, updated=excluded.updated, family=excluded.family", row)
            except (sqlite3.Error, ValueError, OverflowError):
                continue                            # one bad file record, not the whole list


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


def file_family(f, names="", sha=None, vt=False):
    # Best guess, most reliable first: MalwareBazaar's signature, strings in the file, VirusTotal's label, then its name or URL.
    if f is not None:
        try:
            mb = json.loads(f["mb"] or "{}")
        except (ValueError, TypeError, IndexError, KeyError):
            mb = {}
        if mb.get("signature"):
            return mb["signature"], "MalwareBazaar"
        if f["family"]:
            return f["family"], "strings in the file"
        sha = sha or f["sha"]
    fam = vt_family(vt_get(sha) if vt is False else vt) if sha else ""      # vt: the answer when the caller has it (None = none)
    if fam:
        return fam, "VirusTotal"
    fam = name_family(names)
    return (fam, "file name") if fam else ("", "")


def family_tag(fam, how=""):
    if not fam:
        return ""
    return '<span class="tag t-red" title="Looks like %s%s">%s</span>' % (esc(fam), (" (from %s)" % esc(how)) if how else "", esc(fam))


MB_KEY_RE = re.compile(r"[A-Za-z0-9]{20,128}")


def mb_key(con=None):
    # A key saved on the Settings page wins over HUGINN_MALWAREBAZAAR_KEY. It is never shown again once saved.
    k = get_meta(con or db(), "mb_key", "") or ""
    return k if MB_KEY_RE.fullmatch(k) else MB_KEY


def mb_test(key):
    # One lookup of a well-known hash: "ok", "bad" (key refused), "busy" (rate limited) or "error" (no answer).
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=urllib.parse.urlencode({"query": "get_info", "hash": VT_TEST_SHA}).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    try:
        with api_urlopen(req, timeout=15) as r:
            d = json.loads(r.read(2 * 1024 * 1024))
        st = str(d.get("query_status") or "") if isinstance(d, dict) else ""
    except urllib.error.HTTPError as e:
        return "busy" if e.code == 429 else "bad" if e.code in (401, 403) else "error"
    except Exception:
        return "error"
    if st in ("ok", "hash_not_found", "no_results"):
        return "ok"
    return "bad" if "auth" in st else "error"


def mb_parse(d):
    # {"found": ...} from a MalwareBazaar answer, or None when the answer has an unexpected shape.
    if not isinstance(d, dict):
        return None
    st = d.get("query_status")
    if st in ("hash_not_found", "no_results"):
        return {"found": False}
    data = d.get("data")
    if st != "ok" or not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return None
    x = data[0]
    tags = x.get("tags") if isinstance(x.get("tags"), list) else []
    return {"found": True, "signature": clean(str(x.get("signature") or ""), 60),
            "tags": [clean(str(t), 30) for t in tags[:8]], "first_seen": clean(str(x.get("first_seen") or ""), 20)}


def mb_lookup(con, limit=4):
    # Ask MalwareBazaar about files we have not asked about yet (or not found a week ago). Only the hash leaves Huginn.
    key = mb_key(con)
    if not key or float(get_meta(con, "mb_wait_until", "0") or 0) > time.time():
        return 0
    rows = con.execute("SELECT sha FROM files WHERE mb_checked IS NULL OR (mb LIKE '%\"found\": false%' AND mb_checked < ?) "
                       "ORDER BY mtime DESC LIMIT ?", (time.time() - 7 * 86400, limit)).fetchall()
    done = 0
    for (sha,) in rows:
        if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
            continue
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=urllib.parse.urlencode({"query": "get_info", "hash": sha}).encode(),
                                     headers={"Auth-Key": key, "User-Agent": UA})
        try:
            with api_urlopen(req, timeout=20) as r:
                d = json.loads(r.read(2 * 1024 * 1024))
        except urllib.error.HTTPError as e:
            wait = 6 * 3600 if e.code in (401, 403) else 3600 if e.code == 429 else 900
            set_meta(con, "mb_wait_until", time.time() + wait)
            set_meta(con, "mb_error", "%s HTTP %s" % (fmt_ts(time.time()), e.code))
            break
        except Exception as e:
            set_meta(con, "mb_wait_until", time.time() + 900)
            set_meta(con, "mb_error", "%s %s" % (fmt_ts(time.time()), clean(str(e), 120)))
            break
        mb = mb_parse(d)
        if mb is None:
            status = clean(str(d.get("query_status") if isinstance(d, dict) else "unexpected answer"), 60)
            if "auth" in status or "limit" in status:
                set_meta(con, "mb_wait_until", time.time() + 6 * 3600)
                set_meta(con, "mb_error", "%s %s" % (fmt_ts(time.time()), status))
                break
            mb = {"found": False, "odd": status}            # this file only: asked again in a week, the rest go on
            set_meta(con, "mb_error", "%s unexpected answer for one file (%s)" % (fmt_ts(time.time()), status))
        else:
            set_meta(con, "mb_error", "")
        with con:
            con.execute("UPDATE files SET mb=?, mb_checked=? WHERE sha=?", (json.dumps(mb), time.time(), sha))
        done += 1
    return done


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                      # a 3xx comes back as an HTTPError instead of being followed with our key


_api_opener = urllib.request.build_opener(_NoRedirect)


def api_urlopen(req, timeout=20):
    # All lookups that carry a key or go to an outside service use this: HTTPS only, no redirects followed.
    url = req.full_url if hasattr(req, "full_url") else str(req)
    if not url.startswith("https://"):
        raise ValueError("only https lookups are allowed")
    return _api_opener.open(req, timeout=timeout)


VT_KEY_RE = re.compile(r"[0-9a-f]{64}")
VT_TEST_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"   # the EICAR test file, known to every engine


def vt_key(con=None):
    # A key saved on the Settings page wins over HUGINN_VIRUSTOTAL_KEY. It is never shown again once saved.
    k = get_meta(con or db(), "vt_key", "") or ""
    return k if VT_KEY_RE.fullmatch(k) else VT_KEY


def vt_test(key):
    # One lookup of a well-known file: "ok", "bad" (key refused) or "busy" (valid, but over the allowance right now).
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + VT_TEST_SHA, headers={"x-apikey": key, "User-Agent": UA})
    try:
        with api_urlopen(req, timeout=15) as r:
            r.read(64 * 1024)
        return "ok"
    except urllib.error.HTTPError as e:
        return "busy" if e.code == 429 else "bad" if e.code in (401, 403) else "error"
    except Exception:
        return "error"


def vt_get(sha, con=None):
    # The stored VirusTotal answer for a file, or None if it was never asked about.
    r = (con or db()).execute("SELECT data FROM vt WHERE sha=?", (sha,)).fetchone()
    try:
        return json.loads(r[0]) if r and r[0] else None
    except ValueError:
        return None


VT_LABEL_RE = re.compile(r"[a-z0-9_.-]{1,40}(?:/[a-z0-9_.-]{1,40}){0,3}")


def vt_family(v):
    # "trojan.mirai/gafgyt" -> "Mirai". Only a well-formed label counts.
    lab = (v or {}).get("label") or ""
    if not VT_LABEL_RE.fullmatch(lab):
        return ""
    name = lab.split("/")[0].split(".")[-1]
    return name.capitalize() if 2 < len(name) <= 30 else ""


def vt_html(v):
    if v is None:
        return '<span class=muted>%s</span>' % ("not checked yet" if vt_key() else "–")
    if not v.get("found"):
        return '<span class="tag t-orange" title="VirusTotal has never seen this file (checked %s)">novel</span>' % esc(fmt_ts(v.get("at") or 0))
    mal, total = int(v.get("mal") or 0), int(v.get("total") or 0)
    title = "%s of %s engines flag it%s · checked %s" % (mal, total, (" · " + v["label"]) if v.get("label") else "", fmt_ts(v.get("at") or 0))
    return '<span class="tag %s" title="%s">%d/%d</span>' % ("t-red" if mal else "", esc(title), mal, total)


def day_budget(con, key, cap):
    # A daily counter in meta ("YYYY-MM-DD:n"). Returns how many calls are left today (UTC).
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day, _, n = (get_meta(con, key, "") or "").partition(":")
    used = int(n) if day == today and n.isdigit() else 0
    return max(0, cap - used), today, used


def day_take(con, key, cap):
    # Book one call if today's allowance has room. Read and write in one locked transaction, so the background lookups and
    # a test from the web page can never both take the last call or count over each other.
    if con.in_transaction:
        left, today, used = day_budget(con, key, cap)
        if left <= 0:
            return False
        set_meta(con, key, "%s:%d" % (today, used + 1))
        return True
    with con:
        con.execute("BEGIN IMMEDIATE")
        left, today, used = day_budget(con, key, cap)
        if left <= 0:
            return False
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (key, "%s:%d" % (today, used + 1)))
    return True


def day_spend(con, key):
    day_take(con, key, 1 << 30)


def vt_lookup(con, limit=3, pause=16):
    # Ask VirusTotal about captured files: new ones first, unknown ones again after a week, known ones after 30 days.
    key = vt_key(con)
    if not key:
        return 0
    if float(get_meta(con, "vt_wait_until", "0") or 0) > time.time():
        return 0
    left, _t, _u = day_budget(con, "vt_day", VT_DAILY)
    now = time.time()
    shas = [r[0] for r in con.execute(
        "SELECT x.sha FROM (SELECT sha, mtime t FROM files UNION SELECT b, MAX(ts) FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b) x "
        "LEFT JOIN vt v ON v.sha=x.sha WHERE length(x.sha)=64 AND x.sha NOT GLOB '*[^0-9a-f]*' "     # broken values never hold the queue
        "AND (v.sha IS NULL OR (v.data LIKE '%\"found\": false%' AND v.checked<?) OR v.checked<?) "
        "GROUP BY x.sha ORDER BY (v.sha IS NULL) DESC, MAX(x.t) DESC LIMIT ?", (now - 7 * 86400, now - 30 * 86400, min(limit, left)))]
    done = 0
    for sha in shas:
        if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
            continue
        if done:
            time.sleep(pause)                      # free tier: 4 a minute
        req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha, headers={"x-apikey": key, "User-Agent": UA})
        if not day_take(con, "vt_day", VT_DAILY):    # a key test from the web page may have taken the last one
            break
        try:
            with api_urlopen(req, timeout=20) as r:
                d = json.loads(r.read(4 * 1024 * 1024))
            # Only a file object for this very hash, with attributes, counts as found. Anything else (an empty {} from a
            # broken proxy or an API change) is an error, not "VirusTotal knows it" (Codex 049 M10).
            d = d.get("data") if isinstance(d, dict) else None
            a = d.get("attributes") if isinstance(d, dict) else None
            if not (isinstance(d, dict) and d.get("type") == "file" and str(d.get("id") or "").lower() == sha
                    and isinstance(a, dict) and isinstance(a.get("last_analysis_stats"), dict)):
                raise ValueError("unexpected answer from VirusTotal")
            st = a.get("last_analysis_stats") or {}
            cnt = lambda k: st.get(k) if isinstance(st.get(k), int) and 0 <= st.get(k) < 1000 else 0
            label = str((a.get("popular_threat_classification") or {}).get("suggested_threat_label") or "").lower()
            first = a.get("first_submission_date")
            v = {"found": True, "mal": cnt("malicious"), "sus": cnt("suspicious"),
                 "total": sum(cnt(k) for k in ("malicious", "suspicious", "undetected", "harmless")),
                 "label": label if VT_LABEL_RE.fullmatch(label) else "", "first": first if isinstance(first, int) else None}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                v = {"found": False}
            elif e.code == 429:
                set_meta(con, "vt_wait_until", time.time() + 3600)      # over the minute or day allowance: an hour off
                set_meta(con, "vt_error", "%s rate limited, paused for an hour" % fmt_ts(time.time()))
                break
            else:
                set_meta(con, "vt_wait_until", time.time() + 6 * 3600)  # 401 bad key and the like: do not hammer
                set_meta(con, "vt_error", "%s HTTP %s" % (fmt_ts(time.time()), e.code))
                break
        except Exception as e:
            set_meta(con, "vt_wait_until", time.time() + 3600)          # odd answers: try again in an hour, keep the old result
            set_meta(con, "vt_error", "%s %s" % (fmt_ts(time.time()), str(e)[:120]))
            break
        v["at"] = int(time.time())
        with con:
            con.execute("INSERT OR REPLACE INTO vt(sha, checked, data) VALUES(?,?,?)", (sha, time.time(), json.dumps(v)))
        set_meta(con, "vt_error", "")
        done += 1
    return done


GN_CLASSES = {"benign", "malicious", "suspicious", "unknown"}
GN_KEY_RE = re.compile(r"[A-Za-z0-9_-]{20,128}")


def gn_key(con=None):
    # A key saved on the Settings page wins over HUGINN_GREYNOISE_KEY. It is never shown again once saved.
    k = get_meta(con or db(), "gn_key", "") or ""
    return k if GN_KEY_RE.fullmatch(k) else GN_KEY


def gn_daily(con=None):
    # Lookups a day: HUGINN_GREYNOISE_DAILY if set, otherwise a little under the community allowance with or without a key.
    return GN_DAILY if GN_DAILY >= 0 else (40 if gn_key(con) else 20)


def gn_test(key):
    # GreyNoise's ping checks a key without using a lookup: "ok", "bad" (key refused), "busy" (rate limited) or "error".
    req = urllib.request.Request("https://api.greynoise.io/ping", headers={"key": key, "User-Agent": UA, "Accept": "application/json"})
    try:
        with api_urlopen(req, timeout=15) as r:
            r.read(64 * 1024)
        return "ok"
    except urllib.error.HTTPError as e:
        return "busy" if e.code == 429 else "bad" if e.code in (401, 403) else "error"
    except Exception:
        return "error"


def gn_parse(d, ip=None):
    # Only known fields and values are kept; everything else from outside is dropped. Booleans must be real booleans,
    # and an answer about another address than the one asked about counts as nothing seen.
    if not isinstance(d, dict):
        d = {}
    if ip and d.get("ip") is not None:
        try:
            if ipaddress.ip_address(str(d.get("ip"))) != ipaddress.ip_address(ip):
                d = {}
        except ValueError:
            d = {}
    noise, riot = d.get("noise") is True, d.get("riot") is True
    cls = str(d.get("classification") or "unknown").lower()
    return {"seen": noise or riot, "noise": noise, "riot": riot,
            "class": cls if cls in GN_CLASSES else "unknown", "name": ext_text(d.get("name"), 60) or "",
            "last": str(d.get("last_seen") or "")[:10] if re.fullmatch(r"\d{4}-\d\d-\d\d", str(d.get("last_seen") or "")[:10]) else ""}


def gn_benign(data):
    # A scanner GreyNoise knows and calls benign (research, search engines) counts as research. Activity still wins,
    # exactly as for the research flag from names: anyone who logged in or ran something stays on the blocklist.
    try:
        g = json.loads(data) if isinstance(data, str) else (data or {})
    except ValueError:
        return False
    return bool(g.get("seen")) and g.get("class") == "benign"


def research_now(con, ip, base=None):
    # The research flag from every source, the same way everywhere: by name/network (enrich), or GreyNoise's latest answer.
    if base is None:
        r = con.execute("SELECT rdns, org, isp, hostnames, rdns_ok FROM enrich WHERE ip=?", (ip,)).fetchone()
        base = research_flag(r[0], r[1], r[2], r[3], r[4]) if r else 0
    g = con.execute("SELECT data FROM greynoise WHERE ip=?", (ip,)).fetchone()
    return 1 if base or (g and gn_benign(g[0])) else 0


def gn_get(con, ip):
    r = con.execute("SELECT data FROM greynoise WHERE ip=?", (ip,)).fetchone()
    try:
        return json.loads(r[0]) if r and r[0] else None
    except ValueError:
        return None


def gn_html(g):
    if g is None:
        return '<span class=muted>not checked yet</span>' if gn_daily() else "–"
    if not g.get("seen"):
        return "not seen scanning the internet"
    what = ("benign service" if g.get("riot") and not g.get("noise") else "%s scanner" % g.get("class", "unknown"))
    cls = {"benign": "t-grey", "malicious": "t-red", "suspicious": "t-orange"}.get(g.get("class"), "")
    return '<span class="tag %s">%s</span>%s%s' % (cls, esc(what), (" " + esc(g["name"])) if g.get("name") and g["name"].lower() != "unknown" else "",
                                                ' <span class=muted>last seen %s</span>' % esc(g["last"]) if g.get("last") else "")


def first_sendable(rows, n):
    # The first n addresses in query order that may be sent (Codex rc2 M15): read on until the batch is full, so a run
    # of private addresses at the top of the queue (test mode) cannot keep public ones from ever being looked up.
    out = []
    try:
        for r in rows if n > 0 else ():
            if sendable_ip(r[0]):
                out.append(r[0])
                if len(out) >= n:
                    break
    finally:
        if hasattr(rows, "close"):
            rows.close()             # no half-read statement left open on the connection
    return out


def sendable_ip(ip):
    # Only public addresses ever go to an outside service (test mode can store LAN addresses).
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast      # global unicast only
    except ValueError:
        return False


def gn_lookup(con, limit=5):
    # Top attackers first (highest score, active in 30 days), each again after 14 days. Stays under the daily allowance.
    daily, key = gn_daily(con), gn_key(con)
    if not daily or float(get_meta(con, "gn_wait_until", "0") or 0) > time.time():
        return 0
    left, _t, _u = day_budget(con, "gn_day", daily)
    now = time.time()
    ips = [r[0] for r in con.execute(
        "SELECT i.ip FROM ips i LEFT JOIN greynoise g USING(ip) WHERE i.last>=? AND (g.ip IS NULL OR g.checked<?) "
        "ORDER BY (g.ip IS NULL) DESC, i.score DESC, i.last DESC LIMIT ?", (now - 30 * 86400, now - 14 * 86400, 50 * max(1, min(limit, left))))]
    # Addresses that are never sent (LAN in test mode) are dropped before the batch is cut, or they would hold the
    # first places for ever and the public ones behind them would never be asked (Codex 049 M11).
    ips = [ip for ip in ips if sendable_ip(ip)][:min(limit, left)]
    done = 0
    for ip in ips:
        h = {"User-Agent": UA, "Accept": "application/json"}
        if key:
            h["key"] = key
        day_spend(con, "gn_day")
        try:
            with api_urlopen(urllib.request.Request("https://api.greynoise.io/v3/community/" + urllib.parse.quote(ip), headers=h), timeout=15) as r:
                g = gn_parse(json.loads(r.read(256 * 1024)), ip)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                g = gn_parse({}, ip)
            else:
                # 429: the allowance is used up (the community limit is per day); anything else: try again later.
                set_meta(con, "gn_wait_until", time.time() + (6 * 3600 if e.code == 429 else 3600))
                set_meta(con, "gn_error", "%s HTTP %s%s" % (fmt_ts(time.time()), e.code, ", daily allowance used up" if e.code == 429 else ""))
                break
        except Exception as e:
            set_meta(con, "gn_error", "%s %s" % (fmt_ts(time.time()), str(e)[:120]))
            break
        with con:
            con.execute("INSERT OR REPLACE INTO greynoise(ip, checked, data) VALUES(?,?,?)", (ip, time.time(), json.dumps(g)))
            con.execute("UPDATE enrich SET research=? WHERE ip=?", (research_now(con, ip), ip))     # benign -> on, changed -> off
        set_meta(con, "gn_error", "")
        done += 1
        time.sleep(1)
    return done


HB_KEY_RE = re.compile(r"[a-z]{12}")
HB_TYPES = ((1, "suspicious"), (2, "harvester"), (4, "comment spammer"))
HB_TEST_IP = "127.1.1.1"      # Project Honey Pot's test address: always answers 127.1.1.1 (for any key), so it tests the DNS path only
HB_DNS_CHOICES = (("system", "System resolver"), ("127.0.0.1", "Own resolver on this machine (127.0.0.1)"),
                  ("1.1.1.1", "Cloudflare (1.1.1.1)"), ("9.9.9.9", "Quad9 (9.9.9.9)"), ("8.8.8.8", "Google (8.8.8.8)"))
PUBLIC_DNS = {"1.1.1.1", "9.9.9.9", "8.8.8.8"}


def dns_picker(fid, cur):
    # The DNS server choice used by every DNS-based lookup: the list, or any other IPv4 resolver (a LAN Unbound, say).
    opts = list(HB_DNS_CHOICES) + ([] if cur in dict(HB_DNS_CHOICES) else [(cur, cur)])
    return ('<select id="%s" name=dns>%s</select><input name=dns_other inputmode=decimal maxlength=15 placeholder="or another IPv4 server" '
            'aria-label="Another DNS server (IPv4 address)" class="sp-dns-other">'
            % (fid, "".join('<option value="%s"%s>%s</option>' % (esc(v), " selected" if v == cur else "", esc(lbl)) for v, lbl in opts)))


def dns_from_form(f, current):
    return (f.get("dns_other") or "").strip() or (f.get("dns") or "").strip() or current


def hb_dns_ok(v):
    # "system" or one IPv4 server. A local resolver (loopback, LAN) is fine; multicast, 0.0.0.0, broadcast and reserved
    # addresses are not, since the question carries the key.
    if v == "system":
        return True
    try:
        a = ipaddress.IPv4Address(v)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or a.is_reserved or a == ipaddress.IPv4Address("255.255.255.255"))


def hb_dns(con=None):
    # Saved on the Settings page, else HUGINN_HTTPBL_DNS, else the system resolver.
    v = get_meta(con or db(), "hb_dns", "") or HB_DNS or "system"
    return v if hb_dns_ok(v) else "system"


def hb_dns_label(v):
    return dict(HB_DNS_CHOICES).get(v, v)


def dns_name(r, i):
    # A name in a DNS message at offset i: (lower-case name, offset after it). Compression pointers must point backwards,
    # at most 16 hops; anything out of bounds raises OSError.
    labels, hops, end, seen = [], 0, None, set()
    while True:
        if i >= len(r):
            raise OSError("bad DNS name")
        ln = r[i]
        if ln & 0xC0 == 0xC0:
            if i + 1 >= len(r):
                raise OSError("bad DNS name")
            ptr = ((ln & 0x3F) << 8) | r[i + 1]
            if end is None:
                end = i + 2
            hops += 1
            if hops > 16 or ptr >= i or ptr in seen:
                raise OSError("bad DNS name")
            seen.add(ptr)
            i = ptr
            continue
        if ln & 0xC0:
            raise OSError("bad DNS name")
        if ln == 0:
            return ".".join(labels).lower(), (end if end is not None else i + 1)
        if i + 1 + ln > len(r):
            raise OSError("bad DNS name")
        labels.append(r[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln


def dns_ask(server, name, qtype=1, timeout=3, port=53):
    # A minimal DNS client for one question over UDP (A = 1 or TXT = 16): the records of that type for this name, following
    # a CNAME chain inside the answer. A records come as four numbers, TXT records as one string (its parts joined). [] for
    # NXDOMAIN or no such record. Raises OSError when the server does not answer, answers with an error, a truncated or
    # malformed reply.
    tid = os.urandom(2)
    qname = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\0"
    question = qname + qtype.to_bytes(2, "big") + b"\x00\x01"
    query = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    want = name.lower().rstrip(".")
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as sk:
        sk.connect((server, port))
        for _try in range(2):
            sk.send(query)
            end = time.monotonic() + timeout
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                sk.settimeout(left)
                try:
                    r = sk.recv(4096)
                except socket.timeout:
                    break
                if len(r) < 12 or r[:2] != tid or not r[2] & 0x80 or int.from_bytes(r[4:6], "big") != 1:
                    continue                                  # not the answer to this question
                if r[12:12 + len(question)].lower() != question.lower():
                    continue
                if r[2] & 0x02:
                    raise OSError("truncated DNS answer from %s" % server)
                rcode = r[3] & 0x0F
                if rcode == 3:
                    return []
                if rcode != 0:
                    raise OSError("DNS server %s answered with error code %d" % (server, rcode))
                ancount = min(int.from_bytes(r[6:8], "big"), 64)
                i, recs = 12 + len(question), []
                for _a in range(ancount):
                    owner, i = dns_name(r, i)
                    if i + 10 > len(r):
                        raise OSError("short DNS answer")
                    rtype, rclass, rdlen = int.from_bytes(r[i:i + 2], "big"), int.from_bytes(r[i + 2:i + 4], "big"), int.from_bytes(r[i + 8:i + 10], "big")
                    i += 10
                    if i + rdlen > len(r):
                        raise OSError("short DNS answer")
                    if rclass == 1 and rtype == 1 == qtype and rdlen == 4:
                        recs.append((owner, "V", list(r[i:i + 4])))
                    elif rclass == 1 and rtype == 16 == qtype:
                        parts, j = [], i
                        while j < i + rdlen:
                            ln = r[j]
                            if j + 1 + ln > i + rdlen:
                                raise OSError("bad TXT record")
                            parts.append(r[j + 1:j + 1 + ln])
                            j += 1 + ln
                        recs.append((owner, "V", b"".join(parts).decode("utf-8", "replace")))
                    elif rclass == 1 and rtype == 5:
                        recs.append((owner, "CNAME", dns_name(r, i)[0]))
                    i += rdlen
                target = want
                for _hop in range(9):                         # the records for the name asked, through at most 8 CNAMEs
                    vals = [v for o, t, v in recs if o == target and t == "V"]
                    if vals:
                        return vals
                    c = next((v for o, t, v in recs if o == target and t == "CNAME"), None)
                    if c is None:
                        return []
                    target = c
                return []
    raise OSError("no answer from DNS server %s" % server)


def dns_a(server, name, timeout=3, port=53):
    # The four numbers of the A record for this name, or None for NXDOMAIN or no such record (see dns_ask).
    v = dns_ask(server, name, 1, timeout, port)
    return v[0] if v else None


def system_dns():
    # The first name server in /etc/resolv.conf: the "system resolver" for questions the standard library cannot ask (TXT).
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver":
                    try:
                        ipaddress.ip_address(p[1])
                        return p[1]
                    except ValueError:
                        continue
    except OSError:
        pass
    return None


def hb_key(con=None):
    # A key saved on the Settings page wins over HUGINN_HTTPBL_KEY. It is never shown again once saved.
    k = get_meta(con or db(), "hb_key", "") or ""
    return k if HB_KEY_RE.fullmatch(k) else (HB_KEY if HB_KEY_RE.fullmatch(HB_KEY) else "")


def hb_query(key, ip, server="system"):
    # The four numbers of the answer, or None when the address is not listed. Raises OSError when DNS itself fails.
    name = "%s.%s.dnsbl.httpbl.org" % (key, ".".join(reversed(ip.split("."))))
    if server != "system":
        return dns_a(server, name)
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return None
        raise
    return [int(x) for x in infos[0][4][0].split(".")]


def hb_parse(parts):
    # 127.days.threat.type. Anything that does not start with 127 is a resolver making up an answer, never a listing.
    if parts is None:
        return {"listed": False}
    if len(parts) != 4 or parts[0] != 127:
        raise OSError("unexpected DNS answer (does the resolver rewrite unknown names?)")
    days, threat, kind = parts[1], parts[2], parts[3]
    if kind == 0:
        return {"listed": True, "engine": True, "days": days, "threat": 0, "types": []}
    return {"listed": True, "engine": False, "days": days, "threat": threat, "types": [n for b, n in HB_TYPES if kind & b]}


def hb_test(key, server="system"):
    # "ok" when the test address answers through this DNS server, "blocked" when the answer never arrives (a resolver
    # with DNS rebinding protection drops it), "error" when DNS fails. The test address answers for any key, so this
    # proves the path, not the key.
    try:
        parts = hb_query(key, HB_TEST_IP, server)
    except Exception:
        return "error"
    return "ok" if parts and parts[0] == 127 else "blocked"


def hb_get(con, ip):
    r = con.execute("SELECT data FROM httpbl WHERE ip=?", (ip,)).fetchone()
    try:
        return json.loads(r[0]) if r and r[0] else None
    except ValueError:
        return None


def hb_html(h):
    if h is None:
        return '<span class=muted>not checked yet</span>' if hb_key() and HB_DAILY else "–"
    if not h.get("listed"):
        return "not listed"
    days = int(h.get("days") or 0)
    seen = ' <span class=muted>last seen %s</span>' % ("today" if days == 0 else "1 day ago" if days == 1 else "%d days ago" % days)
    if h.get("engine"):
        return '<span class="tag t-grey">search engine</span>' + seen
    types = h.get("types") or []
    tags = "".join('<span class="tag %s">%s</span>' % ("t-orange" if t == "suspicious" else "t-red", esc(t)) for t in types if t in dict((n, 1) for _b, n in HB_TYPES))
    return '%s <span class=mono>threat %d</span>%s' % (tags, int(h.get("threat") or 0), seen)


def hb_lookup(con, limit=20):
    # Top attackers first (highest score, active in 30 days, IPv4 only), each again after 7 days. Stays under HB_DAILY.
    key = hb_key(con)
    if not key or not HB_DAILY or float(get_meta(con, "hb_wait_until", "0") or 0) > time.time():
        return 0
    left, _t, _u = day_budget(con, "hb_day", HB_DAILY)
    now = time.time()
    ips = first_sendable(con.execute(
        "SELECT i.ip FROM ips i LEFT JOIN httpbl h USING(ip) WHERE i.last>=? AND i.ip NOT LIKE '%:%' AND (h.ip IS NULL OR h.checked<?) "
        "ORDER BY (h.ip IS NULL) DESC, i.score DESC, i.last DESC", (now - 30 * 86400, now - 7 * 86400)), min(limit, left))
    done = 0
    for ip in ips:
        day_spend(con, "hb_day")
        try:
            h = hb_parse(hb_query(key, ip, hb_dns(con)))
        except Exception as e:
            set_meta(con, "hb_wait_until", time.time() + 3600)
            set_meta(con, "hb_error", "%s %s" % (fmt_ts(time.time()), str(e).replace(key, "<key>")[:120]))
            break
        with con:
            con.execute("INSERT OR REPLACE INTO httpbl(ip, checked, data) VALUES(?,?,?)", (ip, time.time(), json.dumps(h)))
        set_meta(con, "hb_error", "")
        done += 1
        time.sleep(0.2)
    return done


# ---------------------------------------------------------------- Tor exit nodes (0.48)
# The Tor Project's list of exit addresses, fetched once a day. An attack from one of them came from someone using Tor, not
# from the owner of the address: it is tagged "tor", never counts as coming back (the next visit is likely someone else),
# and is left out of the blocklist unless chosen on Settings. A listing within TOR_WINDOW of the attack counts.
TOR_URL = "https://check.torproject.org/torbulkexitlist"
TOR_WINDOW = 30 * 86400
TOR_GAP = 3 * 86400             # missing from the daily list for longer than this: the next listing is a new period
TOR_KEEP = 365 * 86400
TOR_MAX_BYTES = 4_000_000        # about 1,300 addresses today, about 20 KB
TOR_MAX_ADDRS = 100_000


def tor_tagging(con=None):
    # Turned on on Settings (default). Tagging uses the stored list; downloading it also needs outside lookups (HUGINN_ENRICH).
    return (get_meta(con or db(), "tor_on", "1") or "1") == "1"


def tor_on(con=None):
    return ENRICH and tor_tagging(con)


def tor_bl(con=None):
    # True: Tor exits may be on the blocklist like any other attacker.
    return (get_meta(con or db(), "tor_bl", "0") or "0") == "1"


def tor_parse(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            a = ipaddress.ip_address(line)
        except ValueError:
            continue
        if a.is_global:
            out.add(str(a))
    return out


def tor_is(con, ip, last):
    # Decided by the latest activity: it must fall within TOR_WINDOW of the time the address was on the list. A Tor match
    # long ago, or between two attacks, never covers newer traffic (Codex review 047).
    # Listed periods are kept apart (0.49.1, Codex 049 M8): an address on the list in January and again in April was not a
    # Tor exit in between. Before the first refresh with periods, the single first/last row is all there is.
    rows = con.execute("SELECT first, last FROM torp WHERE ip=?", (ip,)).fetchall()
    if not rows and get_meta(con, "torp_init") != "1":
        rows = con.execute("SELECT first, last FROM tor WHERE ip=?", (ip,)).fetchall()
    return any(a - TOR_WINDOW <= last <= b + TOR_WINDOW for a, b in rows)


def tor_get(con, ip):
    r = con.execute("SELECT first, last FROM tor WHERE ip=?", (ip,)).fetchone()
    return {"first_listed": r[0], "last_listed": r[1]} if r else None


def tor_refresh(con, force=False):
    # Once a day (or at once when forced): fetch the list, note who is on it, and recompute every attacker whose Tor
    # status may change. Returns how many addresses the list held, or None when nothing was fetched.
    if not tor_on(con):
        return None
    now = time.time()
    if not force and now - float(get_meta(con, "tor_fetched", "0") or 0) < 86400 - 600:
        return None
    if not force and float(get_meta(con, "tor_wait_until", "0") or 0) > now:
        return None
    try:
        req = urllib.request.Request(TOR_URL, headers={"User-Agent": UA, "Accept": "text/plain"})
        with api_urlopen(req, timeout=30) as r:
            raw = r.read(TOR_MAX_BYTES + 1)
        if len(raw) > TOR_MAX_BYTES:                  # never take the first part of a cut list as the whole (Codex 047)
            raise OSError("the list was larger than %d bytes" % TOR_MAX_BYTES)
        listed = tor_parse(raw.decode("ascii", "replace"))
        if not 100 <= len(listed) <= TOR_MAX_ADDRS:
            raise OSError("the list held %d addresses" % len(listed))
    except Exception as e:
        set_meta(con, "tor_wait_until", now + 3600)
        set_meta(con, "tor_error", "%s %s" % (fmt_ts(now), str(e)[:120]))
        return None
    with con:
        if get_meta(con, "torp_init") != "1":        # one time: what the single-row table knew becomes the first period
            con.execute("INSERT OR IGNORE INTO torp(ip, first, last) SELECT ip, first, last FROM tor")
            con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('torp_init','1')")
        con.executemany("INSERT INTO tor(ip, first, last) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET last=excluded.last",
                        [(ip, now, now) for ip in listed])
        for ip in listed:                            # still listed (seen within TOR_GAP): extend; otherwise a new period
            if not con.execute("UPDATE torp SET last=? WHERE ip=? AND last>=?", (now, ip, now - TOR_GAP)).rowcount:
                con.execute("INSERT OR IGNORE INTO torp(ip, first, last) VALUES(?,?,?)", (ip, now, now))
        con.execute("DELETE FROM tor WHERE last < ?", (now - TOR_KEEP,))
        con.execute("DELETE FROM torp WHERE last < ?", (now - TOR_KEEP,))
    affected = {r[0] for r in con.execute("SELECT i.ip FROM ips i JOIN tor t USING(ip)")}
    affected |= {r[0] for r in con.execute("SELECT ip FROM ips WHERE (','||COALESCE(tags,'')||',') LIKE '%,tor,%'")}
    with con:
        for ip in affected:
            recompute_ip(con, ip)
    set_meta(con, "tor_fetched", now)
    set_meta(con, "tor_count", len(listed))
    set_meta(con, "tor_error", "")
    return len(listed)


# ---------------------------------------------------------------- netblocks (Team Cymru, 0.47)
NB_RECHECK = 30 * 86400          # blocks and owners change rarely
NB_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def nb_on(con=None):
    return (get_meta(con or db(), "nb_on", "1") or "1") == "1"


def nb_dns(con=None):
    v = get_meta(con or db(), "nb_dns", "") or "system"
    return v if hb_dns_ok(v) else "system"


def nb_server(choice):
    # The address to ask: a chosen public server, or the first name server of the system.
    if choice != "system":
        return choice
    s = system_dns()
    if not s:
        raise OSError("no name server in /etc/resolv.conf")
    return s


def nb_qname(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(a.exploded.split("."))) + ".origin.asn.cymru.com"
    return ".".join(reversed(a.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"


def nb_parse(ip, txts):
    # "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11", one record per announced block that holds the address. The most specific
    # block wins; the first AS when several announce it. Anything that does not fit is left out, so None = not routed.
    a, best = ipaddress.ip_address(ip), None
    for t in txts:
        f = [x.strip() for x in str(t).split("|")]
        if len(f) < 3:
            continue
        asns = [x for x in f[0].split() if re.fullmatch(r"\d{1,10}", x)]
        try:
            net = ipaddress.ip_network(f[1], strict=False)
        except ValueError:
            continue
        if not asns or a not in net:
            continue
        cc = f[2].upper() if re.fullmatch(r"[A-Za-z]{2}", f[2]) else None
        reg = f[3].lower() if len(f) > 3 and re.fullmatch(r"[A-Za-z]{2,12}", f[3]) else None
        day = f[4] if len(f) > 4 and NB_DATE.fullmatch(f[4]) else None
        if best is None or net.prefixlen > best[0].prefixlen:
            best = (net, asns[0], cc, reg, day)
    if best is None:
        return None
    return {"prefix": str(best[0]), "asn": best[1], "cc": best[2], "registry": best[3], "allocated": best[4]}


def nb_asname(txts, asn=None):
    # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US": the owner is the last field.
    # Only the row for the AS number that was asked about counts, so a wrong answer never names another network.
    for t in txts:
        f = [x.strip() for x in str(t).split("|")]
        if asn is not None and f[0] != str(asn):
            continue
        if len(f) >= 5 and f[-1]:
            return ext_text(f[-1], 120)
    return None


def nb_get(con, ip):
    r = con.execute("SELECT n.*, a.name FROM netblock n LEFT JOIN asname a USING(asn) WHERE n.ip=?", (ip,)).fetchone()
    return dict(r) if r else None


def nb_url(prefix):
    return "/ips?" + urllib.parse.urlencode({"net": prefix, "days": "all"})


def nb_html(con, n):
    if n is None:
        return '<span class=muted>not looked up yet</span>' if nb_on(con) else "–"
    if not n.get("prefix"):
        return '<span class=muted>not routed</span>'
    many = con.execute("SELECT COUNT(*) FROM netblock JOIN ips USING(ip) WHERE prefix=?", (n["prefix"],)).fetchone()[0]
    return '<a class=mono href="%s">%s</a> <span class=muted>%s</span>' % (
        esc(nb_url(n["prefix"])), esc(n["prefix"]), "only this attacker" if many <= 1 else "%s attackers in this block" % num(many))


def nb_owner_html(n):
    if not n or not n.get("prefix"):
        return "–"
    bits = [x for x in (("AS" + n["asn"]) if n.get("asn") else "", (n.get("registry") or "").upper(),
                        ("allocated " + n["allocated"]) if n.get("allocated") else "") if x]
    return '%s <span class=muted>%s</span>' % (esc(n.get("name") or "unknown owner"), esc(" · ".join(bits)))


def nb_lookup(con, limit=50):
    # Newest attackers first, each again after 30 days, then the names of new AS numbers. Stays under NB_DAILY.
    if not nb_on(con) or not NB_DAILY or float(get_meta(con, "nb_wait_until", "0") or 0) > time.time():
        return 0
    left, _t, _u = day_budget(con, "nb_day", NB_DAILY)
    if left <= 0:
        return 0
    now = time.time()
    ips = [r[0] for r in con.execute(
        "SELECT i.ip FROM ips i LEFT JOIN netblock n USING(ip) WHERE n.ip IS NULL OR n.checked<? "
        "ORDER BY (n.ip IS NULL) DESC, i.last DESC LIMIT ?", (now - NB_RECHECK, min(limit, left)))]
    done = 0
    try:
        server = nb_server(nb_dns(con))
        for ip in ips:
            if not sendable_ip(ip):
                with con:
                    con.execute("INSERT OR REPLACE INTO netblock(ip, checked) VALUES(?,?)", (ip, time.time()))
                continue
            day_spend(con, "nb_day")
            n = nb_parse(ip, dns_ask(server, nb_qname(ip), 16)) or {}
            with con:
                con.execute("INSERT OR REPLACE INTO netblock VALUES(?,?,?,?,?,?,?)", (ip, time.time(), n.get("prefix"), n.get("asn"),
                            n.get("cc"), n.get("registry"), n.get("allocated")))
            done += 1
            time.sleep(0.1)
        left, _t, _u = day_budget(con, "nb_day", NB_DAILY)
        asns = [r[0] for r in con.execute(
            "SELECT DISTINCT n.asn FROM netblock n LEFT JOIN asname a USING(asn) WHERE n.asn IS NOT NULL AND (a.asn IS NULL OR a.checked<?) LIMIT ?",
            (now - NB_RECHECK, min(20, left)))]
        for asn in asns:
            day_spend(con, "nb_day")
            name = nb_asname(dns_ask(server, "AS%s.asn.cymru.com" % asn, 16), asn)
            with con:
                con.execute("INSERT OR REPLACE INTO asname VALUES(?,?,?)", (asn, time.time(), name))
            time.sleep(0.1)
    except Exception as e:
        set_meta(con, "nb_wait_until", time.time() + 3600)
        set_meta(con, "nb_error", "%s %s" % (fmt_ts(time.time()), str(e)[:120]))
        return done
    set_meta(con, "nb_error", "")
    return done


# ---------------------------------------------------------------- DroneBL (0.51)
# A free DNS list of drones, botnets, open proxies and brute forcers (dronebl.org), no key. The last number of the answer
# names the class. IPv4 only. Answers are in 127.0.0.0/8, which Pi-hole and many routers drop (DNS rebinding protection),
# so every round first asks for DroneBL's test address 127.0.0.2: no answer there means the resolver hides them.
DBL_ZONE = "dnsbl.dronebl.org"
DBL_RECHECK = 7 * 86400
# DNS lists only ask about attackers seen in the last 30 days, like GreyNoise and http:BL: otherwise the weekly recheck of
# every address ever seen grows with the database until it eats the daily allowance before new attackers get a turn.
LOOKUP_ACTIVE = 30 * 86400
# Active = seen by a service, or a fresh IDS alert from an address Huginn already knows (Codex rc2 M16).
LOOKUP_ACTIVE_SQL = "(i.last>=? OR EXISTS(SELECT 1 FROM ids x WHERE x.ip=i.ip AND x.last>=?))"
DBL_CLASSES = {1: "test entry", 2: "test entry", 3: "IRC drone", 5: "bottler", 6: "spambot or drone", 7: "DDoS drone", 8: "SOCKS proxy",
               9: "HTTP proxy", 10: "proxy chain", 11: "web page proxy", 12: "open DNS resolver", 13: "brute force attacker",
               14: "open Wingate proxy", 15: "compromised router or gateway", 16: "autorooting worm",
               17: "botnet (found automatically)", 18: "DNS/MX host name on IRC", 19: "abused VPN", 255: "uncategorised"}


def dbl_on(con=None):
    return (get_meta(con or db(), "dbl_on", "1") or "1") == "1"


def dbl_dns(con=None):
    # Until chosen here: the server picked for Project Honey Pot (the same kind of DNS list, and one that already passes
    # its 127.x answers), otherwise the system's.
    con = con or db()
    v = get_meta(con, "dbl_dns", "") or get_meta(con, "hb_dns", "") or "system"
    return v if hb_dns_ok(v) else "system"


def dbl_query(server, ip):
    # The class numbers DroneBL lists the address under ([] = not listed). Raises OSError when DNS fails or the answer is
    # not DroneBL's (anything outside 127.0.0.x is a resolver making something up).
    codes = []
    for parts in dns_ask(server, ".".join(reversed(ip.split("."))) + "." + DBL_ZONE, 1):
        if len(parts) != 4 or parts[0] != 127 or parts[1] != 0 or parts[2] != 0:
            raise OSError("unexpected DNS answer (does the resolver rewrite unknown names?)")
        if parts[3] not in codes:
            codes.append(parts[3])
    return sorted(codes)[:8]


DNS_TRANSIENT = 15 * 60          # pause after "no answer" or SERVFAIL: a resolver that had to start from scratch, usually


def dns_transient(e):
    return "no answer from DNS server" in str(e) or "error code 2" in str(e)


def dbl_test(server):
    # "ok" when the test address answers, "blocked" when its answer is dropped on the way, "error" when DNS fails. One more
    # try after a short wait: an own resolver with a cold cache can need longer than one question allows (0.52.2).
    for i in range(2):
        try:
            return "ok" if dbl_query(server, "127.0.0.2") else "blocked"
        except Exception:
            if i == 0:
                time.sleep(2)
    return "error"


def dbl_get(con, ip):
    r = con.execute("SELECT checked, codes FROM dronebl WHERE ip=?", (ip,)).fetchone()
    if not r:
        return None
    try:
        codes = [int(x) for x in json.loads(r[1] or "[]") if isinstance(x, int)]
    except ValueError:
        codes = []
    return {"listed": bool(codes), "codes": codes, "classes": [DBL_CLASSES.get(c, "class %d" % c) for c in codes], "checked": r[0]}


def dbl_html(con, d, ip=""):
    if ":" in ip:
        return '<span class=muted>IPv4 only</span>'
    if d is None:
        return '<span class=muted>not looked up yet</span>' if dbl_on(con) and DBL_DAILY else "–"
    if not d["listed"]:
        return '<span class=muted>not listed</span> <span class=muted>· %s</span>' % esc(ago(d["checked"]))
    return '%s <span class=muted>· %s</span>' % (", ".join('<span class="tag t-purple">%s</span>' % esc(c) for c in d["classes"]), esc(ago(d["checked"])))


def dbl_lookup(con, limit=40):
    # Newest attackers first (active in 30 days), IPv4 only, each again after a week. Stays under DBL_DAILY; pauses an hour on errors and six when
    # the resolver drops DroneBL's answers (then every attacker would look "not listed").
    if not dbl_on(con) or not DBL_DAILY or float(get_meta(con, "dbl_wait_until", "0") or 0) > time.time():
        return 0
    left, _t, _u = day_budget(con, "dbl_day", DBL_DAILY)
    if left <= 1:
        return 0
    now = time.time()
    ips = first_sendable(con.execute(
        "SELECT i.ip FROM ips i LEFT JOIN dronebl d USING(ip) WHERE %s AND i.ip NOT LIKE '%%:%%' AND (d.ip IS NULL OR d.checked<?) "
        "ORDER BY (d.ip IS NULL) DESC, i.last DESC" % LOOKUP_ACTIVE_SQL, (now - LOOKUP_ACTIVE, now - LOOKUP_ACTIVE, now - DBL_RECHECK)),
        min(limit, left - 1))
    if not ips:
        return 0
    done = 0
    try:
        server = nb_server(dbl_dns(con))
        day_spend(con, "dbl_day")
        t = dbl_test(server)
        if t != "ok":
            set_meta(con, "dbl_wait_until", time.time() + (6 * 3600 if t == "blocked" else DNS_TRANSIENT))
            set_meta(con, "dbl_error", "%s %s" % (fmt_ts(time.time()), "the DNS server drops DroneBL's answers (127.0.0.x): choose a public "
                                                  "DNS server on Settings, Lookups" if t == "blocked" else "no answer from the DNS server"))
            return 0
        for ip in ips:
            day_spend(con, "dbl_day")
            codes = dbl_query(server, ip)
            old = dbl_get(con, ip)
            with con:                           # the answer and the dronebl tag change together, so an error later cannot split them
                con.execute("INSERT OR REPLACE INTO dronebl(ip, checked, codes) VALUES(?,?,?)", (ip, time.time(), json.dumps(codes)))
                if bool(codes) != bool(old and old["listed"]):
                    recompute_ip(con, ip)
            done += 1
            time.sleep(0.1)
    except Exception as e:
        set_meta(con, "dbl_wait_until", time.time() + (DNS_TRANSIENT if dns_transient(e) else 3600))
        set_meta(con, "dbl_error", "%s %s" % (fmt_ts(time.time()), str(e)[:120]))
        return done
    set_meta(con, "dbl_error", "")
    return done


# ---------------------------------------------------------------- Spamhaus ZEN and Abusix abuse contacts (0.52)
# Spamhaus' free mirrors only answer resolvers on the asker's own network (an own Unbound, say): through a public resolver
# they reply 127.255.255.254, and 127.255.255.252/255 mean a bad query or too many. Those are errors, never a listing.
SH_ZONE = "zen.spamhaus.org"
SH_RECHECK = 7 * 86400
SH_CLASSES = {2: "SBL: spam source", 3: "SBL CSS: snowshoe spam", 4: "XBL: exploited or infected", 5: "XBL: exploited or infected",
              6: "XBL: exploited or infected", 7: "XBL: exploited or infected", 9: "DROP: hijacked network",
              10: "PBL: end-user range (ISP)", 11: "PBL: end-user range"}
SH_BAD = {10, 11}            # PBL alone says "a home connection", not "did something": no tag for it
SH_ERRORS = {252: "the query was malformed", 254: "Spamhaus refuses public DNS resolvers: use your own (Unbound, say)",
             255: "too many queries for the free mirrors"}


def sh_on(con=None):
    return (get_meta(con or db(), "sh_on", "1") or "1") == "1"


def sh_dns(con=None):
    # Until chosen here: the DroneBL server (which follows Project Honey Pot's), as long as it is not a public resolver.
    con = con or db()
    v = get_meta(con, "sh_dns", "") or dbl_dns(con)
    return v if hb_dns_ok(v) else "system"


def sh_query(server, ip):
    codes = []
    for parts in dns_ask(server, ".".join(reversed(ip.split("."))) + "." + SH_ZONE, 1):
        if len(parts) != 4 or parts[0] != 127:
            raise OSError("unexpected DNS answer (does the resolver rewrite unknown names?)")
        if parts[1:3] == [255, 255]:
            raise OSError(SH_ERRORS.get(parts[3], "Spamhaus answered with error code %d" % parts[3]))
        if parts[1:3] != [0, 0]:
            raise OSError("unexpected DNS answer")
        if parts[3] not in codes:
            codes.append(parts[3])
    return sorted(codes)[:8]


def sh_test(server):
    # "ok" when the test address answers, "public" when Spamhaus refuses the resolver, "blocked" when 127.x answers are
    # dropped on the way, "error" otherwise (after one more try, see dbl_test).
    for i in range(2):
        try:
            return "ok" if 2 in sh_query(server, "127.0.0.2") else "blocked"
        except OSError as e:
            if "public DNS" in str(e):
                return "public"
        except Exception:
            pass
        if i == 0:
            time.sleep(2)
    return "error"


def sh_get(con, ip):
    r = con.execute("SELECT checked, codes FROM spamhaus WHERE ip=?", (ip,)).fetchone()
    if not r:
        return None
    try:
        codes = [int(x) for x in json.loads(r[1] or "[]") if isinstance(x, int)]
    except ValueError:
        codes = []
    names = []
    for c in codes:
        n = SH_CLASSES.get(c, "class %d" % c)
        if n not in names:
            names.append(n)
    return {"listed": bool(codes), "codes": codes, "classes": names, "checked": r[0]}


def sh_html(con, d, ip=""):
    if ":" in ip:
        return '<span class=muted>IPv4 only</span>'
    if d is None:
        return '<span class=muted>not looked up yet</span>' if sh_on(con) and SH_DAILY else "–"
    if not d["listed"]:
        return '<span class=muted>not listed · %s</span>' % esc(ago(d["checked"]))
    pbl = {SH_CLASSES[c] for c in SH_BAD}
    return '%s <span class=muted>· %s</span>' % (", ".join('<span class="tag %s">%s</span>' % ("" if n in pbl else "t-red", esc(n))
                                                          for n in sorted(d["classes"], key=lambda n: n in pbl)), esc(ago(d["checked"])))


def ab_on(con=None):
    return (get_meta(con or db(), "ab_on", "1") or "1") == "1"


AB_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")


def ab_get(con, ip):
    r = con.execute("SELECT checked, email FROM abusecontact WHERE ip=?", (ip,)).fetchone()
    return {"email": r[1], "checked": r[0]} if r else None


def ab_html(con, ip, a):
    if a is None:
        return '<span class=muted>not looked up yet</span>' if ab_on(con) and nb_on(con) and AB_DAILY else "–"
    if not a["email"]:
        return '<span class=muted>none found</span>'
    r = con.execute("SELECT first, last, cmds, logins_ok + logins_fail, files FROM ips WHERE ip=?", (ip,)).fetchone()
    utc = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M")     # the mail says UTC, so it is UTC
    when = ("between %s and %s (UTC)" % (utc(r[0]), utc(r[1]))) if r and r[0] else ""
    body = ("Hello,\n\nthe address %s attacked my honeypot %s: %s login attempts, %s commands, %s files.\n\n"
            "The abuse contact was found with the Abusix Abuse Contact DB (abusix.com/contactdb).\n"
            % (ip, when, r[3] if r else "?", r[2] if r else "?", r[4] if r else "?"))
    href = "mailto:%s?%s" % (a["email"], urllib.parse.urlencode({"subject": "Abuse from %s" % ip, "body": body}, quote_via=urllib.parse.quote))
    return '<span class=mono>%s</span> · <a href="%s">Report</a>' % (esc(a["email"]), esc(href))


def dnslist_lookup(con, label, table, on, daily, dns, recheck, query, test, limit=40, ok_test=("ok",)):
    # One lookup round for a DNS list keyed by IPv4 address: newest attackers first, each again after `recheck`, the
    # resolver tested first. Returns (looked up, addresses whose answer changed from empty to something or back).
    k = {"spamhaus": "sh", "abusecontact": "ab"}[table]
    if not on or not daily or float(get_meta(con, k + "_wait_until", "0") or 0) > time.time():
        return 0, []
    left, _t, _u = day_budget(con, k + "_day", daily)
    spare = 1 if test else 0                    # the resolver test costs one; Abusix has none (Codex rc2 L1)
    if left <= spare:
        return 0, []
    now = time.time()
    ips = first_sendable(con.execute(
        "SELECT i.ip FROM ips i LEFT JOIN %s d USING(ip) WHERE %s AND i.ip NOT LIKE '%%:%%' AND (d.ip IS NULL OR d.checked<?) "
        "ORDER BY (d.ip IS NULL) DESC, i.last DESC" % (table, LOOKUP_ACTIVE_SQL), (now - LOOKUP_ACTIVE, now - LOOKUP_ACTIVE, now - recheck)),
        min(limit, left - spare))
    if not ips:
        return 0, []
    done, changed = 0, []
    try:
        server = nb_server(dns)
        if test:
            day_spend(con, k + "_day")
            t = test(server)
            if t not in ok_test:
                msg = {"public": SH_ERRORS[254], "blocked": "the DNS server drops the answers (127.0.0.x): choose another on Settings, Lookups"}
                set_meta(con, k + "_wait_until", time.time() + (6 * 3600 if t in msg else DNS_TRANSIENT))
                set_meta(con, k + "_error", "%s %s" % (fmt_ts(time.time()), msg.get(t, "no answer from the DNS server")))
                return 0, []
        for ip in ips:
            day_spend(con, k + "_day")
            val = query(server, ip)
            old = con.execute("SELECT %s FROM %s WHERE ip=?" % ("codes" if table == "spamhaus" else "email", table), (ip,)).fetchone()
            with con:                           # the answer and the tag it gives change together
                con.execute("INSERT OR REPLACE INTO %s VALUES(?,?,?)" % table, (ip, time.time(), val))
                if (old[0] if old else None) != val:
                    changed.append(ip)
                    if table == "spamhaus":
                        recompute_ip(con, ip)
            done += 1
            time.sleep(0.1)
    except OSError as e:
        pause = 24 * 3600 if any(x in str(e) for x in ("public DNS", "too many")) else DNS_TRANSIENT if dns_transient(e) else 3600
        set_meta(con, k + "_wait_until", time.time() + pause)
        set_meta(con, k + "_error", "%s %s" % (fmt_ts(time.time()), str(e)[:140]))
        return done, changed
    except Exception as e:
        set_meta(con, k + "_wait_until", time.time() + 3600)
        set_meta(con, k + "_error", "%s %s" % (fmt_ts(time.time()), str(e)[:140]))
        return done, changed
    set_meta(con, k + "_error", "")
    return done, changed


def sh_lookup(con, limit=20):
    dns = sh_dns(con)
    if dns in PUBLIC_DNS:                      # Spamhaus answers these with an error code, so do not even ask
        if get_meta(con, "sh_error", "") == "" and sh_on(con):
            set_meta(con, "sh_error", "%s %s" % (fmt_ts(time.time()), SH_ERRORS[254]))
        return 0
    n, _changed = dnslist_lookup(con, "Spamhaus", "spamhaus", sh_on(con), SH_DAILY, dns, SH_RECHECK,
                                lambda srv, ip: json.dumps(sh_query(srv, ip)), sh_test, limit)
    return n


def ab_query(server, ip):
    for t in dns_ask(server, ".".join(reversed(ip.split("."))) + ".abuse-contacts.abusix.org", 16):
        m = AB_EMAIL.search(str(t))
        if m:
            return m.group(0).lower()[:200]
    return ""


def ab_lookup(con, limit=40):
    n, _changed = dnslist_lookup(con, "Abusix", "abusecontact", ab_on(con) and nb_on(con), AB_DAILY, nb_dns(con), 30 * 86400,
                                 ab_query, None, limit)
    return n


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


def hp_goodbye_set(on):
    # 0.41: the logout note on or off ("goodbye on|off" to the locked hp-export key).
    return hp_toggle("goodbye", on, "0.41")


def hp_ids_set(on):
    # 0.44: Suricata on or off ("ids on|off"). Only starts or stops a Suricata already set up on the honeypot.
    return hp_toggle("ids", on, "0.44")


def hp_toggle(word, on, since):
    # Ask the honeypot to turn one thing on or off ("<word> on|off" to the locked hp-export key). Returns (state, error).
    # An honeypot older than `since` ignores the command and starts the whole export instead: only the first line is
    # read, then the connection is closed, so that never costs more than a moment.
    try:
        p = subprocess.Popen(hp_ssh("%s %s" % (word, "on" if on else "off")), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return None, "could not start ssh: %s" % str(e)[:100]
    try:
        first = b""
        deadline = time.time() + 30
        while time.time() < deadline and b"\n" not in first and len(first) < 64:
            r, _w, _x = select.select([p.stdout], [], [], max(0.0, deadline - time.time()))
            if not r:
                break
            chunk = os.read(p.stdout.fileno(), 64 - len(first))
            if not chunk:
                break
            first += chunk
    finally:
        if p.poll() is None:
            p.kill()
        try:
            err = p.communicate(timeout=5)[1] or b""
        except subprocess.TimeoutExpired:
            err = b""
    line = first.split(b"\n", 1)[0].decode("ascii", "replace").strip()
    if line in ("%s on" % word, "%s off" % word):
        state = line.split()[1] == "on"
        return (state, None) if state == bool(on) else (None, "the honeypot reports it is still %s" % ("on" if state else "off"))
    if line.startswith("##") or len(first) >= 64:
        return None, "the honeypot does not know this yet: run update-honeypot.sh there once (Huginn %s or later)" % since
    return None, (err.decode("utf-8", "replace").strip()[:150] or "no answer from the honeypot")


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


def score_parts(sess, lo, lf, cmds, files, tcpip, expl, csvcs, took=False, read=False, sshole=False, web="", ids=False, stepped=False):
    # The one place that defines the score: (label, points), zero points left out. web: "exploit", "probe" and/or "robots".
    parts = [("seen", 1), ("SSHole probe", 10 if sshole else 0), ("took bait", 20 if took else 0), ("read bait", 5 if read else 0),
             ("web exploit", 8 if "exploit" in web else 0), ("web probe", 3 if "probe" in web and "exploit" not in web else 0),
             ("robots.txt trap", 5 if "robots" in web else 0), ("IDS alert", 3 if ids else 0),
             ("login attempts", 2 if lo + lf else 0), ("brute force", 2 if lo + lf >= 10 else 0), ("commands", min(10, cmds // 2)),
             ("files", 15 if files else 0), ("proxy", 10 if tcpip else 0), ("exploit", 10 if expl else 0),
             ("decoy services", 3 * len(csvcs)), ("repeat visits", min(5, sess // 20)), ("stepped up", 5 if stepped else 0)]
    return [(k, v) for k, v in parts if v]


# The same scoring in words, for the Blocklist page. tests/test_polish.py checks that every part of score_parts is named here.
SCORE_HELP = ("1 seen, +2 login attempts, +2 brute force (10 or more), +½ per command (max 10), +15 files, +10 proxy, +10 exploit, "
              "+10 SSHole probe, +20 took bait, +5 read bait, +8 web exploit, +3 web probe, +5 robots.txt trap, "
              "+3 IDS alert (Suricata rule of severity 1, an attack), "
              "+3 per decoy service, +1 per 20 repeat visits (max 5), "
              "+5 stepped up (came back after a quiet spell and got further than before).")


def score_and_tags(sess, lo, lf, cmds, files, tcpip, expl, csvcs, tarpit_s, protos, took=False, read=False, sshole=False, web="", ids=False,
                   back=None, tor=False, dronebl=False, spamhaus=False):
    # back: return_info() of the IP, or None.
    stepped = bool(back and back[3] > back[2] and back[3] >= 3)
    s = sum(v for _k, v in score_parts(sess, lo, lf, cmds, files, tcpip, expl, csvcs, took, read, sshole, web, ids, stepped))
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
    if ids:
        tags.append("ids-alert")
    if len(set(protos) | set(csvcs)) >= 2:
        tags.append("multi-service")
    if tarpit_s >= 60:
        tags.append("tarpitted")
    if back:
        tags.append("returned")
    if stepped:
        tags.append("stepped-up")
    if tor:
        tags.append("tor")
    if dronebl:
        tags.append("dronebl")                 # a label only: it never adds to the score
    if spamhaus:
        tags.append("spamhaus")                # likewise
    return s, ",".join(tags)


# How far an attacker got, from the sums of its sessions (logins_ok, cmds, tcpip, files, sessions). No sessions at all = 0.
WORK_LEVELS = ("only decoys", "connected", "logged in", "ran commands", "left files or used it as a proxy")


def work_level(r):
    lo, cmds, tcpip, files, n = r
    return 4 if files or tcpip else 3 if cmds else 2 if lo else 1 if n else 0


def return_days(con):
    return return_days_saved(settings(con))


def recheck_returned(con):
    # "returned" and "stepped-up" for every stored attacker that can have come back, with the quiet days set now. Runs once
    # after an upgrade and whenever the setting changes (about half a second on two weeks of real data).
    n = return_days(con)
    with con:
        for (ip,) in con.execute("SELECT ip FROM ips WHERE last - first > ? OR (',' || tags || ',') LIKE '%,returned,%'", (n * 86400,)).fetchall():
            recompute_ip(con, ip)
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('returned_days',?)", (str(n),))


def return_info(con, ip, n=None):
    # The latest time this IP came back after n (the setting) or more quiet UTC days, as (quiet days, start of the day it came
    # back, level before, level after), or None. Any activity counts as being there: a session, a decoy service or the tarpit.
    n = return_days(con) if n is None else n
    # Every UTC day with any stored event (commands, logins, decoys, tarpit ...), plus every day a session was open.
    days = {d for (d,) in con.execute("SELECT DISTINCT CAST(ts/86400 AS INTEGER) FROM events WHERE ip=?", (ip,)) if d is not None}
    for a, b in con.execute("SELECT CAST(start/86400 AS INTEGER), CAST(COALESCE(end, start)/86400 AS INTEGER) FROM sessions "
                            "WHERE ip=? AND start IS NOT NULL", (ip,)):
        if a is not None:
            days.update(range(a, max(a, min(b if b is not None else a, a + 366)) + 1))
    # A tarpit catch is logged when it ends, with how long it lasted: the days in between count as being there (Codex 049 M7).
    for ts, secs in con.execute("SELECT ts, a FROM events WHERE ip=? AND kind='tarpit'", (ip,)):
        try:
            end, dur = float(ts), min(max(float(secs or 0), 0.0), 366 * 86400.0)
        except (TypeError, ValueError):
            continue
        days.update(range(int((end - dur) // 86400), int(end // 86400) + 1))
    days = sorted(days)
    back = None
    for a, b in zip(days, days[1:]):
        if b - a - 1 >= n:
            back = (b - a - 1, b * 86400.0)
    if not back:
        return None
    # Files = files really captured. The sessions' file count also holds failed downloads (file_fail), which are only
    # an attempt and must not lift the level to "left files" (Codex 049 M21).
    q = ("SELECT COALESCE(SUM(logins_ok),0), COALESCE(SUM(cmds),0), COALESCE(SUM(tcpip),0), "
         "(SELECT COUNT(*) FROM events WHERE ip=?1 AND kind='file' AND ts %s ?2), COUNT(*) "
         "FROM sessions WHERE ip=?1 AND start %s ?2")
    return (back[0], back[1], work_level(con.execute(q % ("<", "<"), (ip, back[1])).fetchone()),
            work_level(con.execute(q % (">=", ">="), (ip, back[1])).fetchone()))


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
    # Suricata (optional): a rule of severity 1 on traffic from this address. ET Open gives 1 to attacks (exploits, privilege
    # gain, trojans, web application attacks); 2 is mostly scanning and recon, which nearly every attacker does.
    ids = con.execute("SELECT 1 FROM ids WHERE ip=? AND sev=1 LIMIT 1", (ip,)).fetchone() is not None
    rd = return_days(con)
    tor = tor_tagging(con) and tor_is(con, ip, max(lasts))
    # A Tor exit is shared by many users: a later visit is most likely someone else, so it never counts as coming back.
    back = return_info(con, ip, rd) if max(lasts) - min(firsts) > rd * 86400 and not tor else None
    dbl = con.execute("SELECT codes FROM dronebl WHERE ip=?", (ip,)).fetchone()
    dbl = bool(dbl and dbl[0] not in (None, "", "[]"))
    shr = con.execute("SELECT codes FROM spamhaus WHERE ip=?", (ip,)).fetchone()
    try:
        shl = bool(shr and any(c not in SH_BAD for c in json.loads(shr[0] or "[]")))
    except ValueError:
        shl = False
    score, tags = score_and_tags(s["n"], s["lo"], s["lf"], s["c"], s["fi"], s["t"], s["x"], csvcs, t["secs"], protos, took, read, sshole, web, ids, back, tor, dbl, shl)
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
    if rows and RETENTION_DAYS > 0:
        # Older than the history limit: retention would delete it again, and storing it would count it as new (Codex 049 M3).
        # The export can still send such lines after a restart, when the in-memory skip set starts empty.
        cutoff = time.time() - RETENTION_DAYS * 86400
        rows = [r for r in rows if r[1] >= cutoff]
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
        if inserted:
            count_events(con, top)
        for fn, keys in ((recompute_session, sess), (recompute_ip, ips)):
            for k in keys:
                try:
                    fn(con, k)
                except (ValueError, TypeError, OverflowError, sqlite3.Error) as e:
                    log("error", "recompute", repr(e), key=k)
    try:
        note_seen(con, None)
    except Exception as e:                 # never let the "New" page get in the way of collecting data
        if con.in_transaction:
            con.rollback()
        set_meta(con, "last_seen_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
    return inserted


METRIC_SVC_RE = re.compile(r"[a-z0-9_-]{1,20}")


def metric_svc(src, a):
    # The decoy service of an OpenCanary or trap row (vnc, http, smtp...); nothing for Cowrie. Odd values become "other".
    if src not in ("canary", "traps"):
        return ""
    return a if isinstance(a, str) and METRIC_SVC_RE.fullmatch(a) else "other"


def count_events(con, top):
    # Running totals per source, kind and decoy service for /metrics, kept in meta so a restart does not reset them.
    # Called inside store()'s transaction, so it writes with execute and never commits on its own.
    try:
        tot = json.loads(get_meta(con, "metric_totals", "{}") or "{}")
        tot = tot if isinstance(tot, dict) else {}
    except ValueError:
        tot = {}
    for src, kind, a, n in con.execute("SELECT src, kind, CASE WHEN src IN ('canary','traps') THEN a END, COUNT(*) FROM events "
                                       "WHERE rowid>? GROUP BY 1, 2, 3", (top,)):
        k = "%s|%s|%s" % (src, kind, metric_svc(src, a))
        if len(tot) < 500 or k in tot:            # a hard limit on series, whatever a broken export sends
            tot[k] = int(tot.get(k, 0)) + n
    con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('metric_totals',?)", (json.dumps(tot),))


def utc_day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


CAP_CLASSIFY_SECS = 5.0          # web requests over the cap are checked for attacks for at most this long per sync


def decoy_keep(svc, b, memo):
    # Rows kept even over the cap: logins, bait values, and web requests that are attacks, probes, the robots trap or bait
    # replies. Floods repeat the same request, so each distinct request is classified once (memo), within a time budget.
    b = b or ""
    if BAIT and any(x in b for x in BAIT):
        return True
    if canary_is_login(svc, b):
        # A login over the cap is kept when its password has a shape Huginn has not seen yet (what New would show);
        # the same brute-force list over and over is counted, not stored.
        shape = "pw:" + pw_shape(b.rsplit(" / ", 1)[-1])
        if shape not in memo:
            memo[shape] = memo.get("_con") is not None and memo["_con"].execute(
                "SELECT 1 FROM seen WHERE kind='pw' AND key=?", (shape[3:],)).fetchone() is None
            new = memo[shape]
            memo[shape] = False                    # once per sync
            return new
        return False
    if svc not in ("http", "https"):
        return False
    if b not in memo:
        if time.time() > memo.setdefault("_until", time.time() + CAP_CLASSIFY_SECS):
            return False
        try:
            c = web_classify(b)
            memo[b] = c[0] in ("exploit", "probe") or bool(c[5]) or c[6] in WEB_BAIT_REPLIES
        except Exception:
            memo[b] = False
    return memo[b]


CAPPED_SEEN_DAYS = 15


def cap_rows(con, rows):
    # Decoy events beyond DECOY_CAP per IP, service and day are counted in `capped`, not stored, unless they hold something
    # that matters (decoy_keep). The export sends the newest lines again on every sync, so a row is known by its hash:
    # stored ones are in events, counted ones in capped_seen (kept CAPPED_SEEN_DAYS). `upto` = newest activity, also when dropped.
    if DECOY_CAP <= 0:
        return rows
    out, state, dirty, memo, dropped = [], {}, set(), {"_con": con}, []
    since = float(get_meta(con, "capped_seen_since", "0") or 0)
    batch = set()
    for r in rows:
        if r[4] != "canary":
            out.append(r)
            continue
        if r[0] in batch:                        # the same line twice in one export counts once (Codex 049 M2)
            continue
        batch.add(r[0])
        if con.execute("SELECT 1 FROM events WHERE h=?", (r[0],)).fetchone() or \
                con.execute("SELECT 1 FROM capped_seen WHERE h=?", (r[0],)).fetchone():
            continue
        key = (r[2], r[6] or "", utc_day(r[1]))
        st = state.get(key)
        if st is None:
            got = con.execute("SELECT kept, dropped, upto, src FROM capped WHERE ip=? AND svc=? AND day=?", key).fetchone()
            # [kept, dropped, newest, source, old cap's upto]: rows written before 0.36 have no source and only remember a time.
            st = state[key] = ([got[0], got[1], got[2] or 0.0, r[3], (got[2] or 0.0) if got[3] is None else 0.0]
                               if got else [0, 0, 0.0, r[3], 0.0])
        if r[1] < since and r[1] <= st[4]:          # handled by the cap before 0.36 (it remembered times, not rows)
            continue
        st[2] = max(st[2], r[1])
        if st[0] < DECOY_CAP or decoy_keep(r[6] or "", r[7], memo):
            st[0] += 1
            out.append(r)
        else:
            st[1] += 1
            dropped.append((r[0], r[1]))
        dirty.add(key)
    con.executemany("INSERT OR REPLACE INTO capped(ip, svc, day, kept, dropped, upto, src) VALUES(?,?,?,?,?,?,?)",
                    [key + tuple(state[key][:4]) for key in dirty])
    con.executemany("INSERT OR IGNORE INTO capped_seen(h, ts) VALUES(?,?)", dropped)
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
                memo = {"_con": con}
                extra = con.execute("SELECT e.rowid, e.b, w.h IS NOT NULL FROM events e LEFT JOIN webhits w ON w.h=e.h AND "
                                    "(w.level IN ('exploit','probe') OR w.robots=1 OR w.reply IN (%s)) "
                                    "WHERE e.ip=? AND e.kind='canary' AND COALESCE(e.a,'')=? AND e.ts>=? AND e.ts<? ORDER BY e.ts LIMIT -1 OFFSET ?"
                                    % ",".join("'%s'" % x for x in sorted(WEB_BAIT_REPLIES)),
                                    (ip, svc, d * 86400, (d + 1) * 86400, DECOY_CAP)).fetchall()
                # Rows already classified as something that matters, or that would be now, are never deleted.
                gone = [(rid,) for rid, b, known in extra if not known and not decoy_keep(svc, b, memo)]
                con.executemany("DELETE FROM events WHERE rowid=?", gone)
                touched.add(ip)
                con.execute("INSERT OR REPLACE INTO capped(ip, svc, day, kept, dropped, upto) VALUES(?,?,?,?,?,?)",
                            (ip, svc, utc_day(d * 86400), DECOY_CAP + len(extra) - len(gone), len(gone), u))
                continue
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
        # As long as the export can send a line again (OpenCanary keeps 14 daily logs), or a counted row is counted twice.
        con.execute("DELETE FROM capped_seen WHERE ts < ?", (time.time() - CAPPED_SEEN_DAYS * 86400,))
        con.execute("DELETE FROM ids_seen WHERE ts < ?", (time.time() - IDS_MAX_AGE - 86400,))
    if RETENTION_DAYS == 0:          # keep the whole history
        con.execute("PRAGMA optimize")
        return
    cutoff_day = utc_day(time.time() - RETENTION_DAYS * 86400)
    with con:                         # counted-only decoy hits follow the same history limit as stored ones
        gone_ips = [r[0] for r in con.execute("SELECT DISTINCT ip FROM capped WHERE day < ? AND dropped > 0", (cutoff_day,))]
        con.execute("DELETE FROM capped WHERE day < ?", (cutoff_day,))
        gone_ips += [r[0] for r in con.execute("SELECT DISTINCT ip FROM ids WHERE day < ?", (cutoff_day,))]
        con.execute("DELETE FROM ids WHERE day < ?", (cutoff_day,))
        for ip in set(gone_ips):
            recompute_ip(con, ip)
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
        # Lookups of attackers that are gone (Codex 047): their netblock and owner rows would still be counted.
        con.execute("DELETE FROM netblock WHERE ip NOT IN (SELECT ip FROM ips)")
        con.execute("DELETE FROM dronebl WHERE ip NOT IN (SELECT ip FROM ips)")
        con.execute("DELETE FROM spamhaus WHERE ip NOT IN (SELECT ip FROM ips)")
        con.execute("DELETE FROM abusecontact WHERE ip NOT IN (SELECT ip FROM ips)")
        con.execute("DELETE FROM asname WHERE asn NOT IN (SELECT asn FROM netblock WHERE asn IS NOT NULL)")
        # Codex rc2 H3: the rest of what names a removed attacker. Location, GreyNoise and http:BL answers go; first
        # sightings stay as "this was new once", without the address, session or example that came from it.
        for t in ("enrich", "greynoise", "httpbl"):
            con.execute("DELETE FROM %s WHERE ip NOT IN (SELECT ip FROM ips)" % t)
        con.execute("UPDATE seen SET ip=NULL, session=NULL, ex=NULL WHERE ip IS NOT NULL AND ip NOT IN (SELECT ip FROM ips)")
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('events_gen',?)", (str(time.time()),))   # caches start over
    tty_prune(con)
    con.execute("PRAGMA optimize")


def tty_prune(con):
    # Recordings of sessions that retention removed. Only files Huginn names itself (<sha256>.gz or a plain <sha256>).
    keep = {r[0] for r in con.execute("SELECT DISTINCT tty FROM sessions WHERE tty IS NOT NULL")}
    try:
        names = os.listdir(TTY_DIR)
    except OSError:
        return 0
    gone = 0
    for n in names:
        sha = n[:-3] if n.endswith(".gz") else n
        if re.fullmatch(r"[0-9a-f]{64}", sha) and sha not in keep:
            try:
                os.remove(os.path.join(TTY_DIR, n))
                gone += 1
            except OSError:
                pass
    return gone


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


@functools.lru_cache(maxsize=8192)       # bounded: commands can be long
def cmd_shape(s):
    # Same command with other addresses, numbers or payloads = same shape. Order matters: numbers go last.
    # Cached: the same command text comes back from many attackers (Search grouped 6,700 rows into far fewer texts).
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
HEALTH_FORGET = 30 * 86400          # a source silent this long is taken off the list (it is gone, not just quiet)


def health_sources(con, now=None):
    # {key: newest time}: OpenCanary, hp-traps and endlessh from events, Cowrie per listening port from sessions (last 2 days).
    # A source that went silent stays in the list for 30 days, so it keeps alerting instead of being forgotten after two.
    now = now or time.time()
    since = now - HEALTH_FORGET
    out = {}
    for src, last in con.execute("SELECT src, MAX(ts) FROM events WHERE ts>=? AND src IN ('canary','traps','endlessh') GROUP BY src", (since,)):
        out[src] = last
    for src, last in con.execute("SELECT COALESCE(src,'canary'), MAX(upto) FROM capped WHERE upto>=? GROUP BY 1", (since,)):
        if src in ("canary", "traps") and last:                 # hits over the decoy cap are activity too
            out[src] = max(out.get(src, 0), last)
    for port, last in con.execute("SELECT port, MAX(start) FROM sessions WHERE start>=? AND port IS NOT NULL GROUP BY port", (since,)):
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
        cached = {}
    old = cached.get("lim") if isinstance(cached, dict) and isinstance(cached.get("lim"), dict) else {}
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
    for k, v in old.items():                     # a source with too little history this week keeps last known limit
        if k not in lim and isinstance(v, (int, float)):
            lim[k] = v
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
    for k in new:
        log("warning", "collection_problem", issues[k], check=k)
    for k in back:
        log("info", "collection_back", health_label(k), check=k)
    set_meta(con, "health_now", json.dumps(issues))      # /healthz and Account first, whatever happens to the alert
    sent = {k: v for k, v in alerted.items() if k in issues}
    if NTFY_URL and settings(con)["notify"]:
        # Only a problem whose alert went out is marked as alerted, so a failed send is tried again next time.
        try:
            if new:
                ntfy_post("\n".join(issues[k] for k in new), "Huginn: collection problem", 4)
            sent.update((k, now) for k in new)
            if back:
                ntfy_post("Back to normal: " + ", ".join(health_label(k) for k in back), "Huginn: collection is back", 2)
        except Exception as e:
            log("warning", "ntfy_failed", "Could not send the collection alert: %s" % str(e)[:200])
            sent.update((k, alerted[k]) for k in back if k in alerted)   # say "back" again next time
    else:
        sent.update((k, now) for k in new)
    set_meta(con, "health_alerted", json.dumps(sent))
    return issues


def protection_status(con):
    # (items, time) from the last export that had a ##STATUS section, or (None, 0) from an older honeypot.
    try:
        st = json.loads(get_meta(con, "hp_status", "{}"))
        items = st.get("items")
        return (items if isinstance(items, dict) else None), float(st.get("at") or 0)
    except (ValueError, TypeError, AttributeError):
        return None, 0


def log_path(path):
    # A path for the error log without anything secret: feed tokens live in the path or the query (Codex 049 L7).
    p = (path or "").split("?", 1)[0]
    p = re.sub(r"^/feed/[^/]+", "/feed/<token>", p)
    return p[:300]


def cl_html(text):
    # A changelog entry: a headline, then "- " lines as a list. Older entries are one paragraph and stay as they were.
    head, *rest = text.split("\n")
    items = [x[2:] for x in rest if x.startswith("- ")]
    if not items:
        return "<span>%s</span>" % esc(text)
    return '<span><b class="cl-h">%s</b><ul class="cl-l">%s</ul></span>' % (esc(head), "".join("<li>%s</li>" % esc(x) for x in items))


def protection_missing(con):
    items, at = protection_status(con)
    if items is None or time.time() - at > 3600:      # nothing reported recently: the sync check covers that
        return []
    miss = sorted(k for k, ok in items.items() if not ok and not k.startswith("option:"))
    # A fresh report without a single sandbox or limits check proves nothing: say so instead of "all in place" (Codex rc3).
    return miss + ["nocheck:%s" % w for w in ("sandbox", "limits") if not any(k.startswith(w + ":") for k in items)]


def protection_label(key):
    what, _, name = key.partition(":")
    return {"sandbox": "%s sandbox", "limits": "%s memory/file limits", "running": "%s not running", "patch": "%s patch", "nocheck": "no %s checks reported"}.get(what, "%s") % name


def protection_note(con):
    items, at = protection_status(con)
    if items is None:
        return "not reported (update the honeypot: update-honeypot.sh)"
    missing = protection_missing(con)
    kinds = lambda w: sum(1 for k in items if k.startswith(w + ":"))
    ok = "sandbox and limits on %d services, %d patches" % (kinds("sandbox"), kinds("patch"))
    # 0.40: the logout note is a choice, shown here but never a problem.
    bye = ("" if "option:goodbye" not in items else
           " · logout note %s" % ("on" if items["option:goodbye"] else "off (update-honeypot.sh --goodbye-on)"))
    if missing:
        return '<span class="err">missing: %s</span> · reported %s%s' % (esc(", ".join(protection_label(k) for k in missing)), esc(ago(at)), esc(bye))
    # An old report says nothing about now: show what it said, never "all in place" (Codex 049 L8).
    if time.time() - at > 3600:
        old = sorted(k for k, ok in items.items() if not ok and not k.startswith("option:"))
        return '<span class="err">no recent report</span> (last %s%s)%s' % (
            esc(ago(at)), (": missing " + esc(", ".join(protection_label(k) for k in old))) if old else "", esc(bye))
    return "all in place: %s · reported %s%s" % (esc(ok), esc(ago(at)), esc(bye))


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
            store_ids(con, parse_export.ids)
            classify_web(con)
            note_sync(con, t0)
            skip = hashes  # only set once everything is stored
            set_meta(con, "last_ingest", t0)
            set_meta(con, "last_ingest_new", n)
            set_meta(con, "last_ingest_secs", round(time.time() - t0, 1))
            set_meta(con, "last_error", "")
            log("info", "sync", new=n, rows=len(rows), files=len(parse_export.files), secs=round(time.time() - t0, 1))
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
    # "1.0.0-rc1" sorts before "1.0.0" and after every 0.x; anything else unreadable sorts first.
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?", str(v).strip())
    if not m:
        return (0,)
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 10 ** 6)


def check_update(con):
    if not UPDATE_CHECK or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", REPO):
        return
    if time.time() - float(get_meta(con, "update_checked", "0") or 0) < 86400:
        return
    set_meta(con, "update_checked", time.time())
    try:
        req = urllib.request.Request("https://api.github.com/repos/%s/tags?per_page=50" % REPO,
                                     headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
        tags = json.loads(api_urlopen(req, timeout=15).read(500000))
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


def returned_news(con, since, save=True):
    # Attackers that came back and got further than before, not told yet: [(ip, level after)]. One alert per IP and return.
    try:
        told = json.loads(get_meta(con, "ntfy_returned", "{}") or "{}")
    except ValueError:
        told = {}
    out = []
    # Every stepped-up address active since then is checked (they are few); only the announcement is capped.
    for (ip,) in con.execute("SELECT ip FROM ips WHERE last>? AND (',' || tags || ',') LIKE '%,stepped-up,%' ORDER BY score DESC", (since,)):
        if len(out) >= 50:
            break
        back = return_info(con, ip)
        if back and back[3] > back[2] and told.get(ip) != back[1]:
            told[ip] = back[1]
            out.append((ip, back[3]))
    if out and save:
        save_told(con, told)
    returned_news.told = told
    return out


def save_told(con, told):
    keep = sorted(told.items(), key=lambda kv: kv[1])[-2000:]       # bounded: the oldest returns are forgotten first
    set_meta(con, "ntfy_returned", json.dumps(dict(keep)))


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
    if now - last < NOTIFY_EVERY or float(get_meta(con, "ntfy_retry_at", "0") or 0) > now:
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
    if "returned" in ev:
        stepped = returned_news(con, last, save=False)       # remembered only once the alert is out
        if stepped:
            prio = 4
            lines.append("Came back and got further: " + ", ".join("%s (%s)" % (ip, WORK_LEVELS[lv]) for ip, lv in stepped[:5])
                         + (" +%d" % (len(stepped) - 5) if len(stepped) > 5 else ""))
    if not lines:
        set_meta(con, "ntfy_last", now)
        return
    # The period counts as told only when ntfy took the message. A failure keeps it, and the next try comes after 10 minutes
    # with the same period (plus whatever happened since), so a short ntfy outage loses nothing (Codex 049 M18).
    try:
        ntfy_post("\n".join(lines), "Huginn: honeypot activity", prio)
    except Exception as e:
        set_meta(con, "ntfy_retry_at", now + 600)
        set_meta(con, "ntfy_error", "%s %s" % (fmt_ts(now), str(e)[:120]))
        return
    set_meta(con, "ntfy_last", now)
    set_meta(con, "ntfy_error", "")
    if "returned" in ev and stepped:
        save_told(con, returned_news.told)
    set_meta(con, "last_notify", "%s: %s" % (fmt_ts(now), " | ".join(lines))[:500])


_rdns_pool = ThreadPoolExecutor(max_workers=2)


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with api_urlopen(req, timeout=10) as r:
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


class GeoBusy(Exception):
    """ipwho.is answered 429: over the free allowance for now."""


GEO_PAUSE = 3600


def enrich_ip(ip):
    d = {"cc": None, "country": None, "city": None, "asn": None, "org": None, "isp": None, "rdns": None,
         "ports": None, "tags": None, "vulns": None, "hostnames": None, "rdns_ok": None}
    ok = 0                          # 1 only when the location lookup worked: Shodan alone leaves the country empty
    try:
        j = http_json("https://ipwho.is/%s?fields=success,country,country_code,city,connection" % urllib.parse.quote(ip))
        if j.get("success"):
            conn = j.get("connection") or {}
            cc = str(j.get("country_code") or "").upper()
            asn = str(conn.get("asn") or "")
            d.update(cc=cc if re.fullmatch(r"[A-Z]{2}", cc) else None, country=ext_text(j.get("country"), 60), city=ext_text(j.get("city"), 60),
                     asn=asn if re.fullmatch(r"\d{1,10}", asn) else None, org=ext_text(conn.get("org")), isp=ext_text(conn.get("isp")))
            ok = 1
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise GeoBusy()         # over ipwho.is' free allowance: the caller pauses instead of asking again and again
    except Exception:
        pass
    try:
        j = http_json("https://internetdb.shodan.io/" + urllib.parse.quote(ip))
        lst = lambda k, n, rx: [x for x in (str(v) for v in (j.get(k) or [])[:n]) if re.fullmatch(rx, x)]
        d.update(ports=",".join(lst("ports", 40, r"\d{1,5}")) or None,
                 tags=",".join(lst("tags", 20, r"[A-Za-z0-9_.-]{1,40}")) or None,
                 vulns=",".join(lst("vulns", 40, r"(CVE|cve)-\d{4}-\d{3,7}")) or None,
                 hostnames=",".join(lst("hostnames", 10, r"[A-Za-z0-9_.-]{1,253}")) or None)
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
        log("error", "backup_failed", msg)
        try:
            if NTFY_URL and settings(con)["notify"]:
                ntfy_post("Database backup failed: %s" % str(e)[:200], "Huginn: backup failed", 4)
        except Exception as e2:
            log("warning", "ntfy_failed", repr(e2))
        return False


def backup_loop():
    time.sleep(300)
    con = connect()
    while True:
        try:
            if backup_due(con, time.time()):
                backup_once(con)
        except Exception as e:
            log("error", "backup_loop", repr(e))
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
                "OR (e.cc IS NULL AND e.fetched < ?) "      # no country yet (ipwho.is was busy): try again after a day
                "ORDER BY (e.ip IS NULL) DESC, i.last DESC LIMIT 25", (now - ENRICH_TTL, now - 86400))]
            if float(get_meta(con, "geo_wait_until", "0") or 0) > now:
                todo = []                                   # ipwho.is said "too many": wait, the other lookups go on
            for ip in todo:
                if not ipaddress.ip_address(ip).is_global:  # test mode (HUGINN_ALLOW_PRIVATE): never send LAN addresses out
                    with con:
                        con.execute("INSERT OR REPLACE INTO enrich(ip,fetched,ok) VALUES(?,?,1)", (ip, time.time()))
                    continue
                try:
                    d, ok, research = enrich_ip(ip)
                except GeoBusy:
                    set_meta(con, "geo_wait_until", str(time.time() + GEO_PAUSE))
                    set_meta(con, "last_enrich_error", "%s ipwho.is: over the free allowance (429), paused for an hour" % fmt_ts(time.time()))
                    break                                   # nothing stored: these addresses are asked again later
                if not ok:
                    # No location this time: keep what an earlier lookup found, and ask again in a day.
                    old = con.execute("SELECT cc, country, city, asn, org, isp FROM enrich WHERE ip=?", (ip,)).fetchone()
                    if old:
                        for k, v in zip(("cc", "country", "city", "asn", "org", "isp"), old):
                            if d[k] is None:
                                d[k] = v
                research = research_now(con, ip, research)       # keep a benign GreyNoise answer
                fetched = time.time() if ok else time.time() - ENRICH_TTL + 86400  # failed: retry in a day
                with con:
                    con.execute("INSERT OR REPLACE INTO enrich VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (ip, fetched, ok, d["cc"], d["country"], d["city"], d["asn"], d["org"], d["isp"],
                                 d["rdns"], d["ports"], d["tags"], d["vulns"], d["hostnames"], research, d.get("rdns_ok")))
                time.sleep(2)
        except Exception as e:
            set_meta(con, "last_enrich_error", "%s %s" % (fmt_ts(time.time()), str(e)[:200]))
        for f in (tor_refresh, vt_lookup, gn_lookup, hb_lookup, nb_lookup, dbl_lookup, sh_lookup, ab_lookup):        # each keeps to its own daily allowance and pauses itself on errors
            try:
                f(con)
            except Exception as e:
                set_meta(con, "last_enrich_error", "%s %s: %s" % (fmt_ts(time.time()), f.__name__, str(e)[:200]))
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
             "sshole-probe": "t-red", "web-exploit": "t-red", "web-probe": "t-yellow", "robots-trap": "t-orange", "ids-alert": "t-red", "returned": "t-blue", "stepped-up": "t-red", "tor": "t-purple", "dronebl": "t-purple", "spamhaus": "t-purple", "server": "t-blue", "camera": "t-teal", "nas": "t-purple", "router": "t-teal"}


# What each attacker tag means: the tooltip on every tag and the Help page read this one table.
# tests/test_v035.py checks that every tag Huginn can set is explained here.
TAG_HELP = {
    "shell": "Ran at least one command in the fake shell.",
    "dropper": "Downloaded or uploaded a file to the honeypot.",
    "proxy": "Tried to use the honeypot as a proxy (SSH port forwarding) to reach other sites.",
    "exploit": "Sent a known exploit to the Telnet honeypot (Cowrie recognised it by its CVE).",
    "bruteforce": "10 or more login attempts in total.",
    "multi-service": "Used two or more services: SSH, Telnet, the tarpit, or a decoy such as FTP, MySQL, Redis, VNC, mail or web.",
    "tarpitted": "Spent at least a minute stuck in the SSH tarpit.",
    "research": "A known research or internet-measurement scanner, by its name or network, or called benign by GreyNoise. "
                "Left off the blocklist unless it logged in or ran something.",
    "took-bait": "Used a fake credential planted on the honeypot somewhere else: in a login, a command or a decoy service.",
    "read-bait": "Read a bait file (.env, cloud keys, backup scripts and the like), or was handed fake secrets by the web trap.",
    "human-like": "A session with 3 or more commands and a median pause of over 2 seconds between them: probably typed by a person, not pasted by a script.",
    "sshole-probe": "An SSH login with a 257 to 1024 byte password: testing for the SSHole bug in sshd.",
    "web-exploit": "A web request that matched an exploit rule, often for a known CVE.",
    "web-probe": "A web request looking for something specific, such as admin pages or config files, but no exploit.",
    "robots-trap": "Visited a path that only the web trap's robots.txt mentions: a crawler that reads robots.txt to find hidden places.",
    "ids-alert": "Suricata on the honeypot matched a rule of severity 1 on traffic from this address: an attack such as an exploit, not just a scan.",
    "returned": "Came back after a quiet spell with nothing at all from this address (7 days unless changed under Settings).",
    "stepped-up": "Came back after a quiet spell and got further than ever before, for example only knocked first and then ran "
                  "commands, left files or used the honeypot as a proxy.",
    "tor": "The address was a Tor exit node when it attacked (Tor Project's list): someone using Tor, not the owner of the address. "
           "Never counted as coming back, and left out of the blocklist unless chosen on Settings.",
    "dronebl": "DroneBL lists the address as a drone, botnet member, open proxy, brute forcer or compromised router. "
               "The attacker page says which. A label only: it does not change the score.",
    "spamhaus": "Spamhaus lists the address as a spam source, exploited or infected machine (XBL) or hijacked network (DROP). "
                "A listing as an end-user range (PBL) alone does not give this tag. A label only: it does not change the score.",
    "block": "You flagged this attacker: always on the blocklist.",
    "allow": "You flagged this attacker: never on the blocklist.",
}


def tag_title(t):
    if t in TAG_HELP:
        return TAG_HELP[t]
    if t in set(PERSONA.values()):
        return "Persona: the session hit the fake %s." % t
    return ""


def tag_html(tags):
    out = []
    for t in [x for x in (tags or "").split(",") if x]:
        tip = tag_title(t)
        out.append('<span class="tag %s"%s>%s</span>' % (TAG_CLASS.get(t, ""), (' title="%s"' % esc(tip)) if tip else "", esc(t)))
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


HOT_TAGS = {"took-bait", "read-bait", "dropper", "exploit", "sshole-probe", "stepped-up"}     # rare finds: these get the warm colour


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


def script_cell(key, cmds, link=True, diff=None, full=None):
    # What a script does comes first. The hash is only its id, and two scripts can start with the same command.
    # diff (0.39): ("at", n, command) = first command where this script parts from rows that start the same,
    # ("ends", n, None) = same start but shorter. full = every command, for the preview under the row.
    label = " ; ".join(clean(c, 90) for c in cmds) or key[:16]
    href = link and re.fullmatch(r"[0-9a-f]{8,64}", key or "")
    head = ('<a class="scr mono" href="/campaign/script/%s" title="%s">%s</a>' % (esc(key), esc(label), esc(label)) if href
            else '<span class="scr mono" title="%s">%s</span>' % (esc(label), esc(label)))
    if diff and diff[0] == "at":
        txt = clean(diff[2], 160) or "(empty line)"
        head += '<div class="scr-diff mono" title="%s"><span class=muted>differs at command %d:</span> %s</div>' % (esc(txt), diff[1], esc(txt))
    elif diff:
        head += '<div class="scr-diff mono"><span class=muted>same start, ends after %d command%s</span></div>' % (diff[1], "" if diff[1] == 1 else "s")
    elif cmds:
        head += '<div class="hash mono muted">%s</div>' % esc(key[:16])
    if full:
        mark = diff[1] if diff and diff[0] == "at" else 0
        lines = "".join('<div class="pv-l%s"><span class=pv-n>%d</span>%s</div>' % (" pv-d" if i == mark else "", i, esc(clean(c, 200)) or '<span class=muted>(empty)</span>')
                        for i, c in enumerate(full[:PREVIEW_MAX], 1))
        more = ('<div class="pv-l muted">… %s%d more, open the campaign for all</div>' % ("at least " if len(full) >= DIFF_MAX else "", len(full) - PREVIEW_MAX)
                if len(full) > PREVIEW_MAX else "")
        count = ("%d+" % len(full)) if len(full) >= DIFF_MAX else str(len(full))
        head += '<details class="scr-pv"><summary>Preview · %s command%s</summary><div class="pv mono">%s%s</div></details>' % (count, "" if len(full) == 1 else "s", lines, more)
    return head


PREVIEW_MAX = 150
DIFF_MAX = 1000          # commands per script read for Campaigns (comparison and preview)


def script_diffs(lists, n=2):
    # Rows whose first n commands have the same shape (like the campaigns themselves): find, for each, the first command
    # where it parts from all the others. Shapes are worked out once; within a group the rows are sorted, so the longest
    # shared start with any other row is with a neighbour (no comparing every pair, 0.40 after review). A row that is a
    # strict start of a longer one "ends after" its last command; rows that read the same as another get nothing.
    shapes = [[cmd_shape(c) for c in cmds[:DIFF_MAX]] for cmds in lists]
    out = [None] * len(lists)
    groups = {}
    for i, sh in enumerate(shapes):
        if sh:
            groups.setdefault(tuple(sh[:n]), []).append(i)

    def common(a, b):
        k, m = 0, min(len(a), len(b))
        while k < m and a[k] == b[k]:
            k += 1
        return k
    for idx in groups.values():
        if len(idx) < 2:
            continue
        order = sorted(idx, key=lambda i: shapes[i])
        for pos, i in enumerate(order):
            mine = shapes[i]
            near = [order[q] for q in (pos - 1, pos + 1) if 0 <= q < len(order)]
            best = max(common(mine, shapes[j]) for j in near)
            if best < len(mine):
                out[i] = ("at", best + 1, lists[i][best])
            else:
                # A longer row that starts with all of mine sorts right after it (after any equal rows).
                for j in order[pos + 1:]:
                    if common(mine, shapes[j]) < len(mine):
                        break
                    if len(shapes[j]) > len(mine):
                        out[i] = ("ends", len(mine), None)
                        break
    return out


def ip_link(ip, anchor=""):
    return '<a class="mono" href="/ip/%s%s">%s</a>' % (esc(urllib.parse.quote(ip, safe=":")), esc(anchor), esc(ip))


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
                    "bl_min": 3, "bl_days": 30, "notify": True, "notify_events": ["bait", "files", "human", "exploit", "returned", "weekly"], "v": 4,
                    "clock": "24", "ips_cols": ["cc", "network", "first", "last", "sessions", "logins", "cmds", "files", "tags", "score"],
                    "hide_cc": [], "hide_asn": [], "overview": "cards",
                    "return_days": RETURN_DAYS}
# Optional columns of the Attackers list: key -> (header, sort key, css class)
IPS_COLS = [("cc", "CC", None, ""), ("network", "Network", None, ""), ("asn", "ASN", None, ""), ("netblock", "Netblock", None, ""), ("rdns", "Reverse DNS", None, ""),
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
                 ("human", "Human-like sessions"), ("exploit", "Exploit attempts"),
                 ("returned", "An attacker came back after a quiet spell and got further than before"), ("weekly", "Weekly summary (Sunday evening)")]
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
    if saved and saved.get("v", 1) < 4 and "returned" not in out["notify_events"]:
        out["notify_events"] = list(out["notify_events"]) + ["returned"]   # 0.45: the new alert, once
    out["v"] = 4
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
            "<a href='https://github.com/%s' target='_blank' rel='noopener noreferrer'>Source on GitHub</a> · "
            "<a href='%s' target='_blank' rel='noopener noreferrer'>Buy me a coffee</a></footer>" % (HUGINN_VERSION, esc(REPO), COFFEE_URL))


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
            "<a class='hdr-link' href='/help'>Help</a>"
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
    # 0.42: every tile is a link to the list behind its number.
    kpis = [("Attackers 24h", num(k["a"]), "%s new" % num(k["d"]), "", "/ips?days=1"),
            ("Sessions 24h", num(s24), "%s with shell commands" % num(sh24), "", "/ips?days=1&sort=sessions"),
            ("Took the bait 7d", num(bait7[0] or 0), ("%s read bait files" % num(bait7[1] or 0)) if BAIT else "no bait values known yet", " hot" if bait7[0] else "",
             "/ips?days=7&tag=took-bait"),
            ("Attackers 7d", num(w["active"]), " · ".join(x for x in ("%s total" % num(k["c"]), delta) if x), " kpi-x", "/ips?days=7"),
            ("Files captured", num(files), "%s new 7d · %s prior" % (num(files_new), num(files_prior)), " kpi-x hot" if files_new else " kpi-x", "/files"),
            ("Time wasted 7d", esc(dur(tw["total"])) if tw["total"] else "0", "%s tarpit · %s fake shells%s" % (dur(tw["tarpit"]), dur(tw["shell"]), " · %d stuck now" % tw["stuck"] if tw["stuck"] else ""), " kpi-x", "/receipt"),
            ("On blocklist", num(bl), "score ≥%s, %s days" % (st["bl_min"], st["bl_days"]), " kpi-x", "/blocklist")]
    kp = "".join('<a class="kpi%s" href="%s"><div class="kpi-l">%s</div><div class="kpi-v">%s</div><div class="kpi-s">%s</div></a>' % (d, esc(href), esc(a), b, esc(c))
                 for a, b, c, d, href in kpis)
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
    kp, w, tw = board_cached(con, st, ("kpis",), lambda: overview_kpis(con, st))

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
            ('<a class="replay-btn" href="/replay/%s?ip=%s">▶ Replay</a>' % (seg(s["tty"]), esc(urllib.parse.quote(s["ip"])))) if s["tty"] else "")
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
    ccrows = "".join("<tr><td>%s</td><td>%s</td><td class=num>%s</td></tr>"
                     % ((cc_html(None), '<span class=muted>Not known yet</span>', num(r["n"])) if r["cc"] == "??" else
                        (cc_html(r["cc"]), esc(r["country"] or ""), num(r["n"]))) for r in ccs)
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


BOARD_TTL = 300      # Board and the Overview numbers are reused for up to 5 minutes, not rebuilt after every 2-minute sync


def board_cached(con, st, key, fn):
    # Keyed on a 5-minute generation instead of every sync's time stamp: a sync every 2 minutes used to throw the heavy
    # aggregates away before anyone looked at them again (Codex 049 M13). A history cut (retention) starts a new one.
    gen = int(float(get_meta(con, "last_ingest", "0") or 0) // BOARD_TTL)
    full = (key, gen, get_meta(con, "events_gen", ""), tuple(st["hide_cc"]), tuple(st["hide_asn"]))
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
    if kind == "goodbye":
        return "logged out and got the goodbye note (%s)" % (a or "?")
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
    kp, _w, _tw = board_cached(con, st, ("kpis",), lambda: overview_kpis(con, st))
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
    rows = [("Attackers", '<a href="/ips?days=7">%s</a> <span class=muted>%s</span>' % (num(w["active"]), esc(trend(w["active"], w["before"])))),
            ("New attackers", ('<a href="/ips?days=7&amp;sort=first">%s</a>' % num(w["new_ips"])) if w["new_ips"] else "0"),
            ("New countries", " ".join('<a href="/ips?days=7&amp;cc=%s">%s</a>' % (esc(urllib.parse.quote(c)), cc_html(c)) for c in w["new_cc"][:12]) or "–"),
            ("New campaigns", ('<a href="/campaigns">%d</a> <span class=muted>(%d IPs)</span>' % (w["campaigns"], w["campaign_ips"])) if w["campaigns"] else "–"),
            ("New malware", " ".join(('<a href="/files?fam=%s">%s</a> ×%d' % (esc(urllib.parse.quote(k)), family_tag(k), v)) if k != "Unknown"
                                     else '<span class="tag">unknown</span> ×%d' % v
                                     for k, v in sorted(w["families"].items(), key=lambda x: -x[1])[:6]) or "–"),
            ("Took the bait", ('<a href="/ips?days=7&amp;tag=took-bait">%s</a>' % num(w["took"])) if w["took"] else "–")]
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
    # Stuck = an opening with no later close from the same address and port. Matched in time order, so a port that is
    # used again does not hide the new connection behind the old one's close (Codex 049 L2).
    since2 = time.time() - 2 * 86400
    ev = {}
    for ts, ip, port, kind in con.execute("SELECT ts, ip, a, 'o' FROM events WHERE kind='tarpit_open' AND ts>=? UNION ALL "
                                          "SELECT ts, ip, b, 'c' FROM events WHERE kind='tarpit' AND b IS NOT NULL AND ts>=? "
                                          "ORDER BY 1", (since2, since2)):
        ev.setdefault((ip, port), []).append(kind)
    stuck = 0
    for seq in ev.values():
        open_ = 0
        for k in seq:
            if k == "o":
                open_ += 1
            elif open_:
                open_ -= 1
        stuck += open_
    longest = max(rows, key=lambda r: r["longest"], default=None)    # over all rows, like the totals; the address may be hidden
    return {"tarpit": sum(r["tarpit"] for r in rows), "shell": sum(r["shell"] for r in rows),
            "total": sum(r["total"] for r in rows), "top": top, "stuck": stuck,
            "longest": longest, "longest_shown": bool(longest) and any(r is longest for r in visible)}


IPS_SIZES = (25, 50, 100)
IPS_PHONE_HIDE = {"network", "asn", "netblock", "rdns", "first", "sessions", "logins", "files", "tarpit", "tags"}     # what a phone leaves out
SORTS = {"score": "i.score DESC, i.last DESC", "last": "i.last DESC", "first": "i.first DESC",
         "sessions": "i.sessions DESC", "cmds": "i.cmds DESC", "logins": "(i.logins_ok+i.logins_fail) DESC"}


def v_ips(qs, mobile=False):
    con = db()
    q = (qs.get("q") or "").strip()[:100]
    days = qs.get("days") or str(settings()["ips_days"])
    tag = (qs.get("tag") or "").strip()[:30]
    ccf = (qs.get("cc") or "").strip().upper()
    ccf = ccf if re.fullmatch(r"[A-Z]{2}", ccf) else ""
    try:
        netf = str(ipaddress.ip_network((qs.get("net") or "").strip()[:50], strict=True)) if (qs.get("net") or "").strip() else ""
    except ValueError:
        netf = ""
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
        where.append("(i.ip LIKE ? OR e.org LIKE ? OR e.isp LIKE ? OR e.cc=? OR e.rdns LIKE ? OR e.asn=? OR n.prefix=?)")
        like = "%" + q + "%"
        args += [like, like, like, q.upper(), like, q.lstrip("ASas"), q]
    if ccf:
        where.append("e.cc=?")
        args.append(ccf)
    if netf:
        where.append("n.prefix=?")
        args.append(netf)
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
        allc = con.execute("SELECT COUNT(*) FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) LEFT JOIN netblock n USING(ip) " + w0, args).fetchone()[0]
        if not show_hidden:
            where.append(hs[5:])
            args += ha
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = con.execute("SELECT COUNT(*) FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) LEFT JOIN netblock n USING(ip) " + w, args).fetchone()[0]
    if hs:
        nhidden = allc - total if not show_hidden else 0
    pg = min(pg, max(0, (total - 1) // size))          # a page past the end (a stale link, or a number SQLite cannot take) shows the last one
    rows = con.execute("SELECT i.*, e.cc, e.org, e.rdns, e.asn, e.research, f.flag, n.prefix FROM ips i LEFT JOIN enrich e USING(ip) "
                       "LEFT JOIN flags f USING(ip) LEFT JOIN netblock n USING(ip) %s ORDER BY %s LIMIT ? OFFSET ?" % (w, SORTS[sort]), args + [size, pg * size]).fetchall()

    def link(**kw):
        p = {"q": q, "days": days, "tag": tag, "cc": ccf, "net": netf, "sort": sort, "hidden": "1" if show_hidden else "", "n": size if size != size_default else ""}
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
        "netblock": lambda r: ("<td class=mono><a href='%s'>%s</a></td>" % (esc(nb_url(r["prefix"])), esc(r["prefix"]))) if r["prefix"] else "<td>–</td>",
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
    form = ('<form class="filters" method=get action="/ips"><input name=q value="%s" placeholder="IP, network, country code, ASN, netblock">'
            '<select name=days>%s</select><select name=tag>%s</select><input type=hidden name=sort value="%s">%s%s<button>Filter</button></form>'
            % (esc(q), opts(days, [("1", "Last 24h"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days"), ("all", "All time")]),
               opts(tag, [("", "Any tag")] + [(t, t) for t in ["took-bait", "read-bait", "shell", "dropper", "proxy", "exploit", "sshole-probe", "web-exploit", "web-probe", "robots-trap", "ids-alert", "bruteforce", "multi-service", "tarpitted", "returned", "stepped-up", "tor", "dronebl", "spamhaus", "research", "block", "allow"]]), esc(sort),
               (('<input type=hidden name=cc value="%s"><span class="chip on">Country %s <a href="%s" title="Remove country filter">×</a></span>' % (esc(ccf), esc(ccf), esc(link(cc="", p=0)))) if ccf else "")
               + (('<input type=hidden name=net value="%s"><span class="chip on">Netblock %s <a href="%s" title="Remove netblock filter">×</a></span>' % (esc(netf), esc(netf), esc(link(net="", p=0)))) if netf else ""),
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


def seg(x):
    # One path segment of a link inside Huginn, from data that came from the honeypot: URL-encoded, then HTML-escaped.
    return esc(urllib.parse.quote(str(x or ""), safe=""))


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
            out.append('<a class="c-f" href="/campaign/file/%s" title="Captured file">%s</a>' % (seg(files[tok]), esc(tok)))
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
                               " ".join(k for k, t in (("exploit", "web-exploit"), ("probe", "web-probe"), ("robots", "robots-trap")) if t in have),
                               "ids-alert" in have, "stepped-up" in have), key=lambda p: -p[1])
    if sum(v for _k, v in parts) != r["score"]:         # scored by an older version: do not show numbers that do not add up
        return '<div class="sleg muted">Breakdown unavailable</div>'
    segs = "".join('<i class="g%d%s" title="%s: %d"></i>' % (min(v, 60), " hot" if k in ("took bait", "read bait", "SSHole probe", "files", "exploit", "stepped up") else "", esc(k), v) for k, v in parts)
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
    text = text[0].upper() + text[1:] + "."
    back = return_info(con, r["ip"]) if "returned" in tags else None
    if back:
        text += " Came back on %s after %s quiet days" % (time.strftime("%Y-%m-%d", time.gmtime(back[1])), num(back[0]))
        text += (": %s before, %s since." % (WORK_LEVELS[back[2]], WORK_LEVELS[back[3]]) if "stepped-up" in tags else ".")
    return text


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
    ("T1222.002", "Linux File Permissions Modification", r"\bchmod\s+(?:[ugoa]*\+x|(?=[0-7]{1,4}\b)[0-7]{0,3}[1357])"),   # bounded: no backtracking blow-up
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


ATTACK_BUDGET = 64 * 1024        # characters of commands looked at per call: a page with many huge commands stays cheap


def attack_ids(cmds, logins_fail=0, proxy=0, files=0):
    # Techniques in ATTACK order, plus what a session shows without commands (brute force, proxy, transferred files).
    found, seen, left = [], [], ATTACK_BUDGET
    for c in cmds:
        if left <= 0:
            break
        c = (c or "")[:min(left, 4096)]
        seen.append(c)
        left -= len(c)
    for t, _n, rx in ATTACK_RE:
        if any(rx.search(c) for c in seen):
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
    for sid, a, kind in con.execute("SELECT session, a, kind FROM events WHERE ip=? AND kind IN ('cmd','exec_sim') AND ts>=? ORDER BY ts DESC LIMIT 20000", (ip, since)):
        if kind == "cmd":
            cmds_by.setdefault(sid, []).append(a)
        else:
            runs.add(sid)
    for v in cmds_by.values():                       # fetched newest first so the latest survive the limit
        v.reverse()
    for s in con.execute("SELECT session, start, end, proto, logins_ok lo, logins_fail lf, cmds, files, tcpip FROM sessions "
                         "WHERE ip=? AND start>=? ORDER BY start DESC LIMIT 5000", (ip, since)):
        k = "shell" if (s["cmds"] or s["files"]) else ("login" if s["lo"] + s["lf"] else "connect")
        items.append([s["start"], s["end"] or s["start"], (k, (s["proto"] or "?").upper()),
                      {"n": 1, "lo": s["lo"], "lf": s["lf"], "cmds": s["cmds"], "files": s["files"], "proxy": s["tcpip"],
                       "run": s["session"] in runs, "c": cmds_by.get(s["session"], [])}])
    for ts, svc in con.execute("SELECT ts, a FROM events WHERE ip=? AND kind='canary' AND ts>=? ORDER BY ts DESC LIMIT 20000", (ip, since)):
        key = ("web", "Web") if svc in ("http", "https") else ("decoy", (svc or "?").upper())
        items.append([ts, ts, key, {"n": 1}])
    for ts, secs in con.execute("SELECT ts, a FROM events WHERE ip=? AND kind='tarpit' AND ts>=? ORDER BY ts DESC LIMIT 5000", (ip, since)):
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


IDS_SEV_WORDS = {1: "high", 2: "medium", 3: "low", 4: "info"}


def ids_sev(sev):
    return '<span class="sev s%d" title="Suricata severity %d">%s</span>' % (sev or 3, sev or 3, IDS_SEV_WORDS.get(sev, "?"))


def ids_link(sid, sig, sev):
    # The rule name, linking to the rule's own page under Campaigns. Severity 1 (attacks) red, like web exploits.
    cls = {1: "t-red", 2: "t-orange", 3: "t-yellow"}.get(sev, "t-grey")
    return '<a class="tag %s" href="/campaign/ids/%d" title="Suricata rule %d">%s</a>' % (cls, sid, sid, esc(clean(sig, 160)))


def ids_ports(ports):
    # "TCP/80", or just the protocol when there is no port (ICMP is stored with port 0)
    out = sorted({re.sub(r"/0$", "", p) for p in (ports or "").split(",") if re.fullmatch(r"[A-Z0-9-]{1,12}/\d{1,5}", p)})
    return ", ".join(out[:4]) + (" …" if len(out) > 4 else "")


def ids_cves(sig):
    return sorted(set(re.findall(r"CVE[-_](\d{4})[-_](\d{3,7})", sig or "")))


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
    nbr = nb_get(con, ip)
    now = time.time()
    tags = r["tags"] or ""
    if (e and e["research"]) or (not e and research_now(con, ip, base=0)):
        tags += ",research"
    if f:
        tags += "," + f["flag"]

    # Summary
    links = " · ".join(['<a href="/ip/%s/export.json">Export JSON</a>' % esc(urllib.parse.quote(ip, safe=":")),
                        '<a href="/ip/%s/export.csv" title="Only the raw events: lookups, IDS alerts and sessions are in the JSON export">Export events (CSV)</a>' % esc(urllib.parse.quote(ip, safe=":")),
                        ext("https://www.abuseipdb.com/check/" + ip, "AbuseIPDB"), ext("https://viz.greynoise.io/ip/" + ip, "GreyNoise"),
                        ext("https://www.shodan.io/host/" + ip, "Shodan"), ext("https://www.virustotal.com/gui/ip-address/" + ip, "VirusTotal"),
                        ext("https://ipinfo.io/" + ip, "ipinfo"), ext("https://www.projecthoneypot.org/ip_" + ip, "Project Honey Pot"),
                        ext("https://talosintelligence.com/reputation_center/lookup?search=" + urllib.parse.quote(ip), "Cisco Talos")])
    left = kv([("First seen", esc(fmt_tss(r["first"]))), ("Last seen", "%s <span class=muted>(%s)</span>" % (esc(fmt_tss(r["last"])), esc(ago(r["last"])))),
               ("Sessions", num(r["sessions"])), ("Logins", "%s ok · %s failed" % (num(r["logins_ok"]), num(r["logins_fail"]))),
               ("Commands", num(r["cmds"])), ("Files", num(r["files"])), ("Proxy attempts", num(r["tcpip"])), ("Exploits", num(r["exploits"])),
               ("Other services", esc(r["canary_svcs"] or "–") + (" (%s hits)" % num(r["canary"]) if r["canary"] else "")),
               ("Tarpit", esc(dur(r["tarpit_s"])) if r["tarpit_s"] else "–"), ("Protocols", esc(r["protos"] or "–"))])
    if e:
        right = kv([("Country", "%s %s" % (cc_html(e["cc"]), esc(", ".join(x for x in (e["city"], e["country"]) if x)))),
                    ("ASN", esc("AS" + e["asn"]) if e["asn"] else "–"), ("Org", esc(e["org"] or "–")), ("ISP", esc(e["isp"] or "–")),
                    ("Netblock", nb_html(con, nbr)), ("Block owner", nb_owner_html(nbr)),
                    ("Reverse DNS", '<span class=mono>%s</span>' % esc(e["rdns"] or "–")), ("Hostnames", esc(e["hostnames"] or "–")),
                    ("Open ports", esc(e["ports"] or "–")), ("Shodan tags", esc(e["tags"] or "–")),
                    ("Known CVEs", esc((e["vulns"] or "–")[:400])), ("GreyNoise", gn_html(gn_get(con, ip))),
                    ("Project Honey Pot", hb_html(hb_get(con, ip))), ("DroneBL", dbl_html(con, dbl_get(con, ip), ip)),
                    ("Spamhaus", sh_html(con, sh_get(con, ip), ip)), ("Abuse contact", ab_html(con, ip, ab_get(con, ip))),
                    ("Looked up", esc(ago(e["fetched"])))])
    else:
        right = '<p class=muted>Lookup pending (country, network, Shodan) — runs in the background.</p>'
        if nbr:
            right += kv([("Netblock", nb_html(con, nbr)), ("Block owner", nb_owner_html(nbr))])
        extra = [(k, v) for k, g, v in (("DroneBL", dbl_get(con, ip), lambda d: dbl_html(con, d, ip)),
                                         ("Spamhaus", sh_get(con, ip), lambda d: sh_html(con, d, ip)),
                                         ("Abuse contact", ab_get(con, ip), lambda d: ab_html(con, ip, d))) if g for v in [v(g)]]
        if extra:
            right += kv(extra)

    fl = f["flag"] if f else ""
    flag_form = ('<form class="flagform" method=post action="/ip/%s/flag"><label>Blocklist</label><select name=flag>'
                 '<option value=""%s>Automatic (by score)</option><option value=block%s>Always block</option><option value=allow%s>Never block</option></select>'
                 '<input name=note maxlength=200 placeholder="Note" value="%s"><button>Save</button></form>'
                 % (esc(urllib.parse.quote(ip, safe=":")), " selected" if not fl else "", " selected" if fl == "block" else "", " selected" if fl == "allow" else "", esc(f["note"] if f else "")))

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
        links_f = (vt_html(vt_get(sha, con)) + " " + ext("https://bazaar.abuse.ch/sample/" + sha + "/", "MalwareBazaar") + " · " + ext("https://www.virustotal.com/gui/file/" + sha, "VirusTotal")) if sha else (ext("https://urlhaus.abuse.ch/browse.php?search=" + urllib.parse.quote(x["a"] or ""), "URLhaus") if x["a"] else "")
        fam, how = file_family(con.execute("SELECT * FROM files WHERE sha=?", (sha,)).fetchone() if sha else None, x["a"] or "", sha or None)
        frows += "<tr><td class='mono trunc'>%s %s</td><td class=mono>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            family_tag(fam, how), esc(clean(x["a"], 200)), esc(sha[:16] + "…" if sha else ("download failed" if x["kind"] == "file_fail" else "")), esc(ago(x["l"])), num(x["n"]), links_f)
    files_html = ('<div class="card span2"><h3>Files and URLs</h3><table><thead><tr><th>Name / URL</th><th>SHA-256</th><th>Last</th><th>Count</th><th>Lookup</th></tr></thead><tbody>%s</tbody></table></div>' % frows) if frows else ""

    # Related IPs
    same = "SELECT DISTINCT ip FROM sessions WHERE %s IN (SELECT DISTINCT %s FROM sessions WHERE ip=? AND %s IS NOT NULL) AND ip!=?"
    relations = [("Same SSH client (HASSH)", same % ("hassh", "hassh", "hassh"), (ip, ip)),
                 ("Same command script", same % ("cmdhash", "cmdhash", "cmdhash"), (ip, ip)),
                 ("Same file", "SELECT DISTINCT ip FROM events WHERE kind='file' AND b IN (SELECT DISTINCT b FROM events WHERE ip=? AND kind='file' AND b IS NOT NULL) AND ip!=?", (ip, ip))]
    if nbr and nbr.get("prefix"):
        relations.append(("Same netblock %s" % nbr["prefix"], "SELECT ip FROM netblock JOIN ips USING(ip) WHERE prefix=? AND ip!=?", (nbr["prefix"], ip)))
    if ":" not in ip and not (nbr and (nbr.get("prefix") or "").endswith("/24")):      # a /24 block is the same list
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
        for x in con.execute("SELECT session,ts,kind,a,b FROM events WHERE session IN (%s) AND kind IN ('login_ok','login_fail','cmd','file','file_fail','exec_sim','tcpip','proxy_reply','exploit','goodbye') ORDER BY ts" % ph, sids):
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
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">file</span><code>%s · %s</code></div>' % (rel_t, cmd_html(clean(x["a"], 300), fmap), ('<a class="c-f" href="/campaign/file/%s">%s</a>' % (seg(x["b"]), esc(x["b"]))) if re.fullmatch(r"[0-9a-f]{64}", x["b"] or "") else esc(x["b"] or "")))
            elif k == "exec_sim":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">run</span><code>%s · <a class="c-f" href="/campaign/file/%s">%s</a> (simulated, nothing ran)</code></div>'
                             % (rel_t, esc(clean(x["a"], 300)), seg(x["b"]), esc((x["b"] or "")[:16])))
            elif k == "file_fail":
                lines.append('<div class="ln warn"><span class=t>%s</span><span class="pr">fetch</span><code>%s (failed)</code></div>' % (rel_t, cmd_html(clean(x["a"], 300))))
            elif k == "goodbye":
                lines.append('<div class="ln"><span class=t>%s</span><span class="pr">bye</span><code>got the goodbye note on logout (%s)</code></div>' % (rel_t, esc(clean(x["a"], 60))))
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
                   + ((' <a class="replay-btn" href="/replay/%s?ip=%s">▶ Replay</a>' % (seg(s["tty"]), esc(urllib.parse.quote(ip, safe=":")))) if s["tty"] and s["cmds"] else ""))
        meta_ = '<div class="smeta">Session <span class=mono>%s</span>%s%s' % (
            esc(s["session"]), (' · HASSH <a class=mono href="/campaign/hassh/%s">%s</a>' % (seg(s["hassh"]), esc(s["hassh"]))) if s["hassh"] else "",
            (' · script <a class=mono href="/campaign/script/%s">%s</a>' % (esc(s["cmdhash"]), esc(s["cmdhash"]))) if s["cmdhash"] else "") \
            + ((' · terminal <span class=mono>%s</span>' % esc(s["termsize"].replace("x", "×"))) if s["termsize"] else "") \
            + ((' · <a class="replay" href="/replay/%s?ip=%s">▶ Replay</a>' % (seg(s["tty"]), esc(urllib.parse.quote(ip, safe=":")))) if s["tty"] else "")
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
        " on" if key == sf else "", esc(urllib.parse.quote(ip, safe=":")), "" if key == "all" else "?s=" + key, esc(label), num(n))
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

    # Suricata (optional): known attacks by rule, worst first. Rule names come from ET Open, not from the attacker.
    ia = con.execute("SELECT sid, MIN(sev) sev, MAX(sig) sig, MAX(cat) cat, SUM(n) n, MAX(last) l, GROUP_CONCAT(DISTINCT proto || '/' || port) ports "
                     "FROM ids WHERE ip=? GROUP BY sid ORDER BY sev, n DESC LIMIT 60", (ip,)).fetchall()
    if ia:
        irows = "".join("<tr><td>%s</td><td data-h>%s</td><td class=num>%s</td><td class='mono nowrap' data-h>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>"
                        % (ids_link(x["sid"], x["sig"], x["sev"]), esc(x["cat"] or ""), ids_sev(x["sev"]), esc(ids_ports(x["ports"])), num(x["n"]), esc(ago(x["l"])))
                        for x in ia)
        can_html += ('<div class="card span2"><h3>IDS alerts <span class=muted>Suricata, ET Open rules</span></h3><div class="scroll"><table class=wide><thead><tr>'
                     '<th>Rule</th><th data-h>Class</th><th class=num>Severity</th><th data-h>Port</th><th class=num>Hits</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div></div>' % irows)

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
    nb = nb_get(con, ip)
    return {
        "ip": ip, "exported": iso(time.time()), "huginn_version": HUGINN_VERSION,
        "summary": {k: r[k] for k in r.keys() if k not in ("first", "last")} | {"first_seen": iso(r["first"]), "last_seen": iso(r["last"])},
        "network": ({k: e[k] for k in e.keys() if k not in ("ip", "fetched", "ok")} | {"looked_up": iso(e["fetched"])}) if e else None,
        "manual_rule": {"rule": f["flag"], "note": f["note"]} if f else None,
        "sessions": [{k: s[k] for k in s.keys() if k not in ("start", "end")} | {"start": iso(s["start"]), "end": iso(s["end"]),
                      "persona": PERSONA.get(s["port"] or 0)} for s in sess],
        "events": [{"time": iso(x["ts"]), "source": x["src"], "kind": x["kind"], "session": x["session"], "a": x["a"], "b": x["b"]} for x in evs],
        "ids_alerts": [{"day": x["day"], "sid": x["sid"], "severity": x["sev"], "signature": x["sig"], "class": x["cat"], "proto": x["proto"],
                        "port": x["port"], "hits": x["n"], "first": iso(x["first"]), "last": iso(x["last"])}
                       for x in con.execute("SELECT * FROM ids WHERE ip=? ORDER BY first", (ip,))],
        "project_honeypot": hb_get(con, ip),
        "dronebl": ({"listed": d["listed"], "classes": d["classes"], "codes": d["codes"], "looked_up": iso(d["checked"])}
                    if (d := dbl_get(con, ip)) else None),
        "spamhaus": ({"listed": d["listed"], "classes": d["classes"], "codes": d["codes"], "looked_up": iso(d["checked"])}
                     if (d := sh_get(con, ip)) else None),
        "abuse_contact": ({"email": d["email"] or None, "source": "Abusix Abuse Contact DB", "looked_up": iso(d["checked"])}
                          if (d := ab_get(con, ip)) else None),
        "tor_exit": ({k: iso(v) for k, v in tor_get(con, ip).items()} if tor_get(con, ip) else None),
        "netblock": ({k: v for k, v in nb.items() if k not in ("ip", "checked", "name")} | {"owner": nb.get("name"), "looked_up": iso(nb["checked"])}) if nb else None,
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
ENG_MAX = 200000                 # sessions per window; more are left out and the page says so
ENG_OUTCOMES = (("left", "Left at once", "o-none"), ("proxy", "Proxy only", "o-one"), ("cmds", "Ran commands", "o-short"), ("payload", "Went for payload", "o-pay"))
_eng_cache = {}


def day_start(d):
    return datetime(d.year, d.month, d.day, tzinfo=TZ).timestamp()


def eng_sessions(con, since, until):
    # Finished shell sessions that got in, started in [since, until). One dict per session, oldest first.
    rows = con.execute("SELECT s.session, s.ip, s.start, s.duration, s.tcpip, s.files, s.termsize, i.first FROM sessions s "
                       "LEFT JOIN ips i ON i.ip=s.ip WHERE s.start>=? AND s.start<? AND s.logins_ok>0 AND s.duration IS NOT NULL "
                       "ORDER BY s.start LIMIT ?", (since, until, ENG_MAX + 1)).fetchall()
    cmds = {}
    # Every command of the chosen sessions, however long after the start they came.
    for sid, ts, a in con.execute("SELECT e.session, e.ts, e.a FROM sessions s JOIN events e ON e.session=s.session "
                                  "WHERE s.start>=? AND s.start<? AND s.logins_ok>0 AND s.duration IS NOT NULL AND e.kind='cmd' "
                                  "ORDER BY e.ts, e.rowid", (since, until)):
        cmds.setdefault(sid, []).append((ts, a or ""))
    eng_sessions.truncated = len(rows) > ENG_MAX
    rows = rows[:ENG_MAX]
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
    d["median"] = statistics.median(r["dur"] for r in rows) if n else None
    busy = [r["cmds"] for r in rows if r["cmds"]]
    d["cmds_avg"] = sum(busy) / len(busy) if busy else None
    return d


def engagement_data(con, days, version=None):
    key = (days, version, datetime.now(TZ).strftime("%Y-%m-%d"), get_meta(con, "last_ingest", ""),
           con.execute("SELECT COUNT(*), COALESCE(MAX(rowid), 0) FROM sessions").fetchone()[:],
           con.execute("SELECT COALESCE(MAX(rowid), 0) FROM events").fetchone()[0])
    if _eng_cache.get("key") == key:
        return _eng_cache["data"]
    today = datetime.now(TZ).date()
    start = day_start(today - timedelta(days=days - 1))
    rows = eng_sessions(con, start, time.time() + 1)
    truncated = eng_sessions.truncated
    labels = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
    per = {lab: [] for lab in labels}
    for r in rows:
        if r["day"] in per:
            per[r["day"]].append(r)
    data = {"labels": labels, "days": [(lab, eng_summary(per[lab])) for lab in labels], "total": eng_summary(rows), "truncated": truncated}
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
             '%s<p class="muted small note">Finished SSH and Telnet sessions that logged in. Left at once: no command, no file, no proxy use. Commands: average per session that ran any. '
             'New / returning: attackers first seen that day, and those seen before.</p></div>'
             % (leg, rows, ('<p class="err small">Only the first %s sessions of these days are counted.</p>' % num(ENG_MAX)) if d["truncated"] else "")) if t["n"] else '<div class="card">%s</div>' % none_yet("No sessions got in during these days")

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


# ---------------------------------------------------------------- help (0.35)
def v_help():
    # What the tags, badges and numbers mean. Tags come from TAG_HELP, the score from SCORE_HELP: one source each.
    row = lambda term, text: "<tr><td class=nw>%s</td><td>%s</td></tr>" % (term, text)
    table = lambda rows: '<table class="wide help"><tbody>%s</tbody></table>' % "".join(rows)
    tag = lambda t, cls="": '<span class="tag %s">%s</span>' % (cls or TAG_CLASS.get(t, ""), esc(t))
    personas = sorted(set(PERSONA.values()))
    tags = [row(tag(t), esc(TAG_HELP[t])) for t in ("shell", "dropper", "proxy", "exploit", "bruteforce", "human-like", "took-bait", "read-bait",
                                                    "sshole-probe", "web-exploit", "web-probe", "robots-trap", "ids-alert", "multi-service", "tarpitted",
                                                    "returned", "stepped-up", "tor", "dronebl", "spamhaus", "research", "block", "allow")]
    if personas:
        tags.append(row(" ".join(tag(p) for p in personas), "Persona: which fake machine a session hit. Set by the installer (HUGINN_PERSONAS)."))
    sessions = [
        row("Left at once", "Logged in, then nothing: no command, no file, no proxy use."),
        row("Proxy only", "Logged in only to send traffic through the honeypot to other sites."),
        row("Ran commands / One line / Stopped short", "Typed or pasted commands. On Personas: one line and gone, or several lines with no download seen."),
        row("Went for payload", "Downloaded or uploaded a file, or ran a command that fetches or plants something (wget, curl, an SSH key)."),
        row("×N like this", "The same command script, after the parts bots randomise are ignored. Shown once, the repeats folded under it."),
        row("terminal 240×24", "The terminal size the client asked for. Scripts usually ask for none; one bot often uses the same size every time."),
        row("▶ Replay", "Plays the session back as the attacker saw it."),
        row('<span class="tag">T1105</span>', "A MITRE ATT&amp;CK technique recognised in the commands. Click for MITRE's description."),
        row("Timeline", "On an attacker's page: Recon, Access, Commands, Payload and Exploit steps over 30 days, across every service."),
    ]
    files = [
        row('<span class="tag t-red">Mirai</span>', "The malware family, best source first: MalwareBazaar, strings in the file, VirusTotal's label, then the file name or URL. Hover to see which."),
        row('<span class="tag t-red">41/62</span>', "VirusTotal: how many antivirus engines flag the file. Only the SHA-256 is sent, never the file."),
        row('<span class="tag t-orange">novel</span>', "VirusTotal has never seen this file. Rare, and worth a closer look."),
        row('<span class="tag t-green">shared</span>', "You marked the file as shared with Sanesecurity (Share with Sanesecurity, at the bottom of Files)."),
        row('<span class="tag t-orange">UPX</span>', "Packed with UPX, which hides its contents from simple string searches."),
        row('<span class="tag">echo-built</span>', "Written on the honeypot line by line with echo or printf instead of being downloaded."),
        row("Embedded IPs / URLs", "Addresses found inside the file: often its command server or the next download. They feed the C2 list."),
        row("Malware URLs (fetch blocked)", "Downloads the attacker tried. The honeypot has no way out to the internet, so nothing was fetched."),
    ]
    lookups = [
        row('<span class="tag t-grey">benign scanner</span>', "GreyNoise knows the address as a harmless mass scanner (research, search engines). Counts as research."),
        row('<span class="tag t-red">malicious scanner</span>', "GreyNoise has seen the address scanning the internet with bad intent."),
        row("not seen scanning the internet", "GreyNoise has no record of it: not a mass scanner, so more likely aimed or new."),
        row("MalwareBazaar", "abuse.ch's malware database: family names and tags for known files, by hash."),
        row("Project Honey Pot", "Whether the address is listed by Project Honey Pot (http:BL) as a web spammer, e-mail harvester or suspicious "
            "visitor, its threat (0 to 255, higher is worse) and how many days ago it was last seen there. Needs a free key. IPv4 only. "
            "Pi-hole and many routers drop its answers: pick a public DNS server next to the key."),
        row("Netblock", "The announced network block the address belongs to (for example 45.148.10.0/24), from Team Cymru over DNS, and how many "
            "attackers came from the same block. Click it for all of them. Block owner is the AS that announces it, its registry and the date "
            "the block was allocated: a young block is often a fresh rented range. Campaigns lists the busiest blocks. No key needed; on by default."),
        row("Spamhaus", "Whether Spamhaus ZEN lists the IPv4 address: SBL (spam source), XBL (exploited or infected machine), DROP "
            "(hijacked network) or PBL (a home or end-user range, which is no accusation). SBL, XBL and DROP give the tag spamhaus; "
            "the score does not change. Needs your own DNS resolver, since Spamhaus refuses public ones."),
        row("Abuse contact", "Where to report the address: the abuse e-mail of its network, from the free Abusix Abuse Contact DB "
            "(over DNS). Report opens an e-mail with the facts filled in and the reference to Abusix their terms ask for."),
        row("DroneBL", "Whether DroneBL (a free DNS list, no key) has the IPv4 address as a drone, botnet member, open proxy, brute "
            "forcer or compromised router, and which. Tagged dronebl; it does not change the score. Each address again after a week. "
            "Campaigns, DroneBL counts the attackers per class."),
        row("Tor", "Once a day Huginn downloads the Tor Project's list of exit addresses. An attacker listed there within 30 days of its "
            "attack is tagged tor: someone using Tor, not the owner of the address. It never counts as coming back and stays off the "
            "blocklist unless chosen on Settings, Lookups (or tor=1 on a feed). On by default; nothing is sent."),
        row("Keys", "VirusTotal, MalwareBazaar and Project Honey Pot keys are pasted on Settings, Lookups. GreyNoise needs no key. Each keeps to a daily allowance."),
    ]
    ids = [
        row("What it is", "Optional. Suricata on the honeypot matches the traffic sent to it against the free Emerging Threats Open rules and names "
            "known exploits, scanners and tools, often with the CVE. It only listens and never blocks. On the honeypot: "
            "<span class=mono>./update-honeypot.sh --suricata-on</span>."),
        row('<span class="tag t-red">ET EXPLOIT …</span>', "A rule that matched. Click it for the rule's page: what it is, a link to the CVE, and every address that tripped it."),
        row('%s %s %s %s' % (ids_sev(1), ids_sev(2), ids_sev(3), ids_sev(4)),
            "The rule's severity. High is an attack (exploit, privilege gain, trojan, web application attack): it adds 3 to the score and tags the "
            "attacker ids-alert. Medium is mostly scanning and recon, low and info only describe; they are shown, not scored."),
        row("Hits", "How many times the rule matched. Counted once per alert, also when the honeypot sends the same alert again."),
        row("Only seen by Suricata", "An address that tripped a rule without touching any honeypot service. It is listed on the rule's page, "
            "but has no attacker page."),
        row("Settings, Honeypot", "Whether Suricata is on and running, how old its rules are, and the last 7 days, with a button to turn it on or off "
            "once it is set up on the honeypot. Rules are updated daily when the "
            "honeypot has internet, otherwise with <span class=mono>--suricata-rules FILE</span>. A stopped Suricata is alerted like any other honeypot service."),
    ]
    overview = [
        row("Time wasted", "Attacker time spent stuck in the tarpit plus time in fake shells. <i>stuck now</i>: tarpit connections still open."),
        row("Orange line under a bar", "No sync from the honeypot during that time: missing data, not a quiet period. Hover the bar for how long."),
        row("synced … ago", "When Huginn last pulled the honeypot's logs. Red: the last sync failed or is late. Hover it, or see Account, for the reason."),
        row("New", "Things seen for the first time: passwords, commands, files, SSH clients, web attacks. Mark them reviewed when read."),
        row("Engagement", "Day by day, how far attackers get after the login, and before against after a release."),
    ]
    block = [
        row("Who is on it", "Attackers whose score reaches the minimum (Settings, default 3) within the window (default 30 days)."),
        row("Left off", "Research scanners that never logged in or ran anything, and anyone you flagged <i>allow</i>."),
        row("Always on", "Anyone you flagged <i>block</i>."),
        row("Feeds", "The Blocklist page gives links in several formats (plain text, nftables, ipset, MikroTik, CSV) and a C2 list from captured malware."),
    ]
    body = ('<h1>Help</h1><p class=muted>What the tags, badges and numbers in Huginn mean. Hover any tag for its meaning too; press <kbd>?</kbd> for keyboard shortcuts.</p>'
            '<h2>Attacker tags</h2><div class="card">%s</div>'
            '<h2>Score</h2><div class="card"><p>Every attacker gets points for what it did. The score sorts the Attackers list and decides the blocklist.</p><p class=mono>%s</p></div>'
            '<h2>Sessions</h2><div class="card">%s</div><h2>Files</h2><div class="card">%s</div>'
            '<h2>Lookups</h2><div class="card">%s</div><h2>IDS alerts</h2><div class="card">%s</div>'
            '<h2>Overview and pages</h2><div class="card">%s</div><h2>Blocklist</h2><div class="card">%s</div>'
            % (table(tags), esc(SCORE_HELP), table(sessions), table(files), table(lookups), table(ids), table(overview), table(block)))
    return page("Help", body, "/help")


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
    loose = [sha for sha, f in meta.items() if sha not in seen_f and (f["mtime"] or 0) >= since]
    if loose:                                   # one pass over the file events, not one query per file
        older = {r[0] for r in con.execute("SELECT DISTINCT b FROM events WHERE kind='file' AND b IS NOT NULL")}
        for sha in loose:
            if sha not in older:                # only in the metadata: an older file event would be outside the period
                seen_f[sha] = {"names": set(), "ips": set(), "l": meta[sha]["mtime"] or 0, "only_meta": True}
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
        link = "<a class=mono href=\"/campaign/file/%s\">%s…</a>" % (seg(sha), esc(sha[:16])) if not g.get("only_meta") else "<span class=mono>%s…</span>" % esc(sha[:16])
        frows.append("<td>%s</td><td>%s</td><td class='mono wrap'>%s</td>%s%s" % (
            link, family_tag(fam, how) if fam else (esc(f["type"]) if f else "–"), snippet(hit if hit is not None else sha, q), n(len(g["ips"])), when(last)))
    files_ = section("Files", len(found), "<th>SHA-256</th><th>Type</th><th>Match</th><th class=num>IPs</th><th>Last</th>", frows)

    urls = con.execute("SELECT a,ip,session,MAX(ts) l,COUNT(*) c,COUNT(DISTINCT ip) nip FROM events WHERE kind='file_fail' AND ts>=? AND a LIKE ? ESCAPE '\\' GROUP BY a ORDER BY l DESC", (since, like)).fetchall()
    fails = section("Failed downloads", len(urls), "<th>URL</th><th class=num>Tries</th><th class=num>IPs</th><th>Last</th><th>IP</th>",
                    ["<td class='mono wrap'>%s</td>%s%s%s%s" % (snippet(r["a"], q), n(r["c"]), n(r["nip"]), when(r["l"]), who(r["ip"], r["session"])) for r in urls[:SEARCH_ROWS]])

    where = "kind='canary' AND ts>=? AND (b LIKE ? ESCAPE '\\' OR a LIKE ? ESCAPE '\\')"
    # One pass over the decoy rows: the total comes along with the newest ones (it used to be a second full scan).
    can = con.execute("SELECT ts,ip,a,b,COUNT(*) OVER () total FROM events WHERE " + where + " ORDER BY ts DESC LIMIT ?",
                      (since, like, like, SEARCH_ROWS)).fetchall()
    can_n = can[0]["total"] if can else 0
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


SHA256_RE = re.compile(r"[0-9a-f]{64}")
SHARE_MAX = 50          # hp-sample-zip takes at most this many files per zip
SHARE_URL = "https://sanesecurity.com/contact-us/"
SHARE_FRESH = 86400     # a file counts as still on the honeypot if the export listed it within this time


def share_candidates(con, shas, fi, vts):
    # Files worth sending to a signature project: the ones VirusTotal has never seen, or every file when there is no
    # VirusTotal key to tell. Only files hp-fileinfo has looked at (still on the honeypot); already shared ones are left out.
    shared = {r[0] for r in con.execute("SELECT sha FROM shared")}
    have_vt = bool(vt_key())
    fresh = time.time() - SHARE_FRESH
    out = []
    for sha in shas:
        if sha in shared or sha not in fi or not SHA256_RE.fullmatch(sha):
            continue
        if (fi[sha]["updated"] or 0) < fresh:       # no longer in hp-fileinfo's export: deleted from the honeypot
            continue
        v = vts.get(sha)
        if have_vt and not (v is not None and not v.get("found")):
            continue
        out.append(sha)
    return out


def share_card(con, shas, fi, vts, fam=""):
    cand = share_candidates(con, shas, fi, vts)
    n_shared = con.execute("SELECT COUNT(*) FROM shared").fetchone()[0]
    what = "VirusTotal has never seen" if vt_key() else "the honeypot captured (no VirusTotal key, so Huginn cannot tell which are new)"
    intro = ('<p class="muted small">Signature projects such as %s turn new malware into virus signatures (ClamAV and others). '
             'The files stay on the honeypot: run the command there as root, it writes a zip with the password <b>infected</b> '
             'to /root/hp-samples/. Send that zip as their contact page asks. Nothing is uploaded by Huginn.</p>' % ext(SHARE_URL, "Sanesecurity"))
    if not cand:
        body = none_yet("Nothing new to share" + (" (%s shared so far)" % num(n_shared) if n_shared else ""))
    else:
        pick = cand[:SHARE_MAX]
        cmd = "hp-sample-zip " + " ".join(pick)
        body = ('<p>%s file%s %s%s%s.</p><div class="feed"><div class="feed-h"><b>On the honeypot</b><button class="btn-s" data-copy="%s">Copy</button></div>'
                '<div class="mono url">%s</div></div>'
                '<form method=post action="/files/shared" class="pwcheck"><input name=shas required autocomplete=off '
                'placeholder="Paste the line that starts with included:" aria-label="Hashes that went into the zip"> <button>Mark as shared</button></form>'
                '<p class="muted small">After sending the zip, paste the <b>included:</b> line hp-sample-zip printed. Only the hashes '
                'that really went into the zip are marked; a file missing on the honeypot stays in the list.</p>'
                % (num(len(cand)), "" if len(cand) == 1 else "s", esc(what), (" (%s only)" % esc("unknown family" if fam == "unknown" else fam)) if fam else "",
                   (", the first %d in this command" % SHARE_MAX) if len(cand) > SHARE_MAX else "",
                   esc(cmd), esc(cmd)))
    undo = ""
    if n_shared:
        last = con.execute("SELECT sha FROM shared ORDER BY ts DESC LIMIT 1").fetchone()[0]
        undo = ('<form method=post action="/files/unshared" class="inline"><input type=hidden name=shas value="%s">'
                '<button class="btn-s">Undo the last one</button></form>' % esc(last))
    return '<h2>Share with Sanesecurity</h2><div class="card">%s%s%s</div>' % (intro, body, undo)


def mark_shared(con, raw, on=True):
    raw = (raw or "").lower().replace("included:", " ").replace(",", " ")
    shas = [x for x in raw.split() if SHA256_RE.fullmatch(x)][:SHARE_MAX]
    with con:
        for sha in shas:
            if on:
                con.execute("INSERT OR IGNORE INTO shared(sha, ts) VALUES(?,?)", (sha, time.time()))
            else:
                con.execute("DELETE FROM shared WHERE sha=?", (sha,))
    return len(shas)


def v_files(qs=None):
    con = db()
    want = ((qs or {}).get("fam") or "")[:80]
    ev = {r["sha"]: r for r in con.execute("SELECT b sha, MIN(ts) f, MAX(ts) l, COUNT(*) n, COUNT(DISTINCT ip) nip, GROUP_CONCAT(DISTINCT a) names "
                                            "FROM events WHERE kind='file' AND b IS NOT NULL GROUP BY b")}
    fi = {r["sha"]: r for r in con.execute("SELECT * FROM files")}
    shas = sorted(set(ev) | set(fi), key=lambda x: -((ev[x]["l"] if x in ev else 0) or (fi[x]["mtime"] if x in fi else 0)))
    vts = {}
    for sha_, d_ in con.execute("SELECT sha, data FROM vt"):
        try:
            vts[sha_] = json.loads(d_)
        except ValueError:
            pass
    fams = {sha: file_family(fi.get(sha), ev[sha]["names"] if sha in ev else "", sha, vts.get(sha)) for sha in shas}
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
    share = share_card(con, shas, fi, vts, want)      # follows the family filter: pick Mirai, share only Mirai
    shas = shas[:300]
    shared = dict(con.execute("SELECT sha, ts FROM shared").fetchall())
    trs = ""
    for sha in shas:
        e, f = ev.get(sha), fi.get(sha)
        iocs = json.loads(f["iocs"]) if f and f["iocs"] else []
        fam, how = fams[sha]
        kind = (family_tag(fam, how) if fam else "") + ('<div class="ft">%s</div>' % (esc(f["type"]) + (" · " + esc(f["arch"]) if f["arch"] else "") + (' <span class="tag t-orange">UPX</span>' if f["packed"] else "")
                + ('' if f["src"] != "redir" else ' <span class="tag">echo-built</span>')) if f else '<span class=muted>–</span>')
        trs += ("<tr><td class=mono>%s</td><td>%s</td><td class='num nw'>%s</td><td class='mono trunc'>%s</td><td class='mono small iocs'>%s</td><td class=nw>%s</td><td class=num>%s</td><td class=nw>%s</td><td class=nw>%s · %s</td></tr>"
                % (("<a href='/campaign/file/%s'>%s…</a>" % (seg(sha), esc(sha[:16]))) if e else esc(sha[:16]) + "…", kind,
                   esc("%.1f KB" % (f["size"] / 1024.0)) if f else "", esc(clean(e["names"], 200)) if e else "",
                   ioc_cell(iocs),
                   esc(ago(e["l"] if e else f["mtime"])), num(e["nip"]) if e else "", vt_html(vts.get(sha)) + (
                       ' <span class="tag t-green" title="Marked as shared %s">shared</span>' % esc(fmt_ts(shared.get(sha, 0))) if sha in shared else ""),
                   ext("https://bazaar.abuse.ch/sample/%s/" % sha, "MalwareBazaar"), ext("https://www.virustotal.com/gui/file/" + sha, "VirusTotal")))
    urls = con.execute("SELECT a, MAX(ts) l, COUNT(*) n, COUNT(DISTINCT ip) nip FROM events WHERE kind='file_fail' AND a IS NOT NULL GROUP BY a ORDER BY l DESC LIMIT 200").fetchall()
    urs = "".join("<tr><td class='mono trunc'>%s</td><td>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                  % (esc(clean(u["a"], 200)), esc(ago(u["l"])), num(u["n"]), num(u["nip"]), ext("https://urlhaus.abuse.ch/browse.php?search=" + urllib.parse.quote(u["a"]), "URLhaus")) for u in urls)
    body = ('<h1>Files</h1><p class=muted>Captured by the honeypot (uploads and downloads). Never executed here — look them up by hash only.</p>'
            '<div class="card">%s%s</div>%s<h2>Malware URLs (fetch blocked)</h2><div class="card">%s</div>'
            % (chips, '<input class="qf" data-filter="t-files" placeholder="Filter"><table id="t-files" class="wide"><thead><tr><th>SHA-256</th><th>Type</th><th class=num>Size</th><th>Names / URLs</th>'
               '<th>Embedded IPs / URLs</th><th>Last</th><th class=num>IPs</th><th>VirusTotal</th><th>Lookup</th></tr></thead><tbody>%s</tbody></table>' % trs if trs else none_yet("No files captured yet"),
               share,
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
    # The newest event and the history-cut generation say whether anything changed: a COUNT over every login on each
    # check cost as much as the lookup itself (Codex 049 M13).
    key = "%s|%s" % (con.execute("SELECT MAX(rowid) FROM events").fetchone()[0], get_meta(con, "events_gen", ""))
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
    # 0.39: the whole command list of one session per script, so rows that start alike show where they differ and a preview.
    fulls = [[r[0] for r in con.execute("SELECT a FROM events WHERE session=? AND kind='cmd' AND TRIM(COALESCE(a,''))<>'' "
                                         "ORDER BY ts, rowid LIMIT ?", (s["sid"], DIFF_MAX))] for s in scripts]
    diffs = script_diffs(fulls)
    for s, full, diff in zip(scripts, fulls, diffs):
        srows += "<tr><td>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td><td>%s</td></tr>" % (
            script_cell(s["cmdhash"], full[:2], diff=diff, full=full), num(s["c"]), num(s["nip"]), (num(s["nip7"]) if s["nip7"] else '<span class=muted>–</span>'),
            num(s["n"]), esc(fmt_ts(s["f"])), esc(ago(s["l"])))
    stabs = ('<div class="chips"><a class="chip%s" href="/campaigns#c-scripts">All time</a><a class="chip%s" href="/campaigns?active=1#c-scripts">Active, 7 days</a></div>'
             % ("" if active else " on", " on" if active else ""))
    hs = con.execute("SELECT hassh, COUNT(*) n, COUNT(DISTINCT ip) nip, MAX(version) v, MAX(start) l FROM sessions WHERE hassh IS NOT NULL "
                     "GROUP BY hassh ORDER BY nip DESC LIMIT 40").fetchall()
    hrows = "".join("<tr><td class=mono><a href='/campaign/hassh/%s'>%s</a></td><td class='mono trunc'>%s</td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>"
                    % (seg(h["hassh"]), esc(h["hassh"]), esc(clean(h["v"] or "", 60)), num(h["nip"]), num(h["n"]), esc(ago(h["l"]))) for h in hs)
    # Web attacks by rule: how many addresses tried the same thing.
    wa = con.execute("SELECT type, MAX(cve) cve, MAX(sev) sev, MAX(level='exploit') x, COUNT(DISTINCT ip) nip, COUNT(*) n, MAX(ts) l FROM webhits "
                     "WHERE level IN ('exploit','probe') GROUP BY type ORDER BY x DESC, nip DESC, n DESC LIMIT 60").fetchall()
    warows = "".join("<tr><td class=nowrap>%s</td><td class=trunc>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=nowrap>%s</td></tr>"
                     % (web_tag("exploit" if w["x"] else "probe", w["type"], w["cve"]), esc((web_rule_info(w["type"]) or [""] * 7)[6]),
                        num(w["sev"]), num(w["nip"]), num(w["n"]), esc(ago(w["l"]))) for w in wa)

    # IDS rules (Suricata, optional): the rules that matched most addresses, attacks before information.
    ir = con.execute("SELECT sid, MIN(sev) sev, MAX(sig) sig, MAX(cat) cat, COUNT(DISTINCT ip) nip, SUM(n) n, MAX(last) l FROM ids "
                     "GROUP BY sid ORDER BY sev, nip DESC, n DESC LIMIT 60").fetchall()
    irows = "".join("<tr><td>%s</td><td class=trunc data-h>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num data-h>%s</td><td class=nowrap>%s</td></tr>"
                    % (ids_link(x["sid"], x["sig"], x["sev"]), esc(x["cat"] or ""), ids_sev(x["sev"]), num(x["nip"]), num(x["n"]), esc(ago(x["l"]))) for x in ir)
    try:
        ids_on = json.loads(get_meta(con, "hp_ids", "{}") or "{}").get("on")
    except (ValueError, AttributeError):
        ids_on = False
    ids_html = ('<table class="wide"><thead><tr><th>Rule</th><th data-h>Class</th><th class=num>Severity</th><th class=num>IPs</th><th class=num data-h>Hits</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % irows
                if irows else none_yet("No IDS alerts yet" if ids_on else "Suricata is off. On the honeypot: ./update-honeypot.sh --suricata-on"))

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
    # Netblocks (0.47): announced blocks that hold more than one attacker, the busiest first.
    nbs = con.execute("SELECT n.prefix, MAX(n.asn) asn, MAX(n.cc) cc, MAX(n.registry) reg, MAX(n.allocated) alloc, MAX(a.name) name, "
                      "COUNT(*) nip, SUM(i.last>=?) nip7, SUM((','||COALESCE(i.tags,'')||',') LIKE '%,returned,%') ret, MAX(i.last) l "
                      "FROM netblock n JOIN ips i USING(ip) LEFT JOIN asname a USING(asn) WHERE n.prefix IS NOT NULL "
                      "GROUP BY n.prefix HAVING COUNT(*)>=2 ORDER BY nip DESC, l DESC LIMIT 40", (d7,)).fetchall()
    nbrows = "".join("<tr><td class='mono nowrap'><a href='%s'>%s</a></td><td class=trunc data-h title='%s'>%s</td><td>%s</td><td class=num>%s</td>"
                     "<td class=num>%s</td><td class='num' data-h>%s</td><td class=nowrap data-h>%s</td><td class=nowrap>%s</td></tr>"
                     % (esc(nb_url(b["prefix"])), esc(b["prefix"]), esc("AS%s" % b["asn"] if b["asn"] else ""), esc(b["name"] or ("AS" + b["asn"] if b["asn"] else "–")),
                        cc_html(b["cc"]), num(b["nip"]), (num(b["nip7"]) if b["nip7"] else '<span class=muted>–</span>'),
                        (num(b["ret"]) if b["ret"] else '<span class=muted>–</span>'), esc(b["alloc"] or "–"), esc(ago(b["l"]))) for b in nbs)
    nb_done = con.execute("SELECT COUNT(*) FROM netblock").fetchone()[0]
    nb_html_t = ('<table class="wide"><thead><tr><th>Netblock</th><th data-h>Owner</th><th>CC</th><th class=num>IPs</th><th class=num>IPs 7d</th>'
                 '<th class=num data-h>Returned</th><th data-h>Allocated</th><th>Last</th></tr></thead><tbody>%s</tbody></table>' % nbrows
                 if nbrows else none_yet("No block with more than one attacker yet" if nb_done else
                                         ("Netblocks are being looked up in the background" if nb_on(con) else "Netblock lookups are off (Settings, Lookups)")))
    tbl = lambda head, rows: '<table class="wide"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (head, rows)
    # 0.51: what DroneBL says about the attackers, per class (one address can be in several).
    wk = time.time() - 7 * 86400
    dcl = {}
    for ip, codes, last in con.execute("SELECT d.ip, d.codes, i.last FROM dronebl d JOIN ips i USING(ip) WHERE d.codes NOT IN ('', '[]')"):
        try:
            cs = [c for c in json.loads(codes) if isinstance(c, int)]
        except ValueError:
            continue
        for c in cs:
            x = dcl.setdefault(c, [0, 0, 0])
            x[0] += 1
            x[1] += 1 if (last or 0) >= wk else 0
            x[2] = max(x[2], last or 0)
    dbl_done = con.execute("SELECT COUNT(*), SUM(codes NOT IN ('', '[]')) FROM dronebl").fetchone()
    drows = "".join('<tr><td><span class="tag t-purple">%s</span></td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>'
                    % (esc(DBL_CLASSES.get(c, "class %d" % c)), num(x[0]), num(x[1]) if x[1] else '<span class=muted>–</span>', esc(ago(x[2])))
                    for c, x in sorted(dcl.items(), key=lambda kv: (-kv[1][0], kv[0])))
    dbl_html_t = (('<p class="muted small">%s of %s looked-up attackers are on DroneBL. <a href="/ips?tag=dronebl&amp;days=all">Show them</a>.</p>'
                   % (num(dbl_done[1] or 0), num(dbl_done[0])))
                  + tbl('<th>DroneBL class</th><th class=num>IPs</th><th class=num>IPs 7d</th><th>Last</th>', drows)) if drows else none_yet(
        "No attacker listed on DroneBL yet" if dbl_done[0] else ("Attackers are being looked up on DroneBL in the background" if dbl_on(con) and DBL_DAILY
                                                                 else "DroneBL lookups are off (Settings, Lookups)"))
    scl = {}
    for ip, codes, last in con.execute("SELECT d.ip, d.codes, i.last FROM spamhaus d JOIN ips i USING(ip) WHERE d.codes NOT IN ('', '[]')"):
        try:
            names = {SH_CLASSES.get(c, "class %d" % c) for c in json.loads(codes) if isinstance(c, int)}
        except ValueError:
            continue
        for n in names:
            x = scl.setdefault(n, [0, 0, 0])
            x[0] += 1
            x[1] += 1 if (last or 0) >= wk else 0
            x[2] = max(x[2], last or 0)
    sh_done = con.execute("SELECT COUNT(*), SUM(codes NOT IN ('', '[]')) FROM spamhaus").fetchone()
    shrows = "".join('<tr><td><span class="tag">%s</span></td><td class=num>%s</td><td class=num>%s</td><td>%s</td></tr>'
                    % (esc(n), num(x[0]), num(x[1]) if x[1] else '<span class=muted>–</span>', esc(ago(x[2])))
                    for n, x in sorted(scl.items(), key=lambda kv: (-kv[1][0], kv[0])))
    sh_html_t = '<h3 class="sp-gap">Spamhaus</h3>' + ((('<p class="muted small">%s of %s looked-up attackers are on Spamhaus ZEN. '
                                                        '<a href="/ips?tag=spamhaus&amp;days=all">Show those with SBL, XBL or DROP</a>.</p>' % (num(sh_done[1] or 0), num(sh_done[0])))
                                                       + tbl('<th>Spamhaus list</th><th class=num>IPs</th><th class=num>IPs 7d</th><th>Last</th>', shrows)) if shrows else none_yet(
        "No attacker listed on Spamhaus yet" if sh_done[0] else ("Attackers are being looked up on Spamhaus in the background" if sh_on(con) and SH_DAILY
                                                                 else "Spamhaus lookups are off (Settings, Lookups)")))
    # 0.47.1: one tab per grouping instead of one long page. Each tab is a plain #link, so without JavaScript (and in the
    # static demo) it jumps to the section; with it, only the chosen section shows and the choice is remembered.
    tabs = [
        ("scripts", "Command scripts", len(scripts), stabs + (tbl('<th>Script</th><th class=num>Cmds</th><th class=num>IPs</th><th class=num>IPs 7d</th><th class=num>Sessions</th><th>First</th><th>Last</th>', srows)
                                                          if srows else none_yet("No command scripts in the last 7 days" if active else "No command scripts yet"))),
        ("hassh", "SSH clients", len(hs), tbl('<th>HASSH</th><th>Client version</th><th class=num>IPs</th><th class=num>Sessions</th><th>Last</th>', hrows) if hrows else none_yet("No SSH clients yet")),
        ("netblocks", "Netblocks", len(nbs), nb_html_t),
        ("dronebl", "DroneBL & Spamhaus", len(dcl) + len(scl), dbl_html_t + sh_html_t),
        ("web", "Web attacks", len(wa), tbl('<th>Attack</th><th>What it is</th><th class=num>Severity</th><th class=num>IPs</th><th class=num>Requests</th><th>Last</th>', warows) if warows else none_yet("No web attacks recognised yet")),
        ("ids", "IDS alerts", len(ir), ids_html),
        ("mail", "Mail clients", len(hl), tbl('<th>HELO name</th><th class=num>IPs</th><th class=num>Times</th><th>Last</th>', hlrows) if hlrows else none_yet("No mail clients yet")),
        ("proxy", "Proxy use", len(pr), psum + (tbl('<th>Request</th><th>Honeypot</th><th class=num>IPs</th><th class=num>Times</th><th>Last</th>', prows) if prows else none_yet("No proxy checks answered yet"))),
        ("slow", "Slow replies", None, slow),
    ]
    h2 = {"hassh": "SSH clients (HASSH)", "mail": "Mail clients (HELO)"}
    bar = "".join('<a href="#c-%s" data-ctab="%s">%s%s</a>' % (k, k, esc(t), ('<span class=muted>%s</span>' % num(n)) if n else "") for k, t, n, _h in tabs)
    secs = "".join('<section id="c-%s" class="ctab-pane" data-cpane="%s"><h2>%s</h2><div class="card">%s</div></section>' % (k, k, esc(h2.get(k, t)), h)
                   for k, t, _n, h in tabs)
    body = ('<h1>Campaigns</h1><p class=muted>Attackers grouped by command script (addresses, numbers and random markers ignored), SSH client fingerprint (HASSH), netblock (the announced network they come from), web attack (rules from Krawl), IDS rule (Suricata), mail client name (HELO) and what they fetch through the fake SSH proxy.</p>'
            '<nav class="ctabs" aria-label="Campaign groupings">%s</nav><div class="cgrid ctab-wrap">%s</div>' % (bar, secs))
    return page("Campaigns", body, "/campaigns")


def v_campaign(kind, val):
    con = db()
    if kind == "web":
        return v_campaign_web(con, val)
    if kind == "ids":
        return v_campaign_ids(con, int(val))
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
        detail = ('<div class="card"><h3>File</h3><div class=mono>%s</div><p>VirusTotal %s · %s · %s</p>%s</div>'
                  % (esc(val), vt_html(vt_get(val, con)), ext("https://bazaar.abuse.ch/sample/%s/" % val, "MalwareBazaar"), ext("https://www.virustotal.com/gui/file/" + val, "VirusTotal"),
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


def v_campaign_ids(con, sid):
    # One Suricata rule: what it is (from ET Open) and every address that tripped it. Known attackers link to their page.
    ips = con.execute("SELECT ip, SUM(n) n, MAX(last) l, GROUP_CONCAT(DISTINCT proto || '/' || port) ports FROM ids WHERE sid=? "
                      "GROUP BY ip ORDER BY l DESC LIMIT 500", (sid,)).fetchall()
    if not ips:
        return None
    r = con.execute("SELECT sig, cat, MIN(sev) sev, SUM(n) n, MIN(first) f FROM ids WHERE sid=?", (sid,)).fetchone()
    cves = ["CVE-%s-%s" % c for c in ids_cves(r["sig"])]
    detail = ('<div class="card"><h3>%s</h3><p>%s · severity %s · rule %d · first %s · %s hits</p>%s'
              '<p class="muted small">Rule from Emerging Threats Open, matched by Suricata on the honeypot.</p></div>'
              % (esc(clean(r["sig"], 240)), esc(r["cat"] or "no class"), ids_sev(r["sev"]), sid, esc(fmt_ts(r["f"])), num(r["n"]),
                 ("<p>%s</p>" % " · ".join(ext("https://nvd.nist.gov/vuln/detail/" + c, c) for c in cves)) if cves else ""))
    known = {x[0] for x in con.execute("SELECT ip FROM ips WHERE ip IN (%s)" % ",".join("?" * len(ips)), [i["ip"] for i in ips])}
    en = {x["ip"]: x for x in con.execute("SELECT ip, cc, org FROM enrich WHERE ip IN (%s)" % ",".join("?" * len(ips)), [i["ip"] for i in ips])}
    rows = "".join("<tr><td>%s</td><td>%s</td><td class=trunc data-h>%s</td><td class='mono nowrap' data-h>%s</td><td class=num>%s</td><td>%s</td></tr>"
                   % (ip_link(i["ip"]) if i["ip"] in known else '<span class=mono title="Only seen by Suricata">%s</span>' % esc(i["ip"]),
                      cc_html(en[i["ip"]]["cc"] if i["ip"] in en else None), esc(en[i["ip"]]["org"] or "" if i["ip"] in en else ""),
                      esc(ids_ports(i["ports"])), num(i["n"]), esc(ago(i["l"]))) for i in ips)
    title = "IDS rule %d" % sid
    body = ('<h1>%s</h1><div class="grid"><div class="span2">%s</div><div class="card span2"><h3>IPs <span class=muted>%s</span></h3>'
            '<table class="wide"><thead><tr><th>IP</th><th>CC</th><th data-h>Network</th><th data-h>Port</th><th class=num>Hits</th><th>Last</th></tr></thead><tbody>%s</tbody></table></div></div>'
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


def blocklist_ips(con, min_score, days, research, v6, tor=None):
    # tor: True puts Tor exit nodes on the list like any other attacker; None = as chosen on Settings (left out by default).
    tor = tor_bl(con) if tor is None else tor
    since = time.time() - days * 86400
    rows = con.execute(
        "SELECT i.ip, COALESCE(f.flag,'')='block' manual, i.score, (','||COALESCE(i.tags,'')||',' LIKE '%,tor,%' AND COALESCE(f.flag,'')!='block') via_tor, COALESCE(e.research,-1) rs, COALESCE(f.flag,'')!='block' AND (i.logins_ok + i.logins_fail + i.cmds + i.files + i.exploits + i.tcpip) = 0 "
        "AND ','||COALESCE(i.tags,'')||',' NOT LIKE '%,web-exploit,%' AND ','||COALESCE(i.tags,'')||',' NOT LIKE '%,took-bait,%' "
        "AND ','||COALESCE(i.tags,'')||',' NOT LIKE '%,read-bait,%' AND ','||COALESCE(i.tags,'')||',' NOT LIKE '%,sshole-probe,%' maybe "
        "FROM ips i LEFT JOIN enrich e USING(ip) LEFT JOIN flags f USING(ip) "
        "WHERE COALESCE(f.flag,'')!='allow' AND (f.flag='block' OR (i.last>=? AND i.score>=?))",
        (since, min_score)).fetchall()
    out = []
    for ip, manual, score, via_tor, rs, quiet in rows:
        if via_tor and not tor:
            continue
        # No name/network lookup yet: GreyNoise may already know it is a benign scanner (Codex 049 M12).
        maybe = quiet and (rs == 1 or (rs == -1 and research_now(con, ip, base=0)))
        # A scanner by name, and nothing but looking around: left out, unless it tried to log in to a decoy service.
        if maybe and not research and not any(canary_is_login(s, b) for s, b in con.execute("SELECT a,b FROM events WHERE ip=? AND kind='canary' AND b LIKE '% / %'", (ip,))):
            continue
        a = ipaddress.ip_address(ip)
        if not is_public(a) or getattr(a, "scope_id", None) or (a.version == 6 and not v6):
            continue
        # Never-block wins over the score; only your own Block on the IP page wins over never-block.
        if not manual and never_block(a):
            continue
        out.append((not manual, -(score or 0), a))
    if len(out) > BL_MAX:
        out.sort(key=lambda t: (t[0], t[1], t[2].version, int(t[2])))     # manual blocks first, then highest score
        out = out[:BL_MAX]
    out = [t[2] for t in out]
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
        if not is_public(a) or getattr(a, "scope_id", None) or str(a) in BENIGN_IOC or str(a) in C2_EXCLUDE or never_block(a):
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
    keep = sorted((k for k in out if len(sources[k]) >= C2_MIN_SOURCES),
                  key=lambda k: (-len(sources[k]), ipaddress.ip_address(k).version, int(ipaddress.ip_address(k))))[:BL_MAX]
    return {k: out[k] for k in keep}


def bl_params(qs):
    st = settings()
    def gi(k, d, lo, hi):
        try:
            return max(lo, min(hi, int(qs.get(k) or d)))
        except ValueError:
            return d
    tor = qs.get("tor")
    return (gi("min", int(st["bl_min"]), 1, 1000), gi("days", int(st["bl_days"]), 1, 3650), qs.get("research") == "1", qs.get("v6", "1") != "0",
            tor_bl() if tor not in ("0", "1") else tor == "1")


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
        c2 = [i for i in c2_list(db()) if with_v6 or ":" not in i]
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


def metrics_token(con):
    # The token Prometheus must send, or "" while metrics are off. HUGINN_METRICS_TOKEN wins over Settings.
    if METRICS_TOKEN:
        return METRICS_TOKEN
    if get_meta(con, "metrics_on") != "1":
        return ""
    return get_meta(con, "metrics_token", "") or ""


def _mlabel(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


_metrics_cache = {"at": 0, "text": ""}
_metrics_lock = threading.Lock()


def metrics_text(con, now=None):
    # Prometheus text format. Counts only: no addresses, names or anything an attacker typed (a label per attacker would
    # also make one time series per address). Kept for 15 s so several scrapers cost one set of queries.
    now = now or time.time()
    with _metrics_lock:
        if now - _metrics_cache["at"] < 15 and _metrics_cache["text"]:
            return _metrics_cache["text"]
        t0 = time.time()
        out = []

        def metric(name, kind, help_, samples):
            out.append("# HELP huginn_%s %s\n# TYPE huginn_%s %s\n" % (name, help_, name, kind))
            for labels, v in samples:
                lab = ",".join('%s="%s"' % (k, _mlabel(x)) for k, x in labels.items())
                out.append("huginn_%s%s %s\n" % (name, "{%s}" % lab if lab else "", repr(float(v)) if isinstance(v, float) else int(v)))

        metric("info", "gauge", "Huginn version.", [({"version": HUGINN_VERSION}, 1)])
        try:
            tot = json.loads(get_meta(con, "metric_totals", "{}") or "{}")
        except ValueError:
            tot = {}
        samples = []
        for k, n in sorted(tot.items() if isinstance(tot, dict) else []):
            src, _, rest = k.partition("|")
            kind, _, svc = rest.partition("|")
            samples.append(({"source": src, "kind": kind, "service": svc}, int(n) if isinstance(n, int) else 0))
        metric("events_ingested_total", "counter", "Events stored since metrics were added, by source, kind and decoy service.", samples)
        samples = [({"source": src, "kind": kind, "service": metric_svc(src, a)}, n) for src, kind, a, n in con.execute(
            "SELECT src, kind, CASE WHEN src IN ('canary','traps') THEN a END, COUNT(*) FROM events WHERE ts>=? GROUP BY 1, 2, 3", (now - 86400,))]
        merged = {}
        for lab, n in samples:
            key = tuple(sorted(lab.items()))
            merged[key] = merged.get(key, 0) + n
        metric("events_last_24h", "gauge", "Events in the last 24 hours, by source, kind and decoy service.", [(dict(k), n) for k, n in sorted(merged.items())])
        metric("events_stored", "gauge", "Events in the database.", [({}, con.execute("SELECT COUNT(*) FROM events").fetchone()[0])])
        metric("attackers", "gauge", "Addresses active within the window.",
               [({"window": w}, con.execute("SELECT COUNT(*) FROM ips WHERE last>=?", (now - sec,)).fetchone()[0])
                for w, sec in (("1h", 3600), ("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400))])
        metric("attackers_new", "gauge", "Addresses first seen within the window.",
               [({"window": w}, con.execute("SELECT COUNT(*) FROM ips WHERE first>=?", (now - sec,)).fetchone()[0])
                for w, sec in (("24h", 86400), ("7d", 7 * 86400))])
        metric("sessions_last_24h", "gauge", "SSH and Telnet sessions in the last 24 hours, and how many logged in.",
               [({"proto": p or "unknown", "logged_in": "yes" if ok else "no"}, n) for p, ok, n in con.execute(
                   "SELECT proto, logins_ok>0, COUNT(*) FROM sessions WHERE start>=? GROUP BY 1, 2", (now - 86400,))
                if p in (None, "ssh", "telnet")])
        metric("files_captured", "gauge", "Captured files in the database.", [({}, con.execute("SELECT COUNT(*) FROM files").fetchone()[0])])
        st = settings(con)
        metric("blocklist_entries", "gauge", "Addresses on the blocklist with the Settings defaults.",
               [({}, len(blocklist_ips(con, int(st["bl_min"]), int(st["bl_days"]), False, True)))])
        metric("decoy_dropped_today", "gauge", "Repeated decoy tries counted but not stored today (UTC), by service.",
               [({"service": metric_svc("canary", svc)}, n or 0) for svc, n in con.execute(
                   "SELECT svc, SUM(dropped) FROM capped WHERE day=? GROUP BY svc", (utc_day(now),))])
        li = float(get_meta(con, "last_ingest", "0") or 0)
        metric("last_sync_timestamp_seconds", "gauge", "When the last sync with the honeypot finished well (Unix time).", [({}, li)])
        metric("last_sync_duration_seconds", "gauge", "How long the last sync took.", [({}, float(get_meta(con, "last_ingest_secs", "0") or 0))])
        metric("last_sync_new_events", "gauge", "New events in the last sync.", [({}, int(float(get_meta(con, "last_ingest_new", "0") or 0)))])
        metric("sync_error", "gauge", "1 if the last sync failed.", [({}, 1 if (get_meta(con, "last_error", "") or "").strip() else 0)])
        try:
            problems = json.loads(get_meta(con, "health_now", "{}") or "{}")
        except ValueError:
            problems = {}
        problems = problems if isinstance(problems, dict) else {}
        metric("collection_problems", "gauge", "Collection problems right now (see Account).", [({}, len(problems))])
        metric("collection_problem", "gauge", "1 for each check that has a problem right now.",
               [({"check": k[:40]}, 1) for k in sorted(problems)[:50]])
        lk = []
        for svc, budget, daily, key_set, err, wait in (
                ("virustotal", "vt_day", VT_DAILY, bool(vt_key(con)), "vt_error", "vt_wait_until"),
                ("greynoise", "gn_day", gn_daily(con), bool(gn_key(con)), "gn_error", "gn_wait_until"),
                ("httpbl", "hb_day", HB_DAILY if hb_key(con) else 0, bool(hb_key(con)), "hb_error", "hb_wait_until"),
                ("netblock", "nb_day", NB_DAILY if nb_on(con) else 0, False, "nb_error", "nb_wait_until"),
                ("dronebl", "dbl_day", DBL_DAILY if dbl_on(con) else 0, False, "dbl_error", "dbl_wait_until"),
                ("spamhaus", "sh_day", SH_DAILY if sh_on(con) else 0, False, "sh_error", "sh_wait_until"),
                ("abusix", "ab_day", AB_DAILY if ab_on(con) and nb_on(con) else 0, False, "ab_error", "ab_wait_until"),
                ("malwarebazaar", None, 0, bool(mb_key(con)), "mb_error", "mb_wait_until")):
            used = day_budget(con, budget, daily)[2] if budget else 0
            paused = float(get_meta(con, wait, "0") or 0) > now
            lk.append((svc, used, daily, key_set, 1 if (get_meta(con, err, "") or "").strip() else 0, paused))
        metric("lookups_used_today", "gauge", "Outside lookups made today (UTC).", [({"service": x[0]}, x[1]) for x in lk if x[0] != "malwarebazaar"])
        metric("lookups_daily_limit", "gauge", "Most lookups Huginn makes a day.", [({"service": x[0]}, x[2]) for x in lk if x[0] != "malwarebazaar"])
        metric("lookup_key_set", "gauge", "1 if a key is set for the service.", [({"service": x[0]}, 1 if x[3] else 0) for x in lk if x[0] not in ("netblock", "dronebl", "spamhaus", "abusix")])
        metric("lookup_error", "gauge", "1 if the last lookup failed.", [({"service": x[0]}, x[4]) for x in lk])
        metric("lookup_paused", "gauge", "1 while lookups are paused (allowance used up or refused key).", [({"service": x[0]}, 1 if x[5] else 0) for x in lk])
        size = sum(os.path.getsize(DB_PATH + x) for x in ("", "-wal") if os.path.exists(DB_PATH + x))
        metric("database_bytes", "gauge", "Size of the database and its write-ahead log.", [({}, size)])
        metric("backup_last_timestamp_seconds", "gauge", "When the last database backup was made (Unix time, 0 = never).",
               [({}, float(get_meta(con, "backup_last", "0") or 0))])
        metric("metrics_duration_seconds", "gauge", "Time taken to build these metrics.", [({}, round(time.time() - t0, 4))])
        _metrics_cache["at"], _metrics_cache["text"] = now, "".join(out)
        return _metrics_cache["text"]


def metrics_job(base, tok):
    u = urllib.parse.urlsplit(base)
    return ("- job_name: huginn\n  scheme: %s\n  metrics_path: /metrics\n  authorization:\n    credentials: %s\n  static_configs:\n    - targets: ['%s']"
            % (u.scheme or "http", tok, u.netloc or "huginn:8095"))


def metrics_card():
    # Settings: Prometheus metrics on or off, the address and token, and an example job.
    con = db()
    tok = metrics_token(con)
    base = getattr(_local, "base", "") or "http://huginn:8095"
    if METRICS_TOKEN:
        badge = sp_status("On · Managed in .env", "on")
        state, buttons = "The token comes from HUGINN_METRICS_TOKEN in .env.", ""
    elif tok:
        badge, state = sp_status("On", "on"), ""
        buttons = ('<div class="sp-act"><form method=post action="/settings/metrics"><input type=hidden name=on value=0><button class="btn-s">Turn off metrics</button></form>'
                   '<form method=post action="/settings/metrics/token"><button class="btn-s">New token</button></form></div>')
    else:
        badge, state = sp_status("Off"), "Nothing is served at /metrics while off."
        buttons = '<div class="sp-act"><form method=post action="/settings/metrics"><input type=hidden name=on value=1><button>Turn on metrics</button></form></div>'
    detail = ""
    if tok and not METRICS_TOKEN:
        job = metrics_job(base, tok)
        detail = ('<div class="feed"><div class="feed-h"><b>Address</b><button class="btn-s" data-copy="%s/metrics">Copy</button></div><div class="mono url">%s/metrics</div></div>'
                  '<div class="feed"><div class="feed-h"><b>Token</b> <span class="muted small">Send as Authorization: Bearer</span><button class="btn-s" data-copy-url="/settings/metrics/copy?what=token">Copy token</button></div>'
                  '<div class="mono url">••••%s</div></div>'
                  '<div class="feed"><div class="feed-h"><b>Prometheus job</b><button class="btn-s" data-copy-url="/settings/metrics/copy?what=job">Copy</button></div>'
                  '<div class="mono url small">%s</div></div>'
                  % (esc(base), esc(base), esc(tok[-4:]), esc(job.replace(tok, "••••")).replace("\n", "<br>")))
    return ('<div class="sp-panel" id="prometheus"><div class="sp-ph"><h3>Prometheus</h3>%s</div>'
            '<p>Counts for Prometheus and Grafana: events per decoy, attackers, sessions, blocklist size, sync health and lookup allowances.</p>'
            '<p class="sp-help">No IP addresses or attacker input.%s</p>%s%s'
            '<details><summary>Dashboard &amp; logs</summary><p class="sp-help">Grafana dashboard: <span class=mono>examples/grafana</span> in the source.</p>'
            '<p class="sp-help">For JSON logs, set <span class=mono>HUGINN_LOG_FORMAT=json</span>. Works with Grafana Loki, Graylog and Elasticsearch. '
            'Current format: %s.</p></details></div>'
            % (badge, (" " + esc(state)) if state else "", detail, buttons, esc(LOG_FORMAT)))


def base_url(h):
    host = h.headers.get("Host") or ("%s:%d" % (BIND, PORT))
    proto = "http"
    if h.client_address[0] in TRUSTED_PROXIES and h.headers.get("X-Forwarded-Proto") == "https":
        proto = "https"
    return "%s://%s" % (proto, host)


def v_blocklist(h, qs):
    con = db()
    mn, days, research, v6, tor = bl_params(qs)
    ips = blocklist_ips(con, mn, days, research, v6, tor)
    c2 = c2_list(con)
    token = get_meta(con, "feed_token")
    params = urllib.parse.urlencode({"min": mn, "days": days, "research": "1" if research else "0", "v6": "1" if v6 else "0", "tor": "1" if tor else "0"})
    feeds = "".join('<div class="feed"><div class="feed-h"><b>%s</b><button class="btn-s" data-copy="%s">Copy URL</button></div><div class="mono url">%s</div><div class="muted small">%s</div></div>'
                    % (esc(lab), esc("%s/feed/%s/%s?%s" % (base_url(h), token, fmt, params)), esc("%s/feed/••••/%s?%s" % (base_url(h), fmt, params)), esc(desc))
                    for fmt, lab, desc in FEEDS)
    flags = con.execute("SELECT f.*, e.cc FROM flags f LEFT JOIN enrich e USING(ip) ORDER BY f.updated DESC").fetchall()
    frows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (ip_link(f["ip"]), cc_html(f["cc"]), tag_html(f["flag"]), esc(f["note"] or ""), esc(fmt_ts(f["updated"]))) for f in flags)
    sel = lambda name, cur, vals: '<select name=%s>%s</select>' % (name, "".join('<option value="%s"%s>%s</option>' % (v, " selected" if str(v) == str(cur) else "", esc(l)) for v, l in vals))
    form = ('<form class="filters" method=get action="/blocklist"><label>Min score %s</label><label>Seen within %s</label>'
            '<label>Research scanners %s</label><label>Tor exits %s</label><label>IPv6 %s</label><button>Update</button></form>'
            % (sel("min", mn, [(1, "1 (everything)"), (3, "3 (tried to log in)"), (5, "5"), (10, "10 (ran commands)"), (15, "15 (dropped files)"), (25, "25")]),
               sel("days", days, [(1, "24 hours"), (7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year")]),
               sel("research", "1" if research else "0", [("0", "Exclude"), ("1", "Include")]), sel("tor", "1" if tor else "0", [("0", "Exclude"), ("1", "Include")]), sel("v6", "1" if v6 else "0", [("1", "Include"), ("0", "Exclude")])))
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
                 ("Web attack rules", web_rules_note()),
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
    log = "".join('<div class="cl"><span class="mono">%s</span><span class="muted">%s</span>%s</div>' % (esc(v), esc(d), cl_html(t)) for v, d, t in CHANGELOG)
    body = ('<h1>Account</h1>%s<div class="grid">'
            '<div class="card"><h3>Change password</h3><form method=post action="/account/password" class="stack">'
            '<label>Current password<input type=password name=current autocomplete=current-password required></label>'
            '<label>New password <span class=muted>(min 10 characters)</span><input type=password name=new minlength=10 autocomplete=new-password required></label>'
            '<label>Repeat new password<input type=password name=repeat minlength=10 autocomplete=new-password required></label>'
            '<button>Change password</button></form><p class="muted small">Changing it logs out every other browser.</p></div>'
            '<div class="card"><h3>Sessions</h3>%s<p>%s other active %s.</p>'
            '<form method=post action="/account/logout-others"><button class="btn-s"%s>Log out other sessions</button></form></div>'
            '<div class="card"><h3>System</h3>%s</div><div class="card cl-card"><h3>Changelog</h3><div class="cl-scroll">%s</div></div></div>'
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


SETTINGS_SECTIONS = [("appearance", "Appearance", "Make Huginn feel familiar."),
                     ("views", "Views & defaults", "Choose what appears and which ranges to use."),
                     ("notifications", "Notifications", "Pick the events you want to hear about."),
                     ("honeypot", "Honeypot", "Control the message shown at logout."),
                     ("lookups", "Lookups", "Enrich captured files and attacker addresses."),
                     ("metrics", "Metrics", "Connect your monitoring tools."),
                     ("about", "About", "Version, source and support.")]
# Confirmation per ?ok= code: (section it belongs to, text). Unknown codes show nothing.
SETTINGS_OK = {"1": ("", "Settings saved."), "appearance": ("appearance", "Appearance saved."),
               "views": ("views", "Views & defaults saved."), "notifications": ("notifications", "Notifications saved."),
               "test": ("notifications", "Test notification sent."),
               "vt": ("virustotal", "VirusTotal key saved. It works."),
               "vtbusy": ("virustotal", "VirusTotal key saved. It is valid, but over its allowance right now: lookups start when it resets."),
               "vtdel": ("virustotal", "VirusTotal key removed."), "mb": ("malwarebazaar", "MalwareBazaar key saved. It works."),
               "mbbusy": ("malwarebazaar", "MalwareBazaar key saved. abuse.ch is busy right now: lookups start on their own."),
               "mbdel": ("malwarebazaar", "MalwareBazaar key removed."), "gn": ("greynoise", "GreyNoise key saved. It works."),
               "gnbusy": ("greynoise", "GreyNoise key saved. GreyNoise is busy right now: lookups start on their own."),
               "gndel": ("greynoise", "GreyNoise key removed."),
               "hb": ("httpbl", "Saved. Project Honey Pot answers through this DNS server. It cannot confirm the key itself: if no attacker is ever listed, check the key."), "hbdel": ("httpbl", "Project Honey Pot key removed."),
               "nbon": ("netblock", "Saved. Netblocks are looked up in the background, newest attackers first."),
               "nboff": ("netblock", "Netblock lookups are off. What was already looked up stays."),
               "dblon": ("dronebl", "Saved. DroneBL answers through this DNS server; attackers are looked up in the background."),
               "dbloff": ("dronebl", "DroneBL lookups are off. What was already looked up stays."),
               "shon": ("spamhaus", "Saved. Spamhaus answers through this DNS server; attackers are looked up in the background."),
               "shoff": ("spamhaus", "Spamhaus lookups are off. What was already looked up stays."),
               "tor": ("tor", "Saved."), "toron": ("tor", "Saved. The Tor exit list is being downloaded and attackers are tagged."),
               "mon": ("metrics", "Metrics are on. Add the job to Prometheus."),
               "moff": ("metrics", "Metrics are off."), "mtok": ("metrics", "New metrics token. Update it in Prometheus."),
               "byeon": ("honeypot", "Logout message is on."), "byeoff": ("honeypot", "Logout message is off."),
               "idson": ("honeypot", "Suricata is starting. Loading the rules takes about a minute."), "idsoff": ("honeypot", "Suricata is off.")}
SETTINGS_ANCHORS = {"appearance", "views", "notifications", "honeypot", "virustotal", "malwarebazaar", "greynoise", "httpbl", "netblock", "dronebl", "spamhaus", "tor", "metrics", "about"}
# Settings-only wording for shared lists (the keys and the labels on other pages stay as they are).
CARD_LABELS = {"hero": "Summary banner"}
COL_LABELS = {"cc": "Country code", "sessions": "Sessions", "cmds": "Commands"}
EVENT_LABELS = {"bait": "Bait accessed"}
COFFEE_URL = "https://buymeacoffee.com/ancientswede"


def settings_url(code):
    # Where a settings form goes back to: the confirmation code and the part of the page it belongs to.
    sec = SETTINGS_OK.get(code, ("", ""))[0]
    return "/settings?ok=%s%s" % (urllib.parse.quote(code), ("#" + sec) if sec in SETTINGS_ANCHORS else "")


def sp_status(text, kind=""):
    # A status badge: words first, colour only as a hint.
    return '<span class="sp-status%s">%s</span>' % ((" " + kind) if kind else "", esc(text))


def v_settings(ok="", err="", at=""):
    # 0.41: one page with a section menu; every button applies only to its own form (Codex review, huginn-settings-ui).
    st = settings()
    at = at if at in SETTINGS_ANCHORS else ""
    okp = SETTINGS_OK.get(ok)

    def flash(sec):
        out = ""
        if okp and okp[0] == sec:
            out += '<p class="sp-ok" role="status">%s</p>' % esc(okp[1])
        if err and at == sec:
            out += '<p class="sp-err" role="alert" id="err-%s">%s</p>' % (sec, esc(err))
        return out
    top = ""
    if okp and not okp[0]:
        top += '<p class="sp-ok" role="status">%s</p>' % esc(okp[1])
    if err and not at:
        top += '<p class="sp-err" role="alert">%s</p>' % esc(err)
    elif err:
        # The error itself stands at its form further down; up here only where to find it.
        names = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "greynoise": "GreyNoise", "httpbl": "Project Honey Pot", "netblock": "Netblocks", "dronebl": "DroneBL", "spamhaus": "Spamhaus", "tor": "Tor exit nodes", "honeypot": "Logout message",
                 "notifications": "Notifications"}
        top += '<p class="sp-err">Not saved. <a href="#err-%s">See %s</a>.</p>' % (at, esc(names.get(at, at)))

    def choice(name, val, label, extra=""):
        return ('<label class="sp-choice"><input type=radio name=%s value="%s"%s>%s %s</label>'
                % (name, esc(val), " checked" if str(st[name]) == str(val) else "", extra, esc(label)))

    def check(name, val, label, on):
        return '<label class="sp-check"><input type=checkbox name=%s value="%s"%s> %s</label>' % (name, esc(val), " checked" if on else "", esc(label))

    def radios(legend, inner):
        return '<fieldset class="sp-row"><legend>%s</legend><div class="sp-fields"><div class="sp-choices">%s</div></div></fieldset>' % (esc(legend), inner)

    def select(id_, label, name, vals):
        opts = "".join('<option value="%s"%s>%s</option>' % (v, " selected" if str(st[name]) == str(v) else "", esc(l)) for v, l in vals)
        return '<div class="sp-row sp-inrow"><label for="%s">%s</label><div class="sp-fields"><select id="%s" name=%s>%s</select></div></div>' % (id_, esc(label), id_, name, opts)

    def save(scope, label):
        return '<div class="sp-foot"><button>%s</button></div>' % esc(label)

    def section(sid, inner):
        title, desc = next((t, d) for k, t, d in SETTINGS_SECTIONS if k == sid)
        n = [k for k, _t, _d in SETTINGS_SECTIONS].index(sid) + 1
        return ('<section id="%s" class="sp-sec" aria-labelledby="%s-h"><div class="sp-sh"><span class="sp-num">%02d</span>'
                '<div><h2 id="%s-h">%s</h2><p>%s</p></div></div>%s</section>' % (sid, sid, n, sid, esc(title), esc(desc), inner))

    appearance = section("appearance", flash("appearance") + (
        '<form method=post action="/settings" class="sp-panel"><input type=hidden name=scope value=appearance>'
        '<div class="sp-ph"><h3>Display</h3></div>%s%s%s'
        '<div class="sp-row sp-inrow"><label for="sp-title">Page title</label><div class="sp-fields"><input id="sp-title" name=title maxlength=40 value="%s"></div></div>'
        '%s%s</form>'
        % (radios("Theme", choice("theme", "auto", "System") + choice("theme", "light", "Light") + choice("theme", "dark", "Dark")),
           radios("Accent", "".join(choice("accent", a, a.capitalize(), '<span class="dot dot-%s"></span>' % a) for a in ACCENTS)),
           radios("Layout", choice("density", "comfortable", "Comfortable") + choice("density", "compact", "Compact")),
           esc(st["title"]), radios("Clock", choice("clock", "24", "24-hour") + choice("clock", "12", "12-hour (AM/PM)")),
           save("appearance", "Save appearance"))))

    hidden = esc(", ".join(st["hide_cc"] + ["AS" + a for a in st["hide_asn"]]))
    views = section("views", flash("views") + (
        '<form method=post action="/settings" class="sp-panel"><input type=hidden name=scope value=views>'
        '<div class="sp-sub"><h3>Overview cards</h3><div class="sp-grid">%s</div></div>'
        '<div class="sp-sub"><h3>Attacker columns</h3><div class="sp-grid">%s</div></div>'
        '<div class="sp-sub"><h3>Default ranges</h3>%s%s%s'
        '<p class="sp-help">Blocklist defaults apply to the Overview count, Blocklist page and feeds without parameters.</p></div>'
        '<div class="sp-sub"><h3>Attackers that come back</h3>%s'
        '<p class="sp-help">An address seen again after this many days with nothing at all from it is tagged returned, and stepped-up '
        'if it then gets further than before (for example ran commands after only knocking). Saving checks every stored attacker again.</p></div>'
        '<div class="sp-sub"><h3>Hidden countries &amp; networks</h3><label class="sp-label" for="sp-hidden">Country codes and AS numbers</label>'
        '<input id="sp-hidden" name=hidden_nets class="sp-wide" maxlength=500 placeholder="e.g. CN, RU, AS14061" value="%s">'
        '<p class="sp-help">Hidden from Overview and Attackers. Still recorded and blocklisted.</p></div>%s</form>'
        % ("".join(check("cards", k, CARD_LABELS.get(k, l), k in st["cards"]) for k, l in CARDS),
           "".join(check("ips_cols", k, COL_LABELS.get(k, lab), k in st["ips_cols"]) for k, lab, _s, _c in IPS_COLS),
           select("sp-ipsdays", "Attackers time range", "ips_days", [("1", "Last 24h"), ("7", "Last 7 days"), ("30", "Last 30 days"), ("90", "Last 90 days"), ("all", "All time")]),
           select("sp-blmin", "Minimum blocklist score", "bl_min", [(1, "1 (everything)"), (3, "3 (tried to log in)"), (5, "5"), (10, "10 (ran commands)"), (15, "15 (dropped files)"), (25, "25")]),
           select("sp-bldays", "Blocklist time range", "bl_days", [(1, "24 hours"), (7, "7 days"), (30, "30 days"), (90, "90 days"), (365, "1 year")]),
           select("sp-retdays", "Quiet days before returned", "return_days",
                  [(d, "%d days" % d) for d in sorted(set(RETURN_CHOICES) | {return_days_saved(st)})]),
           hidden, save("views", "Save views & defaults"))))

    if not NTFY_URL:
        nstate, ndest = sp_status("Not configured", "warn"), '<div class="sp-notice">Set <span class=mono>HUGINN_NTFY_URL</span> in <span class=mono>.env</span> to send notifications.</div>'
    else:
        u = urllib.parse.urlsplit(NTFY_URL)
        host = (u.hostname or "") + ((":%d" % u.port) if u.port else "")      # never user:password@ from the URL
        nstate = sp_status("Ready", "on") if st["notify"] else sp_status("Off")
        ndest = '<p class="sp-help">Destination: <span class=mono>%s</span> (HUGINN_NTFY_URL)%s.</p>' % (esc(host), " · Access token configured" if NTFY_TOKEN else "")
    notifications = section("notifications", flash("notifications") + (
        '<div class="sp-panel"><div class="sp-ph"><h3>ntfy</h3>%s</div>%s'
        '<form method=post action="/settings"><input type=hidden name=scope value=notifications>%s'
        '<fieldset class="sp-events"><legend>Notify me about</legend><div class="sp-grid">%s</div></fieldset>'
        '<p class="sp-help">At most one summary per hour.</p>%s</form>'
        '<form method=post action="/settings/test-ntfy" class="sp-test"><div><b>Test delivery</b><p class="sp-help">%s</p></div>'
        '<button class="btn-s"%s>Send test notification</button></form></div>'
        % (nstate, ndest, check("notify", "1", "Enable ntfy notifications", st["notify"]),
           "".join(check("notify_events", k, EVENT_LABELS.get(k, l), k in st["notify_events"]) for k, l in NOTIFY_EVENTS),
           save("notifications", "Save notifications"),
           "Uses saved settings." if NTFY_URL else "Available when the ntfy URL is configured. Uses saved settings.",
           "" if NTFY_URL else " disabled")))

    honeypot = section("honeypot", flash("honeypot") + honeypot_card() + ids_card())
    lookups = section("lookups", lookups_card(flash, at, err))
    metrics = section("metrics", flash("metrics") + metrics_card())
    about = section("about", (
        '<div class="sp-panel"><div class="sp-ph"><h3>Huginn %s</h3></div>'
        '<p>Free and open source (AGPL-3.0). Source, issues and releases are on '
        '<a href="https://github.com/%s" target="_blank" rel="noopener noreferrer">GitHub</a>.</p>'
        '<p>If Huginn is useful to you, you can <a href="%s" target="_blank" rel="noopener noreferrer">buy me a coffee</a>.</p></div>'
        % (esc(HUGINN_VERSION), esc(REPO), COFFEE_URL)))

    nav = "".join('<a href="#%s"><span>%02d</span>%s</a>' % (k, i, esc(t)) for i, (k, t, _d) in enumerate(SETTINGS_SECTIONS, 1))
    body = ('<div class="sp"><div class="sp-head"><div><h1>Settings</h1><p>Your workspace, notifications and integrations.</p></div>'
            '<p class="sp-rule">Each button applies only to its own form.</p></div>%s'
            '<div class="sp-layout"><nav class="sp-nav" aria-label="Settings sections"><div class="sp-cap">On this page</div>'
            '<div class="sp-items">%s</div></nav><div class="sp-main">%s%s%s%s%s%s%s</div></div></div>'
            % (top, nav, appearance, views, notifications, honeypot, lookups, metrics, about))
    return page("Settings", body, "/settings")


def goodbye_stats(con):
    # 0.41.1: how often the logout note was shown (event kind goodbye, one per session). Also in /metrics as kind="goodbye".
    n, ips, last, week = con.execute("SELECT COUNT(*), COUNT(DISTINCT ip), MAX(ts), COALESCE(SUM(ts>=?),0) FROM events WHERE kind='goodbye'",
                                     (time.time() - 7 * 86400,)).fetchone()
    if not n:
        return '<p class="sp-usage">Not shown to anyone yet.</p>'
    return ('<p class="sp-usage">Shown %s time%s to %s address%s · %s in the last 7 days · last %s</p>'
            % (num(n), "" if n == 1 else "s", num(ips), "" if ips == 1 else "es", num(week), esc(ago(last))))


def honeypot_card():
    # The optional logout note, turned on and off from here (hp-export "goodbye on|off" on the honeypot).
    con = db()
    items, at = protection_status(con)
    items = items or {}
    patched, on = items.get("patch:goodbye"), items.get("option:goodbye")
    if not items:
        badge, help_, button = sp_status("Not reported"), "Waiting for the honeypot's first report.", ""
    elif not patched:
        badge, help_, button = sp_status("Update required", "warn"), "Run update-honeypot.sh on the honeypot.", ""
    else:
        badge = sp_status("On", "on") if on else sp_status("Off")
        help_ = "Reported %s." % ago(at)
        button = ('<form method=post action="/settings/goodbye"><input type=hidden name=on value=%s><button%s>%s</button></form>'
                  % ("0" if on else "1", ' class="btn-s"' if on else "", "Turn off logout message" if on else "Turn on logout message"))
    return ('<div class="sp-panel"><div class="sp-ph"><h3>Logout message</h3>%s</div>'
            '<p>Show a short note when a logged-in session ends with <span class=mono>exit</span> or <span class=mono>logout</span>.</p>'
            '<div class="sp-notice"><b>Reveals this is a honeypot.</b><p>A bot that types exit may learn to recognise it. Off by default.</p></div>'
            '<details><summary>Message preview</summary><pre class="bye-ex">  Thanks for the 4 min 12 s, 203.0.113.7.\n'
            '  You typed 9 lines. All of it is logged, along with your address.\n  Say hi to the rest of the botnet.</pre>'
            '<p class="sp-help">Sent after the session is logged. Not sent on a plain disconnect.</p></details>'
            '%s<div class="sp-act">%s<span class="sp-help">%s</span></div></div>' % (badge, goodbye_stats(con), button, esc(help_)))


def ids_card():
    # Suricata on the honeypot. Set up once there (update-honeypot.sh --suricata-on installs the package and the rules);
    # after that it can be turned on and off here ("ids on|off" to the locked hp-export key).
    con = db()
    try:
        st = json.loads(get_meta(con, "hp_ids", "{}") or "{}")
    except ValueError:
        st = {}
    items, _at = protection_status(con)
    items = items or {}
    running = items.get("running:suricata")
    ready = items.get("option:suricata")           # installed, configured and with rules (hp-export 0.44)
    week = con.execute("SELECT COUNT(DISTINCT sid), COUNT(DISTINCT ip), COALESCE(SUM(n),0) FROM ids WHERE last>=?", (time.time() - 7 * 86400,)).fetchone()
    button = ""
    form = lambda on, label: ('<form method=post action="/settings/ids"><input type=hidden name=on value=%s><button%s>%s</button></form>'
                              % ("1" if on else "0", "" if on else ' class="btn-s"', label))
    if not st.get("on"):
        badge = sp_status("Off")
        if ready:
            info, button = "", form(True, "Turn on Suricata")
        else:
            info = ('<p class="sp-help">Set it up once on the honeypot: <span class=mono>./update-honeypot.sh --suricata-on</span> '
                    '(installs Suricata and its rules, about 500 MB of memory; without internet there, see Suricata IDS in docs/integrations.md). After that it can be turned on and off here.</p>')
    else:
        badge = sp_status("Not running", "warn") if running is False else sp_status("On", "on")
        rules = st.get("rules")
        info = '<p class="sp-usage">%s · last 7 days: %s rules matched, %s IPs, %s hits</p>' % (
            ("rules updated %s" % ago(rules)) if isinstance(rules, (int, float)) else "no rules yet", num(week[0]), num(week[1]), num(week[2]))
        if isinstance(st.get("dropped"), int) and st["dropped"] > 0:
            info += ('<p class="sp-help">The honeypot holds %s more alerts than one sync takes (%s): the oldest of them were not counted. '
                     'Usually one flood; it clears when eve.json rotates.</p>' % (num(st["dropped"]), num(20000)))
        if isinstance(rules, (int, float)) and time.time() - rules > 14 * 86400:
            info += '<p class="sp-help">The rules are over two weeks old. Without internet on the honeypot: ./update-honeypot.sh --suricata-rules FILE.</p>'
        button = form(False, "Turn off Suricata")
    return ('<div class="sp-panel" id="suricata"><div class="sp-ph"><h3>Suricata IDS</h3>%s</div>'
            '<p>Names known attacks by rule and CVE (Emerging Threats Open). Listens only; never blocks traffic.</p>%s'
            '%s</div>' % (badge, info, ('<div class="sp-act">%s</div>' % button) if button else ""))


def key_form(provider, label, saved, ph_new, invalid=False):
    # One key form: a visible label, an empty password field (a saved key is never shown again).
    bad = (' aria-invalid=true aria-describedby="err-%s"' % provider) if invalid else ""
    return ('<form method=post action="/settings/%s" class="sp-key"><label for="sp-%s-key">%s</label>'
            '<div class="sp-keyrow"><input type=password id="sp-%s-key" name=key autocomplete=off spellcheck=false maxlength=128 placeholder="%s"%s>'
            '<button>Save and test</button></div></form>' % (provider, provider, esc(label), provider, "Paste replacement key" if saved else ph_new, bad))


def hb_form(con, saved, invalid=False):
    # The Project Honey Pot form: which DNS server to ask, and the key (empty keeps a saved key, to change only the server).
    cur = hb_dns(con)
    bad = ' aria-invalid=true aria-describedby="err-httpbl"' if invalid else ""
    return ('<form method=post action="/settings/httpbl" class="sp-key"><label for="sp-httpbl-dns">DNS server</label>'
            '<div class="sp-keyrow">%s</div>'
            '<label for="sp-httpbl-key" class="sp-gap">Access key</label>'
            '<div class="sp-keyrow"><input type=password id="sp-httpbl-key" name=key autocomplete=off spellcheck=false maxlength=128 placeholder="%s"%s>'
            '<button>Save and test</button></div></form>'
            % (dns_picker("sp-httpbl-dns", cur), "Leave empty to keep the saved key" if saved else "Paste key", bad))


def remove_form(provider, saved):
    return ('<form method=post action="/settings/%s/remove" class="sp-remove"><button class="btn-s">Remove saved key</button></form>' % provider) if saved else ""


def lookups_card(flash=lambda s: "", at="", err=""):
    # Outside lookups by hash or address. Keys are pasted here and never shown again, only whether one is set and where from.
    con = db()
    lasterr = lambda k: ('<p class="sp-err small">Last error: %s</p>' % esc(get_meta(con, k, ""))) if get_meta(con, k, "") else ""

    saved = VT_KEY_RE.fullmatch(get_meta(con, "vt_key", "") or "") is not None
    src = "Saved key" if saved else ("Environment key (HUGINN_VIRUSTOTAL_KEY)" if VT_KEY else "")
    _left, _t, vused = day_budget(con, "vt_day", VT_DAILY)
    vn = con.execute("SELECT COUNT(*), COALESCE(SUM(data LIKE '%\"found\": false%'),0) FROM vt").fetchone()
    vt = ('<div class="sp-panel" id="virustotal"><div class="sp-ph"><h3>VirusTotal</h3>%s</div>%s'
          '<p>File verdicts. Sends SHA-256 hashes only; never uploads files.</p>%s%s%s%s'
          '<p class="sp-help">Free key: 500 lookups a day, 4 a minute. Daily cap here: %s (HUGINN_VIRUSTOTAL_DAILY).</p>%s</div>'
          % (sp_status("On", "on") if src else sp_status("Off · No key"), flash("virustotal"),
             ('<p class="sp-usage">%s · %s / %s lookups today · %s files checked · %s unknown hashes</p>'
              % (esc(src), num(vused), num(VT_DAILY), num(vn[0]), num(vn[1]))) if src else "",
             lasterr("vt_error"), key_form("virustotal", "API key", saved, "Paste key", bool(err) and at == "virustotal"), remove_form("virustotal", saved), num(VT_DAILY), ""))

    saved = MB_KEY_RE.fullmatch(get_meta(con, "mb_key", "") or "") is not None
    src = "Saved key" if saved else ("Environment key (HUGINN_MALWAREBAZAAR_KEY)" if MB_KEY else "")
    n = con.execute("SELECT COUNT(*), COALESCE(SUM(mb LIKE '%\"found\": true%'),0) FROM files WHERE mb_checked IS NOT NULL").fetchone()
    mb = ('<div class="sp-panel" id="malwarebazaar"><div class="sp-ph"><h3>MalwareBazaar</h3>%s</div>%s'
          '<p>File families and tags from abuse.ch. Sends SHA-256 hashes only.</p>%s%s%s%s'
          '<p class="sp-help">Needs a free key from auth.abuse.ch.</p></div>'
          % (sp_status("On", "on") if src else sp_status("Off · No key"), flash("malwarebazaar"),
             ('<p class="sp-usage">%s · %s files checked · %s known files</p>' % (esc(src), num(n[0]), num(n[1]))) if src else "",
             lasterr("mb_error"), key_form("malwarebazaar", "Auth-Key", saved, "Paste key", bool(err) and at == "malwarebazaar"), remove_form("malwarebazaar", saved)))

    saved = GN_KEY_RE.fullmatch(get_meta(con, "gn_key", "") or "") is not None
    src = "Saved key" if saved else ("Environment key (HUGINN_GREYNOISE_KEY)" if GN_KEY else "")
    daily = gn_daily(con)
    _left, _t, used = day_budget(con, "gn_day", daily)
    g = con.execute("SELECT COUNT(*), COALESCE(SUM(data LIKE '%\"class\": \"benign\"%'),0) FROM greynoise").fetchone()
    badge = sp_status("Off") if not daily else (sp_status("On", "on") if src else sp_status("On · Free allowance", "on"))
    gn = ('<div class="sp-panel" id="greynoise"><div class="sp-ph"><h3>GreyNoise</h3>%s</div>%s'
          '<p>Identify known mass scanners. Sends IP addresses, top attackers first.</p>%s%s%s%s'
          '<p class="sp-help">No key: %s lookups a day. Free key from viz.greynoise.io: %s a day (HUGINN_GREYNOISE_DAILY changes both). '
          'Benign scanners count as research unless they logged in or ran commands.</p></div>'
          % (badge, flash("greynoise"),
             ('<p class="sp-usage">%s%s / %s lookups today · %s addresses checked · %s benign scanners</p>'
              % ((esc(src) + " · ") if src else "", num(used), num(daily), num(g[0]), num(g[1]))) if daily else "",
             lasterr("gn_error"), key_form("greynoise", "API key (optional)", saved, "Paste key", bool(err) and at == "greynoise"), remove_form("greynoise", saved),
             num(GN_DAILY if GN_DAILY >= 0 else 20), num(GN_DAILY if GN_DAILY >= 0 else 40)))

    saved = HB_KEY_RE.fullmatch(get_meta(con, "hb_key", "") or "") is not None
    src = "Saved key" if saved else ("Environment key (HUGINN_HTTPBL_KEY)" if hb_key(con) else "")
    _left, _t, used = day_budget(con, "hb_day", HB_DAILY)
    h = con.execute("SELECT COUNT(*), COALESCE(SUM(data LIKE '%\"listed\": true%'),0) FROM httpbl").fetchone()
    badge = sp_status("Off · No key") if not src else (sp_status("On", "on") if HB_DAILY else sp_status("Off"))
    hb = ('<div class="sp-panel" id="httpbl"><div class="sp-ph"><h3>Project Honey Pot</h3>%s</div>%s'
          '<p>Known web spammers, e-mail harvesters and suspicious visitors (http:BL). Sends IPv4 addresses, top attackers first.</p>%s%s%s%s'
          '<p class="sp-help">Needs a free access key (12 letters) from projecthoneypot.org, under http:BL. Up to %s lookups a day '
          '(HUGINN_HTTPBL_DAILY). Pi-hole and many routers drop its answers (DNS rebinding protection): then pick a public DNS server. '
          'DNS is not encrypted, so the key and the address can be read on the way.</p></div>'
          % (badge, flash("httpbl"),
             ('<p class="sp-usage">%s · %s / %s lookups today · %s addresses checked · %s listed</p>'
              % (esc(src) + " · DNS " + esc(hb_dns_label(hb_dns(con))), num(used), num(HB_DAILY), num(h[0]), num(h[1]))) if src else "",
             lasterr("hb_error"), hb_form(con, saved, bool(err) and at == "httpbl"), remove_form("httpbl", saved),
             num(HB_DAILY)))

    on = nb_on(con)
    _left, _t, used = day_budget(con, "nb_day", NB_DAILY)
    nn = con.execute("SELECT COUNT(*), COUNT(DISTINCT prefix), (SELECT COUNT(*) FROM ips) FROM netblock").fetchone()
    cur = nb_dns(con)
    opts = list(HB_DNS_CHOICES) + ([] if cur in dict(HB_DNS_CHOICES) else [(cur, cur)])
    nb = ('<div class="sp-panel" id="netblock"><div class="sp-ph"><h3>Netblocks</h3>%s</div>%s'
          '<p>The announced network block each attacker comes from, its owner, registry and allocation date (Team Cymru, over DNS). '
          'Sends IP addresses, no key needed.</p>%s%s'
          '<form method=post action="/settings/netblock" class="sp-key"><label class="sp-check"><input type=checkbox name=on value=1%s> Look up netblocks</label>'
          '<label class="sp-check"><input type=checkbox name=abuse value=1%s> Also look up abuse contacts (Abusix)</label>'
          '<label for="sp-netblock-dns" class="sp-gap">DNS server</label><div class="sp-keyrow">%s'
          '<button>Save</button></div></form>'
          '<p class="sp-help">Each address is looked up again after 30 days. Up to %s lookups a day (HUGINN_NETBLOCK_DAILY). '
          'Abuse contacts come from the free <a href="https://abusix.com/contactdb" target="_blank" rel="noopener noreferrer">Abusix Abuse Contact DB</a> '
          '(same DNS server); a report written with one should say so, and the Report link does. '
          'DNS is not encrypted, so the address can be read on the way.</p></div>'
          % (sp_status("On", "on") if on and NB_DAILY else sp_status("Off"), flash("netblock"),
             ('<p class="sp-usage">DNS %s · %s / %s lookups today · %s of %s attackers looked up · %s blocks</p>'
              % (esc(hb_dns_label(cur)), num(used), num(NB_DAILY), num(nn[0]), num(nn[2]), num(nn[1]))) if on else "",
             lasterr("nb_error"), " checked" if on else "", " checked" if ab_on(con) else "",
             dns_picker("sp-netblock-dns", cur),
             num(NB_DAILY)))

    on = dbl_on(con)
    _left, _t, used = day_budget(con, "dbl_day", DBL_DAILY)
    dn = con.execute("SELECT COUNT(*), COALESCE(SUM(codes NOT IN ('', '[]')), 0) FROM dronebl").fetchone()
    cur = dbl_dns(con)
    opts = list(HB_DNS_CHOICES) + ([] if cur in dict(HB_DNS_CHOICES) else [(cur, cur)])
    dbl = ('<div class="sp-panel" id="dronebl"><div class="sp-ph"><h3>DroneBL</h3>%s</div>%s'
           '<p>Whether an attacker is a known drone, botnet member, open proxy, brute forcer or compromised router '
           '(<a href="https://dronebl.org" target="_blank" rel="noopener noreferrer">dronebl.org</a>, over DNS). Sends IPv4 addresses, no key needed. '
           'A label on the attacker page, it does not change the score.</p>%s%s'
           '<form method=post action="/settings/dronebl" class="sp-key"><label class="sp-check"><input type=checkbox name=on value=1%s> Look up on DroneBL</label>'
           '<label for="sp-dronebl-dns" class="sp-gap">DNS server</label><div class="sp-keyrow">%s'
           '<button>Save</button></div></form>'
           '<p class="sp-help">DroneBL answers in 127.0.0.x, which Pi-hole and many routers drop: Saving tests the DNS server first. '
           'Each address is looked up again after a week, up to %s lookups a day (HUGINN_DRONEBL_DAILY). DNS is not encrypted, so the address can be read on the way.</p></div>'
           % (sp_status("On", "on") if on and DBL_DAILY else sp_status("Off"), flash("dronebl"),
              ('<p class="sp-usage">DNS %s · %s / %s lookups today · %s attackers looked up · %s listed</p>'
               % (esc(hb_dns_label(cur)), num(used), num(DBL_DAILY), num(dn[0]), num(dn[1]))) if on else "",
              lasterr("dbl_error"), " checked" if on else "",
              dns_picker("sp-dronebl-dns", cur),
              num(DBL_DAILY)))

    on = sh_on(con)
    _left, _t, used = day_budget(con, "sh_day", SH_DAILY)
    sn = con.execute("SELECT COUNT(*), COALESCE(SUM(codes NOT IN ('', '[]')), 0) FROM spamhaus").fetchone()
    cur = sh_dns(con)
    shp = ('<div class="sp-panel" id="spamhaus"><div class="sp-ph"><h3>Spamhaus</h3>%s</div>%s'
           '<p>Whether an attacker is on Spamhaus ZEN: a spam source (SBL), an exploited or infected machine (XBL), a hijacked network '
           '(DROP), or a home or end-user range (PBL). Free for non-commercial use, IPv4 only, a label that does not change the score.</p>'
           '<p><b>Needs your own DNS resolver.</b> Spamhaus refuses questions that come through Cloudflare, Quad9, Google and other public '
           'resolvers. Run <a href="https://www.nlnetlabs.nl/projects/unbound/about/" target="_blank" rel="noopener noreferrer">Unbound</a> '
           'on this machine and choose 127.0.0.1 (see Own DNS resolver in docs/integrations.md).</p>%s%s'
           '<form method=post action="/settings/spamhaus" class="sp-key"><label class="sp-check"><input type=checkbox name=on value=1%s> Look up on Spamhaus</label>'
           '<label for="sp-spamhaus-dns" class="sp-gap">DNS server</label><div class="sp-keyrow">%s'
           '<button>Save</button></div></form>'
           '<p class="sp-help">Saving tests the server with Spamhaus\' test address. Up to %s lookups a day (HUGINN_SPAMHAUS_DAILY), each address '
           'again after a week: the free mirrors are for low volumes.</p></div>'
           % (sp_status("On", "on") if on and SH_DAILY and cur not in PUBLIC_DNS else sp_status("Off · Needs own resolver") if on else sp_status("Off"),
              flash("spamhaus"),
              ('<p class="sp-usage">DNS %s · %s / %s lookups today · %s attackers looked up · %s listed</p>'
               % (esc(hb_dns_label(cur)), num(used), num(SH_DAILY), num(sn[0]), num(sn[1]))) if on else "",
              lasterr("sh_error"), " checked" if on else "", dns_picker("sp-spamhaus-dns", cur), num(SH_DAILY)))

    on, inbl = tor_on(con), tor_bl(con)
    fetched = float(get_meta(con, "tor_fetched", "0") or 0)
    tn = con.execute("SELECT COUNT(*) FROM ips WHERE (','||COALESCE(tags,'')||',') LIKE '%,tor,%'").fetchone()[0]
    tor = ('<div class="sp-panel" id="tor"><div class="sp-ph"><h3>Tor exit nodes</h3>%s</div>%s'
           '<p>Tags attackers that came through Tor. Downloads the Tor Project\'s list of exit addresses once a day; sends nothing.</p>%s%s'
           '<form method=post action="/settings/tor" class="sp-key"><label class="sp-check"><input type=checkbox name=on value=1%s> Check attackers against the Tor exit list</label>'
           '<label class="sp-check"><input type=checkbox name=bl value=1%s> Put Tor exits on the blocklist too</label>'
           '<div class="sp-keyrow"><button>Save</button></div></form>'
           '<p class="sp-help">A Tor exit is shared by many people, so an attack from one says little about the next visitor: tagged attackers never count as '
           'coming back, and blocking them mostly blocks Tor users. Your manual Always block still wins. Each blocklist feed can also choose with tor=0 or tor=1.</p></div>'
           % (sp_status("On", "on") if on else sp_status("Off"), flash("tor"),
              ('<p class="sp-usage">%s · %s attackers came through Tor</p>' % (
                  ("%s exit addresses, list updated %s" % (num(int(float(get_meta(con, "tor_count", "0") or 0))), ago(fetched))) if fetched else "list not downloaded yet",
                  num(tn))) if on else "",
              lasterr("tor_error"), " checked" if on else "", " checked" if inbl else ""))
    return vt + mb + gn + hb + nb + dbl + shp + tor


SETTINGS_SCOPES = ("appearance", "views", "notifications")


def save_settings(f, lists):
    # 0.41: each form on Settings sends a scope and only that part changes; the rest stays as saved. Without a scope (an
    # older form) everything is read as before. An unknown scope changes nothing and returns False.
    scope = f.get("scope", "")
    if scope and scope not in SETTINGS_SCOPES:
        return False
    every = not scope
    con = db()
    # Read, change and write in one write transaction: two forms saved at the same time cannot undo each other (Codex 049 M14).
    with con:
        con.execute("BEGIN IMMEDIATE")
        st = settings(con)
        if every or scope == "appearance":
            if f.get("theme") in THEMES:
                st["theme"] = f["theme"]
            if f.get("accent") in ACCENTS:
                st["accent"] = f["accent"]
            if f.get("density") in ("comfortable", "compact"):
                st["density"] = f["density"]
            title = re.sub(r"[\x00-\x1f]", "", (f.get("title") or "").strip())[:40]
            st["title"] = title or "Huginn"
            if f.get("clock") in ("24", "12"):
                st["clock"] = f["clock"]
        if every or scope == "views":
            st["cards"] = [k for k, _ in CARDS if k in lists.get("cards", [])]
            if f.get("ips_days") in ("1", "7", "30", "90", "all"):
                st["ips_days"] = f["ips_days"]
            if f.get("bl_min") in ("1", "3", "5", "10", "15", "25"):
                st["bl_min"] = int(f["bl_min"])
            if f.get("bl_days") in ("1", "7", "30", "90", "365"):
                st["bl_days"] = int(f["bl_days"])
            st["ips_cols"] = [k for k, *_ in IPS_COLS if k in lists.get("ips_cols", [])]
            cc, asn = [], []
            for tok in re.split(r"[\s,;]+", (f.get("hidden_nets") or "").upper())[:100]:
                if re.fullmatch(r"[A-Z]{2}", tok):
                    cc.append(tok)
                elif re.fullmatch(r"(AS)?\d{1,10}", tok):
                    asn.append(tok.lstrip("AS"))
            st["hide_cc"], st["hide_asn"] = sorted(set(cc)), sorted(set(asn))
            if (f.get("return_days") or "").isdigit() and (int(f["return_days"]) in RETURN_CHOICES or int(f["return_days"]) == RETURN_DAYS):
                st["return_days"] = int(f["return_days"])
        if every or scope == "notifications":
            st["notify"] = f.get("notify") == "1"
            st["notify_events"] = [k for k, _ in NOTIFY_EVENTS if k in lists.get("notify_events", [])]
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('settings',?)", (json.dumps(st),))
    if get_meta(con, "returned_days") != str(return_days(con)):
        recheck_returned(con)
    return True


def return_days_saved(st):
    try:
        return max(1, min(365, int(st.get("return_days", RETURN_DAYS))))
    except (TypeError, ValueError):
        return RETURN_DAYS


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
a.kpi{display:block;color:inherit;text-decoration:none;transition:border-color .15s}a.kpi:hover{border-color:var(--accent);text-decoration:none}a.kpi:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
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
.sev{font-size:12px;font-weight:600}.sev.s1{color:var(--red)}.sev.s2{color:var(--orange)}.sev.s3,.sev.s4{color:var(--muted)}
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
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy],[data-copy-url]');if(!b)return;e.preventDefault();
(b.dataset.copyUrl?fetch(b.dataset.copyUrl,{credentials:'same-origin',cache:'no-store'}).then(function(r){if(!r.ok)throw 0;return r.text()}).then(copyText):copyText(b.dataset.copy)).then(function(){var t=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=t},1200)})});
document.querySelectorAll('input[data-filter]').forEach(function(inp){var t=document.getElementById(inp.dataset.filter);if(!t)return;
inp.addEventListener('input',function(){var q=inp.value.toLowerCase();t.querySelectorAll('tbody tr').forEach(function(r){r.hidden=!!q&&r.textContent.toLowerCase().indexOf(q)<0})})});
(function(){
var keys=[['g o','Overview'],['g n','New'],['g a','Attackers'],['g c','Campaigns'],['g p','Personas'],['g e','Engagement'],['g h','Help'],['g f','Files'],['g r','Credentials'],['g b','Blocklist'],['g s','Settings'],
['/','Search / filter'],['t','Switch theme'],['Space','Play / pause a replay'],['?','This help'],['Esc','Close']];
var box=null;function hide(){if(box){box.remove();box=null}}
function show(){if(box){hide();return}box=document.createElement('div');box.className='kbd-help';var c=document.createElement('div');c.className='card';
var h=document.createElement('h3');h.textContent='Keyboard shortcuts';c.appendChild(h);keys.forEach(function(k){var r=document.createElement('div');r.className='kr';
var a=document.createElement('kbd');a.textContent=k[0];var b=document.createElement('span');b.textContent=k[1];r.appendChild(a);r.appendChild(b);c.appendChild(r)});
box.appendChild(c);box.addEventListener('click',function(e){if(e.target===box)hide()});document.body.appendChild(box)}
var hb=document.getElementById('kbdHelp');if(hb)hb.addEventListener('click',function(e){e.preventDefault();show()});
var g=false,gt=null,map={o:'/',n:'/new',a:'/ips',c:'/campaigns',p:'/personas',e:'/engagement',h:'/help',f:'/files',r:'/creds',b:'/blocklist',s:'/settings'};
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
(function(){var nav=document.querySelector('.ctabs');if(!nav)return;var links=nav.querySelectorAll('[data-ctab]'),panes=document.querySelectorAll('[data-cpane]');
function pick(k,push){var ok=false;panes.forEach(function(p){if(p.dataset.cpane===k)ok=true});if(!ok)k=links[0].dataset.ctab;
panes.forEach(function(p){p.hidden=p.dataset.cpane!==k});links.forEach(function(a){if(a.dataset.ctab===k)a.setAttribute('aria-current','true');else a.removeAttribute('aria-current')});
try{localStorage.setItem('hgCtab',k)}catch(e){}if(push)try{history.replaceState(null,'','#c-'+k)}catch(e){}}
document.body.classList.add('ctabs-js');
links.forEach(function(a){a.addEventListener('click',function(ev){ev.preventDefault();pick(a.dataset.ctab,true)})});
var h=(location.hash||'').replace('#c-',''),saved='';try{saved=localStorage.getItem('hgCtab')||''}catch(e){}pick(h||saved,false)})();
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
// Settings: save a form in the background and swap in only its own panel (or section), so the page keeps its place.
// Appearance changes the whole page and still reloads. A form is never sent twice: if the answer is lost, the panel says
// so and a reload shows what was saved. One save at a time per panel; a lost session reloads the page (to the login).
(function(){var main=document.querySelector('.sp-main');if(!main)return;
function unit(f){var p=f.closest('.sp-panel[id]');return p||f.closest('.sp-sec')}
main.addEventListener('submit',function(ev){var f=ev.target;if(!(f instanceof HTMLFormElement))return;
var sc=f.querySelector('input[name=scope]');if(sc&&sc.value==='appearance')return;
var box=unit(f);if(!box||!box.id||!window.fetch||!window.DOMParser)return;ev.preventDefault();
if(box.getAttribute('aria-busy')==='true')return;
var btn=ev.submitter||f.querySelector('button'),body=new URLSearchParams(new FormData(f));if(ev.submitter&&ev.submitter.name)body.append(ev.submitter.name,ev.submitter.value);
if(btn)btn.disabled=true;box.setAttribute('aria-busy','true');
function done(){box.removeAttribute('aria-busy');if(btn)btn.disabled=false}
function lost(){done();var p=box.querySelector('.sp-lost');if(!p){p=document.createElement('p');p.className='sp-err sp-lost';p.setAttribute('role','alert');box.insertBefore(p,box.firstChild.nextSibling)}
p.textContent='No answer from Huginn, so it is not known whether this was saved. Reload the page to see.';p.setAttribute('tabindex','-1');p.focus()}
fetch(f.action,{method:'POST',body:body,credentials:'same-origin',redirect:'follow'}).then(function(r){
if(r.status===401||new URL(r.url,location.href).origin!==location.origin){location.reload();return null}
return r.text()}).then(function(t){if(t===null)return;
var doc=new DOMParser().parseFromString(t,'text/html'),fresh=doc.getElementById(box.id);if(!fresh||!doc.querySelector('.sp-main')){lost();return}
box.innerHTML=fresh.innerHTML;box.removeAttribute('aria-busy');
var msg=box.querySelector('.sp-err[role=alert],.sp-ok[role=status]')||doc.querySelector('.sp-ok[role=status],.sp-err[role=alert]');
if(msg&&!box.contains(msg)){var c=msg.cloneNode(true);box.insertBefore(c,box.firstChild.nextSibling);msg=c}
if(msg){msg.setAttribute('tabindex','-1');msg.focus({preventScroll:true});
var b=msg.getBoundingClientRect();if(b.top<0||b.bottom>innerHeight)msg.scrollIntoView({block:'center'})}}).catch(lost)})})();
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
        ".cl-h{font-weight:600}.cl-l{margin:4px 0 2px;padding-left:18px}.cl-l li{margin:2px 0}"
        # 0.41.1: the changelog takes the height of the System card next to it and scrolls (it does not stretch the row).
        ".cl-card{display:flex;flex-direction:column;min-height:320px}.cl-scroll{flex:1 1 0;min-height:0;overflow-y:auto;padding-right:6px}"
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
        ".scr-diff{font-size:12px;margin-top:2px;max-width:640px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--hot)}"
        ".scr-pv{margin-top:3px;font-size:12px}.scr-pv summary{cursor:pointer;color:var(--accent);width:max-content}"
        ".scr-pv .pv{margin-top:4px;max-width:640px;max-height:260px;overflow:auto;border:1px solid var(--line);border-radius:6px;padding:6px 8px;background:var(--panel2)}"
        ".pv-l{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.45}.pv-n{display:inline-block;min-width:2.6em;color:var(--muted);user-select:none}"
        ".pv-d{background:var(--accent2);border-radius:3px}"
        ".bye-ex{margin:8px 0;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel2);font-size:12px;white-space:pre-wrap}"
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
CSS += ".key-input{flex:1 1 360px;max-width:560px;font-family:var(--mono,monospace)}.help td:first-child{width:220px;vertical-align:top}.help td{line-height:1.5}@media (max-width:800px){.help tr{display:block;padding:8px 0;border-bottom:1px solid var(--line)}.help tr:last-child{border:0}.help td,.help td:first-child{display:block;border:0;padding:2px 0;width:auto;white-space:normal}}"
# 0.41 Settings page (Codex proposal huginn-settings-ui): section menu, one form per part, status badges. All under .sp.
CSS += (".sp{--sp-pad:24px;--sp-row:16px;max-width:1360px;margin:0 auto}html[data-density=compact] .sp{--sp-pad:16px;--sp-row:10px}"
        ".sp .sp-head{display:flex;justify-content:space-between;align-items:center;gap:16px;margin:8px 0 28px}.sp .sp-head h1{margin:0 0 6px}.sp .sp-head p{margin:0;color:var(--muted)}"
        ".sp .sp-rule{font-size:12px;padding:8px 12px;background:var(--panel);border:1px solid var(--line);border-radius:6px}"
        ".sp .sp-layout{display:grid;grid-template-columns:210px minmax(0,1fr);gap:60px;align-items:start}"
        ".sp .sp-nav{position:sticky;top:72px}.sp .sp-cap{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);font-weight:700;padding:0 12px;margin-bottom:10px}"
        ".sp .sp-nav a{display:flex;align-items:center;gap:13px;color:var(--muted);padding:10px 12px;border-radius:6px;text-decoration:none}"
        ".sp .sp-nav a:hover,.sp .sp-nav a:focus-visible{background:var(--accent2);color:var(--accent)}.sp .sp-nav a span{font-size:11px;font-variant-numeric:tabular-nums;opacity:.8}"
        ".sp .sp-main{min-width:0;max-width:1060px}.sp .sp-sec{margin-bottom:40px;scroll-margin-top:72px}.sp .sp-sec .sp-panel{scroll-margin-top:72px}"
        ".sp .sp-sh{display:flex;gap:14px;margin-bottom:16px;align-items:flex-start}.sp .sp-sh h2{font-size:20px;margin:0 0 2px}.sp .sp-sh p{margin:0;color:var(--muted);font-size:13px}"
        ".sp .sp-num{font-size:11px;font-weight:650;color:var(--accent);background:var(--accent2);border:1px solid var(--line);border-radius:7px;display:grid;place-items:center;min-width:32px;height:32px}"
        ".sp .sp-panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:var(--sp-pad);margin-bottom:12px}"
        ".sp .sp-panel>p{max-width:80ch}.sp .sp-ph{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.sp .sp-ph h3{font-size:16px;margin:0}"
        ".sp .sp-status{border:1px solid var(--line);border-radius:5px;padding:3px 8px;font-size:12px;font-weight:600;background:var(--panel2);white-space:nowrap}"
        ".sp .sp-status.on{color:var(--green)}.sp .sp-status.warn{color:var(--orange)}"
        ".sp .sp-row{display:grid;grid-template-columns:190px minmax(0,1fr);margin:0;padding:var(--sp-row) 0;border:0;border-bottom:1px solid var(--line);min-width:0}"
        ".sp fieldset.sp-row{display:flow-root}.sp fieldset.sp-row legend{float:left;width:190px;padding:8px 12px 0 0;font-weight:500}.sp fieldset.sp-row .sp-fields{margin-left:190px}"
        ".sp .sp-row:last-of-type{border-bottom:0}.sp .sp-inrow label{padding-top:8px;font-weight:500}.sp .sp-fields{min-width:0}.sp .sp-inrow input{width:280px;max-width:100%}"
        ".sp .sp-choices{display:flex;flex-wrap:wrap;gap:8px}.sp .sp-choice{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:6px;padding:7px 10px;min-height:38px;cursor:pointer}"
        ".sp .sp-choice:has(input:checked){border-color:var(--accent);background:var(--accent2)}.sp .sp-choice .dot{width:10px;height:10px}"
        ".sp .sp-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:24px}.sp .sp-check{display:flex;gap:10px;align-items:center;min-height:36px;cursor:pointer}"
        ".sp .sp-sub{padding:0 0 22px;margin-bottom:22px;border-bottom:1px solid var(--line)}.sp .sp-sub h3{margin:0 0 10px;font-size:15px}.sp .sp-sub:last-of-type{border:0;margin-bottom:0;padding-bottom:0}"
        ".sp .sp-label{display:block;font-size:13px;margin-bottom:8px}.sp .sp-wide{width:100%}.sp .sp-help{font-size:13px;color:var(--muted);margin:10px 0 0;overflow-wrap:anywhere}"
        ".sp .sp-foot{border-top:1px solid var(--line);padding-top:16px;margin-top:18px;display:flex;justify-content:flex-end}"
        ".sp .sp-notice{padding:12px 14px;border:1px solid var(--line);border-left:3px solid var(--orange);background:var(--panel2);border-radius:5px;margin:0 0 14px;font-size:13px}.sp .sp-notice p{margin:3px 0 0}"
        ".sp .sp-events{border:0;border-top:1px solid var(--line);margin:14px 0 0;padding:14px 0 0;min-width:0}.sp .sp-events legend{padding:0 10px 0 0;font-weight:600;font-size:13px}"
        ".sp .sp-test{border-top:1px solid var(--line);margin-top:18px;padding-top:18px;display:flex;align-items:center;justify-content:space-between;gap:16px}.sp .sp-test .sp-help{margin-top:4px}"
        ".sp .sp-act{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:16px}.sp .sp-act .sp-help{margin:0}.sp .sp-act form{margin:0}"
        ".sp .sp-key{margin-top:16px}.sp .sp-key label.sp-gap{margin-top:12px}.sp .sp-key label{display:block;font-weight:500;font-size:13px;margin-bottom:7px}.sp .sp-keyrow{display:flex;gap:10px}.sp .sp-keyrow input{flex:1;width:0;font-family:var(--mono,monospace)}"
        ".sp .sp-remove{margin-top:10px}.sp .sp-usage{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}"
        ".sp details{margin-top:14px}.sp summary{cursor:pointer;color:var(--accent);font-size:13px;padding:6px 0}"
        ".sp .sp-ok{color:var(--green);margin:0 0 12px}.sp .sp-err{color:var(--red);margin:0 0 12px}"
        "@media (max-width:1050px){.sp .sp-layout{grid-template-columns:170px minmax(0,1fr);gap:28px}.sp .sp-row{grid-template-columns:150px minmax(0,1fr)}"
        ".sp fieldset.sp-row legend{width:150px}.sp fieldset.sp-row .sp-fields{margin-left:150px}}"
        "@media (max-width:1000px){.sp .sp-nav{top:16px}.sp .sp-sec,.sp .sp-sec .sp-panel{scroll-margin-top:16px}}"
        "@media (max-width:760px){.sp .sp-head{display:block;margin-bottom:20px}.sp .sp-rule{display:inline-block;margin-top:12px}.sp .sp-layout{display:block}"
        ".sp .sp-nav{position:static;margin-bottom:24px}.sp .sp-cap{display:none}.sp .sp-items{display:grid;grid-template-columns:1fr 1fr;gap:4px}"
        ".sp .sp-nav a{border:1px solid var(--line);background:var(--panel);padding:10px;font-size:13px}.sp .sp-nav a span{color:var(--accent)}"
        ".sp{--sp-pad:18px}html[data-density=compact] .sp{--sp-pad:16px}.sp .sp-row,.sp fieldset.sp-row{display:block}.sp fieldset.sp-row legend{float:none;width:auto;padding:0 0 8px}"
        ".sp fieldset.sp-row .sp-fields{margin-left:0}.sp .sp-inrow label{display:block;padding:0 0 8px}.sp .sp-inrow input{width:100%}"
        ".sp .sp-grid{grid-template-columns:1fr}.sp .sp-keyrow{flex-direction:column}.sp .sp-keyrow input{width:100%}.sp .sp-test{display:block}.sp .sp-test button{margin-top:10px}"
        ".sp .sp-foot button{width:100%}}")
# Huginn's global nav (header) and h3 (small caps card titles) must not reach the Settings menu and panel titles.
CSS += (".sp nav.sp-nav{display:block;overflow:visible;gap:0}.sp nav.sp-nav a{white-space:normal;padding:10px 12px}"
        ".sp nav.sp-nav a:hover{background:var(--accent2);color:var(--accent)}"
        ".sp h3{font-size:15px;font-weight:650;color:var(--text);text-transform:none;letter-spacing:0;display:block}.sp .sp-ph h3{font-size:16px;margin:0}"
        ".sp .sp-sub:has(+ .sp-foot){border-bottom:0;margin-bottom:0;padding-bottom:4px}"
        # Dark theme: the accents are light, so primary buttons get dark text (white on them was about 2-3:1).
        "html[data-theme=dark] .sp button:not(.btn-s):not(:disabled){color:#0b0f14}"
        "@media (prefers-color-scheme:dark){html:not([data-theme=light]) .sp button:not(.btn-s):not(:disabled){color:#0b0f14}}"
        "@media (max-width:760px){.sp nav.sp-nav a{padding:10px}}")
# 0.28: wide screens (2K) get three columns on the Overview (dense, so a wide card never leaves a hole) and two on Campaigns.
CSS += (".cgrid{display:grid;grid-template-columns:minmax(0,1fr);gap:0 14px}.cgrid h2{margin-top:18px}"
        "@media (min-width:1800px){.grid.ov{grid-template-columns:repeat(3,minmax(0,1fr));grid-auto-flow:dense}"
        ".cgrid{grid-template-columns:repeat(2,minmax(0,1fr));grid-auto-flow:dense}.cgrid .cs-wide{grid-column:span 2}}")
CSS += (".ctabs{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 4px;position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0}"
        ".ctabs a{padding:6px 14px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--muted);text-decoration:none;white-space:nowrap}"
        ".ctabs a:hover,.ctabs a:focus-visible{color:var(--accent)}.ctabs a span{margin-left:6px}.ctabs a[aria-current]{background:var(--accent2);color:var(--accent);border-color:var(--accent)}"
        ".ctab-wrap .ctab-pane{scroll-margin-top:64px}.ctabs-js .ctab-wrap{grid-template-columns:minmax(0,1fr)}.ctabs-js .ctab-pane>h2{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}.ctabs-js .ctab-pane>.card{margin-top:10px}"
        "@media (max-width:1000px){.ctabs{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:thin}.ctabs a{padding:9px 14px}}")
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
        u = urllib.parse.urlsplit(o)
        if u.netloc.lower() != (self.headers.get("Host") or "").lower() or u.scheme not in ("http", "https"):
            return False
        # The scheme counts too when Huginn knows it: https through a trusted proxy that says so, plain http otherwise.
        proto = self.headers.get("X-Forwarded-Proto") if self.client_address[0] in TRUSTED_PROXIES else None
        return proto not in ("http", "https") or u.scheme == proto

    def form(self, lists=None):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > 20000:
            # Never read an unknown or huge body (a negative length would wait forever); drop the connection instead.
            # Codex rc2 M11: and never act on it. An empty form would read as "everything off" on some routes.
            self.close_connection = True
            raise BadBody()
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
            log("error", "http_error", repr(e), method="GET", path=log_path(self.path))
            self.close_connection = True
            self.send(500, "Internal error", "text/plain")
        finally:
            self.finish_body()

    def do_POST(self):
        self._body_read = False
        try:
            self.route_post()
        except BadBody:
            self.send(413, "The form was too large or had no valid length. Nothing was changed.", "text/plain")
        except Exception as e:
            log("error", "http_error", repr(e), method="POST", path=log_path(self.path))
            self.close_connection = True
            self.send(500, "Internal error", "text/plain")
        finally:
            self.finish_body()

    def route_get(self):
        _local.h12 = settings().get("clock") == "12"
        _local.base = base_url(self)
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if path == "/healthz":
            con = db()
            li = float(get_meta(con, "last_ingest", "0") or 0)
            try:
                problems = sorted(json.loads(get_meta(con, "health_now", "{}")))
            except ValueError:
                problems = []
            ok = (time.time() - li) < POLL * 3 and not problems     # 503 whenever something is wrong, as the stability promise says
            if not self.host_ok():          # a page on another name (DNS rebinding) learns only up or down, like any health check
                return self.send(200 if ok else 503, json.dumps({"ok": ok}), "application/json")
            return self.send(200 if ok else 503, json.dumps({"ok": ok, "version": HUGINN_VERSION, "last_ingest_age_s": int(time.time() - li) if li else None,
                                                             "collection_problems": problems}), "application/json")
        if not self.host_ok():
            return self.send(421, "Unknown host. Add this name to HUGINN_ALLOWED_HOSTS and restart Huginn.", "text/plain")
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
        if path == "/metrics":
            con = db()
            tok = metrics_token(con)
            auth = self.headers.get("Authorization") or ""
            if not tok:
                return self.send(404, "Not found", "text/plain")
            if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip().encode(), tok.encode())):
                log("warning", "metrics_refused", client=self.client_ip())
                return self.send(401, "Unauthorized", "text/plain")
            return self.send(200, metrics_text(con), "text/plain; version=0.0.4; charset=utf-8")
        m = re.fullmatch(r"/feed/([A-Za-z0-9_-]{16,64})/(txt|nft|ipset|mikrotik|csv|c2)", path)
        if m:
            tok = get_meta(db(), "feed_token") or ""
            if not hmac.compare_digest(m.group(1), tok):
                return self.send(404, "Not found", "text/plain")
            mn, days, research, v6, tor = bl_params(qs)
            if m.group(2) == "c2":       # its own list (not the attackers): only the address family filter applies
                body, ctype = render_feed("c2", [], v6)
            else:
                body, ctype = render_feed(m.group(2), blocklist_ips(db(), mn, days, research, v6, tor), v6)
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
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.%]{3,90})/export\.(json|csv)", path)
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
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.%]{3,90})", path)
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
        if path == "/help":
            return self.send(200, v_help())
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
        m = (re.fullmatch(r"/campaign/(script|hassh|file)/([0-9a-f]{8,64})", path) or re.fullmatch(r"/campaign/(web)/([a-z0-9_]{1,60})", path)
             or re.fullmatch(r"/campaign/(ids)/([1-9][0-9]{0,9})", path))
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
        if path == "/settings/metrics/copy":
            # 0.41: the metrics token is only handed out on a Copy click, never written into the page itself.
            con = db()
            tok = metrics_token(con)
            if not tok or METRICS_TOKEN:
                return self.send(404, "Not found", "text/plain")
            if qs.get("what") == "token":
                return self.send(200, tok, "text/plain")
            base = getattr(_local, "base", "") or "http://huginn:8095"
            return self.send(200, metrics_job(base, tok), "text/plain")
        return self.send(404, page("Not found", "<h1>Not found</h1>"))

    def route_post(self):
        _local.h12 = settings().get("clock") == "12"
        _local.base = base_url(self)
        path = urllib.parse.urlsplit(self.path).path
        if not self.host_ok():
            return self.send(421, "Unknown host. Add this name to HUGINN_ALLOWED_HOSTS and restart Huginn.", "text/plain")
        if not self.same_origin():
            return self.send(403, "Forbidden", "text/plain")
        con = db()
        if path == "/login":
            ip = self.client_ip()
            f = self.form()
            if not reserve_attempt(ip):
                log("warning", "login_locked", "too many attempts", client=ip)
                return self.send(429, v_login("Too many attempts. Wait 15 minutes."))
            stored = get_meta(con, "pw")
            if not stored or not check_pw(f.get("password", ""), stored):
                log("warning", "login_failed", client=ip)
                time.sleep(1)
                return self.send(401, v_login("Wrong password."))
            release_attempt(ip)
            log("info", "login", client=ip)
            tok = secrets.token_urlsafe(32)
            with con:
                # Codex rc2 M4: the slow check ran outside the lock. Only add the session if the password it checked is
                # still the current one, so a login that raced a password change cannot outlive it.
                con.execute("BEGIN IMMEDIATE")
                if get_meta(con, "pw") != stored:
                    con.rollback()
                    return self.send(401, v_login("The password was just changed. Log in again."))
                con.execute("INSERT INTO logins VALUES(?,?)", (hashlib.sha256(tok.encode()).hexdigest(), time.time() + SESSION_DAYS * 86400))
            ck = "huginn_s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s" % (tok, SESSION_DAYS * 86400, "; Secure" if self.cookie_secure() else "")
            return self.redirect("/", {"Set-Cookie": ck})
        cur = self.authed()
        if not cur:
            return self.send(401, "Unauthorized", "text/plain")
        if path == "/settings":
            lists = {}
            f = self.form(lists)
            if not save_settings(f, lists):
                return self.send(400, v_settings(err="Unknown settings form. Nothing was saved."))
            scope = f.get("scope", "")
            return self.redirect(settings_url(scope if scope in SETTINGS_SCOPES else "1"))
        if path == "/settings/theme":
            with con:
                con.execute("BEGIN IMMEDIATE")
                st = settings(con)
                st["theme"] = THEMES[(THEMES.index(st["theme"]) + 1) % 3] if st["theme"] in THEMES else "auto"
                con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('settings',?)", (json.dumps(st),))
            return self.redirect(self.back())
        if path == "/settings/overview":
            view = self.form().get("view")
            if view in ("cards", "board"):
                with con:
                    con.execute("BEGIN IMMEDIATE")
                    st = settings(con)
                    st["overview"] = view
                    con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('settings',?)", (json.dumps(st),))
            return self.redirect("/")
        if path == "/settings/virustotal":
            key = (self.form().get("key") or "").strip().lower()
            if not VT_KEY_RE.fullmatch(key):
                return self.send(400, v_settings(at="virustotal", err="That does not look like a VirusTotal API key (64 characters, 0-9 and a-f)."))
            # The test is a lookup too: it is booked before it is made and never goes past the daily limit (Codex 049 L5).
            if not day_take(con, "vt_day", VT_DAILY):
                return self.send(429, v_settings(at="virustotal", err="Today's VirusTotal allowance is used up, so the key cannot be tested. Try again tomorrow (UTC)."))
            res = vt_test(key)
            if res == "bad":
                return self.send(400, v_settings(at="virustotal", err="VirusTotal refused that key. Nothing was saved."))
            if res == "error":
                return self.send(502, v_settings(at="virustotal", err="Could not reach VirusTotal to test the key. Nothing was saved, try again."))
            set_meta(con, "vt_key", key)
            set_meta(con, "vt_wait_until", "0")
            set_meta(con, "vt_error", "")
            return self.redirect(settings_url(("vt" if res == "ok" else "vtbusy")))
        if path == "/settings/malwarebazaar":
            key = (self.form().get("key") or "").strip()
            if not MB_KEY_RE.fullmatch(key):
                return self.send(400, v_settings(at="malwarebazaar", err="That does not look like an abuse.ch Auth-Key (letters and digits only)."))
            res = mb_test(key)
            if res == "bad":
                return self.send(400, v_settings(at="malwarebazaar", err="abuse.ch refused that key. Nothing was saved."))
            if res == "error":
                return self.send(502, v_settings(at="malwarebazaar", err="Could not reach MalwareBazaar to test the key. Nothing was saved, try again."))
            set_meta(con, "mb_key", key)
            set_meta(con, "mb_error", "")
            return self.redirect(settings_url(("mb" if res == "ok" else "mbbusy")))
        if path == "/settings/greynoise":
            key = (self.form().get("key") or "").strip()
            if not GN_KEY_RE.fullmatch(key):
                return self.send(400, v_settings(at="greynoise", err="That does not look like a GreyNoise API key (letters, digits, - and _)."))
            res = gn_test(key)
            if res == "bad":
                return self.send(400, v_settings(at="greynoise", err="GreyNoise refused that key. Nothing was saved."))
            if res == "error":
                return self.send(502, v_settings(at="greynoise", err="Could not reach GreyNoise to test the key. Nothing was saved, try again."))
            set_meta(con, "gn_key", key)
            set_meta(con, "gn_wait_until", "0")      # a new key gets a fresh allowance
            set_meta(con, "gn_error", "")
            return self.redirect(settings_url(("gn" if res == "ok" else "gnbusy")))
        if path == "/settings/httpbl":
            f = self.form()
            key = (f.get("key") or "").strip().lower()
            dns = dns_from_form(f, hb_dns(con))
            if not hb_dns_ok(dns):
                return self.send(400, v_settings(at="httpbl", err="Choose a DNS server from the list, or type an IPv4 address."))
            if not key:
                key = hb_key(con)
                if not key:
                    return self.send(400, v_settings(at="httpbl", err="Paste the access key."))
            if not HB_KEY_RE.fullmatch(key):
                return self.send(400, v_settings(at="httpbl", err="That does not look like an http:BL access key (12 lower-case letters)."))
            res = hb_test(key, dns)
            if res == "blocked":
                return self.send(400, v_settings(at="httpbl", err=(
                    "Your DNS resolver dropped Project Honey Pot's answer. Pi-hole and many routers do this to stop DNS rebinding. "
                    "Choose a public DNS server and try again. Nothing was saved.") if dns == "system" else (
                    "No answer from Project Honey Pot through %s. Try another DNS server. Nothing was saved." % hb_dns_label(dns))))
            if res == "error":
                return self.send(502, v_settings(at="httpbl", err="Could not reach the DNS server (%s). Nothing was saved, try again." % hb_dns_label(dns)))
            set_meta(con, "hb_key", key)
            set_meta(con, "hb_dns", dns)
            set_meta(con, "hb_wait_until", "0")
            set_meta(con, "hb_error", "")
            return self.redirect(settings_url("hb"))
        if path == "/settings/netblock":
            f = self.form()
            dns = dns_from_form(f, nb_dns(con))
            if not hb_dns_ok(dns):
                return self.send(400, v_settings(at="netblock", err="Choose a DNS server from the list, or type an IPv4 address."))
            on = f.get("on") == "1"
            if on and dns == "system" and not system_dns():
                return self.send(400, v_settings(at="netblock", err="This system has no name server in /etc/resolv.conf. Choose a public DNS server."))
            set_meta(con, "nb_on", "1" if on else "0")
            set_meta(con, "ab_on", "1" if f.get("abuse") == "1" else "0")
            set_meta(con, "nb_dns", dns)
            set_meta(con, "nb_wait_until", "0")
            set_meta(con, "nb_error", "")
            return self.redirect(settings_url("nbon" if on else "nboff"))
        if path == "/settings/dronebl":
            f = self.form()
            dns = dns_from_form(f, dbl_dns(con))
            if not hb_dns_ok(dns):
                return self.send(400, v_settings(at="dronebl", err="Choose a DNS server from the list, or type an IPv4 address."))
            on = f.get("on") == "1"
            if on:
                try:
                    res = dbl_test(nb_server(dns))
                except OSError:
                    return self.send(400, v_settings(at="dronebl", err="This system has no name server in /etc/resolv.conf. Choose a public DNS server."))
                if res == "blocked":
                    return self.send(400, v_settings(at="dronebl", err=(
                        "Your DNS resolver dropped DroneBL's answer. Pi-hole and many routers do this to stop DNS rebinding. "
                        "Choose a public DNS server and try again. Nothing was saved.") if dns == "system" else (
                        "No answer from DroneBL through %s. Try another DNS server. Nothing was saved." % hb_dns_label(dns))))
                if res == "error":
                    return self.send(502, v_settings(at="dronebl", err="Could not reach the DNS server (%s). Nothing was saved, try again." % hb_dns_label(dns)))
            set_meta(con, "dbl_on", "1" if on else "0")
            set_meta(con, "dbl_dns", dns)
            set_meta(con, "dbl_wait_until", "0")
            set_meta(con, "dbl_error", "")
            return self.redirect(settings_url("dblon" if on else "dbloff"))
        if path == "/settings/spamhaus":
            f = self.form()
            dns = dns_from_form(f, sh_dns(con))
            if not hb_dns_ok(dns):
                return self.send(400, v_settings(at="spamhaus", err="Choose a DNS server from the list, or type an IPv4 address."))
            on = f.get("on") == "1"
            if on:
                if dns in PUBLIC_DNS:
                    return self.send(400, v_settings(at="spamhaus", err="Spamhaus refuses public resolvers such as %s. Choose your own resolver (127.0.0.1 with Unbound, or one on your LAN). Nothing was saved." % hb_dns_label(dns)))
                try:
                    res = sh_test(nb_server(dns))
                except OSError:
                    return self.send(400, v_settings(at="spamhaus", err="This system has no name server in /etc/resolv.conf. Choose your own resolver."))
                if res != "ok":
                    return self.send(400 if res != "error" else 502, v_settings(at="spamhaus", err={
                        "public": "Spamhaus refused %s as a public resolver (it may forward to one). Use your own resolver that asks Spamhaus directly, such as Unbound. Nothing was saved." % hb_dns_label(dns),
                        "blocked": "The DNS server dropped Spamhaus' answer (127.0.0.x), as Pi-hole and many routers do. Choose another. Nothing was saved.",
                    }.get(res, "Could not reach the DNS server (%s). Nothing was saved, try again." % hb_dns_label(dns))))
            set_meta(con, "sh_on", "1" if on else "0")
            set_meta(con, "sh_dns", dns)
            set_meta(con, "sh_wait_until", "0")
            set_meta(con, "sh_error", "")
            return self.redirect(settings_url("shon" if on else "shoff"))
        if path == "/settings/tor":
            f = self.form()
            was = tor_tagging(con)
            set_meta(con, "tor_on", "1" if f.get("on") == "1" else "0")
            set_meta(con, "tor_bl", "1" if f.get("bl") == "1" else "0")
            set_meta(con, "tor_wait_until", "0")
            now_on = tor_tagging(con)
            if now_on != was:
                if now_on:
                    set_meta(con, "tor_fetched", "0")     # the next lookup round downloads the list
                # Tags follow at once: on from the stored list, off for everyone (the list stays for when it is turned on again).
                sql = ("SELECT ip FROM ips JOIN tor USING(ip)" if now_on else
                       "SELECT ip FROM ips WHERE (','||COALESCE(tags,'')||',') LIKE '%,tor,%'")
                with con:
                    for (ip,) in con.execute(sql).fetchall():
                        recompute_ip(con, ip)
            return self.redirect(settings_url("toron" if now_on and not was else "tor"))
        if path == "/settings/metrics":
            on = self.form().get("on") == "1"
            if on and not get_meta(con, "metrics_token"):
                set_meta(con, "metrics_token", secrets.token_urlsafe(32))
            set_meta(con, "metrics_on", "1" if on else "0")
            log("info", "metrics_on" if on else "metrics_off")
            return self.redirect(settings_url(("mon" if on else "moff")))
        if path == "/settings/goodbye":
            want = self.form().get("on") == "1"
            state, err = hp_goodbye_set(want)
            if err:
                log("warning", "goodbye_set_failed", error=err)
                return self.send(502, v_settings(at="honeypot", err="Could not change it: %s" % err))
            # Show the new state at once instead of waiting for the next sync.
            items, _at = protection_status(con)
            if items is not None:
                items["option:goodbye"] = bool(state)
                set_meta(con, "hp_status", json.dumps({"at": time.time(), "items": items}))
            log("info", "goodbye_on" if state else "goodbye_off")
            return self.redirect(settings_url(("byeon" if state else "byeoff")))
        if path == "/settings/ids":
            want = self.form().get("on") == "1"
            state, err = hp_ids_set(want)
            if err:
                log("warning", "ids_set_failed", error=err)
                return self.send(502, v_settings(at="honeypot", err="Could not change Suricata: %s" % err))
            items, _at = protection_status(con)
            if items is not None:
                if state:
                    items["running:suricata"] = True        # starting; the next sync reports whether it really runs
                else:
                    items.pop("running:suricata", None)
                set_meta(con, "hp_status", json.dumps({"at": time.time(), "items": items}))
            try:
                st = json.loads(get_meta(con, "hp_ids", "{}") or "{}")
            except ValueError:
                st = {}
            st["on"] = bool(state)
            set_meta(con, "hp_ids", json.dumps(st))
            log("info", "ids_on" if state else "ids_off")
            return self.redirect(settings_url(("idson" if state else "idsoff")))
        if path == "/settings/metrics/token":
            set_meta(con, "metrics_token", secrets.token_urlsafe(32))
            log("info", "metrics_token_new")
            return self.redirect(settings_url("mtok"))
        if path == "/settings/httpbl/remove":
            set_meta(con, "hb_key", "")
            return self.redirect(settings_url("hbdel"))
        if path == "/settings/greynoise/remove":
            set_meta(con, "gn_key", "")
            return self.redirect(settings_url("gndel"))
        if path == "/settings/malwarebazaar/remove":
            set_meta(con, "mb_key", "")
            return self.redirect(settings_url("mbdel"))
        if path == "/settings/virustotal/remove":
            set_meta(con, "vt_key", "")
            return self.redirect(settings_url("vtdel"))
        if path == "/settings/test-ntfy":
            if not NTFY_URL:
                return self.send(400, v_settings(at="notifications", err="HUGINN_NTFY_URL is not set."))
            try:
                ntfy_post("Test from Huginn. Notifications work.", "Huginn: test")
            except Exception as e:
                return self.send(502, v_settings(at="notifications", err="Sending failed: %s" % str(e)[:150]))
            return self.redirect(settings_url("test"))
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
            h = hash_pw(new)
            with con:                    # the new password and the logout of other sessions in one step
                con.execute("BEGIN IMMEDIATE")
                con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('pw',?)", (h,))
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
        if path in ("/files/shared", "/files/unshared"):
            if not mark_shared(con, self.form().get("shas"), on=path == "/files/shared"):
                return self.send(400, "Bad value", "text/plain")
            return self.redirect("/files")
        m = re.fullmatch(r"/ip/([0-9A-Fa-f:.%]{3,90})/flag", path)
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
            return self.redirect("/ip/" + urllib.parse.quote(ip, safe=":"))
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


ENV_FILE = os.path.join(BASE, ".env")
ENV_CMD = ("systemd-run --quiet --wait --pipe --same-dir --uid=huginn --gid=huginn -p EnvironmentFile=%s -p UMask=0027 "
           "/usr/bin/python3 %s" % (ENV_FILE, os.path.abspath(__file__)))


def need_service_env():
    # Masking, retention and the rest live in .env, which only systemd reads. Without them an import would store your own
    # address in plain text and keep data the service would remove.
    if os.path.exists(ENV_FILE) and not os.environ.get("INVOCATION_ID") and not os.environ.get("HUGINN_HP_HOST"):
        sys.exit("The settings in %s are not loaded, so this would not mask or keep data the way the service does.\n"
                 "Run it as root like this:\n  %s %s" % (ENV_FILE, ENV_CMD, " ".join(sys.argv[1:])))


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
    if not web_rules()[0]:
        log("warning", "web_rules", "No web attack rules loaded from %s, web requests are not classified" % WEB_RULES_FILE,
            error=_web["error"])
    log("info", "start", "Huginn %s listening on %s:%d" % (HUGINN_VERSION, BIND, PORT), version=HUGINN_VERSION,
        metrics=bool(metrics_token(connect())), log_format=LOG_FORMAT)
    if LOG_LEVEL > 20:
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
    h = hash_pw(p1)
    with con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('pw',?)", (h,))
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
    store_ids(con, parse_export.ids)
    while classify_web(con, budget=60.0):
        pass
    note_sync(con, t0)
    set_meta(con, "last_ingest", t0)
    print("parsed %d rows, %d new, %.1fs" % (len(rows), n, time.time() - t0))


def import_files(paths):
    # One-off import of whole log files (cowrie.json*, opencanary.log*, also gzipped). Same parsing and dedupe as the sync,
    # so overlap with stored data is skipped. Reads in blocks to keep memory low.
    hold_db_lock()
    init_db()
    con = connect()
    total_rows = total_new = 0
    failed = False
    for path in paths:
        name = os.path.basename(path)
        section = "COWRIE" if name.startswith("cowrie.json") else "CANARY" if name.startswith("opencanary.log") else None
        if not section:
            print("skip (unknown file type): %s" % path)
            continue
        t0 = time.time()
        n_lines = n_rows = n_new = 0
        try:
            with open(path, "rb") as raw:
                packed = raw.read(2) == b"\x1f\x8b"
            fh = gzip.open(path, "rt", encoding="utf-8", errors="replace") if packed else open(path, encoding="utf-8", errors="replace")
            with fh:
                buf = []
                for line in fh:
                    n_lines += 1
                    buf.append(line.rstrip("\n"))
                    if len(buf) >= 20000:
                        rows, _ = parse_export("##%s\n" % section + "\n".join(buf), set())
                        n_rows += len(rows); n_new += store(con, rows); buf = []
                if buf:
                    rows, _ = parse_export("##%s\n" % section + "\n".join(buf), set())
                    n_rows += len(rows); n_new += store(con, rows)
        except (OSError, EOFError, zlib.error) as e:
            failed = True
            print("%s: FAILED after %d lines (%d rows stored): %s" % (name, n_lines, n_new, e), flush=True)
            total_rows += n_rows; total_new += n_new
            continue
        note = "" if n_rows or not n_lines else "  (no events recognised in %d lines: is this the right file?)" % n_lines
        print("%s: %d rows, %d new, %.1fs%s" % (name, n_rows, n_new, time.time() - t0, note), flush=True)
        total_rows += n_rows; total_new += n_new
    print("total: %d rows, %d new" % (total_rows, total_new))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        serve()
    elif cmd == "set-password":
        set_password()
    elif cmd == "ingest-once":
        need_service_env()
        ingest_once()
    elif cmd == "import" and len(sys.argv) > 2:
        need_service_env()
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
