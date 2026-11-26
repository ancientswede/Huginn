# Running RavenTrap

[← Back to the README](../README.md)

## Updating

Get the new version, then run the update script on each machine. Your settings, keys, login and collected data are never replaced.

```bash
cd Huginn && git pull

# On the RavenTrap machine
./update-huginn.sh              # backup -> install -> checks the new version answers -> rolls back by itself if not
./update-huginn.sh --rollback   # go back to the version before the last update

# On the honeypot
./update-honeypot.sh                          # hp-export, hp-fileinfo, hp-sample-zip, hp-traps
./update-honeypot.sh --cowrie --opencanary    # also upgrade Cowrie and OpenCanary and re-apply RavenTrap's patches
./update-honeypot.sh --goodbye-on             # optional logout note (see Personas and bait); --goodbye-off turns it off
./update-honeypot.sh --suricata-on            # optional Suricata IDS (see Suricata IDS); --suricata-off turns it off
```

- `update-huginn.sh` keeps the code of the last three versions in `/opt/huginn/backups/`, and a compressed copy of the database from just before the newest update. It lists what is new since your version.
- If the new version does not start, the update puts back both the old code and that database copy by itself. Events from the minute in between come back at the next sync while the honeypot's export still holds them.
- `./update-huginn.sh --rollback` goes back to the code before the last update and keeps the current database. Add `--with-db` to also put back the database copy from before that update (the one it replaces is kept next to it as `huginn.db.before-restore-...`).
- RavenTrap checks GitHub's public list of version tags once a day and shows **update x.y.z** in the header when there is a newer one. Nothing about you is sent. Turn it off with `HUGINN_UPDATE_CHECK=0`.
- Running the install scripts again also works. They keep everything that is already set up, but they make no backup and do not roll back on failure.

## Database backups

Once a day RavenTrap saves a compressed copy of its database in `/opt/huginn/data/backups/` and keeps the last 3. Change that with `HUGINN_DB_BACKUPS` (`0` turns it off) and `HUGINN_DB_BACKUP_HOURS`. The first one is made a few minutes after the start.

- Every copy is checked first. If the database is damaged, no copy is saved and the good ones stay. You get a warning on the Account page and through ntfy.
- The copies hold your login hash and feed token, so only RavenTrap's user can read them.
- They sit on the same disk as the database. They save you from a broken update or a damaged database, not from a dead disk: copy them somewhere else too.

To bring one back:

```bash
systemctl stop huginn
runuser -u huginn -- python3 /opt/huginn/app.py backups
runuser -u huginn -- python3 /opt/huginn/app.py restore-db huginn-20261107-120000.db.gz
systemctl start huginn
```

Add your `HUGINN_BASE` if you changed it. In Docker: `docker compose stop huginn`, then `docker compose run --rm huginn restore-db <name>`, then `docker compose start huginn`.

The restore checks the copy before it touches anything, and keeps the database you had next to it as `huginn.db.before-restore-...`. Events after the copy are lost, except those still in the honeypot's export: they come back at the next sync.

## Logs and disk space

The honeypot only needs a short history; RavenTrap keeps the long one.

**On the honeypot** (small disk, lots of logs), `hp-logclean` runs every night:

| What | Kept on the honeypot | Setting in `/etc/default/hp-export` |
|---|---|---|
| Cowrie's logs | gzipped after a day, deleted after 30 days | `LOG_KEEP_DAYS` |
| Session recordings | 30 days | `TTY_KEEP_DAYS` |
| Captured files (malware) | forever | `DOWNLOAD_KEEP_DAYS` (`0` = keep) |
| OpenCanary's log | logrotate: daily, compressed, 30 days | `/etc/logrotate.d/opencanary` |
| hp-traps' logs | 30 days (cleans up itself) | – |
| systemd journal (endlessh) | at most 200 MB | `/etc/systemd/journald.conf.d/huginn-honeypot.conf` |

`hp-logclean -n` shows what it would do. RavenTrap syncs every two minutes, so it has everything long before the honeypot deletes it.

**In RavenTrap**, everything lives in one SQLite database (`/opt/huginn/data/huginn.db`): events, sessions, credentials, files, enrichment. Session recordings are copied over in the background and kept compressed in `/opt/huginn/data/tty`, so replays keep working after the honeypot has deleted its copy. History older than `HUGINN_RETENTION_DAYS` (180 by default) is deleted; set it to `0` to keep everything. The Account page shows the database size, the recordings and the free disk space. How fast it grows depends on your traffic and retention; repeated decoy tries above `HUGINN_DECOY_CAP` are counted, not stored. Account also shows how fast the data folder grows and when the disk would be full.

`update-huginn.sh` keeps the last three versions of the code but only one database copy (the newest), so updates do not eat the disk as the database grows.

## Uninstall

Run from the repository folder as root. Both scripts ask you to type `remove` first (`--yes` skips that).

```bash
# RavenTrap machine: the database is kept in /root/huginn-data-<date> unless you add --purge
./uninstall-huginn.sh [--purge]

# Honeypot: port redirects go first, then the services, the export, RavenTrap's key and the personas/bait
./uninstall-honeypot.sh [--purge] [--restore-ssh]
```

- `--purge` on the honeypot also deletes Cowrie, OpenCanary, their users, all logs and captured files, and the endlessh package (only if the installer set it up).
- `--restore-ssh` puts your admin SSH back on port 22 only. Without it, both 22 and your admin port reach the real sshd.
- You can run the honeypot script again later with `--purge` or `--restore-ssh`.
- Not removed: the Debian packages the installer added (git, python3-venv, build-essential, …), which other software may use, and the backups of `/etc/nftables.conf` it made.
- Delete the port forwards in your router, and the jobs on your firewalls that fetch RavenTrap's blocklists.

## Try it without a honeypot

`tools/make_demo.py` builds a static, read-only copy of RavenTrap with made-up data. Every address, network and AS number comes from the ranges reserved for documentation, so none of it belongs to anyone real:

```bash
python3 tools/make_demo.py ./demo --base /
cd demo && python3 -m http.server 8000   # then open http://127.0.0.1:8000/
```

## Commands

```
app.py serve                 # run the web UI and the collector (what systemd runs)
app.py set-password          # set or reset the login password (logs out every session)
app.py ingest-once           # one sync, for testing (needs the .env settings, see below)
app.py import FILE...        # import full cowrie.json* / opencanary.log* files, also gzipped (needs the .env settings)

./update-huginn.sh [--rollback]          # update / go back (RavenTrap machine)
./update-honeypot.sh [--cowrie] [--opencanary]   # update the honeypot side
./update-honeypot.sh --suricata-on | --suricata-off | --suricata-rules FILE   # optional Suricata IDS
./uninstall-huginn.sh [--purge]                  # remove RavenTrap (keeps the data unless --purge)
./uninstall-honeypot.sh [--purge] [--restore-ssh]   # remove the honeypot side
```

`.env` is read only by systemd. Run `import` and `ingest-once` as root through `systemd-run`, so they get the same settings and user as the service:

```bash
systemd-run --quiet --wait --pipe --same-dir --uid=huginn --gid=huginn -p EnvironmentFile=/opt/huginn/.env -p UMask=0027 \
  /usr/bin/python3 /opt/huginn/app.py import FILE...
```

In Docker the settings are already in the container: `docker compose exec huginn huginn import FILE...` (the files must be inside the container, for example under `/data`).
