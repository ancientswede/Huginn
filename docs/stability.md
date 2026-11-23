# Stability promise

[← Back to the README](../README.md)

From 1.0.0 RavenTrap uses [semantic versioning](https://semver.org). Everything below keeps working the same way through all 1.x releases. A change that would break one of them waits for 2.0.

**Covered:**
- **Blocklist feeds:** `/feed/<token>/txt`, `nft`, `ipset`, `mikrotik`, `csv` and `c2`, with the parameters `min`, `days`, `research`, `tor` and `v6`. The format of each feed stays the same. The CSV feed keeps its columns `value,score,last_seen,country,reason` in that order.
- **Exports:** `/ip/<address>/export.json` and `export.csv`, and `/creds/export.txt` and `export.csv` with `days` and `what`. Fields and columns keep their names and meaning. New JSON fields can be added, and new CSV columns only at the end.
- **`/healthz`:** JSON with `ok`, `version`, `last_ingest_age_s` and `collection_problems`. It answers 200 when all is well and 503 when not: the last sync is too old, or `collection_problems` is not empty. Asked by a host name that is not in `HUGINN_ALLOWED_HOSTS`, it gives only `ok` (same status code).
- **`/metrics`:** metric names, labels and what they count. New metrics can be added.
- **Environment variables** in `.env`: names, meaning and defaults that change behaviour. If one is ever renamed, the old name keeps working until 2.0. They keep the `HUGINN_` prefix from the old name, like the service, user and paths (`huginn`).
- **Upgrades:** `update-huginn.sh` upgrades a database from any earlier version when RavenTrap starts. Going back to an older version is done by restoring a backup (see [Database backups](operations.md#database-backups)).

**Not covered** (can change in any release):
- the web pages, their layout and their addresses, apart from those listed above
- scores, tags and which addresses end up on the blocklist, since these get tuned as attacks change
- lookups that depend on outside services, which can change or stop on their own
