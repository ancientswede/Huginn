# Using the blocklists

[← Back to the README](../README.md)

The ipset and MikroTik feeds also clear the IPv6 list, so an address that left the blocklist is removed. A firewall without IPv6 support should fetch the feed with `v6=0`. Addresses an earlier feed added to an IPv6 list then have to be removed by hand.

The **Blocklist** page builds feed URLs from your filters (minimum score, how recently seen, include research scanners or not, include Tor exit nodes or not). The feed URLs contain a secret token instead of a login, so firewalls can fetch them. Keep them on your LAN. You can rotate the token on the page.

| Format | Use with |
|---|---|
| `txt` | OPNsense/pfSense URL Table alias, pfBlockerNG, `cscli decisions import --format values` (CrowdSec) |
| `nft` | `curl -fsS URL -o /etc/huginn.nft && nft -f /etc/huginn.nft` (complete table with drop rules) |
| `ipset` | `curl -fsS URL \| ipset restore -exist`, then `iptables -I INPUT -m set --match-set huginn4 src -j DROP` |
| `mikrotik` | `/tool fetch url=URL dst-path=huginn.rsc; /import huginn.rsc` |
| `csv` | IP with score, last seen, country and tags (CrowdSec `cscli decisions import -i`) |
| `c2` | Malware download hosts and addresses embedded in captured malware, seen from at least 2 attackers. Attackers can choose these addresses, so use it as advice, not as an automatic block |

**Score:**
- connection: 1
- tried to log in: +2
- brute force: +2
- per command: +½, up to 10
- dropped a file: +15
- used the honeypot as a proxy: +10
- exploit attempt: +10
- SSHole probe: +10
- each other decoy service: +3
- read bait: +5
- took bait: +20

**Before you block anything:**
- Attacking addresses are often infected home routers or short-lived servers whose addresses change hands. That is why the feeds only include IPs seen in the last N days.
- Research scanners (Censys, Shadowserver, BinaryEdge and others) are detected from reverse DNS and network names and left out by default. Anyone who logged in, ran commands, dropped files or tried an exploit is always blocklisted, research network or not.
- Tor exit nodes are left out by default as well: an attack through Tor says nothing about the next person on the same exit. Include them on Settings, Lookups, or with `tor=1` on one feed. An attacker you set to Always block stays on the list.
- "Never block" always wins.
- Some addresses never go on the feeds, whatever their score: the big public DNS resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9 and others) and whatever you put in `HUGINN_NEVER_BLOCK`. Put your own WAN address, VPS and VPN server there. A honeypot that is ever fully taken over could write fake log lines with any source address; this keeps it from making your firewall cut off DNS or your own servers. Only Always block on an IP page overrides it.
- A feed holds at most `HUGINN_BL_MAX` addresses (50000), the highest scores first.
