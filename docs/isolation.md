# ⚠️ Read this before you open any ports

[← Back to the README](../README.md)

A honeypot **invites attacks on purpose**. Port forwarding from the internet into your home network is not something to try just to see what happens. Done wrong, you give strangers a way into the network your family's laptops, phones, NAS and cameras live on. **If you are not sure what the steps below mean, stop here and read up first.**

Only open ports when **all** of this is true:

- **The honeypot is truly isolated.** Use its own VLAN (best) or the hypervisor's firewall (see [How to isolate the honeypot](#how-to-isolate-the-honeypot)), so it cannot open connections to your LAN, your router's admin page, your NAS or your other VLANs. A correct port forward alone is not isolation, and neither is a different subnet. **Test it** from the honeypot. Every one of these must fail:
  ```bash
  ping -c1 <a LAN machine>      # must time out
  nc -zv -w3 <your router> 80   # must fail
  nc -zv -w3 <your NAS> 445     # must fail
  ```
- **You forward only to the honeypot**, and only the ports in [Ports to forward](install.md#ports-to-forward). Never forward its admin SSH port. Never forward anything to Huginn: Huginn stays on your LAN or VPN.
- **You keep it up to date.** Patch the honeypot (`apt upgrade`) and Cowrie (`git pull`). Rebuild it if anything looks wrong. Consider blocking its outbound internet once it is installed.
- **You are allowed to.** Some internet providers forbid running servers or block port 25. In many countries, IP addresses are personal data (GDPR), so keep the retention short.
- **You accept the risk.** Huginn comes with **no warranty** (see sections 15–16 of the [license](../LICENSE)). You are responsible for your own network.

### How to isolate the honeypot

Getting the port forward right in your router only controls what comes **in**. Isolation is about what a successful attacker can reach **from** the honeypot. Pick one of these:

| | How | Verdict |
|---|---|---|
| **1. Own VLAN** | Put the honeypot on its own VLAN (UniFi, OPNsense, pfSense, MikroTik, most managed switches). Add firewall rules: honeypot VLAN → LAN/other VLANs **and the router itself** = **block**, LAN → honeypot = allow only Huginn to the admin port. | **Best.** The network itself keeps it apart. |
| **2. Hypervisor firewall** | No VLAN-capable gear? Keep the honeypot on your normal network, but block it from your LAN with the firewall of the *host* it runs on (Proxmox example below). Rules inside the honeypot itself do not count: an attacker with root just turns them off. | **Acceptable.** It is still on your LAN segment, so get the rules right and test them. |
| **3. Nothing** | Honeypot on the same network as everything else, only a port forward. | **Don't.** One escape from the fake shell and the attacker is inside your home network. |

**Test it from the honeypot** with `tools/check-isolation.sh`, giving it a few machines from your LAN. It also checks the router itself, which is the most common gap:

```bash
cd Huginn && ./tools/check-isolation.sh 192.168.1.10 192.168.1.20:445 192.168.1.30:8006
```

**UniFi (learned on our own honeypot).**
- **"Isolate Network" is not enough.** It blocks the other VLANs, but the honeypot can still reach the **gateway itself** on all its addresses: its SSH (port 22) answered from the honeypot. Add a firewall policy with the honeypot network as source, the **Gateway** zone as destination and action **Block**, placed before the default "allow to Gateway" policy. Allow DNS (port 53) first only if you want the honeypot to resolve names. It does not need to, and the router's DNS may hand out your internal host names.
- **Give the honeypot a static IP address** in its own network settings (in Proxmox: the container's network device, *Static*). DHCP also goes to the gateway, so once that is blocked the lease cannot be renewed and the honeypot drops off the network. A "Fixed IP" in UniFi is still DHCP.
- **Exclude the honeypot from Threat Management (IPS)**, or it silently drops the attacks. See [Router security features can hide the attacks](install.md#router-security-features-can-hide-the-attacks).
- Run `tools/check-isolation.sh` again after every change.

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
