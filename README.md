# OpenVPN Server Toolkit (Cert-Only, Cert+Pass, Networking, Uninstall)

**Author:** Nestor Torres  
**Created:** October 2025  
**Version:** 1

A small toolkit of interactive bash scripts to **install, manage, network-configure, and uninstall** an OpenVPN server on Debian/Ubuntu and RHEL-like systems.

---

## What’s Included

| Script                           | Purpose                                                                                                  | Auth model                                                                          | Distro support                           |
| -------------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------- |
| `openvpn-cert-only-setup.sh`     | Install OpenVPN server + PKI (no firewall/NAT changes) and manage clients via menu                       | **Certificate-only** (server & clients **without** passphrases)                     | apt (Debian/Ubuntu)                      |
| `openvpn-cert-pass-installer.sh` | Install OpenVPN server + PKI, **enable IP forwarding**, optional auto-unlock, manage clients via menu    | **Certificate-only**; **server key encrypted** (askpass); **client keys encrypted** | apt, dnf, yum (Deb/Ubuntu & RHEL family) |
| `networking-setup.sh`            | Add **forwarding + NAT (iptables)**, persist firewall rules, optional autostart, show status             | —                                                                                   | apt, dnf, yum                            |
| `openvpn-uninstall-manager.sh`   | **Interactive uninstaller**: remove artifacts from the above scripts and optionally purge packages/users | —                                                                                   | apt, dnf, yum                            |

---

## Features at a Glance

* Easy-RSA 3 PKI (CA, server, clients) with CRL support
* Generates inline **`.ovpn`** profiles (embeds CA/cert/key/tls-crypt)
* Systemd service: `openvpn-server@server`
* Sensible defaults: `1194/udp`, VPN `10.8.0.0/24`, Google/Cloudflare DNS (per script)
* Optional **server key passphrase** with **askpass** auto-unlock (Script 2)
* Optional **networking helper** to enable IPv4 forwarding, NAT, and persistence across reboots
* **Uninstall manager** rolls back configs, sysctl changes, NAT rules, and persistence

---

## Requirements

* **Root** (or sudo)
* **OpenVPN 2.5+** recommended
* **Debian/Ubuntu** (apt) for all scripts; **RHEL/Rocky/Alma** (dnf/yum) supported by Script 2 + networking/uninstall
* Internet access during install

---

## Quick Start

### A) Simple install, no firewall changes (good for labs)

```bash
sudo ./openvpn-cert-only-setup.sh
# Follow prompts, then use the menu to add a client and produce .ovpn
```

### B) Server & client key passphrases + system IP forwarding (production-leaning)

```bash
sudo ./openvpn-cert-pass-installer.sh
# You'll set CA, server, and client key passphrases.
# Optionally save the server key passphrase to /etc/openvpn/server/server.pass for auto-start.
```

### (Optional) Configure networking (forwarding & NAT)

```bash
sudo ./networking-setup.sh
# Choose "Full network setup" for forwarding + NAT + persistence
# or "Add new route" to add additional VPN CIDR/WAN pairs
```

### Uninstall / Rollback

```bash
sudo ./openvpn-uninstall-manager.sh
# Choose the item to remove:
# 1) cert-only setup, 2) cert+pass installer, or 3) networking setup
# Toggle: purge packages, remove user, purge networking packages.
```

---

## Script Details

### `openvpn-cert-only-setup.sh`

* Installs: `openvpn`, `easy-rsa`, `curl`, `ca-certificates`
* Builds CA, server, and client certs **without passphrases**
* Writes server config: **`/etc/openvpn/server/server.conf`**
* **No networking changes** (no iptables/UFW/sysctl)
* Runtime paths:

  * PKI: `/etc/openvpn/easy-rsa/`
  * Logs: `/var/log/openvpn/`
  * Temp: `/var/run/openvpn-tmp` (via `tmp-dir`)
  * **Client profiles**: **`/etc/openvpn/clients/`**
* Menu: Add / Revoke / List clients, restart/status, export `.ovpn`

**Security defaults**

* `data-ciphers`: AES-256-GCM (fallback AES-256-GCM)
* `auth`: **SHA512**
* `tls-version-min`: **1.2**
* `tls-crypt`: enabled; DH used

---

### `openvpn-cert-pass-installer.sh`

* Supports **apt/dnf/yum**
* Enables **IPv4 forwarding** and persists `net.ipv4.ip_forward=1`
* Builds CA, **server key with passphrase** (askpass optional), and **client keys with passphrases**
* Server config: **`/etc/openvpn/server/server.conf`** (includes `askpass` if saved)
* tls-crypt key at **`/etc/openvpn/ta.key`**
* **Client profiles**: **`/root/openvpn-clients/`**
* Menu: Add / Revoke / List clients, restart/status, export `.ovpn`

**Security defaults**

* `data-ciphers`: AES-256-GCM (fallback AES-256-GCM)
* `auth`: **SHA256**
* `tls-version-min`: **1.2**
* `tls-crypt`, DH, **CRL** at `/etc/openvpn/server/crl.pem`
* Optional **askpass** at `/etc/openvpn/server/server.pass` (0600)

> If you do **not** save the server key passphrase to `server.pass`, systemd cannot prompt at boot and the service will not auto-start. Start OpenVPN in the foreground to type the passphrase.

---

### `networking-setup.sh`

* Adds/updates:

  * **IPv4 forwarding** via `/etc/sysctl.d/99-openvpn-ipforward.conf`
  * **NAT & FORWARD** iptables rules (MASQUERADE + return path)
  * **Persistence** via:

    * `netfilter-persistent` (Debian/Ubuntu), or
    * `iptables-services` (RHEL), or
    * fallback `iptables-restore.service` + `/etc/iptables/rules.v4`
  * Optional **autostart** of `openvpn-server@server`
* “Show current configuration” reports forwarding state, WAN iface, detected VPN CIDR(s), rules, and persistence status

---

### `openvpn-uninstall-manager.sh`

* Interactive removal for:

  1. **`openvpn-cert-only-setup.sh`**
  2. **`openvpn-cert-pass-installer.sh`**
  3. **`networking-setup.sh`**
* Toggles (with colored status):

  * **Purge OpenVPN packages** (apt/dnf/yum)
  * **Remove `openvpn` user/group**
  * **Purge networking packages** (`iptables-persistent` / `netfilter-persistent` or `iptables-services`)
* Cleans:

  * Stops/disables `openvpn-server@server`
  * Removes server configs, PKI, logs, `ipp.txt`, temp dirs
  * Deletes Script-2 artifacts: `server.pass`, `ta.key`, `crl.pem`
  * Reverts **IP forwarding** and drop-ins
  * Deletes **iptables NAT/FORWARD** rules matching known VPN CIDRs parsed from server configs; offers to remove remaining MASQUERADE rules
  * Removes persistence files/units (`/etc/iptables/rules.v4`, `iptables-restore.service`, RHEL `/etc/sysconfig/iptables`)

---

## Paths & Files

| Purpose          | Path                                                                           |
| ---------------- | ------------------------------------------------------------------------------ |
| Server config    | `/etc/openvpn/server/server.conf`                                              |
| PKI (Easy-RSA)   | `/etc/openvpn/easy-rsa/`                                                       |
| CRL (Script 2)   | `/etc/openvpn/server/crl.pem`                                                  |
| tls-crypt key    | Script 1: in PKI; **Script 2:** `/etc/openvpn/ta.key`                          |
| Logs             | `/var/log/openvpn/`                                                            |
| Pool persistence | `/etc/openvpn/server/ipp.txt`                                                  |
| Temp (Script 1)  | `/var/run/openvpn-tmp`                                                         |
| Temp (Script 2)  | `/etc/openvpn/tmp`                                                             |
| Client profiles  | **Script 1:** `/etc/openvpn/clients/` • **Script 2:** `/root/openvpn-clients/` |

---

## Common Tasks

### Start / Status

```bash
sudo systemctl restart openvpn-server@server
sudo systemctl status openvpn-server@server
```

### Add a client (from either installer’s menu)

Run the installer again; if the service is running it drops into the **manager**.
The `.ovpn` file is written to the directory listed in **Paths & Files** above.

### Copy a client profile to your user

```bash
# Example for Script 1
sudo cp /etc/openvpn/clients/alice.ovpn /home/$USER/
sudo chown $USER:$USER /home/$USER/alice.ovpn
```

### Client connection (Linux CLI)

```bash
sudo apt-get install -y openvpn
sudo openvpn --config alice.ovpn
```

---

## Security Notes

* **Passphrases (Script 2):**

  * **CA key passphrase** guards admin actions (issue/revoke)
  * **Server key passphrase** protects the server private key (store in `server.pass` only if necessary; chmod 600)
  * **Client key passphrases** are prompted at connection time on client devices
* **TLS & crypto:** TLS 1.2 minimum, `tls-crypt`, DH; Script 1 uses `auth SHA512`, Script 2 uses `auth SHA256`
* **Backups:** Securely back up `/etc/openvpn/easy-rsa/pki/` (especially `ca.key`)

---

## Troubleshooting

* **Connected but no internet via VPN**

  * Run **`networking-setup.sh`** → “Full network setup”
  * Verify MASQUERADE for your VPN CIDR, and `sysctl net.ipv4.ip_forward` is `1`

* **Service won’t auto-start after reboot (Script 2)**

  * Ensure `/etc/openvpn/server/server.pass` contains the correct passphrase,
    or start OpenVPN in the foreground to enter it interactively

* **NAT rules remain after uninstall**

  * Run **`openvpn-uninstall-manager.sh`** → “Uninstall networking-setup.sh”
  * Allow it to delete remaining MASQUERADE rules if appropriate

* **Where is my `.ovpn`?**

  * Script 1: `/etc/openvpn/clients/`
  * Script 2: `/root/openvpn-clients/`

---

## Example Workflows

### Minimal lab (no system networking)

1. `sudo ./openvpn-cert-only-setup.sh`
2. Add a client from the menu
3. Route traffic upstream or add routes manually (no iptables changes by this script)

### Production-leaning with NAT & auto-start

1. `sudo ./openvpn-cert-pass-installer.sh` → optionally save server passphrase to `server.pass`
2. `sudo ./networking-setup.sh` → “Full network setup”
3. Verify: `sysctl net.ipv4.ip_forward`, `iptables -t nat -S | grep MASQUERADE`, client connectivity

### Clean removal

1. `sudo ./openvpn-uninstall-manager.sh`
2. Choose the installer used and/or networking removal
3. (Optional) Toggle: purge packages, remove `openvpn` user, purge networking packages

---

## License

Provided as-is without warranty. Test in non-production before deploying.

---

## Changelog (Toolkit)

* **v2 (current):**

  * Split installers: **cert-only** (no networking) and **cert+pass** (with optional auto-unlock)
  * Added **networking-setup** helper (forwarding, NAT, persistence, autostart)
  * Added **uninstall manager** with distro-aware package purging and NAT/sysctl rollback
  * Improved client management menus and inline profile generation
