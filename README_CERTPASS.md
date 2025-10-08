# OpenVPN Certificate-Only Installer with Encrypted Private Keys

This installer sets up a production-ready OpenVPN server that uses **only certificate-based authentication** with encrypted private keys. Each client receives a unique certificate and private key that is encrypted with a passphrase, providing strong security without requiring username/password authentication.

## Features

- ✅ **Certificate-only authentication** - No PAM, LDAP, RADIUS, or username/password
- ✅ **Encrypted private keys** - Each client key requires a unique passphrase
- ✅ **Multi-OS support** - Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL/CentOS/AlmaLinux/Rocky
- ✅ **Modern security defaults** - TLS 1.2+, AES-256-GCM, SHA256
- ✅ **Idempotent installation** - Safe to re-run
- ✅ **Client management** - Add, revoke, and list clients
- ✅ **Firewall configuration** - Automatic UFW/firewalld setup
- ✅ **Production-ready** - Proper logging, error handling, and validation

## Quick Start

### 1. Install OpenVPN Server

**Interactive mode (recommended for first-time setup):**
```bash
sudo ./install_openvpn_certpass.sh
```

**Non-interactive mode:**
```bash
sudo ./install_openvpn_certpass.sh --public-ip YOUR_PUBLIC_IP --org "YourCompany"
```

### 2. Add Your First Client

```bash
sudo ./install_openvpn_certpass.sh add-client alice
```

This will:
- Create a certificate for "alice"
- Encrypt the private key with a passphrase (you'll be prompted twice)
- Generate a unified `.ovpn` file
- Create a tar bundle with all files
- Place everything in `/etc/openvpn/clients/alice/`

### 3. Distribute Client Files

Send the client one of these files:
- **`.ovpn` file** - Single file for most OpenVPN clients
- **`alice-bundle.tar.gz`** - Complete bundle with separate PEM files

## Client Connection Process

When a client connects using the `.ovpn` file:

1. **Certificate validation** - Server verifies the client certificate
2. **Private key decryption** - Client is prompted: "Private Key Password:"
3. **TLS handshake** - Secure connection established
4. **VPN tunnel** - Client traffic routed through VPN

**Important:** The client will see a "Private Key Password" prompt - this is the passphrase you set when creating the client certificate.

## Command Reference

### Installation Options

```bash
# Basic installation
sudo ./install_openvpn_certpass.sh --public-ip 1.2.3.4

# Custom configuration
sudo ./install_openvpn_certpass.sh \
  --public-ip vpn.yourcompany.com \
  --port 1194 \
  --proto udp \
  --org "YourCompany" \
  --country US \
  --state CA \
  --city "San Francisco"
```

### Client Management

```bash
# Add a new client
sudo ./install_openvpn_certpass.sh add-client username

# Revoke a client
sudo ./install_openvpn_certpass.sh revoke-client username

# List all clients
sudo ./install_openvpn_certpass.sh list-clients
```

## File Locations

### Server Files
- **Server config:** `/etc/openvpn/server.conf`
- **PKI directory:** `/etc/openvpn/easy-rsa/`
- **Client certificates:** `/etc/openvpn/clients/`
- **Logs:** `/var/log/openvpn/`

### Client Files (per user)
- **Unified config:** `/etc/openvpn/clients/username/username.ovpn`
- **Certificate bundle:** `/etc/openvpn/clients/username/username-bundle.tar.gz`
- **Separate files:** `ca.crt`, `username.crt`, `username.key`

## Security Features

### Server Security
- **TLS 1.2+ only** - Modern TLS requirements
- **AES-256-GCM encryption** - Strong cipher with authentication
- **SHA256 authentication** - Secure hash algorithm
- **Certificate verification** - `verify-client-cert require`
- **CRL support** - Certificate revocation list
- **No root privileges** - Runs as `nobody` user

### Client Security
- **Encrypted private keys** - Each key requires a unique passphrase
- **Certificate-based auth** - No username/password vulnerabilities
- **Perfect forward secrecy** - Ephemeral key exchange
- **Certificate expiration** - Automatic certificate lifecycle

## Troubleshooting

### Check Server Status
```bash
# Service status
sudo systemctl status openvpn-server@server

# View logs
sudo tail -f /var/log/openvpn/server.log

# Check firewall
sudo ufw status  # Ubuntu/Debian
sudo firewall-cmd --list-ports  # RHEL-like
```

### Client Connection Issues
1. **"Private Key Password" prompt** - This is normal and expected
2. **Certificate errors** - Check certificate expiration with `list-clients`
3. **Connection timeout** - Verify firewall rules and public IP
4. **TLS errors** - Ensure client supports TLS 1.2+ and AES-256-GCM

### Common Commands
```bash
# Restart OpenVPN
sudo systemctl restart openvpn-server@server

# Reload configuration
sudo systemctl reload openvpn-server@server

# Check IP forwarding
sysctl net.ipv4.ip_forward

# View active connections
sudo cat /var/log/openvpn/status.log
```

## Why Certificate-Only Authentication?

### Advantages
- **Strong security** - No password-based attacks
- **Unique per client** - Each client has its own certificate
- **Encrypted keys** - Private keys protected with passphrases
- **Audit trail** - Certificate-based access logging
- **No shared secrets** - Each client has unique credentials

### Client Experience
- **Single file deployment** - Just the `.ovpn` file
- **Passphrase prompt** - One-time password entry per session
- **No username/password** - Simpler authentication flow
- **Automatic reconnection** - Cached passphrase for reconnects

## Advanced Configuration

### Custom Network Settings
```bash
sudo ./install_openvpn_certpass.sh \
  --net 10.0.0.0 \
  --mask 255.255.0.0 \
  --public-ip your-server.com
```

### Multiple Servers
Each server needs its own:
- PKI directory (`/etc/openvpn/easy-rsa/`)
- Server configuration (`/etc/openvpn/server.conf`)
- Client directory (`/etc/openvpn/clients/`)

### Certificate Management
```bash
# Check certificate expiration
openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/client.crt -noout -dates

# Renew certificates (if needed)
cd /etc/openvpn/easy-rsa
./easyrsa renew client nopass
```

## Support

This installer is designed for production use with:
- ✅ Ubuntu 20.04/22.04/24.04
- ✅ Debian 11/12
- ✅ RHEL 7+/CentOS 7+/AlmaLinux/Rocky Linux
- ✅ OpenVPN 2.5+ (recommended 2.6+)

For issues or questions, check the server logs and ensure all prerequisites are met.
