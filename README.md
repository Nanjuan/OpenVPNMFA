# OpenVPN Server Setup with MFA (Google Authenticator) on Ubuntu

This comprehensive guide provides everything needed to set up a secure OpenVPN server with Multi-Factor Authentication (MFA) using Google Authenticator on Ubuntu. The setup includes automated scripts, security best practices, and client configuration for Android and iOS devices.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Setup](#quick-setup)
4. [Manual Setup Guide](#manual-setup-guide)
5. [Security Configuration](#security-configuration)
6. [Client Setup](#client-setup)
7. [User Management](#user-management)
8. [Troubleshooting](#troubleshooting)
9. [Security Best Practices](#security-best-practices)

## Overview

This setup provides:
- **OpenVPN Server** with strong encryption (AES-256-GCM)
- **Multi-Factor Authentication** using Google Authenticator
- **PAM Integration** for seamless password + MFA code authentication
- **Automated Scripts** for easy setup and user management
- **Mobile Client Support** for Android and iOS
- **Security Hardening** with best practices

## Prerequisites

- Ubuntu 18.04+ server with root access
- Internet connection
- Domain name or public IP address
- Basic knowledge of Linux command line

## Quick Setup

### 1. Download and Run the Setup Script

```bash
# Download the setup script
wget https://raw.githubusercontent.com/your-repo/openvpn-mfa-setup/main/setup_openvpn_mfa.sh

# Make it executable
chmod +x setup_openvpn_mfa.sh

# Run the setup script
sudo ./setup_openvpn_mfa.sh
```

### 2. Add Your First User

```bash
# Add a new user with MFA
sudo /usr/local/bin/openvpn-user-mgmt.sh add your_username
```

### 3. Distribute Client Configuration

The script creates client configuration files in `/etc/openvpn/client/`. Distribute these securely to your users.

## Manual Setup Guide

### Step 1: Install Required Packages

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install OpenVPN and dependencies
sudo apt install -y openvpn easy-rsa libpam-google-authenticator qrencode ufw

# Install additional security tools
sudo apt install -y fail2ban ufw
```

### Step 2: Configure Easy-RSA

```bash
# Create Easy-RSA directory
sudo make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Configure Easy-RSA
sudo nano vars
```

Add the following configuration:
```bash
export KEY_COUNTRY="US"
export KEY_PROVINCE="CA"
export KEY_CITY="SanFrancisco"
export KEY_ORG="YourOrganization"
export KEY_EMAIL="admin@yourdomain.com"
export KEY_OU="IT"
export KEY_NAME="OpenVPN-CA"
```

### Step 3: Generate Certificates

```bash
# Initialize PKI
source vars
./clean-all
./build-ca --batch

# Generate server certificate
./build-key-server --batch server

# Generate Diffie-Hellman parameters
./build-dh

# Generate TLS-auth key
openvpn --genkey --secret ta.key
```

### Step 4: Configure PAM for Google Authenticator

Create `/etc/pam.d/openvpn`:
```bash
# PAM configuration for OpenVPN with Google Authenticator
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
account required pam_unix.so
session required pam_unix.so
```

### Step 5: Configure OpenVPN Server

Create `/etc/openvpn/server.conf`:
```bash
# OpenVPN Server Configuration with MFA Support
port 1194
proto udp
dev tun

# Certificate and key files
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-auth ta.key 0

# Network configuration
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Push routes to client
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client configuration directory
client-config-dir ccd

# Keepalive settings
keepalive 10 120

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Compression
comp-lzo

# Logging
log-append /var/log/openvpn/openvpn.log
verb 3

# User authentication
plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn

# Additional security
remote-cert-tls client
tls-auth ta.key 0
key-direction 0

# Prevent DNS leaks
push "block-outside-dns"
```

### Step 6: Configure Firewall

```bash
# Enable UFW
sudo ufw enable

# Allow OpenVPN traffic
sudo ufw allow 1194/udp
sudo ufw allow ssh

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure NAT for VPN traffic
sudo nano /etc/ufw/before.rules
```

Add the following to `/etc/ufw/before.rules`:
```bash
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]

# Allow traffic from OpenVPN client to the internet
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT
```

### Step 7: Start OpenVPN Service

```bash
# Enable and start OpenVPN
sudo systemctl enable openvpn@server
sudo systemctl start openvpn@server

# Check status
sudo systemctl status openvpn@server
```

## Security Configuration

### Enhanced Security Settings

For maximum security, use the following configuration in `/etc/openvpn/server.conf`:

```bash
# Ultra-secure configuration
cipher AES-256-GCM
auth SHA256
tls-version-min 1.3
tls-cipher TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# Disable compression
comp-lzo no

# Additional security options
client-to-client
duplicate-cn
max-clients 50
```

### Firewall Hardening

```bash
# Install and configure fail2ban
sudo apt install -y fail2ban

# Create fail2ban configuration for OpenVPN
sudo nano /etc/fail2ban/jail.d/openvpn.conf
```

Add the following configuration:
```ini
[openvpn]
enabled = true
port = 1194
protocol = udp
filter = openvpn
logpath = /var/log/openvpn/openvpn.log
maxretry = 3
bantime = 3600
```

## Client Setup

### Android Setup

1. **Install OpenVPN Connect** from Google Play Store
2. **Transfer the .ovpn file** to your Android device
3. **Open the .ovpn file** with OpenVPN Connect
4. **Enter credentials**:
   - Username: Your system username
   - Password: Your system password + MFA code (no space)
   - Example: `mypass123123456`

### iOS Setup

1. **Install OpenVPN Connect** from App Store
2. **Transfer the .ovpn file** to your iOS device via email or cloud storage
3. **Open the .ovpn file** with OpenVPN Connect
4. **Enter credentials** (same format as Android)

### Authentication Format

When connecting to OpenVPN, users must enter:
- **Username**: System username
- **Password**: System password + 6-digit MFA code (no space)

**Example**: If password is `mypass123` and MFA code is `123456`, enter: `mypass123123456`

## User Management

### Adding Users

```bash
# Add a new user with MFA
sudo /usr/local/bin/openvpn-user-mgmt.sh add username

# The script will:
# 1. Create the user account
# 2. Set up Google Authenticator
# 3. Generate client certificate
# 4. Create client configuration file
# 5. Display QR code for MFA setup
```

### Managing Users

```bash
# List active users
sudo /usr/local/bin/openvpn-user-mgmt.sh list

# Show user status
sudo /usr/local/bin/openvpn-user-mgmt.sh status username

# Revoke user access
sudo /usr/local/bin/openvpn-user-mgmt.sh revoke username

# Reset user MFA
sudo /usr/local/bin/openvpn-user-mgmt.sh reset-mfa username
```

### MFA Management

```bash
# Setup MFA for existing user
sudo /usr/local/bin/mfa-setup.sh setup username

# Test MFA configuration
sudo /usr/local/bin/mfa-setup.sh test username

# Show MFA status
sudo /usr/local/bin/mfa-setup.sh status username

# Reset MFA
sudo /usr/local/bin/mfa-setup.sh reset username
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```bash
# Check OpenVPN service status
sudo systemctl status openvpn@server

# Check firewall
sudo ufw status

# Check logs
sudo tail -f /var/log/openvpn/openvpn.log
```

#### 2. Authentication Failed
```bash
# Check PAM configuration
sudo pam-auth-update

# Test PAM configuration
sudo /usr/local/bin/mfa-setup.sh test username

# Check Google Authenticator configuration
sudo -u username google-authenticator -t -d -f -r 3 -R 30 -w 3
```

#### 3. Certificate Issues
```bash
# Check certificate validity
openssl x509 -in /etc/openvpn/easy-rsa/keys/username.crt -text -noout

# Regenerate certificate
sudo /usr/local/bin/openvpn-user-mgmt.sh revoke username
sudo /usr/local/bin/openvpn-user-mgmt.sh add username
```

### Log Analysis

```bash
# OpenVPN logs
sudo tail -f /var/log/openvpn/openvpn.log

# System logs
sudo journalctl -u openvpn@server -f

# Authentication logs
sudo tail -f /var/log/auth.log
```

## Security Best Practices

### 1. Server Hardening

```bash
# Disable root login
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no

# Use key-based authentication
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no

# Restart SSH service
sudo systemctl restart ssh
```

### 2. Certificate Management

```bash
# Set proper permissions
sudo chmod 600 /etc/openvpn/server.key
sudo chmod 600 /etc/openvpn/ta.key
sudo chmod 644 /etc/openvpn/ca.crt
sudo chmod 644 /etc/openvpn/server.crt

# Regular certificate rotation
sudo /usr/local/bin/openvpn-user-mgmt.sh revoke username
sudo /usr/local/bin/openvpn-user-mgmt.sh add username
```

### 3. Monitoring and Logging

```bash
# Set up log rotation
sudo nano /etc/logrotate.d/openvpn
```

Add the following configuration:
```
/var/log/openvpn/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload openvpn@server
    endscript
}
```

### 4. Backup Strategy

```bash
# Create backup script
sudo nano /usr/local/bin/backup-openvpn.sh
```

Add the following content:
```bash
#!/bin/bash
BACKUP_DIR="/etc/openvpn/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup certificates
cp -r /etc/openvpn/easy-rsa/keys "$BACKUP_DIR/"
cp /etc/openvpn/ca.crt "$BACKUP_DIR/"
cp /etc/openvpn/server.crt "$BACKUP_DIR/"
cp /etc/openvpn/server.key "$BACKUP_DIR/"
cp /etc/openvpn/ta.key "$BACKUP_DIR/"

# Backup configurations
cp /etc/openvpn/server.conf "$BACKUP_DIR/"
cp -r /etc/openvpn/client "$BACKUP_DIR/"

# Backup PAM configuration
cp /etc/pam.d/openvpn "$BACKUP_DIR/"

echo "Backup completed: $BACKUP_DIR"
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/backup-openvpn.sh
```

## File Structure

```
/etc/openvpn/
├── server.conf              # OpenVPN server configuration
├── ca.crt                   # Certificate Authority
├── server.crt              # Server certificate
├── server.key              # Server private key
├── dh2048.pem              # Diffie-Hellman parameters
├── ta.key                  # TLS authentication key
├── easy-rsa/               # Easy-RSA directory
│   └── keys/               # Certificate storage
├── client/                 # Client configurations
│   └── username.ovpn       # Client config files
├── ccd/                    # Client-specific configs
└── backups/                # Backup storage

/etc/pam.d/
└── openvpn                 # PAM configuration

/usr/local/bin/
├── openvpn-user-mgmt.sh    # User management script
└── mfa-setup.sh            # MFA setup script
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Monitor logs** for suspicious activity
2. **Update certificates** before expiration
3. **Review user access** regularly
4. **Update system packages** monthly
5. **Backup configurations** weekly

### Security Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Check for security updates
sudo apt list --upgradable

# Update OpenVPN if available
sudo apt install --only-upgrade openvpn
```

## Conclusion

This setup provides a secure, production-ready OpenVPN server with MFA authentication. The automated scripts make management easy, while the security configurations ensure maximum protection for your network.

For additional support or questions, refer to the troubleshooting section or consult the OpenVPN documentation.

---

**Security Note**: Always keep your server updated, use strong passwords, and regularly review access logs. Consider implementing additional security measures like intrusion detection systems for production environments.

