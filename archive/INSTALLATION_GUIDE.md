# OpenVPN with MFA Installation Guide

## Quick Start Installation

### Prerequisites
- Ubuntu 18.04+ server
- Root or sudo access
- Internet connection
- Public IP address or domain name

### Step 1: Download and Run Setup Script

```bash
# Download the setup script
curl -O https://raw.githubusercontent.com/your-repo/openvpn-mfa-setup/main/setup_openvpn_mfa.sh

# Make executable
chmod +x setup_openvpn_mfa.sh

# Run the setup (this will take 5-10 minutes)
sudo ./setup_openvpn_mfa.sh
```

### Step 2: Add Your First User

```bash
# Add a user (replace 'admin' with your desired username)
sudo /usr/local/bin/openvpn-user-mgmt.sh add admin
```

### Step 3: Test the Setup

```bash
# Check OpenVPN service status
sudo systemctl status openvpn@server

# Check firewall
sudo ufw status

# View logs
sudo tail -f /var/log/openvpn/openvpn.log
```

## Detailed Installation Steps

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y openvpn easy-rsa libpam-google-authenticator qrencode ufw fail2ban

# Create necessary directories
sudo mkdir -p /etc/openvpn/{server,client,ccd}
sudo mkdir -p /var/log/openvpn
```

### 2. Certificate Authority Setup

```bash
# Navigate to Easy-RSA directory
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

### 3. Generate Certificates

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

### 4. Configure PAM for Google Authenticator

```bash
# Create PAM configuration
sudo tee /etc/pam.d/openvpn > /dev/null << 'EOF'
# PAM configuration for OpenVPN with Google Authenticator
auth required pam_google_authenticator.so forward_pass
auth required pam_unix.so use_first_pass
account required pam_unix.so
session required pam_unix.so
EOF
```

### 5. Configure OpenVPN Server

```bash
# Create server configuration
sudo tee /etc/openvpn/server.conf > /dev/null << 'EOF'
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
EOF
```

### 6. Configure Firewall

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
sudo tee /etc/ufw/before.rules > /dev/null << 'EOF'
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]

# Allow traffic from OpenVPN client to the internet
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE

# don't delete the 'COMMIT' line or these nat table rules won't be processed
COMMIT
EOF

# Reload UFW
sudo ufw --force reload
```

### 7. Start OpenVPN Service

```bash
# Enable and start OpenVPN
sudo systemctl enable openvpn@server
sudo systemctl start openvpn@server

# Check status
sudo systemctl status openvpn@server
```

## Client Setup Instructions

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

### Windows/macOS Setup

1. **Install OpenVPN Client** from openvpn.net
2. **Import the .ovpn file** into the client
3. **Enter credentials** (same format as mobile)

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

# Test MFA configuration
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
sudo tee /etc/logrotate.d/openvpn > /dev/null << 'EOF'
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
EOF
```

## Post-Installation Checklist

- [ ] OpenVPN service is running
- [ ] Firewall is configured correctly
- [ ] First user is created with MFA
- [ ] Client configuration files are generated
- [ ] Test connection from mobile device
- [ ] Verify MFA authentication works
- [ ] Check logs for any errors
- [ ] Set up monitoring and alerts
- [ ] Create backup strategy
- [ ] Document server details

## Support

For additional support:
1. Check the troubleshooting section
2. Review OpenVPN logs
3. Consult the OpenVPN documentation
4. Check system logs for errors

## Security Notes

- Always use strong passwords
- Keep the server updated
- Monitor access logs regularly
- Implement additional security measures for production
- Regular backup of configurations and certificates

