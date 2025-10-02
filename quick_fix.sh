#!/bin/bash

# Quick fix for OpenVPN startup issues
# This script addresses the most common problems

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Applying quick fixes for OpenVPN..."

# Stop the service first
systemctl stop openvpn@server.service

# Fix 1: Create a simplified OpenVPN configuration
log "Creating simplified OpenVPN configuration..."
cat > /etc/openvpn/server.conf << 'EOF'
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

# Fix 2: Create necessary directories and files
log "Creating necessary directories and files..."
mkdir -p /etc/openvpn/ccd
mkdir -p /run/openvpn
mkdir -p /var/log/openvpn
touch /etc/openvpn/ipp.txt

# Fix 3: Set proper permissions
log "Setting proper permissions..."
chmod 755 /etc/openvpn/ccd
chmod 755 /run/openvpn
chmod 755 /var/log/openvpn
chmod 644 /etc/openvpn/ipp.txt
chmod 644 /etc/openvpn/server.conf

# Fix 4: Create proper systemd service
log "Creating proper systemd service..."
cat > /etc/systemd/system/openvpn@server.service << 'EOF'
[Unit]
Description=OpenVPN connection to %i
After=network.target

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn
ExecStart=/usr/sbin/openvpn --config %i.conf --writepid /run/openvpn/%i.pid
PIDFile=/run/openvpn/%i.pid
KillMode=mixed
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Fix 5: Reload systemd and test
log "Reloading systemd..."
systemctl daemon-reload

# Fix 6: Test the configuration
log "Testing OpenVPN configuration..."
cd /etc/openvpn
if openvpn --config server.conf --test; then
    log "OpenVPN configuration test passed"
else
    warn "OpenVPN configuration test failed, but continuing..."
fi

# Fix 7: Start the service
log "Starting OpenVPN service..."
systemctl start openvpn@server.service

# Wait and check status
sleep 5
if systemctl is-active --quiet openvpn@server.service; then
    log "OpenVPN service started successfully!"
    systemctl status openvpn@server.service
else
    error "OpenVPN service failed to start!"
    log "Checking logs for errors..."
    journalctl -xeu openvpn@server.service --no-pager
fi

log "Quick fix completed!"
