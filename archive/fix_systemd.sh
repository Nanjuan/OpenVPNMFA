#!/bin/bash

# Fix systemd service configuration for OpenVPN
# This script fixes the working directory issue

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

log "Fixing systemd service configuration for OpenVPN..."

# Stop the service first
systemctl stop openvpn@server.service

# Create correct systemd service file
log "Creating correct systemd service file..."
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

# Reload systemd
log "Reloading systemd..."
systemctl daemon-reload

# Create necessary directories
log "Creating necessary directories..."
mkdir -p /etc/openvpn/ccd
mkdir -p /run/openvpn
mkdir -p /var/log/openvpn

# Create ipp.txt file if it doesn't exist
log "Creating ipp.txt file..."
touch /etc/openvpn/ipp.txt
chmod 644 /etc/openvpn/ipp.txt

# Set proper permissions
log "Setting proper permissions..."
chmod 755 /etc/openvpn/ccd
chmod 755 /run/openvpn
chmod 755 /var/log/openvpn

# Test the configuration
log "Testing OpenVPN configuration..."
cd /etc/openvpn
if openvpn --config server.conf --test; then
    log "OpenVPN configuration test passed"
else
    warn "OpenVPN configuration test failed, but continuing..."
fi

# Start the service
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

log "Systemd service fix completed!"
