#!/bin/bash

# Fix common OpenVPN startup issues
# This script addresses common problems that prevent OpenVPN from starting

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

log "Fixing OpenVPN startup issues..."

# Stop the service first
log "Stopping OpenVPN service..."
systemctl stop openvpn@server.service

# Fix 1: Ensure PAM module is installed
log "Ensuring PAM Google Authenticator module is installed..."
apt install -y libpam-google-authenticator

# Fix 2: Create necessary directories
log "Creating necessary directories..."
mkdir -p /etc/openvpn/server
mkdir -p /run/openvpn
mkdir -p /var/log/openvpn

# Fix 3: Set proper permissions
log "Setting proper permissions..."
chmod 755 /etc/openvpn/server
chmod 755 /run/openvpn
chmod 755 /var/log/openvpn

# Fix 4: Check and fix OpenVPN configuration
log "Checking OpenVPN configuration..."
if [ -f "/etc/openvpn/server.conf" ]; then
    # Fix common configuration issues
    sed -i 's|^plugin.*|plugin /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn|' /etc/openvpn/server.conf
    
    # Ensure working directory is set
    if ! grep -q "cd /etc/openvpn" /etc/openvpn/server.conf; then
        echo "cd /etc/openvpn" >> /etc/openvpn/server.conf
    fi
else
    error "OpenVPN configuration file not found!"
    exit 1
fi

# Fix 5: Create proper systemd service file
log "Creating proper systemd service file..."
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

# Fix 6: Reload systemd and enable service
log "Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable openvpn@server.service

# Fix 7: Test configuration
log "Testing OpenVPN configuration..."
cd /etc/openvpn
if openvpn --config server.conf --test; then
    log "OpenVPN configuration test passed"
else
    warn "OpenVPN configuration test failed, but continuing..."
fi

# Fix 8: Start the service
log "Starting OpenVPN service..."
systemctl start openvpn@server.service

# Wait a moment and check status
sleep 3
if systemctl is-active --quiet openvpn@server.service; then
    log "OpenVPN service started successfully!"
    systemctl status openvpn@server.service
else
    error "OpenVPN service failed to start!"
    log "Checking logs for errors..."
    journalctl -xeu openvpn@server.service --no-pager
fi

log "OpenVPN fix completed!"
