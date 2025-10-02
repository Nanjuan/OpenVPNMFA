#!/bin/bash

# Fix ta.key File Issue Script
# This script fixes the ta.key file access issue

set -e

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Fixing ta.key File Issue"
echo "======================="
echo ""

info "=== 1. Checking ta.key File ==="
log "Checking ta.key file status..."

if [ -f "/etc/openvpn/ta.key" ]; then
    log "✅ ta.key file exists"
    ls -la /etc/openvpn/ta.key
else
    error "❌ ta.key file not found"
    log "Creating new ta.key file..."
    openvpn --genkey --secret /etc/openvpn/ta.key
    log "✅ ta.key file created"
fi
echo ""

info "=== 2. Setting Proper Permissions ==="
log "Setting proper permissions for ta.key file..."

# Set proper permissions for ta.key
chmod 600 /etc/openvpn/ta.key
chown root:root /etc/openvpn/ta.key

log "✅ ta.key permissions set correctly"
echo ""

info "=== 3. Checking All Certificate Files ==="
log "Checking all certificate files..."

for cert in ca.crt server.crt server.key dh2048.pem ta.key; do
    if [ -f "/etc/openvpn/$cert" ]; then
        log "✅ $cert exists"
        ls -la /etc/openvpn/$cert
    else
        error "❌ $cert not found"
    fi
done
echo ""

info "=== 4. Creating Fixed OpenVPN Configuration ==="
log "Creating OpenVPN configuration with proper file paths..."

cat > /etc/openvpn/server.conf << 'EOF'
# OpenVPN Server Configuration with MFA Support
port 1194
proto udp
dev tun

# Certificate files with absolute paths
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
tls-auth /etc/openvpn/ta.key 0

# Network settings
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Compression
comp-lzo

# Logging
log-append /var/log/openvpn/openvpn.log
verb 4

# Authentication - using script with proper environment
auth-user-pass-verify /usr/local/bin/openvpn-auth.sh via-env
script-security 3

# Client connection settings
client-to-client
duplicate-cn
keepalive 10 120
persist-key
persist-tun

# Status file
status /var/log/openvpn/openvpn-status.log
status-version 2

# Additional security
tls-server
remote-cert-tls client

# Performance optimizations
fast-io
mute-replay-warnings
EOF

log "✅ OpenVPN configuration updated with absolute paths"
echo ""

info "=== 5. Creating ipp.txt File ==="
log "Creating ipp.txt file for IP pool persistence..."

touch /etc/openvpn/ipp.txt
chmod 644 /etc/openvpn/ipp.txt
chown root:root /etc/openvpn/ipp.txt

log "✅ ipp.txt file created"
echo ""

info "=== 6. Setting Proper Permissions for All Files ==="
log "Setting proper permissions for all OpenVPN files..."

# Set permissions for certificate files
chmod 600 /etc/openvpn/*.key
chmod 644 /etc/openvpn/*.crt
chmod 644 /etc/openvpn/*.pem
chmod 644 /etc/openvpn/ipp.txt

# Set ownership
chown root:root /etc/openvpn/*

log "✅ All file permissions set correctly"
echo ""

info "=== 7. Testing OpenVPN Configuration ==="
log "Testing OpenVPN configuration..."

# Test the configuration
if openvpn --config /etc/openvpn/server.conf --test-crypto 2>/dev/null; then
    log "✅ OpenVPN configuration is valid"
else
    warn "OpenVPN configuration test failed"
    log "Trying to identify the issue..."
    
    # Check if all required files exist
    for file in ca.crt server.crt server.key dh2048.pem ta.key; do
        if [ ! -f "/etc/openvpn/$file" ]; then
            error "Missing file: $file"
        fi
    done
fi
echo ""

info "=== 8. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service with fixed configuration..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service started successfully"
else
    error "❌ OpenVPN service failed to start"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 9. Testing Authentication Script ==="
log "Testing authentication script with current MFA code..."

if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing authentication for user: $USERNAME"
    
    # Get current MFA code
    SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
    CURRENT_CODE=$(oathtool --totp -b "$SECRET")
    
    log "Current MFA code: $CURRENT_CODE"
    echo ""
    echo "To test authentication:"
    echo "export username=$USERNAME"
    echo "export password='yourpassword$CURRENT_CODE'"
    echo "/usr/local/bin/openvpn-auth.sh"
    echo ""
    echo "Then check logs: sudo tail -f /var/log/openvpn/auth.log"
fi
echo ""

info "=== 10. Monitoring Instructions ==="
log "To monitor authentication attempts:"
echo "sudo tail -f /var/log/openvpn/auth.log"
echo ""
log "To monitor OpenVPN server logs:"
echo "sudo tail -f /var/log/openvpn/openvpn.log"
echo ""

info "=== 11. Client Connection Instructions ==="
log "For OpenVPN client connection:"
echo "1. Username: $USERNAME"
echo "2. Password: yourpassword + 6digitMFAcode (no space)"
echo "3. Use the .ovpn file: /etc/openvpn/client/$USERNAME.ovpn"
echo ""

log "ta.key file fix completed!"
log "Try connecting with your OpenVPN client now."
