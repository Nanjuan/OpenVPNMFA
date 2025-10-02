#!/bin/bash

# Fix OpenVPN Final Issues
# This script addresses ta.key problems, /tmp permissions, and ensures proper server startup

set -e

echo "=========================================="
echo "🔧 Fixing OpenVPN Final Issues"
echo "=========================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to show error
error() {
    echo "❌ $1"
}

# Function to show success
success() {
    echo "✅ $1"
}

# Function to show warning
warn() {
    echo "⚠️  $1"
}

log "=== 1. Stopping OpenVPN Service ==="
systemctl stop openvpn@server.service 2>/dev/null || true
sleep 2

log "=== 2. Fixing /tmp Directory Permissions ==="
# Fix /tmp permissions
chmod 1777 /tmp
chmod +t /tmp

# Create OpenVPN-specific temp directory
mkdir -p /tmp/openvpn
chmod 755 /tmp/openvpn
chown root:root /tmp/openvpn

# Set permissions for all files in /tmp
chmod 755 /tmp/* 2>/dev/null || true
chown root:root /tmp/* 2>/dev/null || true

log "=== 3. Fixing ta.key File ==="
# Check if ta.key exists
if [ ! -f "/etc/openvpn/ta.key" ]; then
    log "Creating ta.key file..."
    openvpn --genkey --secret /etc/openvpn/ta.key
    chmod 600 /etc/openvpn/ta.key
    chown root:root /etc/openvpn/ta.key
else
    log "ta.key already exists, setting permissions..."
    chmod 600 /etc/openvpn/ta.key
    chown root:root /etc/openvpn/ta.key
fi

log "=== 4. Fixing Certificate File Permissions ==="
# Set proper permissions for all certificate files
chmod 600 /etc/openvpn/*.key 2>/dev/null || true
chmod 644 /etc/openvpn/*.crt 2>/dev/null || true
chmod 644 /etc/openvpn/*.pem 2>/dev/null || true
chown root:root /etc/openvpn/*.key 2>/dev/null || true
chown root:root /etc/openvpn/*.crt 2>/dev/null || true
chown root:root /etc/openvpn/*.pem 2>/dev/null || true

log "=== 5. Creating ipp.txt File ==="
# Create ipp.txt file
touch /etc/openvpn/ipp.txt
chmod 644 /etc/openvpn/ipp.txt
chown root:root /etc/openvpn/ipp.txt

log "=== 6. Updating OpenVPN Configuration ==="
# Update server.conf to use absolute paths
cat > /etc/openvpn/server.conf << 'EOF'
# OpenVPN Server Configuration with MFA Support
port 1194
proto udp
dev tun

# Certificate files (absolute paths)
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
tls-auth /etc/openvpn/ta.key 0

# Network configuration
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route 10.8.0.0 255.255.255.0"
push "topology net30"
push "ping 10"
push "ping-restart 120"

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Authentication
auth-user-pass-verify /usr/local/bin/openvpn-auth.sh via-env
script-security 3

# Logging
log /var/log/openvpn/openvpn.log
verb 3
status /var/log/openvpn/openvpn-status.log
status-version 2

# Performance
keepalive 10 120
comp-lzo
persist-key
persist-tun

# Security
user nobody
group nogroup
chroot /var/lib/openvpn
writepid /run/openvpn/server.pid

# Client limits
max-clients 100
duplicate-cn
EOF

log "=== 7. Creating OpenVPN Chroot Directory ==="
# Create chroot directory
mkdir -p /var/lib/openvpn
chmod 755 /var/lib/openvpn
chown root:root /var/lib/openvpn

log "=== 8. Testing /tmp Write Access ==="
# Test /tmp write access
if touch /tmp/openvpn_test_$(date +%s) 2>/dev/null; then
    success "✅ /tmp write access working"
    rm -f /tmp/openvpn_test_* 2>/dev/null || true
else
    error "❌ /tmp write access failed"
    exit 1
fi

log "=== 9. Testing OpenVPN Configuration ==="
# Test OpenVPN configuration
if openvpn --config /etc/openvpn/server.conf --test 2>/dev/null; then
    success "✅ OpenVPN configuration test passed"
else
    warn "⚠️  OpenVPN configuration test failed, but continuing..."
fi

log "=== 10. Starting OpenVPN Service ==="
# Start OpenVPN service
systemctl start openvpn@server.service
sleep 3

# Check service status
if systemctl is-active --quiet openvpn@server.service; then
    success "✅ OpenVPN service started successfully"
else
    error "❌ OpenVPN service failed to start"
    systemctl status openvpn@server.service
    exit 1
fi

log "=== 11. Verifying Service Status ==="
# Show service status
systemctl status openvpn@server.service --no-pager

log "=== 12. Testing Network Interface ==="
# Check if tun0 interface is created
if ip link show tun0 >/dev/null 2>&1; then
    success "✅ TUN interface (tun0) created"
else
    warn "⚠️  TUN interface not created yet"
fi

log "=== 13. Checking Port Binding ==="
# Check if port 1194 is listening
if netstat -tuln | grep -q ":1194 "; then
    success "✅ OpenVPN listening on port 1194"
else
    warn "⚠️  Port 1194 not listening yet"
fi

log "=== 14. Final Verification ==="
echo ""
echo "🔍 Final Status Check:"
echo "======================"
echo "OpenVPN Service: $(systemctl is-active openvpn@server.service)"
echo "TUN Interface: $(ip link show tun0 2>/dev/null | head -1 || echo 'Not created')"
echo "Port 1194: $(netstat -tuln | grep ":1194 " || echo 'Not listening')"
echo "ta.key: $(ls -la /etc/openvpn/ta.key 2>/dev/null || echo 'Missing')"
echo "ipp.txt: $(ls -la /etc/openvpn/ipp.txt 2>/dev/null || echo 'Missing')"

echo ""
echo "🎉 OpenVPN server should now be running properly!"
echo ""
echo "📋 Next Steps:"
echo "1. Try connecting with your OpenVPN client"
echo "2. Monitor logs: sudo tail -f /var/log/openvpn/openvpn.log"
echo "3. Check authentication: sudo tail -f /var/log/openvpn/auth.log"
echo ""
echo "🔧 If issues persist, check:"
echo "- /tmp permissions: ls -la /tmp"
echo "- Certificate files: ls -la /etc/openvpn/"
echo "- Service logs: journalctl -u openvpn@server.service"
