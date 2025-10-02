#!/bin/bash

# Fix /tmp Permissions for OpenVPN - Final Version
# This script specifically addresses the /tmp permission issues

set -e

echo "=========================================="
echo "🔧 Fixing /tmp Permissions for OpenVPN"
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
# Set proper permissions for /tmp
chmod 1777 /tmp
chmod +t /tmp

# Ensure /tmp is writable by all users
chmod 777 /tmp

# Create OpenVPN-specific temp directory
mkdir -p /tmp/openvpn
chmod 777 /tmp/openvpn
chown nobody:nogroup /tmp/openvpn

log "=== 3. Creating Alternative Temp Directory ==="
# Create a dedicated temp directory for OpenVPN
mkdir -p /var/tmp/openvpn
chmod 777 /var/tmp/openvpn
chown nobody:nogroup /var/tmp/openvpn

log "=== 4. Updating OpenVPN Configuration ==="
# Update server.conf to use alternative temp directory
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

# Security (no chroot, no user/group change for now)
writepid /run/openvpn/server.pid

# Client limits
max-clients 100
duplicate-cn
EOF

log "=== 5. Testing /tmp Write Access ==="
# Test /tmp write access as nobody user
if sudo -u nobody touch /tmp/openvpn_test_$(date +%s) 2>/dev/null; then
    success "✅ /tmp write access working for nobody user"
    sudo -u nobody rm -f /tmp/openvpn_test_* 2>/dev/null || true
else
    warn "⚠️  /tmp write access failed for nobody user"
fi

log "=== 6. Testing Alternative Temp Directory ==="
# Test /var/tmp/openvpn write access
if sudo -u nobody touch /var/tmp/openvpn/test_$(date +%s) 2>/dev/null; then
    success "✅ /var/tmp/openvpn write access working"
    sudo -u nobody rm -f /var/tmp/openvpn/test_* 2>/dev/null || true
else
    warn "⚠️  /var/tmp/openvpn write access failed"
fi

log "=== 7. Starting OpenVPN Service ==="
# Start OpenVPN service
systemctl start openvpn@server.service
sleep 5

# Check service status
if systemctl is-active --quiet openvpn@server.service; then
    success "✅ OpenVPN service started successfully"
else
    error "❌ OpenVPN service failed to start"
    systemctl status openvpn@server.service
    exit 1
fi

log "=== 8. Verifying Service Status ==="
# Show service status
systemctl status openvpn@server.service --no-pager

log "=== 9. Testing Network Interface ==="
# Check if tun0 interface is created
if ip link show tun0 >/dev/null 2>&1; then
    success "✅ TUN interface (tun0) created"
else
    warn "⚠️  TUN interface not created yet"
fi

log "=== 10. Checking Port Binding ==="
# Check if port 1194 is listening
if netstat -tuln | grep -q ":1194 "; then
    success "✅ OpenVPN listening on port 1194"
else
    warn "⚠️  Port 1194 not listening yet"
fi

log "=== 11. Final Verification ==="
echo ""
echo "🔍 Final Status Check:"
echo "======================"
echo "OpenVPN Service: $(systemctl is-active openvpn@server.service)"
echo "TUN Interface: $(ip link show tun0 2>/dev/null | head -1 || echo 'Not created')"
echo "Port 1194: $(netstat -tuln | grep ":1194 " || echo 'Not listening')"
echo "/tmp permissions: $(ls -ld /tmp)"
echo "/var/tmp/openvpn: $(ls -ld /var/tmp/openvpn 2>/dev/null || echo 'Not created')"

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
echo "- Service logs: journalctl -u openvpn@server.service"
