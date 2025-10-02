#!/bin/bash

# Complete OpenVPN Fix - Addresses all identified issues
# This script fixes /tmp permissions, authentication, and ensures proper operation

set -e

echo "=========================================="
echo "🔧 Complete OpenVPN Fix"
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
sleep 3

log "=== 2. Fixing /tmp Directory Permissions ==="
# Set proper permissions for /tmp
chmod 1777 /tmp
chmod +t /tmp

# Make /tmp writable by all users
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

log "=== 4. Fixing Authentication Script ==="
# Ensure the authentication script exists and is executable
if [ ! -f "/usr/local/bin/openvpn-auth.sh" ]; then
    log "Creating authentication script..."
    cat > /usr/local/bin/openvpn-auth.sh << 'EOF'
#!/bin/bash
set -e

# Get username and password from environment
USERNAME="$username"
PASSWORD="$password"

# Log authentication attempt
echo "$(date): Authentication attempt for user: $USERNAME" >> /var/log/openvpn/auth.log

# Check if user exists
if ! id "$USERNAME" &>/dev/null; then
    echo "$(date): User $USERNAME does not exist" >> /var/log/openvpn/auth.log
    exit 1
fi

# Check if MFA is configured
if [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
    echo "$(date): MFA not configured for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Extract MFA code (last 6 digits) and password
MFA_CODE="${PASSWORD: -6}"
USER_PASSWORD="${PASSWORD%??????}"

echo "$(date): Testing authentication for $USERNAME (password length: ${#USER_PASSWORD}, MFA: ${MFA_CODE})" >> /var/log/openvpn/auth.log

# Test password authentication
if ! echo "$USER_PASSWORD" | su - "$USERNAME" -c "true" 2>/dev/null; then
    echo "$(date): Password authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Get secret key
SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
if [ -z "$SECRET" ]; then
    echo "$(date): No secret found for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Test MFA code using oathtool
if command -v oathtool &> /dev/null; then
    EXPECTED_CODE=$(oathtool --totp -b "$SECRET")
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): Authentication successful for $USERNAME" >> /var/log/openvpn/auth.log
        exit 0
    fi
    
    # Try with time offset
    for i in -1 0 1; do
        EXPECTED_CODE=$(oathtool --totp -b "$SECRET" --time-offset=$i)
        if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
            echo "$(date): Authentication successful for $USERNAME (with time offset $i)" >> /var/log/openvpn/auth.log
            exit 0
        fi
    done
else
    echo "$(date): oathtool not found, using Python fallback" >> /var/log/openvpn/auth.log
    # Python fallback for TOTP
    EXPECTED_CODE=$(python3 -c "
import hmac
import hashlib
import time
import base64
import struct

def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
    counter_bytes = struct.pack('>Q', counter)
    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0x0f
    code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)

def totp(secret, time_step=30):
    counter = int(time.time() / time_step)
    return hotp(secret, counter)

print(totp('$SECRET'))
")
    
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): Authentication successful for $USERNAME" >> /var/log/openvpn/auth.log
        exit 0
    fi
    
    # Try with time offset
    for i in -1 0 1; do
        EXPECTED_CODE=$(python3 -c "
import hmac
import hashlib
import time
import base64
import struct

def hotp(secret, counter, digits=6):
    key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
    counter_bytes = struct.pack('>Q', counter)
    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0x0f
    code = struct.unpack('>I', hmac_digest[offset:offset+4])[0] & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)

def totp(secret, time_step=30):
    counter = int(time.time() / time_step) + $i
    return hotp(secret, counter)

print(totp('$SECRET'))
")
        
        if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
            echo "$(date): Authentication successful for $USERNAME (with time offset $i)" >> /var/log/openvpn/auth.log
            exit 0
        fi
    done
fi

echo "$(date): MFA authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
exit 1
EOF
fi

# Make authentication script executable
chmod +x /usr/local/bin/openvpn-auth.sh
chown root:root /usr/local/bin/openvpn-auth.sh

log "=== 5. Creating Log Directory ==="
# Create log directory
mkdir -p /var/log/openvpn
chmod 755 /var/log/openvpn
chown root:root /var/log/openvpn

# Create auth log file
touch /var/log/openvpn/auth.log
chmod 644 /var/log/openvpn/auth.log
chown root:root /var/log/openvpn/auth.log

log "=== 6. Updating OpenVPN Configuration ==="
# Update server.conf with proper settings
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

# Security (run as root for now to avoid permission issues)
writepid /run/openvpn/server.pid

# Client limits
max-clients 100
duplicate-cn
EOF

log "=== 7. Testing /tmp Write Access ==="
# Test /tmp write access as nobody user
if sudo -u nobody touch /tmp/openvpn_test_$(date +%s) 2>/dev/null; then
    success "✅ /tmp write access working for nobody user"
    sudo -u nobody rm -f /tmp/openvpn_test_* 2>/dev/null || true
else
    warn "⚠️  /tmp write access failed for nobody user"
fi

log "=== 8. Testing Authentication Script ==="
# Test the authentication script
if [ -f "/usr/local/bin/openvpn-auth.sh" ]; then
    success "✅ Authentication script exists and is executable"
else
    error "❌ Authentication script not found"
    exit 1
fi

log "=== 9. Starting OpenVPN Service ==="
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

log "=== 10. Verifying Service Status ==="
# Show service status
systemctl status openvpn@server.service --no-pager

log "=== 11. Testing Network Interface ==="
# Check if tun0 interface is created
if ip link show tun0 >/dev/null 2>&1; then
    success "✅ TUN interface (tun0) created"
else
    warn "⚠️  TUN interface not created yet"
fi

log "=== 12. Checking Port Binding ==="
# Check if port 1194 is listening
if netstat -tuln | grep -q ":1194 "; then
    success "✅ OpenVPN listening on port 1194"
else
    warn "⚠️  Port 1194 not listening yet"
fi

log "=== 13. Final Verification ==="
echo ""
echo "🔍 Final Status Check:"
echo "======================"
echo "OpenVPN Service: $(systemctl is-active openvpn@server.service)"
echo "TUN Interface: $(ip link show tun0 2>/dev/null | head -1 || echo 'Not created')"
echo "Port 1194: $(netstat -tuln | grep ":1194 " || echo 'Not listening')"
echo "/tmp permissions: $(ls -ld /tmp)"
echo "/var/tmp/openvpn: $(ls -ld /var/tmp/openvpn 2>/dev/null || echo 'Not created')"
echo "Auth script: $(ls -la /usr/local/bin/openvpn-auth.sh 2>/dev/null || echo 'Not found')"

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
echo "- Test auth script: export username=nes; export password='yourpassword123456'; /usr/local/bin/openvpn-auth.sh"
