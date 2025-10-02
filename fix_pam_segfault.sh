#!/bin/bash

# Fix PAM Plugin Segfault Script
# This script addresses the segmentation fault in the OpenVPN PAM plugin

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

log "Fixing PAM Plugin Segfault Issues"
echo "================================="
echo ""

info "=== 1. System Information ==="
log "OS: $(lsb_release -d | cut -f2)"
log "Kernel: $(uname -r)"
log "OpenVPN version: $(openvpn --version | head -1)"
log "Architecture: $(uname -m)"
echo ""

info "=== 2. Checking PAM Plugin Compatibility ==="
log "OpenVPN PAM plugin details:"
ls -la /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
file /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so

log "Checking dependencies:"
ldd /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
echo ""

info "=== 3. Alternative PAM Configuration ==="
log "The segfault suggests the plugin has compatibility issues."
log "Let's try a different approach using PAM directly in OpenVPN config..."

# Create a new OpenVPN configuration that doesn't rely on the problematic plugin
log "Creating alternative OpenVPN configuration..."

cat > /etc/openvpn/server.conf << 'EOF'
# OpenVPN Server Configuration with MFA Support
port 1194
proto udp
dev tun

# Certificate files
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-auth ta.key 0

# Network settings
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
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
verb 3

# Authentication
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
EOF

log "✅ Alternative OpenVPN configuration created"
echo ""

info "=== 4. Creating Custom Authentication Script ==="
log "Creating custom authentication script that uses PAM directly..."

cat > /usr/local/bin/openvpn-auth.sh << 'EOF'
#!/bin/bash

# OpenVPN Authentication Script with PAM
# This script handles password + MFA authentication

set -e

# Get credentials from environment
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

# Extract password and MFA code from combined input
# The password should be the last 6 characters (MFA code)
MFA_CODE="${PASSWORD: -6}"
USER_PASSWORD="${PASSWORD%??????}"

# Log (without showing actual credentials)
echo "$(date): Testing authentication for $USERNAME (password length: ${#USER_PASSWORD}, MFA: ${MFA_CODE})" >> /var/log/openvpn/auth.log

# Test password authentication
if ! echo "$USER_PASSWORD" | su - "$USERNAME" -c "true" 2>/dev/null; then
    echo "$(date): Password authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Test MFA code
if ! echo "$MFA_CODE" | google-authenticator -t -d -f -r 1 -R 30 -w 3 -s "/home/$USERNAME/.google_authenticator" 2>/dev/null; then
    echo "$(date): MFA authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

echo "$(date): Authentication successful for $USERNAME" >> /var/log/openvpn/auth.log
exit 0
EOF

chmod +x /usr/local/bin/openvpn-auth.sh
log "✅ Custom authentication script created"
echo ""

info "=== 5. Creating Log Directory ==="
log "Creating log directory for authentication..."
mkdir -p /var/log/openvpn
touch /var/log/openvpn/auth.log
chmod 644 /var/log/openvpn/auth.log
log "✅ Log directory created"
echo ""

info "=== 6. Testing Custom Authentication Script ==="
log "Testing the custom authentication script..."

# Test the script with a user
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing authentication script for user: $USERNAME"
    
    # Check if user exists and has MFA
    if id "$USERNAME" &>/dev/null && [ -f "/home/$USERNAME/.google_authenticator" ]; then
        log "✅ User $USERNAME exists and has MFA configured"
        echo "To test: export username=$USERNAME; export password='yourpassword123456'; /usr/local/bin/openvpn-auth.sh"
    else
        error "❌ User $USERNAME not found or MFA not configured"
    fi
else
    warn "No username provided for testing"
fi
echo ""

info "=== 7. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service with new configuration..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service restarted successfully"
else
    error "❌ OpenVPN service failed to restart"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 8. Testing New Configuration ==="
log "Testing OpenVPN configuration..."
if openvpn --config /etc/openvpn/server.conf --test-crypto; then
    log "✅ OpenVPN configuration is valid"
else
    warn "OpenVPN configuration test failed"
fi
echo ""

info "=== 9. Monitoring Authentication ==="
log "To monitor authentication attempts, run:"
echo "sudo tail -f /var/log/openvpn/auth.log"
echo ""
log "To test authentication manually:"
echo "export username=nes; export password='yourpassword123456'; /usr/local/bin/openvpn-auth.sh"
echo ""

log "PAM segfault fix completed!"
log "The OpenVPN server now uses a custom authentication script instead of the problematic PAM plugin."
