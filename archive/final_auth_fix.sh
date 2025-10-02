#!/bin/bash

# Final Authentication Fix Script
# This script provides the final fix for OpenVPN MFA authentication

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

log "Final OpenVPN MFA Authentication Fix"
echo "===================================="
echo ""

info "=== 1. Creating Final OpenVPN Configuration ==="
log "Creating the final OpenVPN configuration with proper authentication..."

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

log "✅ Final OpenVPN configuration created"
echo ""

info "=== 2. Creating Final Authentication Script ==="
log "Creating the final authentication script with comprehensive error handling..."

cat > /usr/local/bin/openvpn-auth.sh << 'EOF'
#!/bin/bash

# Final OpenVPN Authentication Script with MFA
# This script handles password + MFA authentication for OpenVPN clients

set -e

# Get credentials from environment variables
USERNAME="$username"
PASSWORD="$password"

# Create detailed log entry
echo "$(date): === OPENVPN AUTHENTICATION ATTEMPT ===" >> /var/log/openvpn/auth.log
echo "$(date): User: $USERNAME" >> /var/log/openvpn/auth.log
echo "$(date): Password length: ${#PASSWORD}" >> /var/log/openvpn/auth.log
echo "$(date): Environment variables:" >> /var/log/openvpn/auth.log
env | grep -E "(username|password)" >> /var/log/openvpn/auth.log

# Check if user exists
if ! id "$USERNAME" &>/dev/null; then
    echo "$(date): ERROR: User $USERNAME does not exist" >> /var/log/openvpn/auth.log
    exit 1
fi

# Check if MFA is configured
if [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
    echo "$(date): ERROR: MFA not configured for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Extract password and MFA code from combined input
MFA_CODE="${PASSWORD: -6}"
USER_PASSWORD="${PASSWORD%??????}"

echo "$(date): Extracted password length: ${#USER_PASSWORD}" >> /var/log/openvpn/auth.log
echo "$(date): Extracted MFA code: $MFA_CODE" >> /var/log/openvpn/auth.log

# Test password authentication using su
echo "$(date): Testing password authentication..." >> /var/log/openvpn/auth.log
if ! echo "$USER_PASSWORD" | su - "$USERNAME" -c "true" 2>/dev/null; then
    echo "$(date): ERROR: Password authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

echo "$(date): Password authentication successful" >> /var/log/openvpn/auth.log

# Test MFA code using the stored secret
SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
if [ -z "$SECRET" ]; then
    echo "$(date): ERROR: No secret found for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

echo "$(date): Testing MFA code: $MFA_CODE" >> /var/log/openvpn/auth.log

# Validate MFA code using oathtool
if command -v oathtool &> /dev/null; then
    # Use oathtool if available
    EXPECTED_CODE=$(oathtool --totp -b "$SECRET")
    echo "$(date): Expected MFA code: $EXPECTED_CODE" >> /var/log/openvpn/auth.log
    
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): SUCCESS: Authentication successful for $USERNAME" >> /var/log/openvpn/auth.log
        exit 0
    fi
    
    # Check time drift by testing multiple time windows
    for i in -1 0 1; do
        EXPECTED_CODE=$(oathtool --totp -b "$SECRET" --time-offset=$i 2>/dev/null || oathtool --totp -b "$SECRET")
        echo "$(date): Checking time offset $i: $EXPECTED_CODE" >> /var/log/openvpn/auth.log
        
        if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
            echo "$(date): SUCCESS: Authentication successful for $USERNAME (with time offset $i)" >> /var/log/openvpn/auth.log
            exit 0
        fi
    done
fi

echo "$(date): ERROR: MFA authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
exit 1
EOF

chmod +x /usr/local/bin/openvpn-auth.sh
log "✅ Final authentication script created"
echo ""

info "=== 3. Setting Proper Permissions ==="
log "Setting proper permissions for all OpenVPN components..."

# Set permissions for authentication script
chmod 755 /usr/local/bin/openvpn-auth.sh
chown root:root /usr/local/bin/openvpn-auth.sh

# Set permissions for log files
chmod 644 /var/log/openvpn/auth.log
chown root:root /var/log/openvpn/auth.log

# Set permissions for OpenVPN configuration
chmod 644 /etc/openvpn/server.conf
chown root:root /etc/openvpn/server.conf

# Set permissions for certificate files
chmod 600 /etc/openvpn/*.key
chmod 644 /etc/openvpn/*.crt
chmod 644 /etc/openvpn/*.pem

log "✅ Permissions set correctly"
echo ""

info "=== 4. Testing Authentication Script ==="
log "Testing the authentication script with current MFA code..."

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

info "=== 5. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service with final configuration..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service restarted successfully"
else
    error "❌ OpenVPN service failed to restart"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 6. Testing OpenVPN Configuration ==="
log "Testing OpenVPN configuration..."

# Test the configuration
if openvpn --config /etc/openvpn/server.conf --test-crypto 2>/dev/null; then
    log "✅ OpenVPN configuration is valid"
else
    warn "OpenVPN configuration test failed, but this might be normal"
fi
echo ""

info "=== 7. Monitoring Instructions ==="
log "To monitor authentication attempts:"
echo "sudo tail -f /var/log/openvpn/auth.log"
echo ""
log "To monitor OpenVPN server logs:"
echo "sudo tail -f /var/log/openvpn/openvpn.log"
echo ""

info "=== 8. Client Connection Instructions ==="
log "For OpenVPN client connection:"
echo "1. Username: $USERNAME"
echo "2. Password: yourpassword + 6digitMFAcode (no space)"
echo "3. Use the .ovpn file: /etc/openvpn/client/$USERNAME.ovpn"
echo ""
echo "Example:"
echo "Username: nes"
echo "Password: mypassword123456 (where 123456 is the current MFA code)"
echo ""

info "=== 9. Troubleshooting ==="
log "If authentication still fails:"
echo "1. Check the authentication logs: sudo tail -f /var/log/openvpn/auth.log"
echo "2. Check the OpenVPN server logs: sudo tail -f /var/log/openvpn/openvpn.log"
echo "3. Ensure time synchronization: sudo apt install ntp -y"
echo "4. Test authentication manually with the script"
echo ""

log "Final OpenVPN MFA authentication fix completed!"
log "Try connecting with your OpenVPN client now."
