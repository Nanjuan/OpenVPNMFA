#!/bin/bash

# Debug OpenVPN Authentication Script
# This script debugs why OpenVPN authentication is failing

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

log "Debugging OpenVPN Authentication"
echo "==============================="
echo ""

info "=== 1. Checking OpenVPN Configuration ==="
log "Current OpenVPN server configuration:"
cat /etc/openvpn/server.conf
echo ""

info "=== 2. Checking Authentication Script ==="
log "Authentication script content:"
cat /usr/local/bin/openvpn-auth.sh
echo ""

info "=== 3. Testing Authentication Script Manually ==="
log "Testing authentication script with environment variables..."

# Test the script with environment variables
export username="nes"
export password="testpassword123456"  # Replace with actual password + MFA

log "Testing with username: $username"
log "Testing with password: ${password:0:11}******"  # Hide MFA part

if /usr/local/bin/openvpn-auth.sh; then
    log "✅ Authentication script works manually"
else
    error "❌ Authentication script failed manually"
fi
echo ""

info "=== 4. Checking OpenVPN Logs ==="
log "Recent OpenVPN server logs:"
tail -20 /var/log/openvpn/openvpn.log
echo ""

info "=== 5. Checking Authentication Logs ==="
log "Recent authentication logs:"
tail -10 /var/log/openvpn/auth.log
echo ""

info "=== 6. Testing OpenVPN Configuration ==="
log "Testing OpenVPN configuration syntax..."
if openvpn --config /etc/openvpn/server.conf --test-crypto 2>&1; then
    log "✅ OpenVPN configuration is valid"
else
    warn "OpenVPN configuration test failed"
fi
echo ""

info "=== 7. Checking Script Permissions ==="
log "Authentication script permissions:"
ls -la /usr/local/bin/openvpn-auth.sh
echo ""

info "=== 8. Creating Enhanced Authentication Script ==="
log "Creating an enhanced authentication script with better debugging..."

cat > /usr/local/bin/openvpn-auth.sh << 'EOF'
#!/bin/bash

# Enhanced OpenVPN Authentication Script with MFA
# This script handles password + MFA authentication with detailed logging

set -e

# Get credentials from environment
USERNAME="$username"
PASSWORD="$password"

# Create detailed log entry
echo "$(date): === AUTHENTICATION ATTEMPT ===" >> /var/log/openvpn/auth.log
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
        EXPECTED_CODE=$(oathtool --totp -b "$SECRET" --time-offset=$i)
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
log "✅ Enhanced authentication script created"
echo ""

info "=== 9. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service with enhanced authentication script..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service restarted successfully"
else
    error "❌ OpenVPN service failed to restart"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 10. Testing Enhanced Authentication ==="
log "Testing enhanced authentication script..."

# Test with a real user
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing enhanced authentication for user: $USERNAME"
    
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

info "=== 11. Monitoring Instructions ==="
log "To monitor authentication attempts:"
echo "sudo tail -f /var/log/openvpn/auth.log"
echo ""
log "To monitor OpenVPN server logs:"
echo "sudo tail -f /var/log/openvpn/openvpn.log"
echo ""

log "OpenVPN authentication debugging completed!"
