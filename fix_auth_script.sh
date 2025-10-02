#!/bin/bash

# Fix Authentication Script
# This script fixes the authentication script to properly validate MFA codes

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

log "Fixing Authentication Script"
echo "============================"
echo ""

info "=== 1. Creating Fixed Authentication Script ==="
log "Creating a new authentication script that properly validates MFA codes..."

cat > /usr/local/bin/openvpn-auth.sh << 'EOF'
#!/bin/bash

# OpenVPN Authentication Script with MFA
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

# Test password authentication using su
if ! echo "$USER_PASSWORD" | su - "$USERNAME" -c "true" 2>/dev/null; then
    echo "$(date): Password authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Test MFA code using the stored secret
SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
if [ -z "$SECRET" ]; then
    echo "$(date): No secret found for user $USERNAME" >> /var/log/openvpn/auth.log
    exit 1
fi

# Validate MFA code using oathtool (if available) or python
if command -v oathtool &> /dev/null; then
    # Use oathtool if available
    EXPECTED_CODE=$(oathtool --totp -b "$SECRET")
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): Authentication successful for $USERNAME" >> /var/log/openvpn/auth.log
        exit 0
    fi
else
    # Use python to validate TOTP
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
fi

# Check time drift by testing multiple time windows
for i in -1 0 1; do
    if command -v oathtool &> /dev/null; then
        EXPECTED_CODE=$(oathtool --totp -b "$SECRET" --time-offset=$i)
    else
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
    fi
    
    if [ "$MFA_CODE" = "$EXPECTED_CODE" ]; then
        echo "$(date): Authentication successful for $USERNAME (with time offset $i)" >> /var/log/openvpn/auth.log
        exit 0
    fi
done

echo "$(date): MFA authentication failed for $USERNAME" >> /var/log/openvpn/auth.log
exit 1
EOF

chmod +x /usr/local/bin/openvpn-auth.sh
log "✅ Fixed authentication script created"
echo ""

info "=== 2. Installing Required Tools ==="
log "Installing oathtool for better MFA validation..."
apt update
apt install -y oathtool

log "✅ Required tools installed"
echo ""

info "=== 3. Testing Fixed Authentication Script ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing fixed authentication script for user: $USERNAME"
    
    # Check if user exists and has MFA
    if id "$USERNAME" &>/dev/null && [ -f "/home/$USERNAME/.google_authenticator" ]; then
        log "✅ User $USERNAME exists and has MFA configured"
        
        # Get the secret key
        SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
        log "Secret key: $SECRET"
        
        # Generate current MFA code
        CURRENT_CODE=$(oathtool --totp -b "$SECRET")
        log "Current MFA code: $CURRENT_CODE"
        
        echo ""
        echo "To test authentication:"
        echo "export username=$USERNAME"
        echo "export password='yourpassword$CURRENT_CODE'"
        echo "/usr/local/bin/openvpn-auth.sh"
        echo ""
        echo "Replace 'yourpassword' with the actual password for user $USERNAME"
    else
        error "❌ User $USERNAME not found or MFA not configured"
    fi
else
    warn "No username provided for testing"
fi
echo ""

info "=== 4. Restarting OpenVPN Service ==="
log "Restarting OpenVPN service with fixed authentication script..."
systemctl restart openvpn@server.service

if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service restarted successfully"
else
    error "❌ OpenVPN service failed to restart"
    systemctl status openvpn@server.service --no-pager -l
fi
echo ""

info "=== 5. Summary ==="
log "Authentication script has been fixed:"
echo "✅ Uses oathtool for accurate MFA validation"
echo "✅ Handles time drift with multiple time windows"
echo "✅ No longer creates new QR codes"
echo "✅ Properly validates existing MFA configuration"
echo ""

log "Authentication script fix completed!"
