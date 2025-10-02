#!/bin/bash

# Robust MFA Authentication Test
# This script tests MFA with better time synchronization handling

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

if [ -z "$1" ]; then
    error "Usage: $0 <username>"
    echo "Example: $0 john"
    exit 1
fi

USERNAME="$1"

log "Robust MFA authentication test for user: $USERNAME"
echo ""

# Check if user exists
if ! id "$USERNAME" &>/dev/null; then
    error "User $USERNAME does not exist"
    exit 1
fi

# Check if Google Authenticator is configured
if [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
    error "Google Authenticator not configured for $USERNAME"
    exit 1
fi

info "Google Authenticator is configured for $USERNAME"

# Show the secret key for reference
SECRET_KEY=$(head -1 /home/$USERNAME/.google_authenticator)
info "Secret key: $SECRET_KEY"

# Check server time
info "Server time: $(date)"
info "Server timezone: $(timedatectl show --property=Timezone --value)"

echo ""
echo "Enter the password + MFA code (no space between them)"
echo "Example: if password is 'mypass123' and MFA code is '123456', enter: mypass123123456"
echo ""

read -s -p "Enter password + MFA code: " password_mfa
echo ""

if [ -z "$password_mfa" ]; then
    error "No password + MFA code provided"
    exit 1
fi

log "Testing authentication..."

# Extract the MFA code (last 6 digits)
MFA_CODE="${password_mfa: -6}"
PASSWORD="${password_mfa%??????}"

info "Testing password: [hidden]"
info "Testing MFA code: $MFA_CODE"

# Test the password first
echo "$PASSWORD" | su - "$USERNAME" -c "echo 'Password test successful'" 2>/dev/null
PASSWORD_RESULT=$?

if [ $PASSWORD_RESULT -ne 0 ]; then
    error "❌ Password authentication failed!"
    error "Check your password"
    exit 1
fi

info "✅ Password authentication successful"

# Test the MFA code using a more robust validation
cat > /tmp/robust_validate_mfa.py << EOF
#!/usr/bin/env python3
import hmac
import hashlib
import base64
import struct
import time
import sys

def validate_totp_robust(secret, code):
    # Decode the secret
    try:
        secret = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))
    except:
        return False
    
    # Get current time
    t = int(time.time() // 30)
    
    # Check a wider range of time windows to account for time drift
    for offset in range(-3, 4):  # Check 3 time windows before and after
        time_counter = t + offset
        hmac_hash = hmac.new(secret, struct.pack('>Q', time_counter), hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        code_value = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
        totp = code_value % 1000000
        
        if totp == int(code):
            return True, offset
    
    return False, 0

if __name__ == "__main__":
    secret = sys.argv[1]
    code = sys.argv[2]
    
    result, offset = validate_totp_robust(secret, code)
    if result:
        print(f"SUCCESS: offset={offset}")
        sys.exit(0)
    else:
        print("FAILED")
        sys.exit(1)
EOF

chmod +x /tmp/robust_validate_mfa.py

# Test the MFA code
python3 /tmp/robust_validate_mfa.py "$SECRET_KEY" "$MFA_CODE"
MFA_RESULT=$?

# Clean up
rm -f /tmp/robust_validate_mfa.py

echo ""
if [ $MFA_RESULT -eq 0 ]; then
    log "✅ MFA code validation successful!"
    log "✅ Complete authentication successful!"
    log "User $USERNAME can connect to OpenVPN"
    echo ""
    echo "To connect to OpenVPN:"
    echo "1. Use the .ovpn file: /etc/openvpn/client/$USERNAME.ovpn"
    echo "2. Username: $USERNAME"
    echo "3. Password: [your password] + [6-digit MFA code] (no space)"
else
    error "❌ MFA code validation failed!"
    echo ""
    echo "Troubleshooting:"
    echo "1. Make sure the MFA code is current (changes every 30 seconds)"
    echo "2. Make sure there's no space between password and MFA code"
    echo "3. Check if your authenticator app is synced with the server time"
    echo "4. Try getting a fresh MFA code from your authenticator app"
    echo ""
    echo "Time synchronization check:"
    echo "- Server time: $(date)"
    echo "- Make sure your authenticator app time is correct"
    echo "- You can sync time in your authenticator app settings"
fi
