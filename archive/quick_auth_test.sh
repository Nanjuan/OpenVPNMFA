#!/bin/bash

# Quick OpenVPN Authentication Test
# This script quickly tests if password + MFA authentication works

set -e

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
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

log "Testing authentication for user: $USERNAME"
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

log "Testing PAM authentication..."

# Test PAM authentication using google-authenticator
echo "$password_mfa" | sudo -u "$USERNAME" google-authenticator -t -d -f -r 3 -R 30 -w 3 2>&1
AUTH_RESULT=$?

echo ""
if [ $AUTH_RESULT -eq 0 ]; then
    log "✅ Authentication successful!"
    log "User $USERNAME can connect to OpenVPN"
    echo ""
    echo "To connect to OpenVPN:"
    echo "1. Use the .ovpn file: /etc/openvpn/client/$USERNAME.ovpn"
    echo "2. Username: $USERNAME"
    echo "3. Password: [your password] + [6-digit MFA code] (no space)"
else
    error "❌ Authentication failed!"
    error "Check your password and MFA code"
    echo ""
    echo "Troubleshooting:"
    echo "1. Make sure the password is correct"
    echo "2. Make sure the MFA code is current (changes every 30 seconds)"
    echo "3. Make sure there's no space between password and MFA code"
    echo "4. Check if Google Authenticator is properly configured for $USERNAME"
    echo ""
    echo "Debug information:"
    echo "Exit code: $AUTH_RESULT"
fi
