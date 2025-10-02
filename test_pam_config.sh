#!/bin/bash

# Test PAM Configuration for OpenVPN
# This script verifies that PAM is properly configured

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

log "Testing PAM configuration for OpenVPN..."

echo ""
info "=== 1. Checking PAM Configuration File ==="
if [ -f "/etc/pam.d/openvpn" ]; then
    log "✅ PAM configuration file exists"
    echo "Content:"
    cat /etc/pam.d/openvpn
    echo ""
else
    error "❌ PAM configuration file not found"
    exit 1
fi

echo ""
info "=== 2. Checking PAM Module ==="
if [ -f "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so" ]; then
    log "✅ PAM Google Authenticator module exists"
    ls -la /lib/x86_64-linux-gnu/security/pam_google_authenticator.so
else
    error "❌ PAM Google Authenticator module not found"
    echo "Installing libpam-google-authenticator..."
    apt install -y libpam-google-authenticator
fi

echo ""
info "=== 3. Checking OpenVPN Plugin ==="
if [ -f "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so" ]; then
    log "✅ OpenVPN PAM plugin exists"
    ls -la /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so
else
    error "❌ OpenVPN PAM plugin not found"
    echo "This might be in a different location, searching..."
    find /usr -name "openvpn-plugin-auth-pam.so" 2>/dev/null || echo "Plugin not found"
fi

echo ""
info "=== 4. Checking OpenVPN Server Configuration ==="
if [ -f "/etc/openvpn/server.conf" ]; then
    log "✅ OpenVPN server configuration exists"
    if grep -q "plugin.*pam" /etc/openvpn/server.conf; then
        log "✅ PAM plugin configured in OpenVPN"
        grep "plugin.*pam" /etc/openvpn/server.conf
    else
        error "❌ PAM plugin not configured in OpenVPN"
    fi
else
    error "❌ OpenVPN server configuration not found"
fi

echo ""
info "=== 5. Testing PAM Configuration ==="
if [ -f "/etc/pam.d/openvpn" ]; then
    log "Testing PAM configuration syntax..."
    if pam-auth-update --package --force; then
        log "✅ PAM configuration syntax is valid"
    else
        warn "⚠️ PAM configuration might have issues"
    fi
fi

echo ""
info "=== 6. Checking OpenVPN Service ==="
if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service is running"
else
    warn "⚠️ OpenVPN service is not running"
fi

echo ""
info "=== 7. Testing PAM Authentication ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing PAM authentication for user: $USERNAME"
    
    if ! id "$USERNAME" &>/dev/null; then
        error "User $USERNAME does not exist"
    elif [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
        error "Google Authenticator not configured for $USERNAME"
    else
        log "User $USERNAME exists and has MFA configured"
        echo "To test authentication, run:"
        echo "sudo ./validate_mfa.sh $USERNAME"
    fi
else
    info "To test PAM authentication for a specific user, run:"
    echo "sudo $0 <username>"
fi

echo ""
log "PAM configuration test completed!"
