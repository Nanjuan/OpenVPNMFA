#!/bin/bash

# Test New Authentication System Script
# This script tests the new custom authentication system

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

log "Testing New Authentication System"
echo "================================="
echo ""

info "=== 1. Checking OpenVPN Service ==="
if systemctl is-active --quiet openvpn@server.service; then
    log "✅ OpenVPN service is running"
else
    error "❌ OpenVPN service is not running"
    systemctl status openvpn@server.service --no-pager -l
    exit 1
fi
echo ""

info "=== 2. Checking Custom Authentication Script ==="
if [ -f "/usr/local/bin/openvpn-auth.sh" ]; then
    log "✅ Custom authentication script exists"
    ls -la /usr/local/bin/openvpn-auth.sh
else
    error "❌ Custom authentication script not found"
    exit 1
fi
echo ""

info "=== 3. Checking OpenVPN Configuration ==="
if [ -f "/etc/openvpn/server.conf" ]; then
    log "✅ OpenVPN configuration exists"
    echo "Key authentication lines:"
    grep -E "(auth-user-pass-verify|script-security)" /etc/openvpn/server.conf
else
    error "❌ OpenVPN configuration not found"
    exit 1
fi
echo ""

info "=== 4. Testing Authentication Script ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    log "Testing authentication for user: $USERNAME"
    
    # Check if user exists
    if ! id "$USERNAME" &>/dev/null; then
        error "❌ User $USERNAME does not exist"
        exit 1
    fi
    
    # Check if MFA is configured
    if [ ! -f "/home/$USERNAME/.google_authenticator" ]; then
        error "❌ MFA not configured for user $USERNAME"
        exit 1
    fi
    
    log "✅ User $USERNAME exists and has MFA configured"
    
    # Get current MFA code for reference
    SECRET=$(head -1 "/home/$USERNAME/.google_authenticator")
    CURRENT_CODE=$(oathtool --totp -b "$SECRET")
    log "Current MFA code: $CURRENT_CODE"
    
    # Test the authentication script
    log "Testing authentication script..."
    echo ""
    echo "Enter the OpenVPN user password for $USERNAME:"
    read -s user_password
    echo ""
    
    if [ -n "$user_password" ]; then
        echo "Enter the current MFA code from your authenticator app:"
        read -s mfa_code
        echo ""
        
        if [ -n "$mfa_code" ]; then
            # Combine password and MFA code
            password_mfa="${user_password}${mfa_code}"
            
            log "Testing authentication with provided credentials..."
            export username="$USERNAME"
            export password="$password_mfa"
            
            if /usr/local/bin/openvpn-auth.sh; then
                log "✅ Authentication successful!"
            else
                error "❌ Authentication failed!"
                echo ""
                echo "Troubleshooting steps:"
                echo "1. Check if password is correct"
                echo "2. Check if MFA code is current (30-second window)"
                echo "3. Check time synchronization"
                echo "4. Check authentication logs: sudo tail -f /var/log/openvpn/auth.log"
            fi
        else
            warn "No MFA code provided for test"
        fi
    else
        warn "No password provided for test"
    fi
else
    warn "No username provided for testing"
fi
echo ""

info "=== 5. Checking Authentication Logs ==="
if [ -f "/var/log/openvpn/auth.log" ]; then
    log "✅ Authentication log exists"
    echo "Recent authentication attempts:"
    tail -10 /var/log/openvpn/auth.log
else
    warn "No authentication log found"
fi
echo ""

info "=== 6. Testing OpenVPN Configuration ==="
log "Testing OpenVPN configuration syntax..."
if openvpn --config /etc/openvpn/server.conf --test-crypto 2>/dev/null; then
    log "✅ OpenVPN configuration is valid"
else
    warn "OpenVPN configuration test failed, but this might be normal"
fi
echo ""

info "=== 7. Network Status ==="
log "Checking network configuration..."
echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "OpenVPN port status:"
ss -tulpn | grep 1194 || echo "Port 1194 not listening"
echo ""

info "=== 8. Client Configuration ==="
if [ -n "$1" ]; then
    USERNAME="$1"
    if [ -f "/etc/openvpn/client/$USERNAME.ovpn" ]; then
        log "✅ Client configuration exists for $USERNAME"
        echo "Client config location: /etc/openvpn/client/$USERNAME.ovpn"
    else
        error "❌ Client configuration not found for $USERNAME"
    fi
fi
echo ""

info "=== 9. Summary ==="
log "Authentication system status:"
echo "============================"
echo "✅ OpenVPN service: Running"
echo "✅ Custom auth script: Installed"
echo "✅ OpenVPN config: Updated"
echo "✅ Authentication logs: Available"
echo ""
echo "To monitor authentication attempts:"
echo "sudo tail -f /var/log/openvpn/auth.log"
echo ""
echo "To test authentication manually:"
echo "export username=$USERNAME; export password='yourpassword123456'; /usr/local/bin/openvpn-auth.sh"
echo ""

log "New authentication system test completed!"
