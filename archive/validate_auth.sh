#!/bin/bash

# OpenVPN Authentication Validation Script
# This script tests if password + MFA authentication works for OpenVPN users

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

# Function to test PAM authentication
test_pam_auth() {
    local username="$1"
    local password_mfa="$2"
    
    log "Testing PAM authentication for user: $username"
    
    # Test PAM authentication using google-authenticator
    echo "$password_mfa" | sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3 > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        log "✅ PAM authentication successful for $username"
        return 0
    else
        error "❌ PAM authentication failed for $username"
        return 1
    fi
}

# Function to test user exists and has MFA configured
test_user_setup() {
    local username="$1"
    
    log "Checking user setup for: $username"
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        error "❌ User $username does not exist"
        return 1
    fi
    log "✅ User $username exists"
    
    # Check if Google Authenticator is configured
    if [ ! -f "/home/$username/.google_authenticator" ]; then
        error "❌ Google Authenticator not configured for $username"
        return 1
    fi
    log "✅ Google Authenticator configured for $username"
    
    # Check if OpenVPN client config exists
    if [ ! -f "/etc/openvpn/client/$username.ovpn" ]; then
        error "❌ OpenVPN client config not found for $username"
        return 1
    fi
    log "✅ OpenVPN client config exists for $username"
    
    return 0
}

# Function to test PAM configuration
test_pam_config() {
    log "Testing PAM configuration..."
    
    # Check if PAM config exists
    if [ ! -f "/etc/pam.d/openvpn" ]; then
        error "❌ PAM configuration not found"
        return 1
    fi
    log "✅ PAM configuration exists"
    
    # Check PAM config content
    if grep -q "pam_google_authenticator" /etc/pam.d/openvpn; then
        log "✅ Google Authenticator PAM module configured"
    else
        error "❌ Google Authenticator PAM module not configured"
        return 1
    fi
    
    # Check if PAM module exists
    if [ ! -f "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so" ]; then
        error "❌ PAM Google Authenticator module not found"
        return 1
    fi
    log "✅ PAM Google Authenticator module exists"
    
    return 0
}

# Function to test OpenVPN service
test_openvpn_service() {
    log "Testing OpenVPN service..."
    
    # Check if service is running
    if systemctl is-active --quiet openvpn@server.service; then
        log "✅ OpenVPN service is running"
    else
        error "❌ OpenVPN service is not running"
        return 1
    fi
    
    # Check if port is listening
    if netstat -tulpn | grep -q ":1194"; then
        log "✅ OpenVPN port 1194 is listening"
    else
        error "❌ OpenVPN port 1194 is not listening"
        return 1
    fi
    
    return 0
}

# Main validation function
validate_auth() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Usage: $0 <username>"
        echo "Example: $0 john"
        exit 1
    fi
    
    log "Starting authentication validation for user: $username"
    echo ""
    
    # Test 1: Check user setup
    info "=== Test 1: User Setup ==="
    if ! test_user_setup "$username"; then
        error "User setup validation failed"
        exit 1
    fi
    echo ""
    
    # Test 2: Check PAM configuration
    info "=== Test 2: PAM Configuration ==="
    if ! test_pam_config; then
        error "PAM configuration validation failed"
        exit 1
    fi
    echo ""
    
    # Test 3: Check OpenVPN service
    info "=== Test 3: OpenVPN Service ==="
    if ! test_openvpn_service; then
        error "OpenVPN service validation failed"
        exit 1
    fi
    echo ""
    
    # Test 4: Interactive authentication test
    info "=== Test 4: Interactive Authentication Test ==="
    echo "Now we'll test the actual password + MFA authentication."
    echo "You'll need to enter the password + MFA code (no space between them)."
    echo "Example: if password is 'mypass123' and MFA code is '123456', enter: mypass123123456"
    echo ""
    
    read -s -p "Enter password + MFA code for $username: " password_mfa
    echo ""
    
    if [ -z "$password_mfa" ]; then
        error "No password + MFA code provided"
        exit 1
    fi
    
    if test_pam_auth "$username" "$password_mfa"; then
        log "🎉 Authentication validation successful!"
        log "User $username can connect to OpenVPN"
    else
        error "Authentication validation failed"
        error "Check your password and MFA code"
        exit 1
    fi
}

# Function to list all OpenVPN users
list_users() {
    log "OpenVPN users:"
    if [ -d "/etc/openvpn/client" ]; then
        ls -la /etc/openvpn/client/*.ovpn 2>/dev/null | awk '{print $9}' | sed 's|/etc/openvpn/client/||' | sed 's|.ovpn||' | while read user; do
            if [ -n "$user" ]; then
                echo "  - $user"
            fi
        done
    else
        warn "No OpenVPN users found"
    fi
}

# Main script logic
case "$1" in
    validate)
        validate_auth "$2"
        ;;
    list)
        list_users
        ;;
    test-user)
        if [ -z "$2" ]; then
            error "Usage: $0 test-user <username>"
            exit 1
        fi
        test_user_setup "$2"
        ;;
    test-pam)
        test_pam_config
        ;;
    test-service)
        test_openvpn_service
        ;;
    help|--help|-h)
        echo "OpenVPN Authentication Validation Script"
        echo ""
        echo "Usage: $0 <command> [username]"
        echo ""
        echo "Commands:"
        echo "  validate <username>  - Full authentication validation"
        echo "  list                 - List all OpenVPN users"
        echo "  test-user <username> - Test user setup only"
        echo "  test-pam             - Test PAM configuration only"
        echo "  test-service         - Test OpenVPN service only"
        echo "  help                 - Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 validate john"
        echo "  $0 list"
        echo "  $0 test-user john"
        ;;
    *)
        error "Invalid command. Use '$0 help' for usage information."
        ;;
esac
