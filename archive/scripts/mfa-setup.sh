#!/bin/bash

# Google Authenticator MFA Setup Script for OpenVPN
# This script helps users set up MFA for OpenVPN authentication

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Function to setup MFA for a user
setup_mfa() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Setting up MFA for user: $username"
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        error "User $username does not exist"
    fi
    
    # Check if Google Authenticator is already configured
    if [ -f "/home/${username}/.google_authenticator" ]; then
        warn "Google Authenticator is already configured for $username"
        read -p "Do you want to reconfigure? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "MFA setup cancelled"
            return
        fi
        
        # Backup existing configuration
        cp "/home/${username}/.google_authenticator" "/home/${username}/.google_authenticator.backup.$(date +%Y%m%d_%H%M%S)"
        log "Existing configuration backed up"
    fi
    
    # Set up Google Authenticator
    log "Configuring Google Authenticator for $username..."
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    # Display QR code
    log "QR code for Google Authenticator setup:"
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
    
    log "MFA setup completed for $username"
    log "Please scan the QR code with your authenticator app"
    log "Test the setup by running: $0 test $username"
}

# Function to test MFA for a user
test_mfa() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Testing MFA for user: $username"
    
    # Check if Google Authenticator is configured
    if [ ! -f "/home/${username}/.google_authenticator" ]; then
        error "Google Authenticator is not configured for $username"
    fi
    
    # Test authentication
    log "Please enter your password + MFA code (no space between them)"
    log "Example: if your password is 'mypass123' and MFA code is '123456', enter: mypass123123456"
    
    # Read password + MFA code
    read -s -p "Enter password + MFA code: " password_mfa
    echo
    
    # Test with PAM
    echo "$password_mfa" | sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    if [ $? -eq 0 ]; then
        log "MFA test successful for $username"
    else
        error "MFA test failed for $username"
    fi
}

# Function to show MFA status
show_mfa_status() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "MFA status for user: $username"
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        error "User $username does not exist"
    fi
    
    # Check if Google Authenticator is configured
    if [ -f "/home/${username}/.google_authenticator" ]; then
        echo "  Google Authenticator: CONFIGURED"
        
        # Show configuration details
        echo "  Configuration details:"
        echo "    - Time-based: $(grep -c "^T" /home/${username}/.google_authenticator || echo "No")"
        echo "    - Counter-based: $(grep -c "^H" /home/${username}/.google_authenticator || echo "No")"
        echo "    - Emergency codes: $(grep -c "^R" /home/${username}/.google_authenticator || echo "No")"
        
        # Show QR code
        log "QR code for Google Authenticator:"
        sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
    else
        echo "  Google Authenticator: NOT CONFIGURED"
        log "Run: $0 setup $username"
    fi
}

# Function to reset MFA
reset_mfa() {
    local username="$1"
    
    if [ -z "$username" ]; then
        error "Username is required"
    fi
    
    log "Resetting MFA for user: $username"
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        error "User $username does not exist"
    fi
    
    # Backup existing configuration
    if [ -f "/home/${username}/.google_authenticator" ]; then
        cp "/home/${username}/.google_authenticator" "/home/${username}/.google_authenticator.backup.$(date +%Y%m%d_%H%M%S)"
        log "Existing configuration backed up"
    fi
    
    # Remove existing configuration
    rm -f "/home/${username}/.google_authenticator"
    
    # Set up new Google Authenticator
    log "Setting up new Google Authenticator for $username..."
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    # Display QR code
    log "New QR code for Google Authenticator setup:"
    sudo -u "$username" google-authenticator -t -d -f -r 3 -R 30 -w 3 -q
    
    log "MFA reset completed for $username"
    log "Please scan the new QR code with your authenticator app"
}

# Function to show help
show_help() {
    echo "Google Authenticator MFA Setup Script for OpenVPN"
    echo ""
    echo "Usage: $0 <command> [username]"
    echo ""
    echo "Commands:"
    echo "  setup <username>         - Setup MFA for user"
    echo "  test <username>          - Test MFA for user"
    echo "  status <username>        - Show MFA status"
    echo "  reset <username>         - Reset MFA for user"
    echo "  help                     - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 setup john"
    echo "  $0 test john"
    echo "  $0 status john"
    echo "  $0 reset john"
    echo ""
    echo "Authentication Format:"
    echo "  When connecting to OpenVPN, enter your password + MFA code"
    echo "  Example: if password is 'mypass123' and MFA code is '123456'"
    echo "  Enter: mypass123123456 (no space between password and MFA code)"
}

# Main script logic
case "$1" in
    setup)
        setup_mfa "$2"
        ;;
    test)
        test_mfa "$2"
        ;;
    status)
        show_mfa_status "$2"
        ;;
    reset)
        reset_mfa "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        error "Invalid command. Use '$0 help' for usage information."
        ;;
esac

