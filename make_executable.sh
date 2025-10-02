#!/bin/bash

# Make all scripts executable
# This script sets proper permissions for all OpenVPN MFA setup scripts

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log "Setting up OpenVPN MFA scripts permissions..."

# Make main setup script executable
if [ -f "setup_openvpn_mfa.sh" ]; then
    chmod +x setup_openvpn_mfa.sh
    log "Made setup_openvpn_mfa.sh executable"
else
    warn "setup_openvpn_mfa.sh not found"
fi

# Make user management script executable
if [ -f "scripts/user-management.sh" ]; then
    chmod +x scripts/user-management.sh
    log "Made scripts/user-management.sh executable"
else
    warn "scripts/user-management.sh not found"
fi

# Make MFA setup script executable
if [ -f "scripts/mfa-setup.sh" ]; then
    chmod +x scripts/mfa-setup.sh
    log "Made scripts/mfa-setup.sh executable"
else
    warn "scripts/mfa-setup.sh not found"
fi

# Make this script executable
chmod +x make_executable.sh
log "Made make_executable.sh executable"

log "All scripts are now executable!"
log "You can now run the setup script with: sudo ./setup_openvpn_mfa.sh"

