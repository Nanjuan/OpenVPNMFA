#!/bin/bash

# OpenVPN Remote Deployment Script
# This script downloads and installs OpenVPN on a remote server

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
warning() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
info() { echo -e "${BLUE}[INFO] $1${NC}"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

log "Starting OpenVPN deployment on remote server..."

# Update system
log "Updating system packages..."
apt update && apt upgrade -y

# Install dependencies
log "Installing dependencies..."
apt install -y curl wget gnupg2 software-properties-common

# Download OpenVPN installation script
log "Downloading OpenVPN installation script..."
wget -O /tmp/openvpn-server-setup.sh https://raw.githubusercontent.com/your-repo/openvpn-server-setup.sh
chmod +x /tmp/openvpn-server-setup.sh

# Run OpenVPN installation
log "Running OpenVPN installation..."
/tmp/openvpn-server-setup.sh

# Cleanup
rm -f /tmp/openvpn-server-setup.sh

log "OpenVPN deployment completed successfully!"
info "Server IP: $(curl -s ifconfig.me)"
info "VPN Port: 1194"
info "Management command: openvpn-manage"

warning "Next steps:"
warning "1. Add your first user: sudo openvpn-manage add <username>"
warning "2. Download client config: sudo cp /etc/openvpn/clients/<username>.ovpn /tmp/"
warning "3. Transfer to your local machine: scp user@server:/tmp/<username>.ovpn ~/"
