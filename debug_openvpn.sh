#!/bin/bash

# Debug OpenVPN service issues
# This script helps diagnose and fix OpenVPN startup problems

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

log "Debugging OpenVPN service issues..."

# Stop the service first
log "Stopping OpenVPN service..."
systemctl stop openvpn@server.service

# Check if OpenVPN config file exists
log "Checking OpenVPN configuration..."
if [ -f "/etc/openvpn/server.conf" ]; then
    log "OpenVPN config file exists"
else
    error "OpenVPN config file not found!"
    exit 1
fi

# Check if certificates exist
log "Checking certificates..."
if [ -f "/etc/openvpn/ca.crt" ]; then
    log "CA certificate exists"
else
    error "CA certificate not found!"
fi

if [ -f "/etc/openvpn/server.crt" ]; then
    log "Server certificate exists"
else
    error "Server certificate not found!"
fi

if [ -f "/etc/openvpn/server.key" ]; then
    log "Server key exists"
else
    error "Server key not found!"
fi

if [ -f "/etc/openvpn/dh2048.pem" ]; then
    log "DH parameters exist"
else
    error "DH parameters not found!"
fi

if [ -f "/etc/openvpn/ta.key" ]; then
    log "TLS-auth key exists"
else
    error "TLS-auth key not found!"
fi

# Check PAM configuration
log "Checking PAM configuration..."
if [ -f "/etc/pam.d/openvpn" ]; then
    log "PAM configuration exists"
    echo "PAM config content:"
    cat /etc/pam.d/openvpn
else
    error "PAM configuration not found!"
fi

# Check if PAM module exists
log "Checking PAM Google Authenticator module..."
if [ -f "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so" ]; then
    log "PAM Google Authenticator module exists"
else
    error "PAM Google Authenticator module not found!"
    log "Installing libpam-google-authenticator..."
    apt install -y libpam-google-authenticator
fi

# Test OpenVPN configuration
log "Testing OpenVPN configuration..."
cd /etc/openvpn
if openvpn --config server.conf --test; then
    log "OpenVPN configuration test passed"
else
    error "OpenVPN configuration test failed!"
    log "Running OpenVPN with verbose output to see errors..."
    openvpn --config server.conf --verb 4 --test
fi

# Check systemd service file
log "Checking systemd service file..."
if [ -f "/etc/systemd/system/openvpn@server.service" ]; then
    log "Systemd service file exists"
    echo "Service file content:"
    cat /etc/systemd/system/openvpn@server.service
else
    error "Systemd service file not found!"
fi

# Check if working directory exists
log "Checking working directory..."
if [ -d "/etc/openvpn/server" ]; then
    log "Working directory exists"
else
    log "Creating working directory..."
    mkdir -p /etc/openvpn/server
fi

# Check if PID directory exists
log "Checking PID directory..."
if [ -d "/run/openvpn" ]; then
    log "PID directory exists"
else
    log "Creating PID directory..."
    mkdir -p /run/openvpn
fi

# Try to start OpenVPN manually to see errors
log "Attempting to start OpenVPN manually to see errors..."
cd /etc/openvpn
timeout 10 openvpn --config server.conf --verb 3 || true

log "Debug completed. Check the output above for any errors."
