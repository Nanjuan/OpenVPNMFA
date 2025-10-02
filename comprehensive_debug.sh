#!/bin/bash

# Comprehensive OpenVPN debugging script
# This script captures the exact error messages

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

log "Comprehensive OpenVPN debugging..."

# Stop the service first
systemctl stop openvpn@server.service

# Check OpenVPN configuration file
log "Checking OpenVPN configuration file..."
if [ -f "/etc/openvpn/server.conf" ]; then
    log "OpenVPN config file exists"
    echo "Configuration file content:"
    cat /etc/openvpn/server.conf
    echo ""
else
    error "OpenVPN config file not found!"
    exit 1
fi

# Check if we're in the right directory
log "Checking working directory..."
pwd
ls -la /etc/openvpn/

# Test OpenVPN configuration with maximum verbosity and capture all output
log "Testing OpenVPN configuration with maximum verbosity..."
cd /etc/openvpn

# Create a temporary log file to capture all output
TEMP_LOG="/tmp/openvpn_debug.log"

log "Running OpenVPN test and capturing all output to $TEMP_LOG..."
timeout 15 openvpn --config server.conf --verb 5 --test > "$TEMP_LOG" 2>&1 || true

# Display the captured output
log "OpenVPN test output:"
cat "$TEMP_LOG"

# Check for specific error patterns
log "Checking for specific error patterns..."

# Check if the issue is with the PAM plugin
log "Checking PAM plugin path..."
if [ -f "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so" ]; then
    log "PAM plugin exists at expected location"
else
    error "PAM plugin not found at expected location!"
    log "Searching for PAM plugin..."
    find /usr -name "openvpn-plugin-auth-pam.so" 2>/dev/null || log "PAM plugin not found anywhere"
fi

# Check if the issue is with certificate files
log "Checking certificate files in detail..."
for cert in ca.crt server.crt server.key dh2048.pem ta.key; do
    if [ -f "/etc/openvpn/$cert" ]; then
        log "Certificate $cert exists"
        ls -la "/etc/openvpn/$cert"
        # Check if certificate is valid
        if [[ "$cert" == *.crt ]]; then
            log "Checking certificate validity for $cert..."
            openssl x509 -in "/etc/openvpn/$cert" -text -noout | head -5
        fi
    else
        error "Certificate $cert not found!"
    fi
done

# Check if the issue is with the working directory in systemd service
log "Checking systemd service configuration..."
if [ -f "/etc/systemd/system/openvpn@server.service" ]; then
    log "Systemd service file exists"
    cat /etc/systemd/system/openvpn@server.service
else
    error "Systemd service file not found!"
fi

# Check if the issue is with the PID directory
log "Checking PID directory..."
if [ -d "/run/openvpn" ]; then
    log "PID directory exists"
    ls -la /run/openvpn/
else
    log "Creating PID directory..."
    mkdir -p /run/openvpn
    chmod 755 /run/openvpn
fi

# Try to run OpenVPN manually to see the exact error
log "Attempting to run OpenVPN manually to capture exact error..."
cd /etc/openvpn
timeout 15 openvpn --config server.conf --verb 4 > "$TEMP_LOG" 2>&1 || true

log "Manual OpenVPN run output:"
cat "$TEMP_LOG"

# Check for common error patterns
log "Checking for common error patterns in the log..."
if grep -q "plugin" "$TEMP_LOG"; then
    error "Plugin-related error found!"
    grep -i "plugin" "$TEMP_LOG"
fi

if grep -q "certificate" "$TEMP_LOG"; then
    error "Certificate-related error found!"
    grep -i "certificate" "$TEMP_LOG"
fi

if grep -q "permission" "$TEMP_LOG"; then
    error "Permission-related error found!"
    grep -i "permission" "$TEMP_LOG"
fi

if grep -q "file not found" "$TEMP_LOG"; then
    error "File not found error!"
    grep -i "file not found" "$TEMP_LOG"
fi

# Clean up temp file
rm -f "$TEMP_LOG"

log "Comprehensive debug completed. Check the output above for specific errors."
