#!/bin/bash

# Fix Easy-RSA 3.x compatibility issues
# This script properly handles Easy-RSA 3.x commands

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
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "Fixing Easy-RSA 3.x compatibility issues..."

# Remove existing Easy-RSA directory and recreate
log "Removing existing Easy-RSA directory..."
rm -rf /etc/openvpn/easy-rsa

# Create new Easy-RSA directory
log "Creating new Easy-RSA directory..."
make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Configure Easy-RSA for Easy-RSA 3.x
log "Configuring Easy-RSA 3.x..."
cat > vars << 'EOF'
set_var EASYRSA_REQ_COUNTRY "US"
set_var EASYRSA_REQ_PROVINCE "CA"
set_var EASYRSA_REQ_CITY "SanFrancisco"
set_var EASYRSA_REQ_ORG "OpenVPN"
set_var EASYRSA_REQ_EMAIL "admin@example.com"
set_var EASYRSA_REQ_OU "IT"
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 3650
set_var EASYRSA_CRL_DAYS 60
EOF

# Initialize PKI for Easy-RSA 3.x
log "Initializing PKI for Easy-RSA 3.x..."
./easyrsa init-pki

# Build CA
log "Building Certificate Authority..."
./easyrsa build-ca nopass

# Build server certificate
log "Building server certificate..."
./easyrsa build-server-full server nopass

# Generate Diffie-Hellman parameters
log "Generating Diffie-Hellman parameters..."
./easyrsa gen-dh

# Generate TLS-auth key
log "Generating TLS-auth key..."
openvpn --genkey --secret ta.key

# Move certificates to proper locations
log "Moving certificates to proper locations..."
cp pki/ca.crt /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/dh.pem /etc/openvpn/dh2048.pem
cp ta.key /etc/openvpn/

# Set proper permissions
chmod 600 /etc/openvpn/server.key
chmod 600 /etc/openvpn/ta.key
chmod 644 /etc/openvpn/ca.crt
chmod 644 /etc/openvpn/server.crt
chmod 644 /etc/openvpn/dh2048.pem

log "Easy-RSA 3.x setup completed successfully!"
log "Certificates generated and moved to proper locations."
log "You can now continue with the OpenVPN setup."
